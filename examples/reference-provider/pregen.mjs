// The PRE-GEN side of the reference provider: configuration, the directory, signed messages and bind.
// The app's workers and the self-check adapter both use this module, so the self-check runs the same code.
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
// In your own project: `npm install @pregen/verify` and import from "@pregen/verify".
import * as pg from "../../packages/verify-js/index.js";

export { pg };
export const TEST_DIRECTORY = "https://www.pregen.org/test/registries.json";              // docs/provider.md step 9
export const TEST_STEWARD = "78c95e45a79c5e271fdec762b92c2ec1b27d6d08e512b7a94779de2429868ef0";
export const PROFILE = "likeness/1";

export class Unavailable extends Error {}                  // network error, timeout, 5xx or 429 after retries

export const sha256 = (data) => createHash("sha256").update(data).digest("hex");
const b64url = (buf) => Buffer.from(buf).toString("base64url");
const now = () => Math.floor(Date.now() / 1000);

// PG-CODE.md §4: the check character. The JS library validates a code's shape (normalizeCode) but does not mint one.
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ", CHECK = ALPHABET + "*~$=!";
export function mintCode(prefix, serial) {
  const digits = String(serial).padStart(6, "0");
  const sum = [...prefix + digits].reduce((s, c, i) => s + ALPHABET.indexOf(c) * (i + 1), 0);
  return `PG-${prefix}-${digits}${CHECK[sum % 37]}`;
}

/** Flags shared by the app and the self-check adapter. Production is the default; --sandbox is explicit. */
export function parseConfig(argv) {
  const { values: v } = parseArgs({ args: argv, allowPositionals: true, options: {
    sandbox: { type: "boolean", default: false },
    "provider-url": { type: "string" }, name: { type: "string", default: "Reference Provider" },
    authority: { type: "string" }, "key-file": { type: "string" },
    directory: { type: "string" }, steward: { type: "string" },
    data: { type: "string" }, port: { type: "string" }, workers: { type: "string", default: "2" },
    "tls-cert": { type: "string" }, "tls-key": { type: "string" }, "give-back": { type: "string" },
  } });
  const sandbox = v.sandbox;
  const port = Number(v.port ?? (sandbox ? 8443 : 3000));
  if (!sandbox && (v.directory || v.steward)) {
    throw new Error("--directory and --steward are for --sandbox only: production uses the PRE-GEN directory and steward key");
  }
  const cfg = {
    sandbox, port, name: v.name, workers: Number(v.workers), giveBack: v["give-back"],
    // provider-identity.md: https:// + your registrable domain. A sandbox also takes localhost and a port.
    providerUrl: v["provider-url"] ?? (sandbox ? `https://localhost:${port}` : undefined),
    authority: v.authority ?? (sandbox ? "TEST" : undefined),
    directoryUrl: v.directory ?? (sandbox ? TEST_DIRECTORY : pg.DIRECTORY_URL),
    steward: v.steward ?? (sandbox ? TEST_STEWARD : pg.STEWARD_PUBLIC_KEY_HEX),
    data: v.data ?? (sandbox ? "data-sandbox" : "data"),             // test and production never share a file
    tls: v["tls-cert"] && v["tls-key"] ? { cert: readFileSync(v["tls-cert"]), key: readFileSync(v["tls-key"]) } : null,
  };
  if (!cfg.providerUrl) throw new Error("production needs --provider-url https://<your domain>");
  pg.checkProviderUrl(cfg.providerUrl, { allowPort: sandbox });
  if (!cfg.authority || !/^[A-Z]{4}$/.test(cfg.authority)) throw new Error("--authority is the four-letter prefix of the registry that holds your creators' licences");
  mkdirSync(cfg.data, { recursive: true });
  // The provider key comes from your secret store: an env var or a file. Never from code, never asked for in a form.
  cfg.key = process.env.PREGEN_PROVIDER_KEY_HEX?.trim() || (v["key-file"] && readFileSync(v["key-file"], "utf8").trim());
  if (!cfg.key) {
    if (!sandbox) throw new Error("production needs PREGEN_PROVIDER_KEY_HEX or --key-file");
    const file = join(cfg.data, "sandbox-provider.key");             // a throwaway test key, never a production one
    if (!existsSync(file)) { writeFileSync(file, pg.newPrivateKeyHex() + "\n"); chmodSync(file, 0o600); }
    cfg.key = readFileSync(file, "utf8").trim();
  }
  return cfg;
}

/** The client: everything that talks to registries. */
export async function openPregen(cfg) {
  const keyId = await pg.fingerprint(await pg.publicKeyHex(cfg.key));
  const signers = [{ role: "provider", key_id: keyId }];
  const redirectUri = cfg.providerUrl + "/callback";
  const party = await pg.partyDocument(cfg.providerUrl, cfg.name, cfg.key,
    { redirectUris: [redirectUri], bindInitiateUri: cfg.providerUrl + "/bind/initiate" });
  const http = (url, init = {}) => fetch(url, { ...init, redirect: "error", signal: AbortSignal.timeout(10_000) });
  const testing = cfg.sandbox;           // sandbox.md: a sandbox answer is accepted only when testing, under a test directory

  // PRE-GEN-CORE.md rule 2: load the directory at least every 24 hours, never accept an older sequence.
  const saved = join(cfg.data, "directory.json");
  let dir = null;
  async function directory() {
    if (dir && now() - dir.loadedAt < 3600) return dir;
    const previous = dir?.toJSON() ?? (existsSync(saved) ? JSON.parse(readFileSync(saved, "utf8")) : undefined);
    dir = await pg.loadDirectory({ url: cfg.directoryUrl, previous, minSequence: previous?.sequence ?? 0,
      stewardPublicKeyHex: cfg.steward, fetch: http });
    writeFileSync(saved, JSON.stringify(dir.toJSON()));
    return dir;
  }

  async function registry(prefix) {
    const r = (await directory()).registries.find((x) => x.prefix === prefix);
    if (!r || r.revoked) throw new Error(`no listed registry has the prefix ${prefix}`);
    return r;
  }

  async function getJson(url, headers = {}) {
    let res;
    try { res = await http(url, { headers }); } catch (e) { throw new Unavailable(`${url}: ${e.message}`); }
    if (res.status >= 500 || res.status === 429) throw new Unavailable(`${url}: HTTP ${res.status}`);
    return { status: res.status, body: await res.json().catch(() => ({})) };
  }

  // The same bytes, at most 3 sends (docs/provider.md, Complete example): a retry gets the same answer (jobs.md).
  async function post(url, payload, headers = {}) {
    const data = JSON.stringify(payload);
    for (let i = 0; ; i++) {
      try {
        const res = await http(url, { method: "POST", body: data,
          headers: { "Content-Type": "application/json", "X-Provider-ID": cfg.providerUrl, ...headers } });
        if (res.status < 500 && res.status !== 429) return { status: res.status, body: await res.json().catch(() => ({})) };
        if (i === 2) throw new Unavailable(`${url}: HTTP ${res.status}`);
      } catch (e) {
        if (e instanceof Unavailable) throw e;
        if (i === 2) throw new Unavailable(`${url}: ${e.message}`);
      }
      await new Promise((r) => setTimeout(r, 1000 * (i + 1)));
    }
  }

  // provider-identity.md, Sandboxes: a laptop has no domain, so a sandbox takes the party document by post.
  // A production registry reads it from https://<your domain>/.well-known/pregen-party.json instead.
  const introduced = new Set();
  async function introduce(entry) {
    if (!cfg.sandbox || introduced.has(entry.prefix)) return;
    const r = await post(entry.api + "/v2/sandbox/party", party);
    if (r.status === 401) throw new Error(`${entry.api} already pinned another key for ${cfg.providerUrl}: start with another --port or --provider-url`);
    if (r.status !== 200) throw new Error(`${entry.api}/v2/sandbox/party: HTTP ${r.status} ${r.body.error ?? ""}`);
    introduced.add(entry.prefix);
  }

  // A message signed by the registry of `prefix`, with a key the directory lists for it (core rule 2). The library
  // checks a key by code, so we name the prefix by its serial-1 code.
  async function registrySigned(env, type, prefix) {
    const body = env?.body;
    if (env?.type !== type || body?.signers?.length !== 1 || body.signers[0].role !== "registry" || env.signatures?.length !== 1) {
      throw new Error(`not a ${type} signed by one registry key`);
    }
    const key = await (await directory()).publicKey(mintCode(prefix, 1), body.signers[0].key_id,
      { fetch: http, at: body.issued_at ?? body.received_at });
    if (!(await pg.verifyBytes(key, env.signatures[0], pg.signingInput(type, body)))) throw new Error(`bad ${type} signature`);
    return body;
  }

  async function signRequest({ code, use, jobId, jobHash, licenseeId, terms }) {
    return pg.signEnvelope("pg.request.v1", { signers, subject_ref: code, provider_id: cfg.providerUrl, profile: PROFILE,
      use, job_id: jobId, job_hash: jobHash, ...(licenseeId ? { licensee_id: licenseeId } : {}), ...(terms ? { terms } : {}) }, cfg.key);
  }

  /** Core rule 3. Returns {answer, body} (verified, any status) or {error, status}. Throws Unavailable. */
  async function ask(request) {
    const entry = (await directory()).registryFor(request.body.subject_ref);
    if (!entry || entry.revoked) return { error: "NO_REGISTRY", status: 0 };
    await introduce(entry);
    const r = await post(entry.api + "/v2/requests", request);
    if (r.status !== 200 || !r.body.answer) return { error: r.body.error ?? `HTTP ${r.status}`, status: r.status };
    // Core rule 5: an answer that does not verify counts as never received.
    const body = await pg.verifyAnswer(r.body.answer, request, { directory: await directory(), fetch: http, testing });
    return { answer: r.body.answer, body };
  }

  /** jobs.md X-3: just before generating, the allow must still be valid. Throws otherwise. */
  async function checkAllow(answer, request) {
    return pg.checkAnswer(answer, request, { directory: await directory(), fetch: http, testing });
  }

  async function makeReport(request, answer, outcome, outputHash, occurredAt) {      // reports.md
    return pg.signEnvelope("pg.report.v1", { signers, request_id: await pg.messageId("pg.request.v1", request.body),
      answer: await pg.messageId("pg.answer.v1", answer.body), job_id: request.body.job_id, outcome,
      output_hash: outputHash, occurred_at: occurredAt }, cfg.key);
  }

  /** reports.md: filed only when an acknowledgement for exactly this report verifies (X-6). Returns the ack. */
  async function fileReport(code, report) {
    const entry = (await directory()).registryFor(code);
    const r = await post(entry.api + "/v2/reports", report);
    if (r.status !== 200 || !r.body.ack) throw new Error(`report refused: ${r.body.error ?? `HTTP ${r.status}`}`);
    const ack = await registrySigned(r.body.ack, "pg.report_ack.v1", entry.prefix);
    if (ack.report !== (await pg.messageId("pg.report.v1", report.body))) throw new Error("the acknowledgement names another report");
    return r.body.ack;
  }

  /** proof.md: the registry's part of the proof, found by the report id, checked against the file's SHA-256. */
  async function fetchProof(code, report, outputSha256) {
    const entry = (await directory()).registryFor(code);
    const id = (await pg.messageId("pg.report.v1", report.body)).slice(0, 16);
    const r = await getJson(`${entry.api}/v2/proofs/${id}`);
    if (r.status !== 200) throw new Error(`proof: HTTP ${r.status} ${r.body.error ?? ""}`);
    await pg.checkProof(r.body, { directory: await directory(), fetch: http, outputSha256, testing });
    return r.body;
  }

  // ── bind.md: a creator connects their licence ──
  async function bindEndpoints(prefix) {
    const entry = await registry(prefix);              // from the verified directory: never a document we did not choose
    const r = await getJson(entry.api + "/.well-known/pregen-registry.json");
    const b = r.body.bind;
    if (r.status !== 200 || r.body.prefix !== prefix || !(r.body.extensions ?? []).includes("bind")
        || !/^https:\/\//.test(b?.authorize ?? "") || !/^https:\/\//.test(b?.token ?? "")) {
      throw new Error(`${entry.name} does not offer bind`);
    }
    return { entry, ...b };
  }

  /** Step 1: OAuth 2.0 code + PKCE S256 + state. The caller stores state and verifier with the account. */
  async function bindStart(prefix, hint) {
    const { entry, authorize } = await bindEndpoints(prefix);
    await introduce(entry);
    const verifier = b64url(randomBytes(32)), state = b64url(randomBytes(16));
    const q = new URLSearchParams({ response_type: "code", client_id: cfg.providerUrl, redirect_uri: redirectUri, state,
      code_challenge: b64url(createHash("sha256").update(verifier).digest()), code_challenge_method: "S256",
      ...(hint ? { hint } : {}) });
    return { url: `${authorize}?${q}`, state, verifier };
  }

  /** Steps 4-5: the signed exchange; returns the registry's pg.binding.v1, verified. */
  async function bindExchange(prefix, code, verifier) {
    const { token } = await bindEndpoints(prefix);
    const env = await pg.signEnvelope("pg.bind_exchange.v1", { signers, provider_id: cfg.providerUrl, code,
      code_verifier: verifier, redirect_uri: redirectUri, issued_at: now() }, cfg.key);
    const r = await post(token, env);
    if (r.status !== 200 || !r.body.binding) throw new Error(`bind: ${r.body.error ?? `HTTP ${r.status}`}`);
    const b = await registrySigned(r.body.binding, "pg.binding.v1", prefix);
    if (b.authority !== prefix || b.provider_id !== cfg.providerUrl || typeof b.licensee_id !== "string"
        || !(b.expires_at > now()) || b.issued_at > now() + 60) throw new Error("the binding is not for this app and authority");
    return r.body.binding;
  }

  /** bind.md "What the person holds": {grants} or {error: "PG_NOT_BOUND"}. Throws Unavailable. */
  async function grants(prefix, licenseeId) {
    const entry = await registry(prefix);
    const path = `/v2/grants?licensee_id=${encodeURIComponent(licenseeId)}`;
    const access = await pg.pgAccess(cfg.providerUrl, cfg.key, entry.api, "GET", path);   // path includes the query
    const r = await getJson(entry.api + path, { "X-Provider-ID": cfg.providerUrl, "PG-Access": access });
    return r.status === 200 ? r.body : { error: r.body.error ?? `HTTP ${r.status}` };
  }

  return { cfg, keyId, party, http, directory, registry, introduce, post, getJson, signRequest, ask, checkAllow,
    makeReport, fileReport, fetchProof, bindStart, bindExchange, grants };
}
