// @pregen/verify — check PRE-GEN signatures against the signed registry
// directory (PG-CODE.md §9.1, PRE-GEN-SPEC.md §2, V-9 to V-12).
// No dependencies: Ed25519 and SHA-256 come from Web Crypto (Node >= 20, browsers).

export const STEWARD_PUBLIC_KEY_HEX = "5cb949aab04186e3e216ec541b847c912fc3f78138c0ec3cb2560b2dad0d1f1b";
/** The successor steward key, created in advance and kept apart (PG-CODE.md §9.1). A directory
 * it signs replaces every directory signed by the current steward key, whatever their sequence. */
export const STEWARD_SUCCESSOR_PUBLIC_KEY_HEX = "658544163d6abd5fef046407980d249817875d87d8cf4b67879a2e265fa5612f"; // pg-ed25519:3e5e20729ce8485eea274c4cb33721d6, created 2026-10-03
export const DIRECTORY_URL = "https://www.pregen.org/registries.json";
/** The origin registry's (PRAMPTA's) operator keys, pinned here as well as in the
 * directory: a stolen steward key cannot add its own key to the bare namespace.
 * A new origin key needs a new release of this library (threat model T4). */
export const ORIGIN_KEY_FINGERPRINTS = Object.freeze([
  "pg-ed25519:1904514fd2ac442f0a5388d13cc313a0", // current
  "pg-ed25519:58d4a309fff25a0f4763cffc5c92cb0e", // next, announced 2026-10-03, offline until rotation
]);
const SCHEMA = "pregen.registries.v2";
const MAX_INT = 2 ** 53 - 1;
const PREFIX = /^[ABCDEFGHJKMNPQRSTVWXYZ]{4}$/;
const FINGERPRINT = /^pg-ed25519:[0-9a-f]{32}$/;
const ISSUER_IN_CODE = /^PG-([ABCDEFGHJKMNPQRSTVWXYZ]{4})-/;
const BARE_CODE = /^PG-(?:[A-Z]{3}-)?[0-9]/;

export class PregenError extends Error {
  constructor(message) { super(message); this.name = "PregenError"; }
}
const fail = (message) => { throw new PregenError(message); };
const utf8 = new TextEncoder();

function bytesCompare(a, b) {
  for (let i = 0; i < a.length && i < b.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

function hexBytes(hex, length) {
  if (typeof hex !== "string" || hex.length !== length * 2 || !/^[0-9a-fA-F]*$/.test(hex)) {
    fail(`expected ${length} bytes of hex`);
  }
  return Uint8Array.from(hex.match(/../g), (h) => parseInt(h, 16));
}

const toHex = (bytes) => Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");

/** Canonical JSON (PRE-GEN-SPEC.md §2) as a string; encode with UTF-8 to sign. */
export function canonicalJson(value) {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail("signed JSON numbers must be safe integers");
    return String(value);
  }
  if (typeof value === "string") {
    if (!value.isWellFormed()) fail("invalid Unicode in signed JSON");
    return JSON.stringify(value); // escapes exactly as §2 requires
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) if (!(i in value)) fail("sparse arrays are not JSON");
    return "[" + value.map(canonicalJson).join(",") + "]";
  }
  if (typeof value === "object" && [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    // UTF-8 byte order is Unicode code point order.
    const keys = Object.keys(value).sort((a, b) => bytesCompare(utf8.encode(a), utf8.encode(b)));
    return "{" + keys.map((k) => canonicalJson(k) + ":" + canonicalJson(value[k])).join(",") + "}";
  }
  fail("signed JSON must contain only JSON values");
}

export async function sha256Hex(data) {
  return toHex(await crypto.subtle.digest("SHA-256", typeof data === "string" ? utf8.encode(data) : data));
}

/** "pg-ed25519:" + first 32 hex of SHA-256(raw public key) (§2.1). */
export async function fingerprint(publicKeyHex) {
  return "pg-ed25519:" + (await sha256Hex(hexBytes(publicKeyHex, 32))).slice(0, 32);
}

/** Ed25519 over raw bytes. False on any bad signature or key encoding. */
export async function verifyBytes(publicKeyHex, signatureHex, message) {
  try {
    const key = await crypto.subtle.importKey("raw", hexBytes(publicKeyHex, 32), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, hexBytes(signatureHex, 64), message);
  } catch {
    return false;
  }
}

/** Verify `obj[signatureField]` over the canonical JSON of `obj` without the excluded fields. */
export async function verifySigned(obj, publicKeyHex, signatureField, exclude = [signatureField]) {
  if (!obj || typeof obj !== "object") return false;
  const body = Object.fromEntries(Object.entries(obj).filter(([k]) => !exclude.includes(k)));
  return verifyBytes(publicKeyHex, obj[signatureField], utf8.encode(canonicalJson(body)));
}

/** A license (§1.2): subject signature over the body, operator countersignature over
 * canonical body || subject signature (64 raw bytes) || license id (ASCII). */
export async function verifyLicense({ body, licenseId, subjectPublicKeyHex, subjectSignatureHex,
  operatorPublicKeyHex, operatorSignatureHex }) {
  const bodyBytes = utf8.encode(canonicalJson(body));
  const subjectValid = await verifyBytes(subjectPublicKeyHex, subjectSignatureHex, bodyBytes);
  let operatorValid = false;
  try {
    const sig = hexBytes(subjectSignatureHex, 64);
    const id = utf8.encode(String(licenseId));
    const message = new Uint8Array(bodyBytes.length + 64 + id.length);
    message.set(bodyBytes); message.set(sig, bodyBytes.length); message.set(id, bodyBytes.length + 64);
    operatorValid = await verifyBytes(operatorPublicKeyHex, operatorSignatureHex, message);
  } catch { /* bad encoding: invalid */ }
  return { subjectValid, operatorValid };
}

/** The namespace of a PG code: its four-letter prefix, or "" for the bare namespace. */
export function issuerOf(code) {
  if (typeof code !== "string") fail("PG code must be a string");
  const c = code.trim().toUpperCase();
  const m = ISSUER_IN_CODE.exec(c);
  if (m) return m[1];
  if (!BARE_CODE.test(c)) fail("unrecognized PG namespace");
  return "";
}

function httpsUrl(value, field) {
  let url;
  try { url = new URL(value); } catch { fail(`registry ${field} must be a URL`); }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    fail(`registry ${field} must use HTTPS without credentials, query or fragment`);
  }
}

function checkInvariants(d) {
  if (!d || typeof d !== "object" || Array.isArray(d)) fail("directory must be an object");
  if (d.schema !== SCHEMA) fail(`schema must be ${SCHEMA}`);
  if (!Number.isSafeInteger(d.sequence) || d.sequence < 1) fail("sequence must be a positive integer");
  if (!FINGERPRINT.test(String(d.steward_key_id))) fail("steward_key_id must be a pg-ed25519 fingerprint");
  if (!Array.isArray(d.registries) || d.registries.length === 0) fail("registries must be a non-empty list");
  const seen = new Set();
  for (const r of d.registries) {
    if (!r || typeof r !== "object") fail("registry entry must be an object");
    if (typeof r.name !== "string" || !r.name.trim()) fail("registry name must be nonempty");
    httpsUrl(r.api, "api");
    httpsUrl(r.keys, "keys");
    if (r.prefix !== "" && !(typeof r.prefix === "string" && PREFIX.test(r.prefix))) fail(`bad prefix ${r.prefix}`);
    if (seen.has(r.prefix)) fail(r.prefix === "" ? "the bare namespace is listed twice" : `prefix ${r.prefix} is listed twice`);
    seen.add(r.prefix);
    if (!Array.isArray(r.key_fingerprints) || !r.key_fingerprints.length
        || !r.key_fingerprints.every((f) => FINGERPRINT.test(String(f)))) {
      fail(`registry ${r.name}: key_fingerprints must list pg-ed25519 fingerprints`);
    }
  }
  if (!seen.has("")) fail("no registry holds the bare namespace");
  // Revocation (PG-CODE.md §9.1): a revoked registry keeps its entry; a revoked key keeps its listing.
  for (const r of d.registries) {
    if (r.revoked !== undefined && !(r.revoked && typeof r.revoked === "object" && typeof r.revoked.at === "string")) {
      fail(`registry ${r.name}: revoked must be an object with "at"`);
    }
  }
  if (d.revoked_keys !== undefined && !(Array.isArray(d.revoked_keys)
      && d.revoked_keys.every((k) => k && FINGERPRINT.test(String(k.key_id)) && typeof k.at === "string"))) {
    fail("revoked_keys must list {key_id, at}");
  }
}

/** A directory accepted under V-12. Build one with verifyDirectory() or loadDirectory(). */
export class Directory {
  #d;
  #originPin;
  constructor(token, directory, originPin) {
    if (token !== Directory.#token) fail("use verifyDirectory() or loadDirectory()");
    this.#d = structuredClone(directory);
    this.#originPin = originPin;
  }
  static #token = Symbol();
  static _make(directory, originPin) { return new Directory(Directory.#token, directory, originPin); }

  /** Store this and pass it as minSequence next time, so an older copy is refused. */
  get sequence() { return this.#d.sequence; }
  get registries() { return structuredClone(this.#d.registries); }
  /** The signed directory itself: persist it and pass it back as `previous`. */
  toJSON() { return structuredClone(this.#d); }

  /** The registry that owns a code's namespace (resolve codes only there, V-11), or null. */
  registryFor(code) {
    let issuer;
    try { issuer = issuerOf(code); } catch { return null; }
    const r = this.#d.registries.find((x) => x.prefix === issuer);
    return r ? structuredClone(r) : null;
  }

  /** V-10, V-14: "valid", "unknown_issuer", "issuer_mismatch" or "revoked". */
  checkSigner(code, signerKeyId) {
    const r = this.registryFor(code);
    if (!r) return "unknown_issuer";
    if (r.revoked || (this.#d.revoked_keys || []).some((k) => k.key_id === signerKeyId)) return "revoked";
    if (!r.key_fingerprints.includes(signerKeyId)) return "issuer_mismatch";
    if (r.prefix === "" && this.#originPin && !this.#originPin.includes(signerKeyId)) return "issuer_mismatch";
    return "valid";
  }

  /** The public key behind `keyId`, which must belong to the owner of `code`'s namespace.
   * The key comes from the owner's key set and must hash to the listed fingerprint. */
  async publicKey(code, keyId, { fetch: fetchFn = globalThis.fetch } = {}) {
    const verdict = this.checkSigner(code, keyId);
    if (verdict !== "valid") fail(`${keyId} may not sign ${code}: ${verdict}`);
    const res = await fetchFn(this.registryFor(code).keys, { redirect: "error" });
    if (!res.ok) fail(`key set: HTTP ${res.status}`);
    const entry = ((await res.json()).keys || []).find((k) => k && k.key_id === keyId);
    if (!entry || (await fingerprint(entry.public_key_hex)) !== keyId) fail(`no key ${keyId} in the key set`);
    return entry.public_key_hex;
  }
}

/** A newer directory may add registries and keys, never remove or move them (PG-CODE.md §9.1). */
function checkContinuity(next, previous) {
  if (next.sequence < previous.sequence) fail(`sequence ${next.sequence} is older than ${previous.sequence} already seen`);
  if (next.sequence === previous.sequence) {
    if (canonicalJson(next) !== canonicalJson(previous)) fail("a different directory with the same sequence");
    return;
  }
  keepsHistory(next, previous);
}

/** Revocations a successor's first directory may drop (PG-CODE.md §9.1). */
function annulments(d) {
  if (d.annulled === undefined) return [];
  const since = Date.parse(d.steward_compromised_since);
  if (!Array.isArray(d.annulled) || Number.isNaN(since)) fail("annulled needs a list and steward_compromised_since");
  return d.annulled.map((a) => ({ ...a, since }));
}
const annulledAt = (list, field, value, at) =>
  list.some((a) => a[field] === value && Date.parse(at) >= a.since);

function keepsHistory(next, previous, annulled = []) {
  for (const a of previous.annulled || []) {
    if (!(next.annulled || []).some((x) => same(x, a))) fail("an annulment was removed");
  }
  for (const old of previous.registries) {
    const now = next.registries.find((r) => r.prefix === old.prefix);
    if (!now) fail(`namespace ${old.prefix || "(bare)"} was removed`);
    for (const f of old.key_fingerprints) if (!now.key_fingerprints.includes(f)) fail(`key ${f} was removed from ${now.name}`);
    if (old.revoked && !(now.revoked && same(now.revoked, old.revoked))
        && !annulledAt(annulled, "prefix", old.prefix, old.revoked.at)) fail(`the revocation of ${old.name} was undone`);
  }
  for (const k of previous.revoked_keys || []) {
    if (!(next.revoked_keys || []).some((x) => same(x, k))
        && !annulledAt(annulled, "key_id", k.key_id, k.at)) fail(`the revocation of key ${k.key_id} was undone`);
  }
}

/** V-12: accept the directory only with the pinned steward's signature, its invariants,
 * a sequence no lower than one already seen and, given the last accepted directory,
 * nothing removed from it. With the built-in steward key the origin keys are pinned too. */
export async function verifyDirectory(directory, { stewardPublicKeyHex = STEWARD_PUBLIC_KEY_HEX, successorPublicKeyHex,
  minSequence = 0, previous, originKeyFingerprints } = {}) {
  if (!Number.isSafeInteger(minSequence) || minSequence < 0) fail("minSequence must be a nonnegative integer");
  checkInvariants(directory);
  const successor = successorPublicKeyHex !== undefined ? successorPublicKeyHex
    : stewardPublicKeyHex === STEWARD_PUBLIC_KEY_HEX ? STEWARD_SUCCESSOR_PUBLIC_KEY_HEX : null;
  const currentId = await fingerprint(stewardPublicKeyHex);
  const successorId = successor ? await fingerprint(successor) : null;
  const bySuccessor = successorId !== null && directory.steward_key_id === successorId;
  if (directory.steward_key_id !== currentId && !bySuccessor) fail("signed by a different steward key");
  if (!(await verifySigned(directory, bySuccessor ? successor : stewardPublicKeyHex, "signature"))) fail("bad steward signature");
  const prev = previous instanceof Directory ? previous.toJSON() : previous;
  if (prev && successorId !== null && prev.steward_key_id === successorId && !bySuccessor) {
    fail("the steward key was handed over; directories signed by the old key are refused");
  }
  // Handover: the successor's first directory replaces the old key's line, whatever its sequence
  // (a thief holding the old key may have raised it). Within one key's line the usual rules hold.
  const handover = bySuccessor && (!prev || prev.steward_key_id !== successorId);
  if (!handover) {
    if (directory.sequence < minSequence) fail(`sequence ${directory.sequence} is older than ${minSequence} already seen`);
    if (prev) checkContinuity(directory, prev);
  } else if (prev) {
    // A handover may restart the sequence, never drop a listing or a revocation, except
    // revocations the old key signed after it was compromised, named in `annulled`.
    keepsHistory(directory, prev, annulments(directory));
  }
  const pin = originKeyFingerprints !== undefined ? originKeyFingerprints
    : stewardPublicKeyHex === STEWARD_PUBLIC_KEY_HEX ? ORIGIN_KEY_FINGERPRINTS : null;
  return Directory._make(directory, pin && [...pin]);
}

/** Download and verify the directory from pregen.org. Pass the last accepted one as `previous`. */
export async function loadDirectory({ url = DIRECTORY_URL, minSequence = 0, previous, fetch: fetchFn = globalThis.fetch } = {}) {
  const res = await fetchFn(url, { redirect: "error" });
  if (!res.ok) fail(`directory: HTTP ${res.status}`);
  return verifyDirectory(await res.json(), { minSequence, previous });
}

/** Is this registry decision genuine, and signed by a key of the registry that owns `code`?
 * Signatures only: use checkDecision() before generating. */
export async function verifyDecision(decision, code, { directory, fetch: fetchFn = globalThis.fetch } = {}) {
  const dir = directory || (await loadDirectory({ fetch: fetchFn }));
  const key = await dir.publicKey(code, decision && decision.operator_key_id, { fetch: fetchFn });
  return verifySigned(decision, key, "operator_signature");
}

// Members this library knows how to handle: the core (PRE-GEN-SPEC.md §1.1) and the origin
// registry's (PRE-GEN-EXTENSIONS.md X.2). A `critical` member outside this set makes an allow unusable.
const UNDERSTOOD = new Set(["schema_version", "decision_id", "nonce", "disposition", "allowed", "reason",
  "policy_version", "subject_id", "licensee_id", "provider_id", "license_id", "prompt_hash", "model", "modality",
  "intended_use", "obligations", "generation_id", "issued_at", "expires_at", "critical", "operator_key_id",
  "operator_signature", "subject_authority", "rules_text", "rules_text_hash", "watermark_payload", "is_hard_refusal",
  "revocation_epoch", "max_cache_age_seconds", "cache_scope", "provider_user_binding", "provider_identity_link_id",
  "detection_id", "remediation"]);
const MAX_DECISION_LIFETIME = 900;
const ECHOED = ["subject_id", "provider_id", "licensee_id", "prompt_hash", "model", "modality"];
const isEmpty = (v) => v === undefined || v === null || v === "" || (Array.isArray(v) && v.length === 0);
const same = (a, b) => canonicalJson(a) === canonicalJson(b);

/** Everything a provider must check before generating on a decision (PRE-GEN-SPEC.md §5.4):
 * a genuine signature by the owner of the license's namespace (V-1, V-2, V-10), the decision
 * answers exactly this request (V-4), it is within its validity window (V-3), it carries a
 * verified user binding when a user was named (V-13), it is a license-backed allow (P-5), its
 * registry and key are not revoked (V-14) and it lists no `critical` member this library does not
 * understand (E-3). `requireVerifiedAuthority` also refuses a subject whose authority is not "verified".
 * `request` is what you sent: the /v1/verify body plus provider_id and licensee_id.
 * Throws PregenError with the reason; returns the decision when you may generate. */
export async function checkDecision(decision, request, { directory, fetch: fetchFn = globalThis.fetch,
  now = Math.floor(Date.now() / 1000), requireVerifiedAuthority = false } = {}) {
  if (!decision || typeof decision !== "object") fail("decision must be an object");
  if (!request || typeof request !== "object") fail("request must be an object");
  if (decision.allowed !== true || decision.disposition !== "allow") fail(`not an allow: ${decision.disposition}`);
  if (typeof decision.license_id !== "string" || !decision.license_id) fail("an allow must name its license");
  if (decision.critical !== undefined) {
    if (!Array.isArray(decision.critical)) fail("critical must be a list");
    const unknown = decision.critical.filter((m) => !UNDERSTOOD.has(m));
    if (unknown.length) fail(`critical members this library does not understand: ${unknown.join(", ")}`); // E-3
  }
  if (requireVerifiedAuthority && decision.subject_authority !== "verified") {
    fail(`the subject's authority is ${decision.subject_authority ?? "not stated"}, not verified`);
  }

  if (decision.schema_version !== "pg.decision.v1") fail(`unsupported schema_version: ${decision.schema_version}`);
  const exp = decision.expires_at, iat = decision.issued_at;
  if (!Number.isSafeInteger(exp) || exp <= 0) fail("expires_at must be a positive integer");
  if (!Number.isSafeInteger(iat) || iat <= 0 || iat >= exp || iat > now + 60) {
    fail("issued_at must be a positive integer before expires_at and not in the future");
  }
  if (exp - iat > MAX_DECISION_LIFETIME) fail(`a decision lives at most ${MAX_DECISION_LIFETIME} seconds`); // PRE-GEN §1.1
  if (exp <= now) fail("decision expired");

  for (const f of ECHOED) {
    if ((decision[f] ?? "") !== (request[f] ?? "")) fail(`${f} does not match the request`);
  }
  const got = decision.intended_use ?? {}, sent = request.intended_use ?? {};
  if (typeof got !== "object" || typeof sent !== "object") fail("intended_use must be an object");
  for (const k of new Set([...Object.keys(got), ...Object.keys(sent)])) {
    const ok = isEmpty(sent[k]) ? isEmpty(got[k]) : same(got[k] ?? null, sent[k]); // empty and absent are the same
    if (!ok) fail(`intended_use.${k} does not match the request`);
  }
  for (const f of ["generation_id", "provider_identity_link_id"]) {
    if (!isEmpty(request[f]) && decision[f] !== request[f]) fail(`${f} does not match the request`);
  }
  if (!isEmpty(request.provider_user_id) || !isEmpty(request.provider_identity_link_id)) {
    if (decision.provider_user_binding !== "verified" || isEmpty(decision.provider_identity_link_id)) {
      fail("no verified binding to the user you named");
    }
  }

  if (!(await verifyDecision(decision, decision.license_id, { directory, fetch: fetchFn }))) fail("bad signature");
  return decision;
}

/** An offline sandbox registry for tests and CI: no network, no secret, its own throwaway keys.
 * Its directory is signed by a throwaway steward key, so nothing it signs is ever accepted by
 * the real directory. Answers the documented sandbox subjects:
 *   sbx-allowed → allow · sbx-revoked, sbx-expired → PG_NO_LICENSE · sbx-exhausted → PG_USAGE_LIMIT
 *   sbx-optedout → PG_SUBJECT_OPTED_OUT · anything else → PG_NO_SUBJECT
 * Use `sim.fetch` in place of fetch and `sim.directory` in checkDecision. */
export async function createSimulator({ baseUrl = "https://simulator.pregen.invalid" } = {}) {
  const keygen = async () => {
    const k = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const pub = toHex(await crypto.subtle.exportKey("raw", k.publicKey));
    const sign = async (body) => toHex(await crypto.subtle.sign({ name: "Ed25519" }, k.privateKey, utf8.encode(canonicalJson(body))));
    return { pub, id: await fingerprint(pub), sign };
  };
  const steward = await keygen(), operator = await keygen();
  const dirBody = { schema: SCHEMA, sequence: 1, steward_key_id: steward.id, simulator: true,
    registries: [{ name: "PRE-GEN simulator (not a registry)", prefix: "", api: baseUrl, keys: baseUrl + "/keys",
      key_fingerprints: [operator.id] }] };
  const directory = await verifyDirectory({ ...dirBody, signature: await steward.sign(dirBody) },
    { stewardPublicKeyHex: steward.pub, successorPublicKeyHex: null, originKeyFingerprints: [operator.id] });
  const answers = { "sbx-allowed": ["allow", null], "sbx-revoked": ["deny", "PG_NO_LICENSE"], "sbx-expired": ["deny", "PG_NO_LICENSE"],
    "sbx-exhausted": ["deny", "PG_USAGE_LIMIT"], "sbx-optedout": ["deny", "PG_SUBJECT_OPTED_OUT"] };
  // What PRAMPTA's /v1 does with receipts (R-10), so a provider's tests meet the same rules: a receipt
  // needs an allow issued to this pair for the same prompt_hash; the identical receipt again gets the
  // first answer, a different one is a conflict; release is refused once a receipt exists, and the
  // sandbox licences have no usage limit, so there is nothing to release.
  const decisions = new Map(), receipts = new Map();
  let n = 0;
  // A real Response, as fetch returns: json(), text(), headers — clients read error bodies with text().
  const reply = (status, body) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  const refuse = (status, detail) => reply(status, { detail });
  const header = (init, name) => {
    const h = init && init.headers; if (!h) return "";
    return (typeof h.get === "function" ? h.get(name) : h[name] ?? h[name.toLowerCase()]) || "";
  };
  async function simFetch(url, init = {}) {
    const path = new URL(String(url)).pathname;
    if (path === "/keys") return reply(200, { current_key_id: operator.id, keys: [{ key_id: operator.id, public_key_hex: operator.pub, status: "active" }] });
    const req = init.body ? JSON.parse(init.body) : {};
    if (path.replace(/\/$/, "") === "/v1/verify") {
      const [disposition, reason] = answers[req.subject_id] || ["deny", "PG_NO_SUBJECT"];
      const now = Math.floor(Date.now() / 1000);
      const named = !isEmpty(req.provider_user_id) || !isEmpty(req.provider_identity_link_id);
      const body = { schema_version: "pg.decision.v1", decision_id: `sim-${++n}`, simulator: true,
        allowed: disposition === "allow", disposition, reason, is_hard_refusal: reason === "PG_SUBJECT_OPTED_OUT",
        subject_id: req.subject_id ?? "", provider_id: header(init, "X-Provider-ID"), licensee_id: header(init, "X-Licensee-ID"),
        license_id: disposition === "allow" ? "PG-RND-000001-SIMULAT" : null,
        prompt_hash: req.prompt_hash ?? "", model: req.model ?? "", modality: req.modality ?? "",
        intended_use: req.intended_use ?? {}, generation_id: req.generation_id ?? "",
        provider_user_binding: named ? "verified" : "unbound",
        provider_identity_link_id: req.provider_identity_link_id || (named ? "sim-link" : ""),
        issued_at: now, expires_at: now + 300, cache_scope: "not_cacheable", max_cache_age_seconds: 0,
        operator_key_id: operator.id };
      decisions.set(body.decision_id, body);
      return reply(200, { ...body, operator_signature: await operator.sign(body) });
    }
    const pair = (d) => d.provider_id === header(init, "X-Provider-ID") && d.licensee_id === header(init, "X-Licensee-ID");
    const release = path.match(/^\/v1\/receipts\/([^/]+)\/release$/);
    if (release) {
      const d = decisions.get(decodeURIComponent(release[1]));
      if (!d || d.disposition !== "allow") return refuse(404, "No authorized decision found for this decision_id");
      if (!pair(d)) return refuse(403, "This decision was not issued to your provider/licensee pair");
      if (receipts.has(d.decision_id)) return refuse(409, { error: "already_receipted", error_description: "A receipt says this decision was used." });
      return refuse(409, { error: "nothing_to_release", error_description: "This licence has no usage limit; nothing was reserved." });
    }
    if (path.replace(/\/$/, "") === "/v1/receipts") {
      const d = decisions.get(req.decision_id);
      if (!d || d.disposition !== "allow") return refuse(400, "No authorized decision found for this decision_id");
      if (d.prompt_hash !== req.prompt_hash) return refuse(400, "prompt_hash does not match the authorized decision");
      if (!pair(d)) return refuse(403, "This decision was not issued to your provider/licensee pair");
      if (!String(req.output_hash ?? "").trim()) return refuse(400, "output_hash is required to identify the reported output");
      if (req.schema_version && req.v && req.schema_version !== req.v) return refuse(400, "Conflicting receipt schema versions");
      const v = req.schema_version || req.v || "pg.receipt.v2";
      if (v !== "pg.receipt.v2" && v !== "pg.receipt.v3") return refuse(400, "Unsupported receipt schema version");
      const eventType = req.event_type ?? "output_accepted";
      // The body PRAMPTA hashes (app/core/receipt_body.py), so receipt_hash binds the answer to these bytes.
      const body = { v, decision_id: d.decision_id, subject_id: d.subject_id, licensee_id: d.licensee_id, provider_id: d.provider_id,
        prompt_hash: req.prompt_hash, output_hash: req.output_hash, model: req.model ?? "",
        obligations_applied: req.obligations_applied ?? {}, watermark_embedded: req.watermark_embedded ?? false,
        generated_at: req.generated_at ?? 0, ...(v === "pg.receipt.v3" ? { event_type: eventType } : {}) };
      const receiptHash = await sha256Hex(canonicalJson(body));
      const stored = receipts.get(d.decision_id);
      if (stored) {
        if (stored !== receiptHash) return refuse(409, { error: "receipt_conflict", error_description: "A different receipt for this decision already exists." });
        return reply(200, { status: "already_recorded", decision_id: d.decision_id, receipt_hash: receiptHash, compliant: true,
          provider_signature_verified: false });
      }
      receipts.set(d.decision_id, receiptHash);
      return reply(200, { schema_version: v, status: "recorded", decision_id: d.decision_id, receipt_hash: receiptHash,
        compliant: true, obligation_violations: [], provider_signature_verified: false, provider_signed_event_type: false });
    }
    return reply(404, { error: "not simulated" });
  }
  return { baseUrl, directory, fetch: simFetch, operatorPublicKeyHex: operator.pub };
}
