// End to end: a local reference registry (--sandbox, HTTPS), a test directory signed by a throwaway steward key,
// and this app, driven like a browser. Needs Python with fastapi, uvicorn, cryptography and jsonschema:
//   PYTHON=/path/to/python npm test        (default: python3)
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createPrivateKey, sign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest, createServer } from "node:https";
import { createServer as netServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { pg, sha256 } from "../pregen.mjs";

const HERE = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO = resolve(HERE, "../..");
const PY = process.env.PYTHON ?? "python3";
const PYENV = { ...process.env, PYTHONPATH: `${REPO}/packages/verify-py:${REPO}/packages/registry` };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((ok) => { const s = netServer().listen(0, () => { const p = s.address().port; s.close(() => ok(p)); }); });

test("reference provider, end to end against a local sandbox registry", async (t) => {
  const deps = spawnSync(PY, ["-c", "import fastapi, uvicorn, cryptography, jsonschema"], { env: PYENV });
  assert.equal(deps.status, 0, `${PY} needs fastapi, uvicorn, cryptography and jsonschema (set PYTHON=…): ${deps.stderr}`);
  const tmp = mkdtempSync(join(tmpdir(), "pregen-refprov-"));
  const procs = new Set();
  t.after(() => { for (const p of procs) p.kill("SIGKILL"); rmSync(tmp, { recursive: true, force: true }); });

  // A self-signed certificate for localhost and 127.0.0.1: everything speaks HTTPS, as the directory requires.
  const cert = join(tmp, "cert.pem"), key = join(tmp, "key.pem");
  assert.equal(spawnSync(PY, ["-c", `
import datetime, ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
k = ec.generate_private_key(ec.SECP256R1())
n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
now = datetime.datetime.now(datetime.timezone.utc)
c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(x509.random_serial_number())
     .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=1))
     .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
     .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(k, hashes.SHA256()))
open(${JSON.stringify(cert)}, "wb").write(c.public_bytes(serialization.Encoding.PEM))
open(${JSON.stringify(key)}, "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
`], { env: PYENV }).status, 0);
  const ca = readFileSync(cert);

  // An HTTPS client that trusts that certificate, follows no redirect and sends cookies only where it got them.
  const call = (url, { method = "GET", headers = {}, body } = {}) => new Promise((ok, fail) => {
    const req = (url.startsWith("https:") ? httpsRequest : httpRequest)(url, { method, headers, ca }, (res) => {
      let text = "";
      res.on("data", (d) => (text += d)).on("end", () => ok({ status: res.statusCode, headers: res.headers, text,
        json: () => JSON.parse(text) }));
    });
    req.on("error", fail).end(body);
  });
  const keyFetch = async (url) => { const r = await call(url); return { ok: r.status === 200, status: r.status, json: async () => r.json() }; };

  const [rport, aport, dport] = [await freePort(), await freePort(), await freePort()];
  // The registry speaks HTTPS; the app runs as `npm start` does: plain HTTP on loopback, which a sandbox allows for
  // the bind redirect (RFC 8252 §7.3). Its provider id is bound to its key: https://<32 hex>.localhost:<port>.
  const REG = `https://127.0.0.1:${rport}`, APP = `http://localhost:${aport}`;

  // The registry: init --sandbox, then serve over HTTPS.
  const regDir = join(tmp, "registry");
  const init = spawnSync(PY, ["-m", "pregen_registry.cli", "init", "--dir", regDir, "--prefix", "TEST", "--name",
    "Local Test Registry", "--api", REG, "--sandbox"], { env: PYENV, encoding: "utf8" });
  assert.equal(init.status, 0, init.stderr);
  const logs = { registry: "", app: "" };
  // Answers live 6 seconds here (a sandbox-only override; 300 by default), so a lost answer expires within the test.
  const TTL = 6;
  const reg = spawn(PY, ["-m", "pregen_registry.cli", "serve", "--dir", regDir, "--host", "127.0.0.1", "--port", String(rport),
    "--ssl-certfile", cert, "--ssl-keyfile", key], { env: { ...PYENV, PREGEN_REGISTRY_ANSWER_TTL: String(TTL) } });
  procs.add(reg);
  reg.stderr.on("data", (d) => (logs.registry += d));

  // The test directory: the same format as pregen.org's, signed by a throwaway test steward key (sandbox.md).
  const steward = pg.newPrivateKeyHex();
  const operator = readFileSync(join(regDir, "operator.key"), "utf8").trim();
  const directory = { schema: "pregen.registries.v2", sequence: 1, issued_at: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
    steward_key_id: await pg.fingerprint(await pg.publicKeyHex(steward)), providers: [],
    registries: [{ name: "Local Test Registry", prefix: "TEST", api: REG, keys: `${REG}/keys`,
      key_fingerprints: [await pg.fingerprint(await pg.publicKeyHex(operator))] }] };
  const der = Buffer.from("302e020100300506032b657004220420" + steward, "hex");
  directory.signature = sign(null, Buffer.from(pg.canonicalJson(directory)), createPrivateKey({ key: der, format: "der", type: "pkcs8" })).toString("hex");
  const stewardPub = await pg.publicKeyHex(steward);
  const dirServer = createServer({ cert: ca, key: readFileSync(key) }, (q, r) => r.end(JSON.stringify(directory))).listen(dport);
  t.after(() => dirServer.close());
  const dir = await pg.verifyDirectory(directory, { stewardPublicKeyHex: stewardPub });

  // The app: its provider key from a file, the local directory and steward, served over HTTPS on localhost.
  const keyFile = join(tmp, "provider.key");
  const providerKey = pg.newPrivateKeyHex();
  writeFileSync(keyFile, providerKey + "\n", { mode: 0o600 });
  const PROVIDER = await pg.sandboxProviderUrl(providerKey, aport);
  const appArgs = ["--sandbox", "--port", String(aport), "--authority", "TEST",
    "--directory", `https://127.0.0.1:${dport}/registries.json`, "--steward", stewardPub, "--key-file", keyFile,
    "--data", join(tmp, "app"), "--lost-answer-wait", String(TTL + 3)];
  const childEnv = { ...process.env, NODE_EXTRA_CA_CERTS: cert, NODE_NO_WARNINGS: "1" };
  let app;
  async function startApp(env = {}) {
    app = spawn(process.execPath, ["app.mjs", ...appArgs], { cwd: HERE, env: { ...childEnv, ...env } });
    procs.add(app);
    app.stdout.on("data", (d) => (logs.app += d));
    app.stderr.on("data", (d) => (logs.app += d));
    app.exited = new Promise((ok) => app.on("exit", (c) => { procs.delete(app); ok(c); }));
    for (let i = 0; ; i++) {
      if ((await call(`${APP}/.well-known/pregen-party.json`).catch(() => null))?.status === 200) return;
      assert.ok(i < 100 && app.exitCode === null, `the app did not start:\n${logs.app}\n${logs.registry}`);
      await sleep(200);
    }
  }
  for (let i = 0; (await call(`${REG}/keys`).catch(() => null))?.status !== 200; i++) {
    assert.ok(i < 100, `the registry did not start:\n${logs.registry}`);
    await sleep(200);
  }
  await startApp();

  // A creator's browser: a cookie for the app only.
  function browser() {
    let cookie = "", csrf = "";
    const go = async (url, form) => {
      const body = form && new URLSearchParams(form).toString();
      const headers = { ...(cookie && url.startsWith(APP) ? { cookie } : {}),
        ...(body ? { "content-type": "application/x-www-form-urlencoded" } : {}) };
      const r = await call(url, { method: form ? "POST" : "GET", headers, body });
      if (r.headers["set-cookie"] && url.startsWith(APP)) cookie = r.headers["set-cookie"][0].split(";")[0];
      return r;
    };
    return {
      go, cookie: () => cookie,
      async signUp(email) {
        assert.equal((await go(`${APP}/signup`, { email, password: "correct horse battery" })).status, 303);
        csrf = /name=csrf value="([^"]+)"/.exec((await go(`${APP}/`)).text)[1];
      },
      post: (path, form) => go(APP + path, { csrf, ...form }),
      async connect() {                      // bind.md: the app sends us to the registry; we approve like a person
        const start = await go(`${APP}/connect`, { csrf });
        assert.equal(start.status, 303);
        const authorize = new URL(start.headers.location);
        assert.equal(authorize.origin, REG);
        assert.equal(authorize.searchParams.get("code_challenge_method"), "S256");
        const consent = (await go(authorize.href)).text;
        assert.match(consent, /Connect your licences/);
        // Post the consent form as a browser would: its hidden fields (the one-time consent nonce among them).
        const unescape = (v) => v.replace(/&(#x?[0-9a-f]+|amp|lt|gt|quot);/gi, (_, e) => ({ amp: "&", lt: "<", gt: ">", quot: '"' })[e.toLowerCase()]
          ?? String.fromCodePoint(e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : Number(e.slice(1))));
        const fields = Object.fromEntries([...consent.matchAll(/<input\b[^>]*>/g)].map(([tag]) => [
          /\bname=["']?([^"' >]+)/.exec(tag)?.[1], unescape(/\bvalue=(?:"([^"]*)"|'([^']*)'|([^\s>]*))/.exec(tag)?.slice(1).find((x) => x !== undefined) ?? "")])
          .filter(([k]) => k));
        assert.ok(fields.consent, "the consent page carries a one-time consent nonce");
        const back = await go(authorize.origin + authorize.pathname, { ...fields, decision: "approve" });
        assert.equal(back.status, 303, back.text);
        const callback = new URL(back.headers.location);
        assert.equal(callback.searchParams.get("iss"), "TEST");
        const done = await go(callback.href);
        assert.equal(done.status, 303, done.text);
      },
      async job(code, product) {
        const r = await this.post("/jobs", { code, product, prompt: "a portrait in soft light" });
        assert.equal(r.status, 303, r.text);
        return r.headers.location.split("/").pop();
      },
      async wait(id) {
        for (let i = 0; i < 150; i++) {
          const j = (await go(`${APP}/jobs/${id}.json`)).json();
          if (j.state === "done" || j.state === "unresolved") return j;
          await sleep(200);
        }
        assert.fail(`job ${id} did not finish:\n${logs.app}`);
      },
    };
  }

  async function provenOutput(b, j) {        // proof.md: the proof checks against the exact file it sits next to
    assert.ok(j.output && j.proof, JSON.stringify(j));
    const file = (await b.go(APP + j.output)).text, proof = (await b.go(APP + j.proof)).json();
    const checked = await pg.checkProof(proof, { directory: dir, fetch: keyFetch, outputSha256: sha256(file), testing: true });
    assert.equal(checked.outputHash, sha256(readFileSync(join(tmp, "app", "outputs", `${j.id}.txt`))));
    assert.deepEqual(JSON.parse(readFileSync(join(tmp, "app", "outputs", `${j.id}.txt.proof.json`), "utf8")), proof);
    return checked;
  }
  const statement = async () => (await call(`${REG}/v2/statement`, { headers: { "X-Provider-ID": PROVIDER,
    "PG-Access": await pg.pgAccess(PROVIDER, providerKey, REG, "GET", "/v2/statement") } })).json();
  const CODE1 = "PG-TEST-000001N", CODE9 = "PG-TEST-000009V", CODE12 = "PG-TEST-0000123";

  const a = browser();
  let c;                                      // the connected creator of step 5, used for code 9
  await t.test("sign in and connect a licence", async () => {
    await a.signUp("a@example.test");
    await a.connect();
    assert.match((await a.go(`${APP}/`)).text, /licence on <b>PG-TEST-0000123<\/b>: purposes research;\s+active, 3 uses left/);
    // The session is read from the exact cookie name only, and two values of it are no session (a planted cookie).
    const [name, value] = a.cookie().split("=");
    assert.equal(name, "sid");                // no TLS here; behind TLS it is __Host-sid
    const signedIn = async (cookie) => /Signed in as/.test((await call(`${APP}/`, { headers: { cookie } })).text);
    assert.ok(await signedIn(`${name}=${value}`));
    assert.ok(!(await signedIn(`__Host-sid=${value}`)));
    assert.ok(!(await signedIn(`${name}=${"A".repeat(43)}; ${name}=${value}`)));
  });

  await t.test("an allowed job on code 12 gets a proof that checks against its file", async () => {
    const j = await a.wait(await a.job(CODE12, "research-still"));
    assert.equal(j.outcome, "generated", JSON.stringify(j));
    const checked = await provenOutput(a, j);
    assert.equal(checked.subjects[0].code, CODE12);
    // bind.md B-3c: the allow names the binding the app stored for this creator
    const proof = (await a.go(APP + j.proof)).json();
    const stored = new DatabaseSync(join(tmp, "app", "app.db"), { readOnly: true }).prepare("SELECT binding FROM bindings").get();
    const binding = JSON.parse(stored.binding);
    assert.equal(proof.subjects[0].answer.body.ext.bind.binding, await pg.messageId("pg.binding.v1", binding.body));
    assert.equal(proof.subjects[0].request.body.licensee_id, binding.body.licensee_id);
  });

  await t.test("a job outside the licence is refused with its reason", async () => {
    const j = await a.wait(await a.job(CODE12, "ad-banner"));
    assert.deepEqual([j.outcome, j.reason], ["refused", "PG_SCOPE_VIOLATION"]);
    assert.match(j.message, /^Refused by the registry: PG_SCOPE_VIOLATION/);
    assert.equal(j.output, null);
  });

  await t.test("the self-check kit passes with this app's adapter", async () => {
    // Not spawnSync: this process serves the test directory the self-check loads.
    const kid = spawn(process.execPath, ["selfcheck.mjs", "./adapter.mjs", ...appArgs], { cwd: HERE, env: childEnv });
    const r = { stdout: "", stderr: "" };
    kid.stdout.on("data", (d) => (r.stdout += d));
    kid.stderr.on("data", (d) => (r.stderr += d));
    r.status = await new Promise((ok) => kid.on("exit", ok));
    t.diagnostic(r.stdout.split("\n").filter((l) => /passed|FAIL|SKIP/.test(l)).join("\n"));
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /^3\d passed, 0 failed, 0 skipped$/m);
  });

  await t.test("a licensee_id that is no longer bound shows 'connect your licence'", async () => {
    const b = browser();                      // the same test creator connects from another account: bind B-1
    await b.signUp("b@example.test");
    await b.connect();
    const j = await a.wait(await a.job(CODE12, "research-still"));
    assert.equal(j.outcome, "not_connected");
    assert.match(j.message, /^Connect your licence: the connection between your licence and this app has ended/);
    assert.match((await a.go(`${APP}/`)).text, /TEST: Connect your licence/);
    b.connected = true;
    c = b;
  });

  // Code 9 from a connected creator: the app sends no licensee_id there (it is not among the binding's grants), so the
  // request rests on the provider's own purchase.

  await t.test("a crash after the allow: at restart the use is given back", async () => {
    assert.ok(c?.connected, "needs the connected creator from the step before");
    // The self-check left one bought use of code 9 free (it gives back every allow it gets).
    const before = (await statement()).grants.reduce((n, g) => n + g.given_back, 0);
    app.kill("SIGTERM");
    await app.exited;
    await startApp({ PREGEN_CRASH_AFTER_ALLOW: "1" });
    const id = await c.job(CODE9, "research-still");
    const code = await Promise.race([app.exited, sleep(20000).then(() => "still running")]);
    assert.equal(code, 70, `the app should stop right after storing the allow:\n${logs.app}`);
    await startApp();
    const j = await c.wait(id);
    assert.equal(j.outcome, "given_back", JSON.stringify(j));
    const after = (await statement()).grants.reduce((n, g) => n + g.given_back, 0);
    assert.equal(after, before + 1);
  });

  await t.test("two jobs race for the last bought use: exactly one allow", async () => {
    const ids = [await c.job(CODE9, "research-still"), await c.job(CODE9, "research-still")];
    const jobs = await Promise.all(ids.map((id) => c.wait(id)));
    assert.deepEqual(jobs.map((j) => `${j.outcome} ${j.reason ?? ""}`.trim()).sort(), ["generated", "refused PG_USAGE_LIMIT"]);
    const generated = jobs.find((j) => j.outcome === "generated");
    await provenOutput(c, generated);
    assert.equal((await c.go(APP + generated.proof)).json().subjects[0].request.body.licensee_id, undefined);
  });

  await t.test("an allow lost on the way: answer null not_generated, the use given back, no resend", async () => {
    const before = (await statement()).grants.reduce((n, g) => n + g.given_back, 0);
    app.kill("SIGTERM");
    await app.exited;
    await startApp({ PREGEN_DROP_ANSWER: "1" });          // the registry issues an allow; the app never sees it
    const j = await c.wait(await c.job(CODE12, "research-still"));
    assert.equal(j.outcome, "unavailable");
    const givenBack = async () => (await statement()).grants.reduce((n, g) => n + g.given_back, 0);
    assert.equal(await givenBack(), before, "nothing is reported before that answer has certainly expired");
    let after = before;
    for (let i = 0; i < 60 && after === before; i++) { await sleep(500); after = await givenBack(); }
    assert.equal(after, before + 1, "the answer null report gives the use back once the answer expired");
    assert.equal((await c.wait(j.id)).message, j.message, "the creator still reads 'could not be reached'");
    app.kill("SIGTERM");
    await app.exited;
    await startApp();
  });

  await t.test("an ended connection blocks only its own codes", async () => {
    const appDb = new DatabaseSync(join(tmp, "app", "app.db"));
    const { licensee_id: lic } = appDb.prepare("SELECT b.licensee_id FROM bindings b JOIN accounts a ON a.id = b.account_id "
      + "WHERE a.email = 'b@example.test'").get();
    // Revoked at the registry (B-2): the licence's code is "connect your licence"; code 1 still generates.
    const revoke = spawnSync(PY, ["-m", "pregen_registry.cli", "bindings", "--dir", regDir, "--revoke", lic], { env: PYENV, encoding: "utf8" });
    assert.equal(revoke.status, 0, revoke.stderr);
    assert.equal((await c.wait(await c.job(CODE12, "research-still"))).outcome, "not_connected");
    assert.equal((await c.wait(await c.job(CODE1, "research-still"))).outcome, "generated");
    // Expired in the app's own record: the same, decided before anything is sent.
    appDb.prepare("UPDATE bindings SET expires_at = 0 WHERE licensee_id = ?").run(lic);
    appDb.close();
    const r = await c.post("/jobs", { code: CODE12, product: "research-still", prompt: "x" });
    assert.match(r.text, /Connect your licence: the connection between your licence and this app has ended/);
    const one = await c.wait(await c.job(CODE1, "research-still"));
    assert.equal(one.outcome, "generated");
    assert.equal((await c.go(APP + one.proof)).json().subjects[0].request.body.licensee_id, undefined);
  });

  await t.test("registry down: 'registry unavailable', not a refusal", async () => {
    reg.kill("SIGKILL");
    const j = await c.wait(await c.job(CODE9, "research-still"));
    assert.equal(j.outcome, "unavailable");
    assert.match(j.message, /could not be reached/);
  });
});
