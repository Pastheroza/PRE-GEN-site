// The site's lookup proxy (api/lookup.js): a code is asked in the spelling and at the route its registry reads,
// answers show TOG only. No network: registry answers below were recorded live on 2026-11-10.
// Run: node --test test/lookup.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const handler = require("../api/lookup.js");
const REGISTRIES = require("../registries.json");   // the proxy's own copy: a registry added here is listed there
REGISTRIES.registries.push(
  { name: "PRE-GEN Test Registry", prefix: "TEST", api: "https://sandbox.pregen.org" },   // as in test/registries.json
  { name: "A migrated registry", prefix: "ZYXW", api: "https://zyxw.example" });

const PRAM_PG = "https://api2.prampta.com/v1/pg/";
const RECORDED = {
  // PRAMPTA: its policy names /v1/pg/{code}; it reads PG spellings only.
  "https://api2.prampta.com/.well-known/pg-policy": [200, { issuer: "PRAMPTA", pregen_version: "5", prefix: "PRAM",
    format_version: "2026-08-19", resolver_url_template: "https://api2.prampta.com/v1/pg/{code}",
    reserved_subject_serial_floor: 900000000, spec: "https://www.pregen.org/docs/pg-code" }],
  [PRAM_PG + "PG-PRAM-000043R"]: [200, { kind: "subject", found: true, status: "active" }],
  [PRAM_PG + "PG-PRAM-000099J"]: [404, { error: "not_found", detail: { error: "not_found" }, request_id: "2518c8aa" }],
  [PRAM_PG + "TOG-PRAM-123456789G"]: [400, { error: "invalid_format", detail: { error: "invalid_format" }, request_id: "b6ea4a5c" }],
  "https://api2.prampta.com/v1/subjects/PG-0000016": [200, require("./subject-PG-0000016.json")],
  "https://api2.prampta.com/v1/licenses/PG-STD-000001-K7M2QX9/proof": [404, { detail: "License not found", request_id: "884ae566" }],
  // The sandbox publishes no policy and no /v1/pg: the fallback route is asked, its 404 is not called "unknown".
  "https://sandbox.pregen.org/.well-known/pg-policy": [404, { detail: "Not Found" }],
  "https://sandbox.pregen.org/v1/pg/PG-TEST-000001N": [404, { detail: "Not Found" }],
  // A registry whose policy names /v2/codes; its answer is the sandbox's recorded /v2 answer, in the PG spelling.
  "https://zyxw.example/.well-known/pg-policy": [200, { resolver_url_template: "https://zyxw.example/v2/codes/{code}" }],
  "https://zyxw.example/v2/codes/PG-ZYXW-0000014": [200, { code: "PG-TEST-000001N", registry: "TEST", status: "active",
    name: "Test subject 1 (allow)", level: "verified", subject_key: { key_id: "pg-ed25519:e9d2d58988e65dbe81975c357fbe3bd2",
      public_key_hex: "59c3f4a451a9002def6ddfd3efeb01e33546d28d918f82820f4e3dced51459e3", custody: "managed" } }],
};

const asked = [];
globalThis.fetch = async (url) => {
  asked.push(url);
  const [status, body] = RECORDED[url] ?? [404, { detail: "Not Found" }];
  return { status, ok: status < 300, json: async () => structuredClone(body) };
};

async function lookup(code) {
  const out = {};
  const res = { setHeader() {}, status(s) { out.status = s; return this; }, json(b) { out.body = b; } };
  asked.length = 0;
  await handler({ method: "GET", query: { code }, headers: {} }, res);
  return { ...out, asked: asked.filter((u) => !u.endsWith("/pg-policy")) };
}
const noPG = (body) => assert.doesNotMatch(JSON.stringify(body), /(^|[^O])PG-[A-Z0-9]/);

test("an old person is asked in its PG spelling at the route PRAMPTA publishes, and shown TOG", async () => {
  const want = { code: "TOG-PRAM-000043R", kind: "subject", status: "active" };
  const first = await lookup("TOG-PRAM-000043R");
  assert.deepEqual([first.status, first.body, first.asked], [200, want, [PRAM_PG + "PG-PRAM-000043R"]]);
  assert.deepEqual((await lookup("PG-PRAM-000043R")).body, want);   // one code, one cache entry
});

test("a person PRAMPTA never issued is unknown, in the TOG spelling", async () => {
  const r = await lookup("TOG-PRAM-000099J");
  assert.deepEqual([r.status, r.body, r.asked], [200, { code: "TOG-PRAM-000099J", status: "unknown" }, [PRAM_PG + "PG-PRAM-000099J"]]);
});

test("a 9-digit person exists only as TOG and is asked so; the registry's refusal is passed on", async () => {
  const r = await lookup("TOG-PRAM-123456789G");
  assert.deepEqual([r.status, r.body.error, r.asked], [400, "invalid_format", [PRAM_PG + "TOG-PRAM-123456789G"]]);
});

// The card live main shows for PG-0000016, as the proxy now answers it: lookup.md's fields and the registry's words.
const BRAND = { code: "TOG-0000016", kind: "subject", status: "active", visibility: "public", aliases: ["PRAMPTA"],
  owner_verified: true, subject_type: "brand", lifecycle_status: "commercial_enabled", authority_status: "self",
  subject_key: { public_key_hex: "02ffb782f2f0fecbc02aa3908963026a65b0e8f43e225a714190577cfc67225b", custody: "managed" },
  rules_text: "", registered_at: "2026-08-22T00:55:14.185363+00:00" };

test("a bare code goes to the first registry as before; only its curated card is shown, TOG", async () => {
  const r = await lookup("TOG-0000016");
  assert.deepEqual(r.asked, ["https://api2.prampta.com/v1/subjects/PG-0000016"]);
  assert.deepEqual([r.status, r.body], [200, BRAND]);   // no subject id, banner, auto-approve, tiers or controls
  noPG(r.body);
});

test("typed as live answered it: trimmed and case-folded, one code, one TOG spelling out", async () => {
  const want = { code: "TOG-PRAM-000043R", kind: "subject", status: "active" };
  for (const typed of ["pg-pram-000043r", " tog-pram-000043r ", "TOG-PRAM-000043R"]) {
    const r = await lookup(typed);
    assert.deepEqual([r.status, r.body], [200, want], typed);
  }
  assert.deepEqual((await lookup("pg-0000016")).body, BRAND);
});

test("the page shows a bare code's card as live main does, every code TOG", async () => {
  const el = () => ({ value: "", innerHTML: "", addEventListener() {}, focus() {} });
  const els = { pgForm: el(), pgInput: el(), pgResult: el() };
  let done;
  const shown = new Promise((r) => { done = r; });
  globalThis.document = { getElementById: (id) => els[id] };
  globalThis.window = { location: { search: "?code=TOG-0000016" }, history: { replaceState() {} } };
  const saved = globalThis.fetch;
  globalThis.fetch = async (url) => {
    assert.equal(url, "/api/lookup?code=TOG-0000016");
    setTimeout(done, 0);
    return { status: 200, json: async () => structuredClone(BRAND) };
  };
  const { readFile } = await import("node:fs/promises");
  const lib = new URL("../packages/verify-js/index.js", import.meta.url).href;
  const src = (await readFile(new URL("../lookup.js", import.meta.url), "utf8")).replace('"/packages/verify-js/index.js"', JSON.stringify(lib));
  await import("data:text/javascript," + encodeURIComponent(src));
  await shown;
  globalThis.fetch = saved;
  const html = els.pgResult.innerHTML;
  assert.deepEqual([...html.matchAll(/<dt>(.*?)<\/dt><dd>(.*?)<\/dd>/g)].map((m) => [m[1], m[2]]), [
    ["Aliases", "PRAMPTA"], ["Owner", "the registry says it verified the owner"], ["Type", "brand"],
    ["Lifecycle", "commercial_enabled"], ["Authority", "self"], ["Key custody", "managed"],
    ["Subject key", '<span class="mono">02ffb782f2f0fecbc02a…</span>'], ["Registered", "2026-08-22"]]);
  assert.match(html, /<span class="pg-code">TOG-0000016<\/span><span class="pg-badge ok">active<\/span><span class="pg-badge ">public<\/span>/);
  assert.equal(els.pgInput.value, "TOG-0000016");
});

test("an old licence number stays reachable through its proof, never shown", async () => {
  const r = await lookup("PG-STD-000001-K7M2QX9");
  assert.deepEqual(r.asked, ["https://api2.prampta.com/v1/licenses/PG-STD-000001-K7M2QX9/proof"]);
  assert.deepEqual([r.status, r.body], [200, { code: "(an old licence number)", status: "unknown" }]);
});

test("no policy: the route the site asked before; a missing route is not called unknown", async () => {
  const r = await lookup("TOG-TEST-000001N");
  assert.deepEqual([r.status, r.asked], [404, ["https://sandbox.pregen.org/v1/pg/PG-TEST-000001N"]]);
});

test("a /v2 answer is read as it stands, every code shown TOG", async () => {
  const r = await lookup("TOG-ZYXW-0000014");
  assert.deepEqual(r.asked, ["https://zyxw.example/v2/codes/PG-ZYXW-0000014"]);
  assert.equal(r.body.code, "TOG-TEST-000001N");
  assert.equal(r.body.subject_key.custody, "managed");
  noPG(r.body);
});

test("not a code, mistyped, or an unlisted prefix: nothing is asked", async () => {
  assert.deepEqual([await lookup("TOG-PRAM-000037K")].map((r) => [r.status, r.body.error, r.asked.length]), [[422, "check_mismatch", 0]]);
  assert.deepEqual([await lookup("TOG-PRAM-0000-37J")].map((r) => [r.status, r.body.error, r.asked.length]), [[422, "invalid_code", 0]]);
  assert.deepEqual([await lookup("TOG-NWRD-900000042R")].map((r) => [r.status, r.body.error, r.asked.length]), [[404, "unknown_issuer", 0]]);
});

test("the page asks for an old licence number by its folded id, however it was typed", async () => {
  const { normalizeTyped } = await import("../packages/verify-js/index.js");
  for (const typed of ["PG–STD–000001–K7M2QX9", "PG-STD-000001-K7M2QX9.", "https://www.pregen.org/lookup/PG-STD-000001-K7M2QX9",
    "РG-STD-000001-K7M2QX9", "PG-STD-OOOOO1-K7M2QX9", "pg-std-000001-k7m2qx9"]) {
    assert.throws(() => normalizeTyped(typed), (e) => e.reason === "ask_registry" && e.folded === "PG-STD-000001-K7M2QX9", typed);
  }
});
