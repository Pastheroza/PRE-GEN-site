// The site's lookup proxy (api/lookup.js): PG codes are retired, so a PG- string gets one neutral message and nothing
// is asked; a ToG code is asked at the route its registry publishes, through the marked transition shim at a registry
// not yet migrated; answers never show PG-. No network: registry answers below were recorded live on 2026-11-10.
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
  "https://api2.prampta.com/v1/subjects/PG-0000016": [200, require("./subject-PG-0000016.json")],
  // The sandbox publishes no policy and no /v1/pg: the fallback route is asked, its 404 is not called "unknown".
  "https://sandbox.pregen.org/.well-known/pg-policy": [404, { detail: "Not Found" }],
  "https://sandbox.pregen.org/v1/pg/PG-TEST-000001N": [404, { detail: "Not Found" }],
  // A migrated registry: its policy names /v2/codes (it announces TOG); the sandbox's recorded /v2 answer, with a PG
  // string left in a free-text field.
  "https://zyxw.example/.well-known/pg-policy": [200, { resolver_url_template: "https://zyxw.example/v2/codes/{code}" }],
  "https://zyxw.example/v2/codes/TOG-ZYXW-0000014": [200, { code: "TOG-ZYXW-0000014", registry: "ZYXW", status: "active",
    rules_text: "Formerly PG-ZYXW-0000014.",
    name: "Test subject 1 (allow)", level: "verified", subject_key: { key_id: "pg-ed25519:e9d2d58988e65dbe81975c357fbe3bd2",
      public_key_hex: "59c3f4a451a9002def6ddfd3efeb01e33546d28d918f82820f4e3dced51459e3", custody: "managed" } }],
};

const asked = [];
globalThis.fetch = async (url) => {
  asked.push(url);
  const [status, body] = RECORDED[url] ?? [404, { detail: "Not Found" }];
  return { status, ok: status < 300, json: async () => structuredClone(body) };
};

async function lookup(code, ip) {
  const out = {};
  const res = { setHeader() {}, status(s) { out.status = s; return this; }, json(b) { out.body = b; } };
  asked.length = 0;
  await handler({ method: "GET", query: { code }, headers: ip ? { "x-forwarded-for": ip } : {} }, res);
  return { ...out, asked: asked.filter((u) => !u.endsWith("/pg-policy")) };
}
const noPG = (body) => assert.doesNotMatch(JSON.stringify(body), /(^|[^O])PG-[A-Z0-9]/);

const RETIRED = "PG codes are retired. Use the ToG code your registry shows you.";
const retired = (r) => assert.deepEqual([r.status, r.body, r.asked],
  [422, { error: "invalid_code", detail: RETIRED }, []]);

test("the shim: a person of the old shape is asked in PG at a registry not yet migrated, and shown TOG", async () => {
  const want = { code: "TOG-PRAM-000043R", kind: "subject", status: "active" };
  const first = await lookup("TOG-PRAM-000043R");
  assert.deepEqual([first.status, first.body, first.asked], [200, want, [PRAM_PG + "PG-PRAM-000043R"]]);
});

test("a PG string is not a code: one neutral message, no TOG suggestion, nothing asked", async () => {
  for (const typed of ["PG-PRAM-000043R", "pg-pram-000043r", "PG-0000016", " pg-std-000001-k7m2qx9 ", "PG-PRAM-900000037K",
    "PG–0000016", "(PG-0000016)", "PG0000016", "P G-0000016", "РГ-0000016"]) {
    retired(await lookup(typed, "203.0.113.7"));   // its own address: the rate limit is per IP
  }
});

test("a person PRAMPTA never issued is unknown, in the TOG spelling", async () => {
  const r = await lookup("TOG-PRAM-000099J");
  assert.deepEqual([r.status, r.body, r.asked], [200, { code: "TOG-PRAM-000099J", status: "unknown" }, [PRAM_PG + "PG-PRAM-000099J"]]);
});

test("the shim asks nothing else at a registry not yet migrated: a 9-digit person or an act is not found", async () => {
  for (const code of ["TOG-PRAM-123456789G", "TOG-LIC-PRAM-ZZZZ-QH28-TDQ8"]) {
    const r = await lookup(code);
    assert.deepEqual([r.status, r.body, r.asked], [200, { code, status: "unknown" }, []], code);
  }
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

test("typed as live answered it: trimmed and case-folded, one code out", async () => {
  const want = { code: "TOG-PRAM-000043R", kind: "subject", status: "active" };
  for (const typed of [" tog-pram-000043r ", "TOG-PRAM-000043R"]) {
    const r = await lookup(typed);
    assert.deepEqual([r.status, r.body], [200, want], typed);
  }
  assert.deepEqual((await lookup("tog-0000016")).body, BRAND);
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

test("a migrated registry is asked for the TOG code at its /v2 route; a PG string left in its answer is not shown", async () => {
  const r = await lookup("TOG-ZYXW-0000014");
  assert.deepEqual(r.asked, ["https://zyxw.example/v2/codes/TOG-ZYXW-0000014"]);
  assert.equal(r.body.code, "TOG-ZYXW-0000014");
  assert.equal(r.body.rules_text, "Formerly (a retired code).");
  noPG(r.body);
});

test("no policy: the route the site asked before; a missing route is not called unknown", async () => {
  const r = await lookup("TOG-TEST-000001N");
  assert.deepEqual([r.status, r.asked], [404, ["https://sandbox.pregen.org/v1/pg/PG-TEST-000001N"]]);
});

test("not a code, mistyped, or an unlisted prefix: nothing is asked", async () => {
  assert.deepEqual([await lookup("TOG-PRAM-000037K")].map((r) => [r.status, r.body.error, r.asked.length]), [[422, "check_mismatch", 0]]);
  assert.deepEqual([await lookup("TOG-PRAM-0000-37J")].map((r) => [r.status, r.body.error, r.asked.length]), [[422, "invalid_code", 0]]);
  assert.deepEqual([await lookup("TOG-NWRD-900000042R")].map((r) => [r.status, r.body.error, r.asked.length]), [[404, "unknown_issuer", 0]]);
});

test("a ToG code holding a PG-looking group, wrapped or mistyped, is not a code, never retired", async () => {
  for (const typed of ['"TOG-PG-PRAM-9R3M-11B2-QVD3"', "(TOG-PG-PRAM-9R3M-11B2-QVD3)", "TO-PG-PRAM-9R3M-11B2-QVD3",
    "PG-PRAM-ZZZZ-K6X4-RZJB", "(TOG-LIC-PRAM-ZZZZ-HPG0-RJ0C)"]) {
    const r = await lookup(typed, "203.0.113.8");
    assert.deepEqual([r.status, r.body, r.asked], [422, { error: "invalid_code", detail: "Not a code." }, []], typed);
  }
});

test("the page: a typed PG string gets only the retired message, and nothing is asked", async () => {
  const { normalizeTyped } = await import("../packages/verify-js/index.js");
  for (const typed of ["PG–STD–000001–K7M2QX9", "PG-STD-000001-K7M2QX9.", "https://www.pregen.org/lookup/PG-STD-000001-K7M2QX9",
    "РG-STD-000001-K7M2QX9", "pg-pram-000043r", "PG 000 042 *", "https://api2.prampta.com/v1/pg/PG-PRAM-000043R"]) {
    assert.throws(() => normalizeTyped(typed), (e) => e.reason === "malformed" && e.message === RETIRED && !e.hints, typed);
  }
  const el = () => ({ value: "", innerHTML: "", addEventListener() {}, focus() {} });
  const els = { pgForm: el(), pgInput: el(), pgResult: el() };
  globalThis.document = { getElementById: (id) => els[id] };
  globalThis.window = { location: { search: "?code=PG-PRAM-000043R" }, history: { replaceState() {} } };
  const saved = globalThis.fetch;
  let fetched = 0;
  globalThis.fetch = async () => { fetched++; return { status: 500, json: async () => ({}) }; };
  const { readFile } = await import("node:fs/promises");
  const lib = new URL("../packages/verify-js/index.js", import.meta.url).href;
  const src = (await readFile(new URL("../lookup.js", import.meta.url), "utf8")).replace('"/packages/verify-js/index.js"', JSON.stringify(lib));
  await import("data:text/javascript," + encodeURIComponent(src + "\n// typed PG"));
  globalThis.fetch = saved;
  assert.equal(fetched, 0);
  assert.match(els.pgResult.innerHTML, /PG codes are retired\. Use the ToG code your registry shows you\./);
  assert.doesNotMatch(els.pgResult.innerHTML, /TOG-PRAM/);   // no suggestion
});

// lookup.md, ToG codes: pending and expired in plain words; a company holder; a licence names its ToG code and level.
async function shownFor(answer, tag) {
  const el = () => ({ value: "", innerHTML: "", addEventListener() {}, focus() {} });
  const els = { pgForm: el(), pgInput: el(), pgResult: el() };
  let done;
  const shown = new Promise((r) => { done = r; });
  globalThis.document = { getElementById: (id) => els[id] };
  globalThis.window = { location: { search: "?code=" + answer.code }, history: { replaceState() {} } };
  const saved = globalThis.fetch;
  globalThis.fetch = async () => { setTimeout(done, 0); return { status: 200, json: async () => structuredClone(answer) }; };
  const { readFile } = await import("node:fs/promises");
  const lib = new URL("../packages/verify-js/index.js", import.meta.url).href;
  const src = (await readFile(new URL("../lookup.js", import.meta.url), "utf8")).replace('"/packages/verify-js/index.js"', JSON.stringify(lib));
  await import("data:text/javascript," + encodeURIComponent(src + "\n// " + tag));
  await shown;
  globalThis.fetch = saved;
  return [...els.pgResult.innerHTML.matchAll(/<dt>(.*?)<\/dt><dd>(.*?)<\/dd>/g)].map((m) => [m[1], m[2]]);
}

test("the page: a pending or expired ToG code in plain words, a company holder, a licence's ToG code", async () => {
  const head = { code: "TOG-PRAM-900000037K", kind: "subject", registry: "PRAM" };
  assert.deepEqual((await shownFor({ ...head, status: "pending" }, "pending"))[0],
    ["Status", "Not verified yet. It permits nothing and forbids nothing. A code not verified within 7 days of its issue is deleted."]);
  assert.match((await shownFor({ ...head, status: "expired" }, "expired"))[0][1], /^Deleted: it was not verified within 7 days\./);
  assert.deepEqual(await shownFor({ ...head, status: "active", holder: "company", domain: "northwind.example", level: "channel" }, "co"),
    [["Holder", "a company"], ["Domain", "northwind.example"], ["Level", "channel (the registry's claim)"], ["Registry", "PRAM"]]);
  const lic = { code: "TOG-LIC-NWRD-PRAM-ZZZZ-84RN-RT04", kind: "license", registry: "PRAM", status: "active", issuer: "PRAM",
    subject: "TOG-PRAM-900000037K" };
  assert.deepEqual((await shownFor({ ...lic, subject_level: "verified" }, "lic1")).slice(0, 1),
    [["ToG code", '<span class="mono">TOG-PRAM-900000037K</span> · identity verified']]);
  assert.deepEqual((await shownFor({ ...lic, subject_level: "channel" }, "lic2")).slice(0, 1),
    [["ToG code", '<span class="mono">TOG-PRAM-900000037K</span> · channel, identity not verified']]);
});
