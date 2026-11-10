// The site's lookup proxy (api/lookup.js): PG- input is asked in its TOG spelling, answers show TOG only.
// Run: node --test test/lookup.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const handler = createRequire(import.meta.url)("../api/lookup.js");
const asked = [];
globalThis.fetch = async (url) => {
  asked.push(url);
  return { status: 200, json: async () => ({ code: decodeURIComponent(url.split("/").at(-1)), kind: "subject",
    status: "active", note: "also PG-PRAM-000037J.", license_id: "PG-STD-000001-K7M2QX9" }) };
};

async function lookup(code) {
  const out = {};
  const res = { setHeader() {}, status(s) { out.status = s; return this; }, json(b) { out.body = b; } };
  asked.length = 0;
  await handler({ method: "GET", query: { code }, headers: {} }, res);
  return { ...out, asked: asked.slice() };
}

test("a PG person is asked and shown in its TOG spelling", async () => {
  const r = await lookup("PG-PRAM-000037J");
  assert.deepEqual(r.asked, ["https://api2.prampta.com/v2/codes/TOG-PRAM-000037J"]);
  assert.equal(r.body.code, "TOG-PRAM-000037J");
  assert.equal(r.body.note, "also TOG-PRAM-000037J.");
  assert.equal(r.body.license_id, "(an old licence number)");
  assert.doesNotMatch(JSON.stringify(r.body), /(^|[^O])PG-[A-Z0-9]/);
});

test("a bare code goes to the first registry", async () => {
  assert.deepEqual((await lookup("TOG-0000016")).asked, ["https://api2.prampta.com/v2/codes/TOG-0000016"]);
});

test("an old licence number stays reachable, never shown", async () => {
  const r = await lookup("PG-STD-000001-K7M2QX9");
  assert.deepEqual(r.asked, ["https://api2.prampta.com/v2/codes/PG-STD-000001-K7M2QX9"]);
  assert.equal(r.body.code, "(an old licence number)");
});

test("not a code, mistyped, or an unlisted prefix: nothing is asked", async () => {
  assert.deepEqual([await lookup("TOG-PRAM-000037K")].map((r) => [r.status, r.body.error, r.asked.length]), [[422, "check_mismatch", 0]]);
  assert.deepEqual([await lookup("tog-pram-000037j")].map((r) => [r.status, r.body.error, r.asked.length]), [[422, "invalid_code", 0]]);
  assert.deepEqual([await lookup("TOG-NWRD-900000042R")].map((r) => [r.status, r.body.error, r.asked.length]), [[404, "unknown_issuer", 0]]);
});

test("the page asks for an old licence number by its folded id, however it was typed", async () => {
  const { normalizeTyped } = await import("../packages/verify-js/index.js");
  for (const typed of ["PG–STD–000001–K7M2QX9", "PG-STD-000001-K7M2QX9.", "https://www.pregen.org/lookup/PG-STD-000001-K7M2QX9",
    "РG-STD-000001-K7M2QX9", "PG-STD-OOOOO1-K7M2QX9", "pg-std-000001-k7m2qx9"]) {
    assert.throws(() => normalizeTyped(typed), (e) => e.reason === "ask_registry" && e.folded === "PG-STD-000001-K7M2QX9", typed);
  }
});
