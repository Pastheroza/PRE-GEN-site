// extensions/terms.md: a person's terms as a signed record, the floor and the person's rules, and what a proof shows
// about the terms its request accepted. spec/test-vectors/terms.json runs here and in verify-py (tests/test_terms.py); the
// tables below hold only what the vectors do not.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { CATEGORIES, PROHIBITED_FOR_MINORS, INTIMATE, floor, forbids, termsOpens, checkTerms, checkProof,
  signEnvelope, messageId, verifyDirectory, fingerprint, publicKeyHex, sha256Hex, PregenError } from "../index.js";

const V = JSON.parse(readFileSync(new URL("../../../spec/test-vectors/answers.json", import.meta.url)));
const T = JSON.parse(readFileSync(new URL("../../../spec/test-vectors/terms.json", import.meta.url)));
const NOW = V.now, CODE = "PG-TEST-000001N", OTHER_CODE = "PG-TEST-000003X", DROP = Symbol("drop");
const fetch = async (url) => (url in V.key_sets ? { ok: true, status: 200, json: async () => V.key_sets[url] }
  : { ok: false, status: 404, json: async () => ({}) });
const directory = await verifyDirectory(V.directory, { stewardPublicKeyHex: V.steward_public_key_hex, now: V.now });
const KEY = await sha256Hex("pregen-answer-vector-registry"), OTHER_KEY = await sha256Hex("pregen-answer-vector-other_registry");
const signer = async (key) => [{ role: "registry", key_id: await fingerprint(await publicKeyHex(key)) }];
const RULES = { purposes: ["editorial", "personal"], excluded_categories: ["gambling", "political"] };

async function terms({ key = KEY, ...change } = {}) {
  const body = { signers: await signer(key), subject_ref: CODE, profile: "likeness/1", version: 1,
    template: { id: "prampta-likeness", version: 1, jurisdiction: "US" },
    legal: { sha256: "b".repeat(64), url: "https://registry.test.example/terms-template-1.txt" },
    rules: RULES, minor: false, assent: "registry", instruction: "c".repeat(64), factor: "authenticator", issued_at: NOW - 100,
    ...change };
  return signEnvelope("pg.terms.v1", Object.fromEntries(Object.entries(body).filter(([, v]) => v !== DROP)), key);
}
const check = (env, code = CODE) => checkTerms(env, code, { directory, fetch });

// ── vocabulary and floor (TC1, TH1, TH6; D3: advertising is the 16th code) ──

test("the closed vocabulary holds the floor", () => {
  assert.equal(CATEGORIES.length, 16);
  assert.ok(CATEGORIES.includes("advertising"));
  assert.deepEqual([...PROHIBITED_FOR_MINORS].sort(), ["adult", "sexual", "violence"]);
  assert.deepEqual([...INTIMATE].sort(), ["adult", "sexual"]);
  assert.ok(INTIMATE.every((c) => PROHIBITED_FOR_MINORS.includes(c)) && PROHIBITED_FOR_MINORS.every((c) => CATEGORIES.includes(c)));
});

// the floor never reads a spelling of its own words as the word: the caller refuses it as outside CATEGORIES
const SPELLED = [["Sexual"], ["ADULT"], ["sex‍ual"], ["adult "], ["аdult"]].map((categories) => ({ purpose: "personal", categories }));
const FLOOR = [...T.floor.map((v) => [v.use, v.minor, v.result]), ...SPELLED.map((use) => [use, true, null])];
for (const [use, minor, expected] of FLOOR) {
  test(`floor(${JSON.stringify(use)}, ${minor}) is ${expected}`, () => assert.equal(floor(use, minor), expected));
}

test("floor refuses categories that are not a list of words", () => {
  for (const categories of ["sexual", [["adult"]], [1]]) {
    assert.throws(() => floor({ purpose: "personal", categories }, true), PregenError);
  }
});

const FORBIDS = T.forbids.map((v) => [v.rules, v.use, v.result]);
for (const [rules, use, expected] of FORBIDS) {
  test(`forbids(${JSON.stringify(rules)}, ${JSON.stringify(use)}) is ${expected}`, () => assert.equal(forbids(rules, use), expected));
}

const OPENS = T.opens.map((v) => [v.old, v.new, v.result]);
OPENS.forEach(([old, next, expected], i) => test(`termsOpens case ${i}`, () => assert.equal(termsOpens(old, next), expected)));

// ── the record ──

for (const v of T.records) {
  test(`record vector: ${v.name}`, async () => {
    if (v.ok) assert.deepEqual(await check(v.envelope, v.code), v.envelope.body);
    else await assert.rejects(check(v.envelope, v.code), PregenError);
  });
}

test("a published version checks out and says whose word it is", async () => {
  const env = await terms();
  const body = await check(env);
  assert.deepEqual(body, env.body);
  assert.equal(body.assent, "registry");
  const later = await terms({ version: 2, amends: await messageId("pg.terms.v1", body), factor: DROP }); // only narrows
  assert.equal((await check(later)).version, 2);
});

const BAD = [ // beyond the vectors
  { profile: "likeness/2" }, { instruction: DROP }, { factor: null }, { minor: 0 }, { issued_at: -1 }, { subject_ref: OTHER_CODE },
  { rules: { excluded_categories: [] } },
  { template: { id: "prampta-likeness", version: 1 } }, { template: { id: "Prampta", version: 1, jurisdiction: "US" } },
  { template: { id: "prampta-likeness", version: 1, jurisdiction: "U‍S" } },
  { legal: { sha256: "B".repeat(64), url: "https://x" } },
  { legal: { sha256: "b".repeat(64), url: "https://x/a b" } }, { legal: { sha256: "b".repeat(64), url: "https://" + "x".repeat(2041) } },
  { template: { id: "prampta-likeness", version: 1, jurisdiction: "USA" } },
];
for (const change of BAD) {
  test(`checkTerms refuses ${JSON.stringify(change)}`, async () => {
    await assert.rejects(check(await terms(change)), PregenError);
  });
}

test("PL1: a number canonical JSON refuses is refused, not crashed", async () => {
  const env = await terms();
  for (const change of [{ version: 1.5 }, { version: 2 ** 53 }, { issued_at: NOW + 0.5 }]) {
    await assert.rejects(check({ ...env, body: { ...env.body, ...change } }), /signed JSON/);
  }
});

test("PL1: an integral number is that integer however it is written", async () => {
  // JSON.parse reads 1.0 and 1e0 as 1; verify-py reads them the same way (tests/test_terms.py runs these texts too).
  const env = await terms();
  const text = JSON.stringify(env).replace('"version":1,', '"version":1.0,').replace(`"issued_at":${NOW - 100}`, `"issued_at":${NOW - 100}e0`);
  assert.notEqual(text, JSON.stringify(env));
  assert.deepEqual(await check(JSON.parse(text)), env.body);
});

test("PM1, PM10: only this person's terms, signed by their registry's key", async () => {
  await assert.rejects(check(await terms(), OTHER_CODE), /another person/);
  await assert.rejects(check(await terms({ key: OTHER_KEY })), /may not sign/);
  const env = await terms();
  await assert.rejects(check({ ...env, body: { ...env.body, minor: true } }), /bad signature/);
  const two = { ...env, body: { ...env.body, signers: [...env.body.signers, ...env.body.signers] }, signatures: [...env.signatures, ...env.signatures] };
  await assert.rejects(check(two), /exactly one registry key/);
});

// ── what a proof shows about the terms (D1: cited only through the provider's signed request) ──

const POLICY = { kind: "policy", rule: "test" }, GRANT = { kind: "grant", grant: { format: "pg.grant.v1", id: "e".repeat(64) } };
const USE = { purpose: "personal", categories: ["fashion"] };

async function finding({ use = USE, record, cite, carry = true, basis = POLICY, code = CODE } = {}) {
  record ??= await terms();
  const s = await signer(KEY);
  const asked = { subject_ref: code, provider_id: "https://frame.example", profile: "likeness/1", use, job_id: "job-1", job_hash: "a".repeat(64) };
  if (cite !== DROP) asked.terms = cite ?? (await messageId("pg.terms.v1", record.body));
  const answer = await signEnvelope("pg.answer.v1", { signers: s, request_id: await messageId("pg.request.v1", asked),
    profile: "likeness/1", status: "allow", basis, issued_at: NOW - 10, expires_at: NOW + 290 }, KEY);
  const report = { type: "pg.report.v1", signatures: [], body: { answer: await messageId("pg.answer.v1", answer.body),
    outcome: "generated", output_hash: "d".repeat(64), job_id: "job-1", occurred_at: NOW } };
  const ack = await signEnvelope("pg.report_ack.v1", { signers: s, report: await messageId("pg.report.v1", report.body),
    answer: report.body.answer, received_at: NOW }, KEY);
  const item = { request: { type: "pg.request.v1", body: asked, signatures: [] }, answer, report, ack };
  if (carry) item.terms = record;
  const [s0] = (await checkProof({ format: "pg.proof.v1", subjects: [item] }, { directory, fetch, now: NOW })).subjects;
  return [s0.terms, s0.termsAssent];
}

test("a proof for a false claim is refused", async () => {   // identity round B4e: checkProof skipped the steward's ruling
  await assert.rejects(finding({ code: "PG-TEST-000002Z", cite: DROP, carry: false }), /false claim/);
});

for (const v of T.proofs) {
  test(`proof vector: ${v.name}`, async () => {
    const [s0] = (await checkProof(v.bundle, { directory, fetch, now: NOW })).subjects;
    assert.deepEqual([s0.terms, s0.termsAssent], [v.terms, v.terms_assent]);
  });
}

test("PL1: a proof reads integral numbers as verify-py does", async () => {
  const text = JSON.stringify(T.proofs[0].bundle);
  for (const spelled of [text.replace('"version":1,', '"version":1.0,'),                          // the carried terms
    text.replace(`"issued_at":${NOW - 10},`, `"issued_at":${NOW - 10}.0,`)]) {                      // the answer (core)
    assert.notEqual(spelled, text);
    const [s0] = (await checkProof(JSON.parse(spelled), { directory, fetch, now: NOW })).subjects;
    assert.deepEqual([s0.terms, s0.termsAssent], ["ok", "registry"]);
  }
});

test("terms in a proof", async () => { // beyond the vectors
  assert.deepEqual(await finding(), ["ok", "registry"]);
  assert.deepEqual(await finding({ cite: DROP, carry: false }), ["absent", null]);
  assert.deepEqual(await finding({ cite: "f".repeat(64) }), ["unverified", null]);                         // not the version accepted
  assert.deepEqual(await finding({ record: await terms({ subject_ref: OTHER_CODE }) }), ["unverified", null]); // PM1
  assert.deepEqual(await finding({ use: { purpose: "commercial" } }), ["outside", "registry"]);
  assert.deepEqual(await finding({ use: { purpose: "personal", categories: ["adult"] }, basis: GRANT }), ["outside", "registry"]);
  assert.deepEqual(await finding({ use: { purpose: "personal", categories: ["violence"] } }), ["ok", "registry"]);
  for (const spelled of [["Sexual"], "fashion"]) {                                                          // TC1
    assert.deepEqual(await finding({ use: { purpose: "personal", categories: spelled } }), ["outside", "registry"]);
  }
});

test("TOG-CODE.md §7.3: terms of one person under either spelling", async () => {
  assert.equal((await check(await terms(), "TOG-TEST-000001N")).subject_ref, CODE);
  assert.equal((await check(await terms({ subject_ref: "TOG-TEST-000001N" }))).subject_ref, "TOG-TEST-000001N");
});
