// TOG-CODE.md: spec/test-vectors/tog-code.json, every section, replayed here and in verify-py. Generated from the
// reference model spec/tools/tog_code.py; a disagreement is an erratum, never a local fix.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { CROCKFORD, TOG_VALUES, FIXTURE_PREFIXES, RETIRED, CodeError, PregenError, checkChar, parseCode, codeKey, normalizeTyped, codeFor,
  metadataOk, codeVerdict, checkParties, admissionRefusal, findCodes, issuerOf, kindOf, describe } from "../index.js";

const V = JSON.parse(readFileSync(new URL("../../../spec/test-vectors/tog-code.json", import.meta.url)));

// {result} or {error[, hints][, message]}, as the generator writes them; `message` only for the retired message.
function run(fn) {
  try {
    return { result: fn() };
  } catch (e) {
    if (!(e instanceof CodeError)) throw e;
    return { error: e.reason, ...(e.hints && { hints: e.hints }), ...(e.message === RETIRED && { message: RETIRED }) };
  }
}
const expected = ({ result, error, hints, message }) =>
  (error ? { error, ...(hints && { hints }), ...(message && { message }) } : { result });

test("alphabet: tables, limits, fixtures", () => {
  const a = V.alphabet;
  assert.equal(CROCKFORD, a.crockford);
  assert.equal(TOG_VALUES, a.tog_values);
  assert.deepEqual([...FIXTURE_PREFIXES], a.fixture_prefixes);
  assert.equal(checkChar("0".repeat(a.max_body)), "0");
  assert.throws(() => checkChar("0".repeat(a.max_body + 1)), CodeError);
});

test("examples: every printed code parses, is its own key, and is an example", () => {
  for (const codes of Object.values(V.examples)) {
    for (const c of codes) {
      const p = parseCode(c);
      assert.equal(codeKey(c), c);
      assert.equal(p.example || p.shape.startsWith("old_"), true, c);
    }
  }
});

test("check_char: both tables", () => {
  for (const { body, tog, pg } of V.check_char) {
    assert.equal(run(() => checkChar(body)).result ?? null, tog, body);
    assert.equal(run(() => checkChar(body, CROCKFORD)).result ?? null, pg, body);
  }
});

test("parse: one reading per string", () => {
  for (const c of V.parse) {
    const got = run(() => parseCode(c.code));
    assert.deepEqual(got, c.parsed ? { result: c.parsed } : expected(c), c.code);
    if (c.parsed) assert.equal(kindOf(c.code), c.parsed.kind, c.code);
  }
});

test("describe: what a string claims", () => {
  for (const c of V.describe) assert.deepEqual(run(() => describe(c.code)), expected(c), c.code);
});

test("must_reject: each string fails with its class", () => {
  assert.equal(V.must_reject.length, 69);
  for (const { string, error, why } of V.must_reject) assert.deepEqual(run(() => parseCode(string)), { error }, why);
});

test("refused_by_0_13: the 0.13 grammar refuses every TOG code; 0.14 still routes it", () => {
  // The grammar @pregen/verify 0.13 published (PG-CODE.md §7), verbatim.
  const OLD = /^(?:PG-(?:([ABCDEFGHJKMNPQRSTVWXYZ]{4})-)?(?:[0-9]{6,}[0-9A-HJKMNP-TV-Z*~$=!]|[A-Z]{3}-[0-9]{6,}-[0-9A-HJKMNP-TV-Z]{6}[0-9A-HJKMNP-TV-Z*~$=!])|PG-[A-Z]{3}-[0-9]{6,})$/;
  for (const c of V.refused_by_0_13) assert.equal(OLD.test(c), false, c);
  for (const c of V.refused_by_0_13.filter((x) => x.startsWith("TOG-"))) assert.equal(issuerOf(c), parseCode(c).issuer, c);
});

test("code_key: the code itself, no folding; a PG string is not a code", () => {
  for (const c of V.code_key) assert.deepEqual(run(() => codeKey(c.code)), expected(c), c.code);
  for (const c of V.code_key) {
    if (c.result) assert.equal(c.result, c.code);
    if (c.code.startsWith("PG-")) assert.equal(c.error, "malformed", c.code);
  }
});

test("typed: folded where a person types, one reading or none; a typed PG string gets only the retired message", () => {
  for (const c of V.typed) assert.deepEqual(run(() => normalizeTyped(c.input)), expected(c), JSON.stringify(c.input));
  for (const t of ["PG–STD–000001–K7M2QX9", "РG-STD-000001-K7M2QX9", "pg 000 042 *", "https://api2.prampta.com/v1/pg/PG-PRAM-000037J"]) {
    assert.deepEqual(run(() => normalizeTyped(t)), { error: "malformed", message: RETIRED }, t);
  }
});

test("migrate: a PG id a registry migrates is, from outside, not a code anywhere", () => {
  for (const { old } of V.migrate.filter((c) => c.old.startsWith("PG-"))) {
    for (const fn of [parseCode, codeKey, kindOf, issuerOf, describe]) assert.throws(() => fn(old), CodeError, old);
    assert.deepEqual(findCodes(`see ${old}.`), [], old);
    assert.equal(codeVerdict("aa".repeat(32), null, old), "Not a code.", old);
  }
});

test("code_for: codes computed from records", () => {
  for (const c of V.code_for) assert.deepEqual(run(() => codeFor(c.act)), expected(c), c.name);
});

test("metadata: readable copies against their record", () => {
  for (const c of V.metadata) assert.equal(metadataOk(c.meta, c.act, c.licence), c.ok, c.name);
});

test("verdict: what a verifier may say before signatures", () => {
  for (const c of V.verdict) assert.equal(codeVerdict(c.file, c.act, c.caption, c.ingredient), c.words, JSON.stringify(c.caption));
});

test("lookup: a registry finds a person by number and answers in TOG", () => {
  // What a registry looks a person up by: (issuer, legacy class, number). An over-padded number is PG_MALFORMED.
  const personKey = (code) => {
    const p = parseCode(code);
    assert.equal(p.kind, "subject");
    return `${p.issuer}|${p.cls}|${BigInt(p.serial)}`;
  };
  const issued = new Map(V.lookup.issued.map((c) => [personKey(c), c]));
  for (const c of V.lookup.cases) {
    const got = run(() => {
      const hit = issued.get(personKey(c.asked));
      if (hit === undefined) return { status: "not_found" };
      return codeKey(c.asked) === hit ? { status: "found", code: hit } : { status: "PG_MALFORMED", hint: hit };
    });
    const { asked, ...want } = c;
    assert.deepEqual(got.result ?? got, want, asked);
  }
});

test("parties: dated party checks against a v3-shaped directory", () => {
  for (const c of V.parties.cases) {
    const got = checkParties(c.code, V.parties.directories[c.directory], { at: c.at, provider: c.provider });
    assert.deepEqual(got, { ok: c.ok, facts: c.facts }, `${c.directory} ${c.code} at ${c.at}`);
  }
});

test("admission: prefixes the steward admits or refuses", () => {
  const A = V.admission, fixtures = Object.fromEntries(Object.entries(A.fixtures).map(([k, v]) => [k, { entity: v.entity }]));
  for (const c of A.in_order) {
    const dir = Object.fromEntries(c.directory.map((k) => [k, fixtures[k]]));
    assert.equal(admissionRefusal(c.prefix, c.entity, c.government, dir, []), c.refusal, c.prefix);
  }
  for (const c of A.cases) {
    const dir = c.directory === null ? fixtures : Object.fromEntries(Object.entries(c.directory).map(([k, v]) => [k, { entity: v }]));
    const got = admissionRefusal(c.prefix, c.entity, c.government, dir, c.fixtures_reserved ? FIXTURE_PREFIXES : []);
    assert.equal(got === "", c.refusal === "", c.prefix);   // normative
    assert.equal(got, c.refusal, c.prefix);                 // the wording too, while it agrees
  }
});

test("find_codes: codes in free text", () => {
  for (const c of V.find_codes) assert.deepEqual(findCodes(c.text), c.codes, c.text);
});

// ── beyond the vectors: directory v3, the TOG spelling in comparisons, readable copies in a proof ──
import { canonicalJson, fingerprint, verifyDirectory, checkProof, checkChannelProof, signEnvelope, messageId, publicKeyHex, sha256Hex,
  DIRECTORY_URL, DIRECTORY_V2_URL } from "../index.js";

const hex = (b) => Buffer.from(b).toString("hex");
const steward = await (async () => {
  const k = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pub = hex(await crypto.subtle.exportKey("raw", k.publicKey)), id = await fingerprint(pub);
  const sign = async (d) => ({ ...d, signature: hex(await crypto.subtle.sign({ name: "Ed25519" }, k.privateKey,
    new TextEncoder().encode(canonicalJson(d)))) });
  return { pub, id, sign };
})();
const T0 = "2026-01-01T00:00:00Z", T1 = "2028-01-01T00:00:00Z";
const entry = (prefix, extra = {}) => ({ name: prefix, prefix, api: `https://${prefix.toLowerCase()}.test`,
  keys: `https://${prefix.toLowerCase()}.test/keys`, key_fingerprints: [steward.id], ...extra });
const v3 = (registries, extra = {}) => steward.sign({ schema: "pregen.registries.v3", sequence: 1, steward_key_id: steward.id,
  registries, ...extra });
const load = async (d, opts = {}) => verifyDirectory(await d, { stewardPublicKeyHex: steward.pub, successorPublicKeyHex: null, ...opts });

test("directory v3: 4-8 letter prefixes, dated roles, routing of TOG codes; v2 still reads", async () => {
  assert.equal(DIRECTORY_URL, "https://www.pregen.org/registries.v3.json");
  assert.equal(DIRECTORY_V2_URL, "https://www.pregen.org/registries.json");
  const d = await load(v3([entry("PRAM", { entity: "PRAMPTA Inc.", group: "g1", roles: { home: { from: T0, until: null } } }),
    entry("KOBEMK", { entity: "Kobe market KK", group: "g2", roles: { market: { from: T0, until: T1 } },
      provider_domains: [{ domain: "https://kobe.example", from: T0, until: null }] })],
    { resolver: "https://resolver.example", min_library: "0.14.0" }));
  assert.equal(d.registryFor("TOG-PRAM-900000037K").prefix, "PRAM");
  assert.equal(d.registryFor("PG-PRAM-000037J"), null);   // not a code: no registry
  assert.equal(d.registryFor("TOG-LIC-KOBEMK-PRAM-ZZZZ-BYAV-K2AQ").prefix, "KOBEMK");
  const at = Date.parse("2027-01-01T00:00:00Z") / 1000, late = Date.parse("2029-01-01T00:00:00Z") / 1000;
  assert.deepEqual(d.parties("TOG-LIC-KOBEMK-PRAM-ZZZZ-BYAV-K2AQ", { at, provider: "https://kobe.example" }),
    { ok: true, facts: ["issuer KOBEMK (Kobe market KK)", "home PRAM (PRAMPTA Inc.)", "KOBEMK also generated it (https://kobe.example)"] });
  assert.equal(d.parties("TOG-LIC-KOBEMK-PRAM-ZZZZ-BYAV-K2AQ", { at: late }).ok, false);
  for (const bad of [entry("PRA"), entry("LICX"), entry("PRAM", { roles: { branch: { from: T0, until: null } } }),
    entry("PRAM", { roles: { home: { from: "2026-02-30T00:00:00Z", until: null } } }), entry("PRAM", { government: "no" }),
    entry("PRAM", { provider_domains: ["https://x.example"] }), entry("PRAM", { void_from: 5 })]) {
    await assert.rejects(load(v3([bad])), PregenError, JSON.stringify(bad));
  }
  await assert.rejects(load(v3([entry("PRAM")], { min_library: "next" })), PregenError);
  // a v2 directory keeps its own rules: 4 Crockford letters only, no party checks
  const v2 = await steward.sign({ schema: "pregen.registries.v2", sequence: 7, steward_key_id: steward.id, registries: [entry("PRAM")] });
  const d2 = await load(v2);
  assert.equal(d2.registryFor("TOG-PRAM-900000037K").prefix, "PRAM");
  assert.throws(() => d2.parties("TOG-PRAM-900000037K"), /v3/);
  await assert.rejects(load(steward.sign({ schema: "pregen.registries.v2", sequence: 1, steward_key_id: steward.id,
    registries: [entry("KOBEMK")] })), /bad prefix/);
  // two lines: v2 then v3 is accepted whatever the sequences; v3 then v2 is refused
  const next = await load(v3([entry("PRAM")]), { previous: d2 });
  assert.equal(next.sequence, 1);
  await assert.rejects(load(v2, { previous: next }), /v3 directory was already accepted/);
});

test("one code, one spelling: false claims and channel lines compare by the code; a PG string matches nothing", async () => {
  const d = await load(v3([entry("ZYXW")], {
    false_claims: [{ anchor: "wikidata:Q1", code: "TOG-ZYXW-1234567R", at: T0, reason: "test" },
      { anchor: "wikidata:Q3", code: "PG-ZYXW-1234568=", at: T0, reason: "test" }] }));
  assert.equal(d.isFalseClaim("TOG-ZYXW-1234567R"), true);
  assert.equal(d.isFalseClaim("TOG-ZYXW-1234567R", "wikidata:Q1"), true);
  assert.equal(d.isFalseClaim("PG-ZYXW-1234567R", "wikidata:Q1"), false);
  assert.equal(d.isFalseClaim("TOG-ZYXW-1234567R", "wikidata:Q2"), false);
  assert.equal(d.isFalseClaim("TOG-ZYXW-1234568="), false);    // a PG line names no one
  const url = "https://example.com/.well-known/pregen", line = (t) => () => `PRE-GEN: ${t}`;
  assert.equal(await checkChannelProof("TOG-ZYXW-1234567R", url, ["https://example.com"], line("TOG-ZYXW-1234567R")), true);
  assert.equal(await checkChannelProof("TOG-ZYXW-1234567R", url, ["https://example.com"], line("PG-ZYXW-1234567R")), false);
  assert.equal(await checkChannelProof("PG-ZYXW-1234567R", url, ["https://example.com"], line("PG-ZYXW-1234567R")), false);
  assert.equal(await checkChannelProof("TOG-ZYXW-1234567R", url, ["https://example.com"], line("tog-zyxw-1234567r")), false);
});

// A proof with readable copies, on answers.json's directory and keys (prefix TEST, flat model).
const A = JSON.parse(readFileSync(new URL("../../../spec/test-vectors/answers.json", import.meta.url)));
const aDir = await verifyDirectory(A.directory, { stewardPublicKeyHex: A.steward_public_key_hex, now: A.now });
const aFetch = async (url) => ({ ok: url in A.key_sets, status: url in A.key_sets ? 200 : 404, json: async () => A.key_sets[url] ?? {} });
const KEY = await sha256Hex("pregen-answer-vector-registry");

async function proof(code, { grant = true, copies = (c) => c } = {}) {
  const signers = [{ role: "registry", key_id: await fingerprint(await publicKeyHex(KEY)) }], NOW = A.now;
  const grantEnv = await signEnvelope("pg.grant.v1", { signers, subject_ref: code, scope: "test" }, KEY);
  const gid = await messageId("pg.grant.v1", grantEnv.body);
  const asked = { subject_ref: code, provider_id: "https://frame.example", profile: "likeness/1",
    use: { purpose: "personal" }, job_id: "job-1", job_hash: "a".repeat(64) };
  for (let n = 0; ; n++) {   // an answer whose id gives a code (6 in 7 do)
    const answer = await signEnvelope("pg.answer.v1", { signers, request_id: await messageId("pg.request.v1", asked),
      profile: "likeness/1", status: "allow", basis: grant ? { kind: "grant", grant: { format: "pg.grant.v1", id: gid } }
        : { kind: "policy", rule: "test" }, issued_at: NOW - 10 - n, expires_at: NOW + 290 }, KEY);
    const id = await messageId("pg.answer.v1", answer.body);
    const act = { type: "pg.answer.v1", id, signer: "TEST", subject_ref: code, grant: grant ? { id: gid, signer: "TEST" } : null };
    let want;
    try { want = { code: codeFor(act), ...(grant && { licence: codeFor({ type: "pg.grant.v1", id: gid, signer: "TEST", subject_ref: code }) }) }; } catch { continue; }
    const report = { type: "pg.report.v1", signatures: [], body: { answer: id, outcome: "generated", output_hash: "d".repeat(64),
      job_id: "job-1", occurred_at: NOW } };
    const ack = await signEnvelope("pg.report_ack.v1", { signers, report: await messageId("pg.report.v1", report.body), answer: id,
      received_at: NOW }, KEY);
    const item = { request: { type: "pg.request.v1", body: asked, signatures: [] }, answer, report, ack,
      ...(grant && { grant: grantEnv }), ...copies(want) };
    return () => checkProof({ format: "pg.proof.v1", subjects: [item] }, { directory: aDir, fetch: aFetch, now: NOW });
  }
}

test("proof.md step 3: readable copies equal the codes recomputed from the signed parts", async () => {
  const code = "TOG-TEST-000001N";
  assert.equal((await (await proof(code))()).subjects.length, 1);                                    // both copies
  assert.equal((await (await proof(code, { copies: () => ({}) }))()).subjects.length, 1);             // none: the record is enough
  assert.equal((await (await proof(code, { grant: false }))()).subjects.length, 1);                   // terms basis, code only
  const wrong = (c) => c.slice(0, -1) + (c.endsWith("0") ? "1" : "0");
  for (const copies of [(w) => ({ ...w, code: wrong(w.code) }), (w) => ({ ...w, licence: wrong(w.licence) }),
    (w) => ({ ...w, code: w.code.replace("TOG-PG-LIC-", "TOG-PG-") }),
    (w) => ({ ...w, grant: undefined })]) {                                                          // licence not at hand
    await assert.rejects((await proof(code, { copies }))(), /readable copy/);
  }
  // a licence copy on a terms basis is a mismatch
  await assert.rejects((await proof(code, { grant: false, copies: (w) => ({ ...w, licence: "TOG-LIC-TEST-ZZZZ-QH28-TDQ8" }) }))(), /readable copy/);
});
