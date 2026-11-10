// extensions/identity.md in the library (stress identity round, fix B): which channels count, where a confirmation may
// stand, what an unreadable page means, and an anchor list that fails blocks only the people it held.
// ../verify-py/tests/identity_cases.json runs here and in verify-py (tests/test_identity.py), so both read every case alike.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkChannelProof, wikidataOfficialUrls, decideIdentity, verifyAnchors, verifyDirectory, signEnvelope, fingerprint,
  publicKeyHex, sha256Hex, canonicalJson, verifyAnswer, checkAnswer, PregenError, DIRECTORY_MAX_AGE, SETTLED_AFTER } from "../index.js";

const CASES = JSON.parse(readFileSync(new URL("../../verify-py/tests/identity_cases.json", import.meta.url)));
const V = JSON.parse(readFileSync(new URL("../../../spec/test-vectors/answers.json", import.meta.url)));
const ANCHOR_LISTS = JSON.parse(readFileSync(new URL("../../../spec/test-vectors/anchors.json", import.meta.url)));
const NOW = V.now, KEY = await sha256Hex("pregen-answer-vector-registry");
const directory = await verifyDirectory(V.directory, { stewardPublicKeyHex: V.steward_public_key_hex, now: NOW });
const keys = async (url) => (url in V.key_sets ? { ok: true, status: 200, json: async () => V.key_sets[url] }
  : { ok: false, status: 404, json: async () => ({}) });
const page = (value) => async () => { if (value === "RAISE") throw new Error("HTTP 429"); return value; };

for (const c of CASES.channel) {
  test(`checkChannelProof: ${c.name}`, async () => {
    const run = () => checkChannelProof(c.code, c.proof_url, c.official, page(c.page), { seenConfirmed: c.seen_confirmed });
    if (c.expect === "raises") await assert.rejects(run, /HTTP 429/);
    else assert.equal(await run(), c.expect);
  });
}

const wikidata = (body) => async () => ({ ok: true, status: 200, json: async () => body });
for (const c of CASES.wikidata) {
  test(`wikidataOfficialUrls: ${c.name}`, async () => {
    const fetch = wikidata({ entities: { Q11571: { claims: c.claims } } });
    assert.deepEqual(await wikidataOfficialUrls("wikidata:Q11571", { fetch, now: CASES.now }), c.expect);
  });
}

test("wikidataOfficialUrls: a merged or missing entity is refused", async () => {
  for (const body of [{ entities: { Q1: { claims: {} } } }, { entities: {} }, {}]) {
    await assert.rejects(wikidataOfficialUrls("wikidata:Q11571", { fetch: wikidata(body) }), /no entity/);
  }
});

const json = (body) => ({ ok: true, status: 200, json: async () => body });
for (const c of CASES.wikidata_at) {
  test(`wikidataOfficialUrls at: ${c.name}`, async () => {
    const answers = { [CASES.wikidata_at_api]: c.revisions, [CASES.wikidata_at_entity]: { entities: { Q11571: { claims: c.claims } } } };
    const fetch = async (url) => { assert.ok(url in answers, url); return json(answers[url]); };
    const run = () => wikidataOfficialUrls("wikidata:Q11571", { fetch, now: CASES.now, at: CASES.now - SETTLED_AFTER });
    if (c.expect.raises) await assert.rejects(run, (e) => e instanceof PregenError && e.message.includes(c.expect.raises));
    else assert.deepEqual(await run(), c.expect);
  });
}

test("wikidataOfficialUrls at: an unreadable revision list is refused", async () => {
  const fetch = async () => ({ ok: false, status: 503, json: async () => ({}) });
  await assert.rejects(wikidataOfficialUrls("wikidata:Q11571", { fetch, at: CASES.now }), /HTTP 503/);
});

for (const c of CASES.decide) {
  test(`decideIdentity: ${c.name}`, () => {
    const run = () => decideIdentity(c.claims, { frozen: c.frozen ?? null });
    if (c.expect === "raises") assert.throws(run, (e) => e instanceof PregenError && /no decision/.test(e.message));
    else assert.deepEqual(run(), c.expect);
  });
}

const hex = (b) => Buffer.from(b).toString("hex");
const stewardKey = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const stewardHex = hex(await crypto.subtle.exportKey("raw", stewardKey.publicKey));
async function signed(sequence, add) {
  const { signature, false_claims, ...base } = V.directory; // eslint-disable-line no-unused-vars
  const d = { ...base, sequence, steward_key_id: await fingerprint(stewardHex), ...add };
  return { ...d, signature: hex(await crypto.subtle.sign({ name: "Ed25519" }, stewardKey.privateKey, new TextEncoder().encode(canonicalJson(d)))) };
}
for (const c of CASES.directory) {
  test(`directory: ${c.name}`, async () => {
    const previous = c.previous ? await signed(1, c.previous) : undefined;
    const run = async () => verifyDirectory(await signed(2, c.add), { stewardPublicKeyHex: stewardHex, previous, now: NOW });
    if (c.raises) return assert.rejects(run, (e) => e instanceof PregenError && e.message.includes(c.raises));
    const d = await run();
    for (const [anchor, at, expect] of c.frozen || []) assert.equal(Boolean(d.frozen(anchor, at)), expect, `${anchor} ${at}`);
    for (const [code, anchor, expect] of c.false_claim || []) assert.equal(d.isFalseClaim(code, anchor), expect, `${code} ${anchor}`);
  });
}

async function anchors(entries, issuedAt = NOW - 10) {
  const body = { signers: [{ role: "registry", key_id: await fingerprint(await publicKeyHex(KEY)) }], registry: "TEST",
    issued_at: issuedAt, anchors: entries };
  return verifyAnchors(await signEnvelope("pg.anchors.v1", body, KEY), "TEST", { directory, fetch: keys, now: NOW });
}
const entry = (code, anchor = "wikidata:Q11571") => ({ anchor, code, level: "verified", proof_url: "", status: "active" });

// spec/test-vectors/anchors.json: TOG lines kept, PG lines folded, foreign codes dropped; an entry that is not a person
// code fails the whole list.
for (const c of ANCHOR_LISTS.cases) {
  test(`anchor list vector: ${c.name}`, async () => {
    const a = c.anchor ?? "wikidata:Q11571", run = anchors(c.codes.map((code) => entry(code, a)));
    if (c.error) await assert.rejects(run, (e) => e instanceof PregenError && e.message.includes(c.error));
    else assert.deepEqual(await run, c.keep.map((code) => entry(code, a)));
  });
}

test("verifyAnchors refuses a list naming a code twice", async () => {
  await assert.rejects(anchors([entry("PG-TEST-000001N"), entry("PG-TEST-000001N", "wikidata:Q1")]), /each code once/);
});

test("verifyAnchors refuses a malformed entry", async () => {
  for (const bad of ["PG-TEST-000001N", { code: 1 }]) await assert.rejects(anchors([entry("PG-TEST-000003X"), bad]), /entry is/);
});

test("verifyAnchors refuses an old list", async () => {
  await assert.rejects(anchors([entry("PG-TEST-000001N")], NOW - DIRECTORY_MAX_AGE - 1), /24 hours/);
});

test("verifyAnchors drops a false claim only under its own anchor", async () => {
  const fc = "PG-TEST-000002Z"; // the vector directory: a false claim under wikidata:Q42
  assert.deepEqual(await anchors([entry(fc, "wikidata:Q42"), entry("PG-TEST-000001N")]), [entry("TOG-TEST-000001N")]);
  assert.deepEqual(await anchors([entry(fc)]), [entry("TOG-TEST-000002Z")]);
});

test("a false claim is weighed under another anchor but never generated alone", async () => {
  const c = V.cases.find((x) => x.name === "a code the steward recorded as a false claim");
  assert.equal((await verifyAnswer(c.answer, c.request, { directory, fetch: keys, now: NOW })).status, "allow");
  await assert.rejects(checkAnswer(c.answer, c.request, { directory, fetch: keys, now: NOW }), /false claim/);
});

// The provider's identity step (docs/provider.md step 4) for one claim, as identity.md defines it.
const SITE = "https://cristianoronaldo.com", NEW = "https://cr7-media.example";
async function claim(code, proofUrl, nowUrls, thenUrls, pages, answer, seen = false) {
  const getText = async (url) => pages[url] ?? "";
  const confirmed = await checkChannelProof(code, proofUrl, nowUrls, getText, { seenConfirmed: seen });
  const settled = confirmed && await checkChannelProof(code, proofUrl, nowUrls.filter((u) => thenUrls.includes(u)), getText);
  const gone = thenUrls.filter((u) => !nowUrls.includes(u));
  const refusal_only = !confirmed && (seen || await checkChannelProof(code, proofUrl, gone, getText));
  return { code, confirmed, settled, refusal_only, answer };
}
async function channels(nowSites, thenSites) {
  const entity = (sites) => ({ entities: { Q11571: { claims: { P856: sites.map((u) => ({ mainsnak: { datavalue: { value: u } }, rank: "normal" })) } } } });
  const answers = { [CASES.wikidata_at_api]: { query: { pages: [{ title: "Q11571", revisions: [{ revid: 123 }] }] } },
    [CASES.wikidata_at_entity]: entity(thenSites), "https://www.wikidata.org/wiki/Special:EntityData/Q11571.json": entity(nowSites) };
  const fetch = async (url) => json(answers[url]);
  return [await wikidataOfficialUrls("wikidata:Q11571", { fetch, now: CASES.now }),
    await wikidataOfficialUrls("wikidata:Q11571", { fetch, now: CASES.now, at: CASES.now - SETTLED_AFTER })];
}
const OUT = { status: "deny", reason: "PG_SUBJECT_OPTED_OUT" };

test("a channel added today refuses but does not permit", async () => {
  const [nowUrls, thenUrls] = await channels([SITE, NEW], [SITE]);
  const pages = { [NEW + "/.well-known/pregen"]: "PRE-GEN: PG-XXXX-000001V" };
  const c = await claim("PG-XXXX-000001V", NEW + "/.well-known/pregen", nowUrls, thenUrls, pages, { status: "allow" });
  assert.deepEqual([c.confirmed, c.settled], [true, false]);
  assert.deepEqual(decideIdentity([c]), { status: "not_blocked", reason: "PG_IDENTITY_UNCONFIRMED", code: null });
  const d = await claim("PG-XXXX-000001V", NEW + "/.well-known/pregen", nowUrls, thenUrls, pages, OUT);
  assert.equal(decideIdentity([d]).status, "deny");
});

test("a recent refusal survives replacing the channel", async () => {
  const [nowUrls, thenUrls] = await channels([NEW], [SITE]);
  const pages = { [SITE + "/.well-known/pregen"]: "PRE-GEN: PG-AAAA-000001N", [NEW + "/.well-known/pregen"]: "PRE-GEN: PG-XXXX-000001V" };
  const ron = await claim("PG-AAAA-000001N", SITE + "/.well-known/pregen", nowUrls, thenUrls, pages, OUT);
  const thief = await claim("PG-XXXX-000001V", NEW + "/.well-known/pregen", nowUrls, thenUrls, pages, { status: "allow" });
  assert.deepEqual([ron.confirmed, ron.refusal_only], [false, true]);
  assert.deepEqual(decideIdentity([ron, thief]), { status: "deny", reason: "PG_SUBJECT_OPTED_OUT", code: "PG-AAAA-000001N" });
});

test("a refusal seen this week survives its line being deleted", async () => {
  const [nowUrls, thenUrls] = await channels([SITE], [SITE]);
  const ron = await claim("PG-AAAA-000001N", SITE + "/.well-known/pregen", nowUrls, thenUrls, {}, OUT, true);
  assert.deepEqual([ron.confirmed, ron.refusal_only], [false, true]);
  assert.equal(decideIdentity([ron]).reason, "PG_SUBJECT_OPTED_OUT");
  const never = await claim("PG-AAAA-000001N", SITE + "/.well-known/pregen", nowUrls, thenUrls, {}, { status: "allow" });
  assert.deepEqual([never.confirmed, never.refusal_only], [false, false]);
});
