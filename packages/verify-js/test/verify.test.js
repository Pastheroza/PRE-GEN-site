import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalJson, fingerprint, verifyDirectory, verifyDecision, checkDecision, PregenError, issuerOf } from "../index.js";

const hex = (b) => Buffer.from(b).toString("hex");
async function keypair() {
  const k = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pub = hex(await crypto.subtle.exportKey("raw", k.publicKey));
  const sign = async (obj, field) => {
    const body = Object.fromEntries(Object.entries(obj).filter(([f]) => f !== field));
    return { ...obj, [field]: hex(await crypto.subtle.sign({ name: "Ed25519" }, k.privateKey, new TextEncoder().encode(canonicalJson(body)))) };
  };
  return { pub, id: await fingerprint(pub), sign };
}

const steward = await keypair();
const origin = await keypair();   // the registry with bare codes
const other = await keypair();    // a registry with prefix NWRD

async function directory(sequence = 2, registries) {
  return steward.sign({
    schema: "pregen.registries.v2", sequence, steward_key_id: steward.id,
    registries: registries || [
      { name: "Origin", prefix: "", api: "https://origin.test", keys: "https://origin.test/keys", key_fingerprints: [origin.id] },
      { name: "Other", prefix: "NWRD", api: "https://other.test", keys: "https://other.test/keys", key_fingerprints: [other.id] },
    ],
  }, "signature");
}
const load = async (d, minSequence) => verifyDirectory(await d, { stewardPublicKeyHex: steward.pub, minSequence });
const keysFetch = (keys) => async (url) => ({ ok: true, json: async () => ({ keys: keys[url] || [] }) });
const keySets = {
  "https://origin.test/keys": [{ key_id: origin.id, public_key_hex: origin.pub }],
  "https://other.test/keys": [{ key_id: other.id, public_key_hex: other.pub }],
};

test("a directory signed by the pinned steward is accepted", async () => {
  assert.equal((await load(directory())).sequence, 2);
});

test("a tampered, foreign-signed, older or malformed directory is refused", async () => {
  const d = await directory();
  await assert.rejects(load({ ...d, registries: d.registries.slice(0, 1) }), PregenError);
  await assert.rejects(verifyDirectory(d), /different steward/); // default pin is the real steward key
  await assert.rejects(load(d, 3), /older/);
  await assert.rejects(load(directory(2, [{ name: "X", prefix: "", api: "http://x.test", keys: "https://x.test/k", key_fingerprints: [origin.id] }])), /HTTPS/);
  await assert.rejects(load(directory(2, [
    { name: "A", prefix: "", api: "https://a.test", keys: "https://a.test/k", key_fingerprints: [origin.id] },
    { name: "B", prefix: "", api: "https://b.test", keys: "https://b.test/k", key_fingerprints: [other.id] }])), /twice/);
});

test("namespaces are symmetric: each key signs only in its own namespace", async () => {
  const dir = await load(directory());
  assert.equal(dir.checkSigner("PG-000042*", origin.id), "valid");
  assert.equal(dir.checkSigner("PG-000042*", other.id), "issuer_mismatch");
  assert.equal(dir.checkSigner("PG-NWRD-000042-K", other.id), "valid");
  assert.equal(dir.checkSigner("PG-NWRD-000042-K", origin.id), "issuer_mismatch");
  assert.equal(dir.checkSigner("PG-ABCD-000042-K", origin.id), "unknown_issuer");
  assert.equal(dir.registryFor("pg-nwrd-000042-k").name, "Other");
  assert.equal(issuerOf("PG-RND-000042-ZZZZZZ1"), "");
});

test("a decision is genuine only when signed by a key of the namespace owner", async () => {
  const dir = await load(directory());
  const decision = await origin.sign({ decision_id: "d1", allowed: true, license_id: "PG-RND-000042-ZZZZZZ1",
    operator_key_id: origin.id }, "operator_signature");
  const opts = { directory: dir, fetch: keysFetch(keySets) };
  assert.equal(await verifyDecision(decision, decision.license_id, opts), true);
  assert.equal(await verifyDecision({ ...decision, allowed: false }, decision.license_id, opts), false);

  // A listed registry signing a bare code (someone else's namespace) is refused.
  const forged = await other.sign({ decision_id: "d2", allowed: true, operator_key_id: other.id }, "operator_signature");
  await assert.rejects(verifyDecision(forged, "PG-000042*", opts), /issuer_mismatch/);

  // A key set that serves a different key under the listed id is refused.
  const swapped = keysFetch({ "https://origin.test/keys": [{ key_id: origin.id, public_key_hex: other.pub }] });
  await assert.rejects(verifyDecision(decision, decision.license_id, { directory: dir, fetch: swapped }), /no key/);
});

test("canonical JSON refuses what cannot be signed portably", () => {
  assert.equal(canonicalJson({ "\u{10000}": 1, "": 2, b: [true, null, "a\nb"] }),
    '{"b":[true,null,"a\\nb"],"":2,"\u{10000}":1}');
  assert.throws(() => canonicalJson({ x: 1.5 }), PregenError);
  assert.throws(() => canonicalJson({ x: 2 ** 53 }), PregenError);
  assert.throws(() => canonicalJson({ x: "\ud800" }), PregenError);
  assert.throws(() => canonicalJson({ x: undefined }), PregenError);
});

test("a stolen steward key cannot add its own key to the pinned origin namespace", async () => {
  const thief = await keypair();
  const d = await directory(3, [
    { name: "Origin", prefix: "", api: "https://origin.test", keys: "https://origin.test/keys", key_fingerprints: [origin.id, thief.id] }]);
  const pinned = await verifyDirectory(d, { stewardPublicKeyHex: steward.pub, originKeyFingerprints: [origin.id] });
  assert.equal(pinned.checkSigner("PG-000042*", thief.id), "issuer_mismatch");
  assert.equal(pinned.checkSigner("PG-000042*", origin.id), "valid");
});

test("a newer directory may add but never remove or fork", async () => {
  const prev = await directory(2);
  const fewer = await directory(3, [prev.registries[0]]);
  await assert.rejects(load(fewer).then((x) => verifyDirectory(fewer, { stewardPublicKeyHex: steward.pub, previous: prev })), /removed/);
  const dropKey = await directory(3, [{ ...prev.registries[0], key_fingerprints: [other.id] }, prev.registries[1]]);
  await assert.rejects(verifyDirectory(dropKey, { stewardPublicKeyHex: steward.pub, previous: prev }), /removed/);
  const fork = await directory(2, [...prev.registries, { name: "New", prefix: "ABCD", api: "https://n.test", keys: "https://n.test/k", key_fingerprints: [other.id] }]);
  await assert.rejects(verifyDirectory(fork, { stewardPublicKeyHex: steward.pub, previous: prev }), /same sequence/);
  const grown = await directory(3, [...prev.registries, { name: "New", prefix: "ABCD", api: "https://n.test", keys: "https://n.test/k", key_fingerprints: [other.id] }]);
  assert.equal((await verifyDirectory(grown, { stewardPublicKeyHex: steward.pub, previous: prev })).sequence, 3);
});

test("checkDecision: everything a provider must check before generating", async () => {
  const dir = await load(directory());
  const now = 1_800_000_000;
  const request = { subject_id: "sub_1", provider_id: "acme", licensee_id: "lic-1", prompt_hash: "a".repeat(64),
    model: "m", modality: "image", intended_use: { use_case: "commercial", categories: ["ads"] }, provider_user_id: "u1" };
  const base = { decision_id: "d1", allowed: true, disposition: "allow", license_id: "PG-RND-000042-ZZZZZZ1",
    subject_id: "sub_1", provider_id: "acme", licensee_id: "lic-1", prompt_hash: "a".repeat(64), model: "m", modality: "image",
    intended_use: { use_case: "commercial", categories: ["ads"], channel: "", territory: "" },
    provider_user_binding: "verified", provider_identity_link_id: "link-1",
    issued_at: now - 10, expires_at: now + 60, operator_key_id: origin.id };
  const opts = { directory: dir, fetch: keysFetch(keySets), now };
  const signed = (patch) => origin.sign({ ...base, ...patch }, "operator_signature");

  assert.equal((await checkDecision(await signed({}), request, opts)).decision_id, "d1");
  const refuse = async (patch, re, req = request) => assert.rejects(checkDecision(await signed(patch), req, opts), re);
  await refuse({ allowed: false, disposition: "deny" }, /not an allow/);
  await refuse({ disposition: "not_blocked", allowed: false }, /not an allow/);
  await refuse({ expires_at: now }, /expired/);
  await refuse({ expires_at: 0 }, /expires_at/);
  await refuse({ issued_at: now + 3600, expires_at: now + 7200 }, /issued_at/);
  await refuse({ provider_id: "" }, /provider_id/);                              // empty is not a wildcard
  await refuse({ prompt_hash: "b".repeat(64) }, /prompt_hash/);
  await refuse({ intended_use: { ...base.intended_use, channel: "tv" } }, /intended_use.channel/);
  await refuse({ intended_use: { ...base.intended_use, use_case: "personal" } }, /use_case/);
  await refuse({ provider_user_binding: "unbound" }, /binding/);
  await refuse({ provider_identity_link_id: "" }, /binding/);
  await refuse({ license_id: null }, /license/);
  const tampered = { ...(await signed({})), model: "other" };
  await assert.rejects(checkDecision(tampered, { ...request, model: "other" }, opts), /bad signature/);
});

test("a successor steward key takes over from a stolen one, whatever the thief's sequence", async () => {
  const successor = await keypair();
  const opts = { stewardPublicKeyHex: steward.pub, successorPublicKeyHex: successor.pub };
  const thiefDir = await directory(50);                       // old key, sequence raised by a thief
  const handover = await successor.sign({ ...(await directory(51)), steward_key_id: successor.id }, "signature");
  delete handover.signature;
  const signedHandover = await successor.sign({ ...handover, sequence: 3 }, "signature");
  const taken = await verifyDirectory(signedHandover, { ...opts, previous: thiefDir, minSequence: 50 });
  assert.equal(taken.sequence, 3);
  await assert.rejects(verifyDirectory(thiefDir, { ...opts, previous: taken }), /handed over/);
  const shrunk = await successor.sign({ ...handover, sequence: 4, registries: handover.registries.slice(0, 1) }, "signature");
  await assert.rejects(verifyDirectory(shrunk, { ...opts, previous: taken }), /removed/); // usual rules within the new line
  await assert.rejects(verifyDirectory(signedHandover, { stewardPublicKeyHex: steward.pub }), /different steward/); // no successor pinned
});
