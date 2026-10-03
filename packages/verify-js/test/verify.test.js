import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalJson, fingerprint, verifyDirectory, verifyDecision, PregenError, issuerOf } from "../index.js";

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
