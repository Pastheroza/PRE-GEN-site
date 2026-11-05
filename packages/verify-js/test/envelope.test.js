import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { signEnvelope, signingInput, messageId, publicKeyHex, newPrivateKeyHex, fingerprint, verifyBytes, sha256Hex } from "../index.js";

const V = JSON.parse(readFileSync(new URL("../../../spec/test-vectors/messages.json", import.meta.url)));
const hex = (b) => Buffer.from(b).toString("hex");

test("signEnvelope reproduces every signed v5 message vector byte for byte", async () => {
  const seeds = {};
  for (const name of Object.keys(V.keys)) {
    const seed = await sha256Hex(`pregen-vector-${name}`);
    seeds[V.keys[name].key_id] = seed;
    assert.equal(await publicKeyHex(seed), V.keys[name].public_key_hex);
  }
  for (const v of V.vectors) {
    const env = v.envelope;
    const got = await signEnvelope(env.type, env.body, ...(env.body.signers || []).map((s) => seeds[s.key_id]));
    assert.deepEqual(got, env, v.name);
    assert.equal(hex(signingInput(env.type, env.body)), v.signing_input_hex);
    assert.equal(await messageId(env.type, env.body), v.message_id);
  }
});

test("a new key signs what verifies; no key, no signatures", async () => {
  const k = newPrivateKeyHex();
  const pub = await publicKeyHex(k);
  const body = { signers: [{ role: "provider", key_id: await fingerprint(pub) }], x: 1 };
  const env = await signEnvelope("pg.test.v1", body, k);
  assert.equal(await verifyBytes(pub, env.signatures[0], signingInput("pg.test.v1", body)), true);
  assert.deepEqual((await signEnvelope("pg.request.v1", { a: 1 })).signatures, []);
});
