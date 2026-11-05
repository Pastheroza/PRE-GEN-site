// The gate compares no policy version or epoch: an answer carrying such a member is refused for carrying it, whatever
// its value (the Python suite pins the rest: tests/test_answer_design_limits.py).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { signEnvelope, verifyDirectory, checkAnswer, sha256Hex } from "../index.js";

const V = JSON.parse(readFileSync(new URL("../../../spec/test-vectors/answers.json", import.meta.url)));
const fetch = async (url) => (url in V.key_sets ? { ok: true, status: 200, json: async () => V.key_sets[url] }
  : { ok: false, status: 404, json: async () => ({}) });

for (const extra of [{ policy_version: "2026-01-01" }, { policy_version: "2031-12-31" }, { epoch: 1 }, { epoch: 7 },
  { rules_text_hash: "0".repeat(64) }, { block_hash: "0".repeat(64) }, { model_id: "m-1" }]) {
  test(`checkAnswer refuses an answer carrying ${JSON.stringify(extra)}, whatever its value`, async () => {
    const allow = V.cases.find((c) => c.name === "allow");
    const directory = await verifyDirectory(V.directory, { stewardPublicKeyHex: V.steward_public_key_hex, now: V.now });
    const key = await sha256Hex("pregen-answer-vector-registry");
    const plain = await signEnvelope("pg.answer.v1", allow.answer.body, key);
    assert.equal((await checkAnswer(plain, allow.request, { directory, fetch, now: V.now })).status, "allow");
    const answer = await signEnvelope("pg.answer.v1", { ...allow.answer.body, ...extra }, key);
    await assert.rejects(checkAnswer(answer, allow.request, { directory, fetch, now: V.now }),
      new RegExp(`members the core does not define: ${Object.keys(extra)[0]}$`));
  });
}
