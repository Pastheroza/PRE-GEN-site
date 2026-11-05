// The gate compares no policy version or epoch: answers that differ only in such members get the plain allow's
// verdict (the Python suite pins the rest: tests/test_answer_design_limits.py).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { signEnvelope, verifyDirectory, checkAnswer, sha256Hex } from "../index.js";

const V = JSON.parse(readFileSync(new URL("../../../spec/test-vectors/answers.json", import.meta.url)));
const fetch = async (url) => (url in V.key_sets ? { ok: true, status: 200, json: async () => V.key_sets[url] }
  : { ok: false, status: 404, json: async () => ({}) });

for (const extra of [{ policy_version: "2026-01-01" }, { policy_version: "2031-12-31" }, { epoch: 1 }, { epoch: 7 },
  { rules_text_hash: "0".repeat(64) }]) {
  test(`checkAnswer compares no policy version or epoch: ${JSON.stringify(extra)}`, async () => {
    const allow = V.cases.find((c) => c.name === "allow");
    const directory = await verifyDirectory(V.directory, { stewardPublicKeyHex: V.steward_public_key_hex, now: V.now });
    const key = await sha256Hex("pregen-answer-vector-registry");
    const answer = await signEnvelope("pg.answer.v1", { ...allow.answer.body, ...extra }, key);
    const body = await checkAnswer(answer, allow.request, { directory, fetch, now: V.now });
    assert.equal(body.status, "allow");
  });
}
