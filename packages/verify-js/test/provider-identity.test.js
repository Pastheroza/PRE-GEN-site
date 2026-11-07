import { test } from "node:test";
import assert from "node:assert/strict";
import { checkProviderUrl, partyDocument, pgAccess, newPrivateKeyHex, publicKeyHex, fingerprint, verifyBytes,
  signingInput, PregenError } from "../index.js";

test("a provider URL is the app's domain and nothing else", () => {
  assert.equal(checkProviderUrl("https://frame.example"), "https://frame.example");
  assert.equal(checkProviderUrl("https://alice.github.io"), "https://alice.github.io");
  for (const bad of ["http://frame.example", "https://frame.example/", "https://Frame.example", "https://frame.example:8443",
    "https://www.frame.example?x=1", "https://frame.example#a", "https://a@frame.example", "https://frame.example.",
    "https://localhost", "https://frame", "frame.example", 42]) {
    assert.throws(() => checkProviderUrl(bad), PregenError, String(bad));
  }
  assert.equal(checkProviderUrl("https://localhost:8443", { allowPort: true }), "https://localhost:8443");
  assert.equal(checkProviderUrl("https://frame.example:8443", { allowPort: true }), "https://frame.example:8443");
});

test("the party document carries a first keyset signed by the key, the same every time", async () => {
  const k = newPrivateKeyHex();
  const kid = await fingerprint(await publicKeyHex(k));
  const doc = await partyDocument("https://frame.example", "Frame", k, { redirectUris: ["https://frame.example/pregen/callback"] });
  assert.deepEqual(doc, await partyDocument("https://frame.example", "Frame", k, { redirectUris: ["https://frame.example/pregen/callback"] }));
  assert.deepEqual([doc.party_id, doc.name, doc.roles, doc.redirect_uris], ["https://frame.example", "Frame", ["provider"], ["https://frame.example/pregen/callback"]]);
  const ks = doc.keysets[0];
  assert.deepEqual(ks.body.signers, [{ role: "provider", key_id: kid }]);
  assert.equal(ks.body.kind, "first");
  assert.equal(ks.body.provider_id, "https://frame.example");
  assert.equal(await verifyBytes(ks.body.keys[0].public_key_hex, ks.signatures[0], signingInput(ks.type, ks.body)), true);
  await assert.rejects(partyDocument("https://frame.example/", "Frame", k), PregenError);
});

test("PG-Access is a base64url pg.access.v1 envelope over method, path and time", async () => {
  const k = newPrivateKeyHex();
  const pub = await publicKeyHex(k);
  const h = await pgAccess("https://frame.example", k, "https://r.example/", "get", "/v2/grants/abc?x=1", { now: 1_800_000_000 });
  assert.match(h, /^[A-Za-z0-9_-]+$/);
  const env = JSON.parse(Buffer.from(h, "base64url").toString());
  assert.deepEqual(env.body, { signers: [{ role: "provider", key_id: await fingerprint(pub) }], provider_id: "https://frame.example",
    aud: "https://r.example", method: "GET", path: "/v2/grants/abc?x=1", issued_at: 1_800_000_000 });
  assert.equal(await verifyBytes(pub, env.signatures[0], signingInput("pg.access.v1", env.body)), true);
});
