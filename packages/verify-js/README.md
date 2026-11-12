# @pregen/verify

The PRE-GEN client for JavaScript. Ask a registry before you generate, as a provider known by
its domain (no account), and check what comes back against the signed registry directory at
[pregen.org](https://www.pregen.org/registries.v3.json). The PRE-GEN steward key is built in; no
dependencies (Web Crypto, Node 20+ or a modern browser).

Ask with a signed `pg.request.v1` (`POST {api}/v2/requests`), check the answer with
`checkAnswer`, report with a signed `pg.report.v1`, keep the proof (`checkProof`). Guide:
https://www.pregen.org/docs/provider.md

## Ask and check (PRE-GEN v5, `PRE-GEN-CORE.md`)

```js
import { loadDirectory, checkAnswer } from "@pregen/verify";

// Keep the last accepted directory (any storage) and pass it back each time.
const directory = await loadDirectory({ previous: saved });
saved = directory.toJSON();

// request: the pg.request.v1 envelope you sent to POST /v2/requests; answer: the registry's reply
await checkAnswer(answer, request, { directory });   // throws with the reason, or you may generate
```

`checkAnswer` does core rules 2 and 5: the answer is signed by a key the directory lists for
the subject's prefix (registry and key not revoked), answers exactly this request under the
same profile, is within its lifetime, is an `allow`, and is not a sandbox answer unless you
pass `testing: true`.

## No account: a provider known by its domain (`extensions/provider-identity.md`)

```js
import { newPrivateKeyHex, partyDocument, signEnvelope, pgAccess } from "@pregen/verify";
const key = newPrivateKeyHex();     // make it once and keep it secret, server-side: a new key is a new identity
const doc = await partyDocument("https://app.example", "App", key);  // serve at https://app.example/.well-known/pregen-party.json
const req = await signEnvelope("pg.request.v1", body, key);         // body.signers = [{ role: "provider", key_id }]
const hdr = await pgAccess("https://app.example", key, registryApi, "GET", path);  // the PG-Access header for GETs
```

Also exported: `checkProviderUrl`, `signingInput`, `publicKeyHex`, `messageId`, `verifyAnswer`.

## One person, one home registry, and proof in a video

- `verifyAnchors(list, prefix, { directory })` — a registry's signed anchor list (`extensions/identity.md`). Another
  registry's codes are dropped, and so is an entry the steward found false under its own anchor. Kept entries come back
  as listed. A list naming a code twice, or an entry that is not a person code (a `PG-` line included), is refused.
- `wikidataOfficialUrls(anchor, { fetch })` — the channels Wikidata lists as current: not deprecated, not ended,
  started, each value in its property's own form. A website counts by its host alone. With
  `at: now - SETTLED_AFTER`, the channels of the item as it stood 7 days earlier (its last revision then).
- `checkChannelProof(code, proofUrl, officialUrls, getText, { seenConfirmed })` — did the person
  confirm this code on their own channel? Only at `https://<official host>/.well-known/pregen` (`getText` returns
  the text) or in a post or profile by the official account itself (`getText` returns `{ author, text }` from the
  platform's record of who wrote it), as a line `ToG: <code>` (the earlier `PRE-GEN: <code>` still counts; never shown). A page that cannot be read (`getText` throws) is
  unconfirmed, unless you saw it confirmed at the last check (`seenConfirmed: true`): then it throws, no decision.
- `decideIdentity(claims, { frozen: directory.frozen(anchor) })` — "who proved it, not who came first"; generate only
  on `allow`. A steward freeze denies first (`PG_SUBJECT_UNAVAILABLE`). Each claim is `{ code, confirmed, settled,
  refusal_only, answer }`. A person has one home registry: two confirmed claims are a duplicate, the stricter
  answer decides, and an allow permits only when every confirmed claim allows on a `settled` channel (it stood on
  Wikidata 7 days ago too; missing means not settled), and a `refusal_only` claim counts only for a refusal of the person. An `answer` of
  `null` (no valid answer, or its registry's anchor list failed: pass that list's last verified entries) throws, no
  decision, only when that claim is confirmed or refusal-only and no such claim refuses the person. For one claim:

  ```js
  const nowUrls = await wikidataOfficialUrls(anchor, { fetch });
  const thenUrls = await wikidataOfficialUrls(anchor, { fetch, at: Math.floor(Date.now() / 1000) - SETTLED_AFTER });
  const confirmed = await checkChannelProof(code, proofUrl, nowUrls, getText, { seenConfirmed: seenThisWeek });
  const settled = confirmed && await checkChannelProof(code, proofUrl, nowUrls.filter((u) => thenUrls.includes(u)), getText);
  const gone = thenUrls.filter((u) => !nowUrls.includes(u));   // removed, replaced or ended this week
  const refusal_only = !confirmed && (seenThisWeek || await checkChannelProof(code, proofUrl, gone, getText));
  ```
  Keep, for 7 days, which claims you saw confirmed (`seenThisWeek`).
- `directory.isFalseClaim(code, anchor)` — the steward found this claim false and has not reversed it
  (`false_claim_reversals`; the latest entry by `at` decides). Without `anchor`, under any anchor: `checkAnswer`
  refuses such a code, so a private person's code an entry names is never generated; `verifyAnswer` still weighs it.
- `checkProof(bundle, { directory, outputSha256 })` — a platform's check of the `pg.proof.v1` bundle
  carried with an output (`extensions/proof.md`): each subject also says what it shows about the terms its request
  accepted, `terms`: `absent`, `ok`, `outside` or `unverified` (and `termsAssent`: `registry`).

## A person's terms (`extensions/terms.md`)

- `checkTerms(envelope, code, { directory })` — a `pg.terms.v1` record as the person's registry published it.
  Accept it by putting `await messageId("pg.terms.v1", body)` in your request's `terms`.
- `floor(use, minor)`, `forbids(rules, use)`, `termsOpens(old, next)`; `CATEGORIES` (the closed vocabulary of
  likeness/1, which a request carrying `terms` must keep to), `PROHIBITED_FOR_MINORS`, `INTIMATE`.

## Codes (`TOG-CODE.md`)

Every code is written `TOG-`: persons `TOG-PRAM-900000037K`, licences and acts
`TOG-<PG|PG-LIC|AG|AG-LIC|LIC>-<ISSUER>[-<HOME>]-XXXX-XXXX-XXXX`. PG codes are retired and not
compatible: a `PG-` string is not a code anywhere, never folded or converted, and an object whose
signed bytes hold one gives no code.

- `parseCode(code)` — the one reading of a code exactly as it stands in a message: shape, kind,
  basis, issuer, home and example flag. Never repaired. Throws `CodeError` with `reason`
  `malformed` or `mistyped`. `kindOf(code)` gives the kind alone; `describe(code)` what the string
  claims, for support tools, never beside a video.
- `codeKey(code)` — the key every comparison uses: the code itself, once it parses; no folding
  (the library compares false claims and terms this way).
- `normalizeTyped(typed)` — only where a person types, pastes or scans: folds width, dashes,
  look-alikes, a resolver URL and O/0, I/L/1 by slot, and returns the one code meant, for a "Did you
  mean …?" prompt. Two readings fail with both as `hints`. A typed `PG-` string fails with the one
  message `RETIRED` ("PG codes are retired. Use the ToG code your registry shows you.") and no
  suggestion.
- `codeFor(act)`, `metadataOk(meta, act, licence)`, `codeVerdict(fileHash, act, caption, ingredient)` —
  a code is computed from its record and compared, never read; readable copies are refused on any
  mismatch (`checkProof` does this for an entry's `code` and `licence`).
- `checkChar`, `findCodes`, `checkParties` / `directory.parties(code, { at })` (v3 only),
  `admissionRefusal` (the steward's prefix check).

## The registry directory

The library reads directory v3 (`DIRECTORY_URL`, `registries.v3.json`: 4–8 letter prefixes,
entity, group, dated roles, provider domains, `void_from`, `closed`) and the frozen v2 file
(`DIRECTORY_V2_URL`). Once a v3 directory is accepted, a v2 one passed after it is refused.

The directory check refuses an older directory, a newer one that removes
a registry or key, undoes a revocation or drops a false claim, a reversal or a freeze, and a different one with the same sequence. No registry is pinned by default: every registry, the first one included,
is trusted only through the signed directory. You may pin any registry's keys
yourself (`pinnedKeys` / `pinned_keys`, prefix → fingerprints, `""` for bare
codes), so that even a stolen steward key cannot add a key to that prefix.

A successor steward key (`pg-ed25519:3e5e20729ce8485eea274c4cb33721d6`) is
pinned in the library: a directory it signs replaces those of the current
steward key whatever their sequence, so a thief holding the old key cannot
outbid it; it must keep every listing and revocation of the directory it
replaces, except revocations the old key signed after the declared
`steward_compromised_since`, which it names in `annulled`.

A listing in the directory proves which registry may issue a code, not that
it holds any right over a person or a work. A signed answer proves what the
registry answered, not that the output was lawful.

## Test v5 on the public test network

Load the test directory with
`loadDirectory({ url: "https://www.pregen.org/test/registries.json", stewardPublicKeyHex: "78c95e45a79c5e271fdec762b92c2ec1b27d6d08e512b7a94779de2429868ef0" })`,
ask the PRE-GEN Test Registry at `https://sandbox.pregen.org` (codes `TOG-TEST-000001N` …
`TOG-TEST-0000123`, where 9 tests a purchase, 10 a person's terms, 11 a minor and 12 a creator's licence through bind; introduce yourself with `POST /v2/sandbox/party`), and pass `testing: true`
to `checkAnswer` / `checkProof`. With the real directory, `checkAnswer` refuses `testing: true`.
Walk-through: https://www.pregen.org/docs/provider.md, step 9.

## Earlier interface (`pg.decision.v1`, `/v1/verify`): legacy, not for new integrations

```js
import { checkDecision } from "@pregen/verify";
// request: what you sent to /v1/verify, plus provider_id and licensee_id
await checkDecision(decision, request, { directory });   // throws with the reason, or you may generate
```

`checkDecision` checks everything a provider must check before generating
(`PRE-GEN-SPEC.md` §5.4):

1. the decision is a license-backed `allow` (P-5);
2. every echoed member equals what you sent, empty ones included, and
   intended-use members you did not send are empty (V-4);
3. `schema_version` is `pg.decision.v1`; `issued_at` and `expires_at` are present,
   at most 900 seconds apart, and `expires_at` has not passed (V-3);
4. if you named a user, the binding is `verified` with a link id (V-13);
5. the signature chain: the directory is signed by the PRE-GEN steward key
   (`pg-ed25519:dcdd244659e6d0e2426f2b504cb11590`), the license's namespace
   belongs to one listed registry, the decision's key is one of that
   registry's keys and hashes to its fingerprint, and the signature verifies;
6. neither that registry nor that key is revoked in the directory (V-14);
7. the decision lists no `critical` member the library does not understand (E-3).

Pass `requireVerifiedAuthority: true` to also refuse a subject whose rights holder the
registry has not verified (`subject_authority` other than `verified`).

### Offline simulator (legacy /v1 interface)

```js
import { createSimulator, checkDecision } from "@pregen/verify";
const sim = await createSimulator();           // offline registry, throwaway keys
globalThis.fetch = sim.fetch;                   // or pass sim.fetch to your HTTP client
// …your normal code: POST sim.baseUrl + "/v1/verify/", then:
await checkDecision(decision, request, { directory: sim.directory, fetch: sim.fetch });
```

`sbx-allowed` → `allow`; `sbx-revoked`, `sbx-expired` → `PG_NO_LICENSE`;
`sbx-exhausted` → `PG_USAGE_LIMIT`; `sbx-optedout` → `PG_SUBJECT_OPTED_OUT`;
anything else → `PG_NO_SUBJECT`. Receipts follow the earlier /v1 interface's rules (R-10): a receipt needs an
allow issued to this provider and licensee for the same `prompt_hash`; the identical receipt
again returns the first answer (`already_recorded`), a different one is `409 receipt_conflict`;
`receipt_hash` binds each answer to the bytes sent. Release answers as the sandbox does
(`nothing_to_release`: the sandbox licences have no usage limit; `already_receipted` after a receipt).
With `@prampta/sdk` 0.7.0 pass `baseUrl: sim.baseUrl`, `operatorPublicKeyHex:
sim.operatorPublicKeyHex` and `pregenDirectory: sim.directory`. The simulator's
keys are new on every run and its directory is signed by a throwaway steward,
so nothing it signs is ever accepted by the real directory.

## Other functions

`verifyDecision` (signatures only), `verifyDirectory`,
`Directory.checkSigner` / `registryFor` / `publicKey`, `verifySigned`, `canonicalJson`,
`fingerprint`, `checkPublicKey` (refuses keys no one can be held to), `issuerOf` (the registry to ask, from
the shape only) and `normalizeCode` (deprecated: use `normalizeTyped`).

Tests: `npm test` runs the unit tests and the PRE-GEN Level 1 conformance
vectors with every verifier operation required.

Apache-2.0. Part of the PRE-GEN standard,
[github.com/Pastheroza/PRE-GEN-site](https://github.com/Pastheroza/PRE-GEN-site).
