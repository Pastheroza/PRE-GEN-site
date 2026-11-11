# pregen

The PRE-GEN client for Python. Ask a registry before you generate, as a provider known by its
domain (no account), and check what comes back against the signed registry directory at
[pregen.org](https://www.pregen.org/registries.v3.json). The PRE-GEN steward key is built in.
Same API as the npm package `@pregen/verify`.

Ask with a signed `pg.request.v1` (`POST {api}/v2/requests`), check the answer with
`check_answer`, report with a signed `pg.report.v1`, keep the proof (`check_proof`). Guide:
https://www.pregen.org/docs/provider.md

## Ask and check (PRE-GEN v5, `PRE-GEN-CORE.md`)

```python
import pregen

# Keep the last accepted directory (any storage) and pass it back each time.
directory = pregen.load_directory(previous=saved)
saved = directory.to_json()

# request: the pg.request.v1 envelope you sent to POST /v2/requests; answer: the registry's reply
pregen.check_answer(answer, request, directory)   # raises with the reason, or you may generate
```

`check_answer` does core rules 2 and 5: the answer is signed by a key the directory lists for
the subject's prefix (registry and key not revoked), answers exactly this request under the
same profile, is within its lifetime, is an `allow`, and is not a sandbox answer unless you
pass `testing=True`.

## No account: a provider known by its domain (`extensions/provider-identity.md`)

```python
key = pregen.new_private_key_hex()      # make it once and keep it secret, server-side: a new key is a new identity
doc = pregen.party_document("https://app.example", "App", key)   # serve at https://app.example/.well-known/pregen-party.json
req = pregen.sign_envelope("pg.request.v1", body, key)  # body["signers"] = [{"role": "provider", "key_id": ...}]
hdr = pregen.pg_access("https://app.example", key, registry_api, "GET", path)  # the PG-Access header for GETs
```

Also exported: `check_provider_url`, `signing_input`, `public_key_hex`, `message_id`, `verify_answer`.

## One person, one home registry, and proof in a video

- `verify_anchors(list, prefix, directory)` — a registry's signed anchor list (`extensions/identity.md`). Another
  registry's codes are dropped, and so is an entry the steward found false under its own anchor. Kept entries come back
  as listed. A list naming a code twice, or an entry that is not a person code (a `PG-` line included), is refused.
- `wikidata_official_urls(anchor)` — the channels Wikidata lists as current: not deprecated, not ended, started, each
  value in its property's own form. A website counts by its host alone. With `at=now - pregen.SETTLED_AFTER`, the
  channels of the item as it stood 7 days earlier (its last revision then).
- `check_channel_proof(code, proof_url, official_urls, get_text, seen_confirmed=False)` — did the person
  confirm this code on their own channel? Only at `https://<official host>/.well-known/pregen` (`get_text` returns
  the text) or in a post or profile by the official account itself (`get_text` returns `{"author", "text"}` from the
  platform's record of who wrote it), as a line `PRE-GEN: <code>`. A page that cannot be read (`get_text` raises) is
  unconfirmed, unless you saw it confirmed at the last check (`seen_confirmed=True`): then it raises, no decision.
- `decide_identity(claims, frozen=directory.frozen(anchor))` — "who proved it, not who came first"; generate only on
  `allow`. A steward freeze denies first (`PG_SUBJECT_UNAVAILABLE`). Each claim is `{"code", "confirmed", "settled",
  "refusal_only", "answer"}`. A person has one home registry: two confirmed claims are a duplicate, the stricter
  answer decides, and an allow permits only when every confirmed claim allows on a `settled` channel (it stood on
  Wikidata 7 days ago too; missing means not settled), and a `refusal_only` claim counts only for a refusal of the person. An `answer` of `None`
  (no valid answer, or its registry's anchor list failed: pass that list's last verified entries) raises, no
  decision, only when that claim is confirmed or refusal-only and no such claim refuses the person. For one claim:

  ```python
  now_urls = pregen.wikidata_official_urls(anchor)
  then_urls = pregen.wikidata_official_urls(anchor, at=int(time.time()) - pregen.SETTLED_AFTER)
  confirmed = pregen.check_channel_proof(code, proof_url, now_urls, get_text, seen_confirmed=seen_this_week)
  settled = confirmed and pregen.check_channel_proof(code, proof_url, [u for u in now_urls if u in then_urls], get_text)
  gone = [u for u in then_urls if u not in now_urls]          # removed, replaced or ended this week
  refusal_only = not confirmed and (seen_this_week or pregen.check_channel_proof(code, proof_url, gone, get_text))
  ```
  Keep, for 7 days, which claims you saw confirmed (`seen_this_week`).
- `directory.is_false_claim(code, anchor)` — the steward found this claim false and has not reversed it
  (`false_claim_reversals`; the latest entry by `at` decides). Without `anchor`, under any anchor: `check_answer`
  refuses such a code, so a private person's code an entry names is never generated; `verify_answer` still weighs it.
- `check_proof(bundle, directory, output_sha256=...)` — a platform's check of the `pg.proof.v1` bundle
  carried with an output (`extensions/proof.md`): each subject also says what it shows about the terms its request
  accepted, `terms`: `absent`, `ok`, `outside` or `unverified` (and `terms_assent`: `registry`).

## A person's terms (`extensions/terms.md`)

- `check_terms(envelope, code, directory)` — a `pg.terms.v1` record as the person's registry published it.
  Accept it by putting `message_id("pg.terms.v1", body)` in your request's `terms`.
- `floor(use, minor)`, `forbids(rules, use)`, `terms_opens(old, new)`; `CATEGORIES` (the closed vocabulary of
  likeness/1, which a request carrying `terms` must keep to), `PROHIBITED_FOR_MINORS`, `INTIMATE`.

## ToG codes (`TOG-CODE.md`)

Every code is written `TOG-`: a person `TOG-PRAM-900000037K`, a licence `TOG-LIC-…`, an output made under a
yes `TOG-PG-…` or `TOG-PG-LIC-…`, one approved after it was made `TOG-AG-…`. PG codes are retired and not compatible:
a `PG-` string is not a code anywhere, never folded or converted, and an object whose signed bytes hold one gives no
code.

- `parse_code(code)` reads a code exactly as it stands: shape, kind, basis, the registry to ask (`issuer`), home and
  example flag. No network. `kind_of(code)` gives the kind alone; `describe(code)` what
  the string claims, for support tools, never beside a video. Raises `NotACode` or `Mistyped`.
- `code_key(code)` is the key: compare, hash and look up codes only by it. It is the code itself, once it parses; no
  folding.
- `normalize_typed(typed)` only where a person types, pastes or scans: the one code meant, for "Did you mean …?".
  Ambiguous input raises `NotACode` with both codes in `hints`. A typed `PG-` string raises `NotACode` with the one
  message `RETIRED` ("PG codes are retired. Use the ToG code your registry shows you.") and no suggestion.
- `code_for(act)` computes an act's code from its record; `metadata_ok(meta, act, licence)` checks readable copies
  against it, and `check_proof` refuses a bundle whose `code` or `licence` copy differs. A code is never proof.
- `code_verdict(file_hash, act, caption, ingredient)` is what a verifier may say before signatures.
- `find_codes(text)`, `check_char(body)`, `admission_refusal(prefix, entity, government, listed)` (the steward's
  prefix check), `check_parties(code, entries, at, provider)` and `Directory.parties(code)` (directory v3).

Errors are `CodeError` subclasses with `reason`: `malformed`, `mistyped`, `no_code`.

## The registry directory

`load_directory()` reads directory v3 (`DIRECTORY_URL`, prefixes of 4 to 8 letters, dated roles). The frozen v2
file stays at `DIRECTORY_V2_URL` for clients before 0.14; both verify. A v2 directory after a v3 one is refused.

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
`pregen.load_directory("https://www.pregen.org/test/registries.json", steward_public_key_hex="78c95e45a79c5e271fdec762b92c2ec1b27d6d08e512b7a94779de2429868ef0")`,
ask the PRE-GEN Test Registry at `https://sandbox.pregen.org` (codes `TOG-TEST-000001N` …
`TOG-TEST-0000123`, where 9 tests a purchase, 10 a person's terms, 11 a minor and 12 a creator's licence through bind; introduce yourself with `POST /v2/sandbox/party`), and pass `testing=True`
to `check_answer` / `check_proof`. With the real directory, `check_answer` refuses `testing=True`.
Walk-through: https://www.pregen.org/docs/provider.md, step 9.

## Earlier interface (`pg.decision.v1`, `/v1/verify`): legacy, not for new integrations

```python
# request: what you sent to /v1/verify, plus provider_id and licensee_id
pregen.check_decision(decision, request, directory)   # raises with the reason, or you may generate
```

`check_decision` checks everything a provider must check before generating
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

Pass `require_verified_authority=True` to also refuse a subject whose rights holder the
registry has not verified (`subject_authority` other than `verified`).

### Offline simulator (legacy /v1 interface)

```python
sim = pregen.Simulator()                        # offline registry, throwaway keys
decision = sim.verify(request, provider_id="acme", licensee_id="lic-1")
pregen.check_decision(decision, {**request, "provider_id": "acme", "licensee_id": "lic-1"},
                      sim.directory, sim.get_json)
status, ack = sim.receipt(receipt, provider_id="acme", licensee_id="lic-1")  # /v1 receipt rules: (200, ...)
sim.release(decision["decision_id"], "acme", "lic-1")                        # (409, nothing_to_release) in sandbox
```

Same sandbox answers as the npm package, and the earlier /v1 interface's receipt rules (as the
first registry serves them): the identical receipt again returns the first answer, a different
one is 409, a receipt needs an allow for this pair and the same `prompt_hash`, and
`receipt_hash` binds the answer to the bytes sent. Nothing it signs is ever accepted by the
real directory.

## Other functions

`verify_decision` (signatures only), `verify_directory`,
`Directory.check_signer` / `registry_for` / `public_key`, `verify_signed`,
`canonical_json`, `fingerprint`, `check_public_key` (refuses keys no one can be held to), `issuer_of` (the registry
to ask, from the shape only) and `normalize_code` (deprecated: use `normalize_typed`).

Tests: `pytest packages/verify-py/tests`, and the PRE-GEN Level 1 vectors with
`python3 spec/conformance/level1/run_conformance.py --adapter "python3 packages/verify-py/tests/conformance_adapter.py"`.

Apache-2.0. Part of the PRE-GEN standard,
[github.com/Pastheroza/PRE-GEN-site](https://github.com/Pastheroza/PRE-GEN-site).
