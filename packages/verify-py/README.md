# pregen

The PRE-GEN client for Python. Ask a registry before you generate, as a provider known by its
domain (no account), and check what comes back against the signed registry directory at
[pregen.org](https://www.pregen.org/registries.json). The PRE-GEN steward key is built in.
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

## One person in several registries, and proof in a video

- `verify_anchors(list, prefix, directory)` — a registry's signed anchor list (`extensions/identity.md`).
- `check_channel_proof(code, proof_url, wikidata_official_urls(anchor), get_text)` — did the person
  confirm this code on their own channel?
- `decide_identity(claims)` — "who proved it, not who came first"; generate only on `allow`.
- `check_proof(bundle, directory, output_sha256=...)` — a platform's check of the `pg.proof.v1` bundle
  carried with an output (`extensions/proof.md`).

## The registry directory

The directory check refuses an older directory, a newer one that removes
a registry or key or undoes a revocation, and a different one with the same sequence. No registry is pinned by default: every registry, the first one included,
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
ask the PRE-GEN Test Registry at `https://sandbox.pregen.org` (codes `PG-TEST-000001N` …
`PG-TEST-000008H`; introduce yourself with `POST /v2/sandbox/party`), and pass `testing=True`
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
`Directory.check_signer` / `registry_for` / `public_key`, `verify_license`
(subject signature plus operator countersignature), `verify_signed`,
`canonical_json`, `fingerprint`, `check_public_key` (refuses keys no one can be held to), `issuer_of` (canonical
codes only) and `normalize_code` (for what a person types, never for a code in a message).

Tests: `pytest packages/verify-py/tests`, and the PRE-GEN Level 1 vectors with
`python3 spec/conformance/level1/run_conformance.py --adapter "python3 packages/verify-py/tests/conformance_adapter.py"`.

Apache-2.0. Part of the PRE-GEN standard,
[github.com/Pastheroza/PRE-GEN-site](https://github.com/Pastheroza/PRE-GEN-site).
