# PRE-GEN conformance suite

**License:** Apache License 2.0 — see [`spec/LICENSE`](../LICENSE); licensed
separately from the PRAMPTA service, same as the rest of `spec/`.

Two independent levels, stated plainly:

> **If your implementation passes Level 1, it's compatible at the
> crypto/pg-code layer.** It canonicalizes JSON the same way, verifies
> Ed25519 signatures the same way, and (if it mints PG codes at all)
> computes check characters and formats identifiers the same way as the
> reference.
>
> **If it also passes Level 2, it's compatible as a service** — a real
> client can register a subject, issue a license, call `/verify`, get the
> right refusal for the right reason, submit a receipt, and trust that the
> audit chain it's building is internally consistent.

Neither level is exhaustive, and passing both is necessary but not
sufficient for a conformance claim: `PRE-GEN-SPEC.md` §8 defines the
profiles and lists, requirement by requirement, what these checks do and do
not cover. The text is normative; a vector that disagrees with it is an
erratum (§0.3). **Level 2's refusal-code coverage is a
representative subset, not every registered code** — one per category
(request/identity/subject_trust/license) plus happy-path, a receipt, and
audit-chain re-validation. `review` (`PG_HELD_FOR_REVIEW`, the only code in
that category) isn't covered — it needs a high-risk-subject precondition
heavier than the others. Full coverage is separate work, not implied here.

## Level 1 — offline (`level1/`)

A CLI adapter protocol: one JSON request on stdin, one JSON response on
stdout, one process per call. This is what makes Level 1 usable by an
implementation in *any* language, not just the two libraries in this repository.

```
{"op": "canonical_json", "input": {...}}
→ {"canonical_utf8": "...", "sha256_hex": "..."}

{"op": "verify_signature", "message": {...}, "public_key_hex": "...", "signature_hex": "..."}
→ {"valid": true}

{"op": "pg_check_char", "body": "000042"} → {"check_char": "*"}
{"op": "pg_verify_check_char", "body": "000042", "check_char": "*"} → {"valid": true}
{"op": "pg_subject_code", "serial": 42} → {"code": "PG-000042*"}
{"op": "pg_license_id", "license_class": "STD", "subject_serial": 1, "tail": "K7M2QX"} → {"license_id": "..."}

{"op": "verify_license", "body": {...}, "license_id": "PG-PRM-…",
 "subject_public_key_hex": "...", "subject_signature_hex": "...",
 "operator_public_key_hex": "...", "operator_signature_hex": "..."}
→ {"subject_valid": true, "operator_valid": true}

{"op": "verify_directory", "directory": {...}, "steward_public_key_hex": "...", "min_sequence": 0}
→ {"valid": true}

{"op": "check_namespace", "directory": {...}, "code": "PG-NWRD-…", "signer_key_id": "pg-ed25519:…"}
→ {"result": "valid" | "issuer_mismatch" | "unknown_issuer"}
```

**v5 messages (PRE-GEN-CORE.md, Messages and rule 5), required by default:**

```
{"op": "message_id", "type": "pg.answer.v1", "body": {...}} → {"message_id": "<hex>"}
{"op": "signing_input", "type": "pg.answer.v1", "body": {...}} → {"signing_input_hex": "<hex>"}
{"op": "verify_envelope", "envelope": {...}, "public_keys": {"<key_id>": "<hex>", ...}} → {"valid": true}
{"op": "check_answer", "answer": {...}, "request": {...}, "directory": {...}, "steward_public_key_hex": "...",
 "key_sets": {"<keys url>": {...}}, "now": 1790000000, "testing": false} → {"ok": true} or {"ok": false, "error": "…"}
```

The vectors are `test-vectors/messages.json` (8 messages), `test-vectors/small-order-keys.json` (the C1 forgeries
`verify_envelope` must refuse) and `test-vectors/answers.json` (20 answer checks, from `spec/tools/answer_vectors.py`).
A pre-v5 implementation runs with `--allow-missing-v5` and is not v5 conformant. A run where no operation ran fails.

An adapter answers `{"unsupported": true}` for an op it doesn't implement.
For release gates, require the operations your profile claims, for example
`--require-op verify_signature --require-op verify_license --require-op verify_directory`.
An unsupported required operation fails the run. Passes, failures and skips
are counted separately; cryptographic checks include tampered-body rejection.
`check_namespace` requests also carry the pinned `steward_public_key_hex` so
the TypeScript adapter can verify the directory before consulting it.
The `pg_*` ops are backend-only today (`spec/README.md`: the SDKs "receive
codes, they never mint them") — every other implementation answers those
`unsupported`, and the runner reports them **skipped**, not failed. No
adapter needs a "sign as operator" capability: `vectors.json`'s `signing`
cases already carry a precomputed signature from a fixed public test key,
so an adapter's job is to canonicalize the body and verify that signature
— exactly what a real consumer does, never what only PRAMPTA does.

Run against one implementation: write an adapter (any language) that answers the ops above, then, from the
repository root,

```bash
python3 spec/conformance/level1/run_conformance.py --adapter "<your command>"
```

The two libraries ship adapters, and each release runs them first:

```bash
python3 spec/conformance/level1/run_conformance.py --adapter "python3 packages/verify-py/tests/conformance_adapter.py"
python3 spec/conformance/level1/run_conformance.py --adapter "node packages/verify-js/test/conformance-adapter.js"
```

## Level 2 — live server

Level 2 is a set of HTTP scenarios: each step a request with an expected status and the fields to check in the
answer. They run against the first registry's earlier interface (`/v1`) and are not published in this repository
yet.

## Sabotage-testing this suite

If you change the runner or an adapter, prove it catches a real break before trusting it: corrupt one character of
your implementation's canonical JSON, rerun Level 1, confirm a clear multi-case failure, then revert.
