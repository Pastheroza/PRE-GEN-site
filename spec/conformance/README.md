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

Neither level is exhaustive. Level 1 replays every case in
`spec/test-vectors/vectors.json` — that corpus itself isn't infinite, but
it's the actual contract (`spec/README.md`: "where prose and vectors
disagree, the vectors win"). **Level 2's refusal-code coverage is a
representative subset, not all 36 registered codes** — one per category
(request/identity/subject_trust/license) plus happy-path, a receipt, and
audit-chain re-validation. `review` (`PG_HELD_FOR_REVIEW`, the only code in
that category) isn't covered — it needs a high-risk-subject precondition
heavier than the others. Full 36-code coverage is real, separate, tracked
work, not implied here.

## Level 1 — offline (`level1/`)

A CLI adapter protocol: one JSON request on stdin, one JSON response on
stdout, one process per call. This is what makes Level 1 usable by an
implementation in *any* language, not just the four already in this repo.

```
{"op": "canonical_json", "input": {...}}
→ {"canonical_utf8": "...", "sha256_hex": "..."}

{"op": "verify_signature", "message": {...}, "public_key_hex": "...", "signature_hex": "..."}
→ {"valid": true}

{"op": "pg_check_char", "body": "000042"} → {"check_char": "*"}
{"op": "pg_verify_check_char", "body": "000042", "check_char": "*"} → {"valid": true}
{"op": "pg_subject_code", "serial": 42} → {"code": "PG-000042*"}
{"op": "pg_license_id", "license_class": "STD", "subject_serial": 1, "tail": "K7M2QX"} → {"license_id": "..."}
```

An adapter answers `{"unsupported": true}` for an op it doesn't implement.
The `pg_*` ops are backend-only today (`spec/README.md`: the SDKs "receive
codes, they never mint them") — every other implementation answers those
`unsupported`, and the runner reports them **skipped**, not failed. No
adapter needs a "sign as operator" capability: `vectors.json`'s `signing`
cases already carry a precomputed signature from a fixed public test key,
so an adapter's job is to canonicalize the body and verify that signature
— exactly what a real consumer does, never what only PRAMPTA does.

Run against one implementation:

```bash
# Backend (source of truth)
python3 level1/run_conformance.py --adapter "python3 level1/adapters/backend_adapter.py"

# Reference server (pg_registry.py) -- crypto only, predates the PG-code redesign
python3 level1/run_conformance.py --adapter "python3 level1/adapters/reference_adapter.py"

# Python SDK -- crypto only
python3 level1/run_conformance.py --adapter "python3 level1/adapters/python_sdk_adapter.py"

# TypeScript SDK -- crypto only, zero build step via sucrase
cd ../../sdk/typescript && npm ci   # once, for sucrase-node + @noble/ed25519
python3 ../../spec/conformance/level1/run_conformance.py \
  --adapter "sdk/typescript/node_modules/.bin/sucrase-node spec/conformance/level1/adapters/typescript_sdk_adapter.ts" \
  --env "NODE_PATH=$(pwd)/node_modules"
```

`backend/tests/test_conformance_level1.py` runs all four in CI
(`.github/workflows/ci.yml`'s `conformance` job) as part of the normal
backend test suite.

## Level 2 — live server (`level2/`)

Pure JSON scenario files (`level2/scenarios/*.json`) — an ordered list of
HTTP steps, each with an expected status and (optionally) fields to check
in the response and values to save into named variables for later steps.
No embedded crypto anywhere: every subject registers managed-custody (the
only custody mode since self-custody registration was retired platform-
wide — `backend/app/api/subjects/registration.py`'s own docstring), and
managed-custody license issuance needs no client signature either
(`backend/app/api/licenses.py::issue_presigned`). That's what keeps these
scenarios genuinely portable to a foreign server implementation, not just
readable as documentation of one.

Run against any live server:

```bash
python3 level2/run_scenarios.py --base-url http://localhost:8000/v1
```

`scripts/conformance-level2-drill.sh` (repo root) spins up a real backend
against a throwaway SQLite database, runs the scenarios, and tears down —
the same background-uvicorn / poll-`/healthz` / `trap ... EXIT` shape
`scripts/restore-drill.sh` already uses for the backup/restore drill, not
a new pattern. This is what CI runs.

## Sabotage-testing this suite

If you're modifying the runner or an adapter, prove it actually catches a
real break before trusting it: temporarily corrupt one character of
`backend/app/core/crypto.py::canonical_json`'s separator, rerun Level 1
against the backend adapter, confirm a clear multi-case failure, then
revert. This is exactly how Level 1 was itself verified while being built
— see `future_warnings_for_valera.md`'s "Закрытые" log, 2026-08-24 entry,
for the actual sabotage run and its output.
