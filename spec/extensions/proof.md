# Extension `proof` — the record travels with the output

**Solves:** a PG code printed on a video proves nothing. A platform needs the signed record
of *this* output, even after re-encoding.

**Requires:** [`reports`](reports.md).

## The bundle — `pg.proof.v1`

`{"format": "pg.proof.v1", "subjects": [{request, answer, report, ack}, …]}` — one entry per
subject of the job, each part exactly as signed. Schema: `schemas/proof.json`. The bundle
itself is unsigned: every part is.

The report names the output by its SHA-256 (`output_hash`) and may add `bindings`:
`[{alg, value}]`, fingerprints that survive re-encoding (C2PA *soft bindings*; `alg` is a
C2PA soft-binding algorithm name).

## Carrying it

- **C2PA manifest:** the bundle as an assertion labelled `org.pregen.proof`.
- **Watermark:** a short payload `<prefix>:<16 hex>` — the registry and the first 16 hex
  characters of the report id. From it a platform fetches that registry's part:
  `GET {api}/v2/proofs/{16 hex}` → a `pg.proof.v1` bundle with that subject.

For a job with several subjects the full bundle travels in the C2PA manifest; from the
watermark alone a platform recovers the subject it names.

## Checking it

A platform accepts the bundle when, for every subject:

1. the answer verifies through a directory loaded in the last 24 hours (core rules 2 and 5)
   and was a valid `allow` **at the report's `occurred_at`** — it is checked as of the moment
   the output was made, not today;
2. the acknowledgement is signed by a key the directory lists for the subject's prefix, and
   names this report and this answer; the report's outcome is `generated`;

and all reports name one `output_hash` and one `job_id`. Given the file, its SHA-256 must
equal `output_hash`; after re-encoding the platform matches a soft binding instead.

A revoked registry's bundles fail, including old ones (`PRE-GEN-SPEC.md` V-14). A bundle
shows what was permitted and by whom; it does not decide whether a use is lawful.

The libraries implement the check as `checkProof` / `check_proof`.
