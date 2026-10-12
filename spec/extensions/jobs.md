# Extension `jobs` — one generation, several subjects, never twice

**Solves:**
- a video with two people from two registries;
- ten workers picking up the same job;
- a crash mid-generation.

## The manifest

The provider fixes the job once, in a manifest: a canonical JSON object with `job_id`,
`provider_id`, the asks, and anything else the job depends on (prompt hash, model,
modality). The asks are sorted by `subject_ref`; each is `{subject_ref, registry, profile,
use}`, where `registry` is the prefix (`""` for the origin).

`job_hash` = SHA-256 of the canonical manifest. Every request of the job carries it.

## What a registry guarantees

| Rule | Otherwise |
|---|---|
| One `job_hash` per (`provider_id`, `job_id`) | `PG_JOB_CONFLICT` (409) |
| One request per (`provider_id`, `job_id`, `subject_ref`) | `PG_ASK_CONFLICT` (409) |
| After a `generated` report for that subject of the job, no new answer | `PG_ASK_CLOSED` (409, with the stored `ack`) |
| The identical request while an answer is open gets that same answer | — |

**A new generation always needs a new `job_id`.**

The registry cannot stop two workers of one provider from both generating on the same answer:
that is the provider's part (X-1 below). "Never twice" holds when both sides keep their rules.

Only the provider can guarantee that its asks to *different* registries come from one
manifest. A verifier can check it afterwards: all requests carry the same `job_hash`, and
the manifest hashes to it.

## What the provider's client guarantees

- **X-1** — Claim the job atomically, in storage every worker shares.
- **X-2** — Build the manifest once and never change it. Send every ask from it.
- **X-3** — Verify every answer, and re-check its time just before generating.
- **X-4** — Generate only when every ask has a valid `allow` (the core rule).
- **X-5** — Store the output hash and the signed reports before sending them.
- **X-6** — A report is filed only when its acknowledgement verifies.
- **X-7** — A job that may have started generating is never restarted automatically. Its
  outcome is unknown until a person resolves it.
