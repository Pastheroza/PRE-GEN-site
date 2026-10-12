# Extension `reports` — what happened, signed by both sides

**Solves:** after the answer, nobody can prove what the provider actually did. With
`reports`, the provider signs a statement of what it did, and the registry signs that it
received it.

**Requires:** [`provider-keys`](provider-keys.md).

## Report — `pg.report.v1`, signed by `provider`

`POST {api}/v2/reports` → `{"ack": <pg.report_ack.v1>}`

| Member | Rule |
|---|---|
| `signers` | `[{role: "provider", key_id}]` — the provider's current key |
| `request_id` | the request id |
| `answer` | the answer's message id, or `null` if no usable answer was received |
| `request` | the full request body — **present exactly when `answer` is `null`** |
| `job_id` | the request's |
| `outcome` | `generated` or `not_generated` |
| `output_hash` | SHA-256 hex of the output when `generated`; `""` otherwise |
| `occurred_at` | integer time |

Members added by other extensions: `mode` ([`observe`](observe.md)) and
`obligations_applied` (the profile).

**A report never grants anything.** An answer whose signature did not verify counts as
never received.

## Acknowledgement — `pg.report_ack.v1`, signed by `registry`

| Member | Rule |
|---|---|
| `report` | the report's message id |
| `answer` | as in the report |
| `answer_status` | that answer's status, or `none` |
| `provider_key_id` | the provider key the registry verified the report with |
| `received_at` | integer time |

Members added by [`limits`](limits.md): `counted`, `released`.

## Rules

- **Filed only when acknowledged.** A report counts as filed only when an acknowledgement
  for exactly its message id verifies.
- **No deadline.** Reports are accepted whenever they arrive: recording facts is the
  point.
- **One report per answer.** Plus at most one report with `answer: null` per subject of a
  job. The identical report again gets the stored acknowledgement — even if the provider's
  key has since been rotated or revoked. A different report is `PG_REPORT_CONFLICT`
  (HTTP 409).
- **One `generated` report per subject of a job.**

**Registry checks, in order:**
1. Schema.
2. Authentication.
3. An identical report already acknowledged: return the stored acknowledgement.
4. Provider key current, and the signature valid.
5. `request` present exactly when `answer` is `null`, and its id matches.
6. The answer belongs to this request and provider.
7. Conflicts.
8. Acknowledgement.
