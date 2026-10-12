# Profile `likeness/1` — a person's likeness and voice

The first PRE-GEN profile. It says what `use` contains, which reasons and obligations
exist, and which refusals nothing can override.

## `use`

`{purpose, rights?, territory?, channel?, categories?}`
- `purpose`: `personal`, `educational`, `research`, `editorial` or `commercial`;
- `rights`: a list of strings;
- `territory`, `channel`: strings;
- `categories`: the content categories the provider declares for this output, for example
  `sexual`, `political` or `violence`. The floor and immutable denials are checked against
  them.

## Answer members this profile adds

- **`level`** — `self`, `asserted`, `consented` or `verified`, as defined in
  [`lookup`](../extensions/lookup.md). A claim, not evidence.
- **`obligations`** — a list of `{id, params}`, for example `watermark` or `disclosure`. A
  registry lists the ids it uses in its published policy. A report may name the ids applied
  (`obligations_applied`).

## The floor — refused before any grant is considered

These refusals are never overridden by a grant, an extension or a registry policy
(`PRE-GEN-SPEC.md` E-1, R-4):

| Case | Reason |
|---|---|
| An opt-out in effect | `PG_SUBJECT_OPTED_OUT` |
| The subject is pending, paused, disputed or withdrawn | `PG_SUBJECT_UNAVAILABLE` |
| A fixed protection forbids the use — a minor's likeness in a sexualised or otherwise prohibited category | `PG_PROHIBITED_USE` |
| An immutable denial | `PG_IMMUTABLE_DENIAL` |

## Other reasons

| Reason | Meaning |
|---|---|
| `PG_NO_LICENSE` | no grant covers this licensee and use |
| `PG_USAGE_LIMIT` | the grant's uses are spent |
| `PG_SCOPE_VIOLATION` | outside the grant's scope |
| `PG_REVIEW_REQUIRED` | with status `review` |
| `PG_NOT_CONNECTED` | this use needs a connected end user |

**A registry may add its own reasons.** A provider treats an unknown reason as a refusal.

## Give-back window

24 hours from `issued_at` ([`limits`](../extensions/limits.md)).
