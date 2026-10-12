# Extension `sandbox` — the same test subjects everywhere

**Solves:** every provider needs to test refusals, not only success. Every registry's
sandbox should answer alike.

## Standard subjects

A registry whose document says `"sandbox": true` publishes these subjects on its own
prefix, with fixed serials:

| Serial | Answer (`likeness/1`, `purpose: "research"`) |
|---|---|
| 1 | `allow` — basis a grant with no usage limit |
| 2 | `deny`, `PG_NO_LICENSE` |
| 3 | `deny`, `PG_SUBJECT_OPTED_OUT` |
| 4 | `deny`, `PG_USAGE_LIMIT` |
| 5 | `deny`, `PG_PROHIBITED_USE` |
| 6 | `review`, `PG_REVIEW_REQUIRED` |
| 7 | `not_blocked`, `PG_NO_LICENSE` |
| 8 | not registered — `deny`, `PG_UNKNOWN_SUBJECT` |

## Rules

- **Every sandbox answer carries `ext: {"sandbox": true}`.**
- **Never accepted in production.** A client MUST NOT accept a sandbox answer unless it is
  explicitly configured for testing.
- **Test directory.** Sandbox registries are listed in a test directory, signed by a test
  steward key. Clients accept it only in testing mode.
- **Credentials.** A sandbox MAY issue credentials without an account, because it holds no
  real people.

## Example

The **PRE-GEN Test Registry** (prefix `TEST`): serial 1 is `PG-TEST-000001` plus its check
character.
