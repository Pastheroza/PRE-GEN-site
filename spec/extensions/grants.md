# Extension `grants` — licences as signed objects

**Solves:** an `allow` says "a grant permits this". With `grants`, the grant itself is a
signed object that anyone can fetch and check.

## Grant — `pg.grant.v1`, signed by `rights_holder`, then `registry`

| Member | Rule |
|---|---|
| `subject_ref` | the subject's PG code |
| `licensee_id` | who the grant is for; `""` = any licensee of the registry |
| `profile` | e.g. `likeness/1` |
| `use` | what is granted; schema from the profile |
| `not_before`, `expires_at` | integer times |
| `max_uses` | integer ≥ 1, or `null` for no limit (counted by [`limits`](limits.md)) |

## Signers

- **`rights_holder` key** — the subject's key the registry publishes in the subject record
  ([`lookup`](lookup.md)), together with its custody:
  - `self` — the rights holder holds the key;
  - `managed` — the registry holds it for them.
- **`registry` key** — valid for the subject's prefix in the directory.

## In an answer

`basis: {"kind": "grant", "grant": {"format": "pg.grant.v1", "id": "<message id of the
grant>"}}`.

`GET {api}/v2/grants/{id}` returns `{"grant": <envelope>}` to the grant's licensee, its
provider, and anyone the registry's policy allows.

## Older licences

A licence issued under the earlier interface is referenced, never re-wrapped:
`{"format": "pg.license.v2", "license_id", "id"}`, where
`id` = SHA-256(`canonical(body) || subject_signature || ASCII(license_id)`).

**A verifier that does not support a grant format treats the basis as unverifiable, not as
valid.**
