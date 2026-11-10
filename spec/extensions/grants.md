# Extension `grants` — licences as signed objects

**Solves:** an `allow` says "a grant permits this". With `grants`, the grant itself is a
signed object that anyone can fetch and check.

## Grant — `pg.grant.v1`, signed by `rights_holder`, then `registry`

| Member | Rule |
|---|---|
| `subject_ref` | the subject's code, in its TOG spelling (`TOG-CODE.md` §7.3) |
| `licensee_id` | who the grant is for; `""` = any licensee of the registry |
| `profile` | e.g. `likeness/1` |
| `use` | what is granted; schema from the profile (`likeness/1`: `{purposes, categories?, resale?}`) |
| `not_before`, `expires_at` | integer times |
| `max_uses` | integer ≥ 1, or `null` for no limit (counted by [`limits`](limits.md)) |

## Signers

- **`rights_holder` key** — the subject's key the registry publishes in the subject record
  ([`lookup`](lookup.md)), together with its custody:
  - `self` — the rights holder holds the key;
  - `managed` — the registry holds it for them.
- **`registry` key** — valid for the subject's prefix in the directory.

## The licence's code

A grant's code is its `TOG-LIC` code (`TOG-CODE.md` §6), computed from the signed grant, never
read off a string:

- **Issuer:** the registry that signed the grant. It is the first prefix.
- **Tail:** the first 55 bits of the message id of the object the home signed for the grant:
  its countersignature in the home model, the grant itself in the flat model. **There is no
  market counter:** a code tells nothing about how many licences a registry sold.
- **Home:** shown only when the home's countersignature says so, and never when the home is the
  issuer.
- A grant whose code would end in a symbol, or whose tail would start `ZZZZ`, is signed again
  with a changed body before it is issued. A registry refuses a code it has already issued.

A grant has exactly one code. Its message id stays the reference everywhere a machine cites it.

## In an answer

`basis: {"kind": "grant", "grant": {"format": "pg.grant.v1", "id": "<message id of the
grant>"}}`.

`GET {api}/v2/grants/{id}` returns `{"grant": <envelope>}` to the grant's licensee, its
provider, and anyone the registry's policy allows.

## Older licences

A licence issued under the earlier interface is referenced, never re-wrapped:
`{"format": "pg.license.v2", "license_id", "id"}`, where
`id` = SHA-256(`canonical(body) || subject_signature || ASCII(license_id)`).

**Its code is a `TOG-LIC` code, computed from that `id`** exactly like a grant's, in the flat
model: issuer = its signer, tail = that id. If that gives a symbol check or a `ZZZZ` tail, the home
countersigns it once and the code comes from the countersignature; the licence is never signed
again. Only its own registry computes that code, once, when it migrates (`TOG-CODE.md` §6.2). Its PG
`license_id` stays inside its signed bytes, and where needed in an internal column to rebuild that
signature: never accepted from outside, never shown. No verifier accepts the old `pg.license.v2`
itself: its bytes hold a PG id (`TOG-CODE.md` §17). From the switch, every new licence is a
`pg.grant.v1`; no registry issues a new `pg.license.v2`.

**A verifier that does not support a grant format treats the basis as unverifiable, not as
valid.**
