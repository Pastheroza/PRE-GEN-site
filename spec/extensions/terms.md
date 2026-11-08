# Extension `terms` — a person's terms of generation

**Solves:** without this extension what a person allows is the registry's private setting, and
a provider learns it only from refusals. With it, the person's terms are a public, signed
record that keeps every version: the uses they allow and the categories they refuse. A
provider reads them before it asks, accepts them by signing its request, and the registry's
signed answer covers that request, so every output can name the exact version it was made
under.

**Requires:** [`provider-identity`](provider-identity.md) (acceptance is the provider's own
signature). **Works with** [`lookup`](lookup.md) (where the terms are found) and
[`proof`](proof.md) (what an output shows). The answer does not change: an app on an earlier
library keeps working.

## The terms — `pg.terms.v1`

Signed by the registry alone (`schemas/terms.json`):

```json
{"type": "pg.terms.v1",
 "body": {"signers": [{"role": "registry", "key_id": "pg-ed25519:…"}],
          "subject_ref": "PG-TEST-000001N", "profile": "likeness/1",
          "version": 2, "amends": "<message id of version 1>",
          "template": {"id": "example-likeness", "version": 1, "jurisdiction": "US"},
          "legal": {"sha256": "<sha-256 of the legal text>", "url": "https://registry.test.example/terms-template-1.txt"},
          "rules": {"purposes": ["editorial", "educational", "personal", "research"],
                    "excluded_categories": ["adult", "gambling", "political"]},
          "minor": false, "assent": "registry", "instruction": "<sha-256>",
          "issued_at": 1794000000},
 "signatures": ["…"]}
```

| Member | Rule |
|---|---|
| `signers` | exactly one: the registry, with a key the directory lists for the code's prefix |
| `subject_ref`, `profile` | the subject, and the profile that shapes `rules` |
| `version` | 1 for the subject's first terms, then one more for each version |
| `amends` | the message id of the version before; present exactly when `version` > 1 |
| `template` | `{id, version, jurisdiction}`: one of the registry's templates (`jurisdiction` an ISO 3166-1 alpha-2 code, or a reserved one such as `EU`). A person never writes terms freehand |
| `legal` | `{sha256, url}`: the template's text, which governs process, remedies and interpretation, never scope |
| `rules` | the machine layer, shaped by the profile; it alone governs scope (`profiles/likeness-1.md`) |
| `minor` | whether the registry knew the subject to be a minor when it signed this version |
| `assent` | `registry` (below). `self` and `agent` are reserved and refused |
| `instruction` | the SHA-256 of the canonical form of the registry's private record of the act that made this version |
| `factor` | `authenticator` or `email`: the second factor the registry checked; present exactly when this version opens (T-3) |
| `issued_at` | the registry's time |

The **terms id** is the record's message id. Arrays are sorted in code point order and hold
no duplicates; no string holds a control or format character; every number is an integer within
±(2^53 − 1). A record that breaks any of this is not a terms record.

## Rules

- **T-1 Only for a subject the registry publishes.** A registry publishes terms only for a
  subject it publishes ([`lookup`](lookup.md)) and that is confirmed or verified. A subject that
  is not, or is no longer, is answered as if it had no terms.
- **T-2 Versions only grow, and none is withdrawn from view.** Each version names the one
  before (`amends`). `GET {api}/v2/terms/{id}` → HTTP 200 `{"terms": <envelope>}` for every
  version ever published, otherwise 404 `PG_UNKNOWN_TERMS`. Outputs cite old versions, so the
  record outlives the subject's later changes.
- **T-3 What opens takes the person's own press and a second factor.** A version **opens**
  when it is version 1, adds a purpose, removes an exclusion, changes the template, or turns
  `minor` from true to false. Everything else only **closes**. A version that opens is made
  only on the subject's own authenticated instruction with a second factor, and names that
  factor in `factor`. A version that only closes names none. The registry never makes a first
  version on its own: there is no backfill from a subject's settings.
- **T-4 `registry` assent is the registry's word.** It means the subject's authenticated
  instruction at this registry, or the registry's own closing act (it learns the subject is a
  minor, for example). It never means the subject's own key, and a verifier never presents it as
  one. `factor` stops someone else in the subject's session; it is not evidence outside this
  registry.
- **T-5 Accepting is signing.** A request accepts the subject's current terms by carrying their
  id as `terms` (`schemas/request.json`) and the provider's signature: `signers` with a key from
  the provider's own party document ([`provider-identity`](provider-identity.md)). That signature
  is the acceptance, and a registry cannot produce it. A request that carries `terms`:
  - carries `signers` (otherwise `PG_MALFORMED`);
  - declares `use.categories` only in the profile's closed vocabulary (otherwise
    `PG_MALFORMED`, never a signed answer and never normalised);
  - goes only to a registry that declares `terms`. A registry that does not answers it
    `PG_MALFORMED`.

  A request without `terms` is answered as before.
- **T-6 The answer does not change.** It names the request by `request_id`, the request's
  message id, which covers `terms`: the registry's signature on the answer covers the version
  the provider accepted. A subject's terms are a record the request names, not a version of
  the registry's rules.
- **T-7 A stale id binds nothing.** A request whose `terms` is not the subject's current id,
  is another subject's, or names terms where the subject has none, gets `deny`,
  `PG_TERMS_NOT_ACCEPTED`. It is signed, but the registry keeps no ask for it ([`jobs`](jobs.md)):
  the provider looks the terms up again and asks again under the same `job_id`, and that ask is
  not a conflict. A replay of the stale request gets the same refusal and spends nothing.
- **T-8 Only a provider known by its domain accepts.** A provider that asks with a credential
  the registry issued, or with a key the registry holds, cannot accept terms: a request from it
  that carries `terms` gets `deny`, `PG_TERMS_NOT_ACCEPTED`, after the floor.
- **T-9 Narrowing stops new allows.** An `allow` about a subject that has terms lives at most
  300 seconds (`expires_at − issued_at`). One already issued stays valid for that lifetime.

## The gate

A registry answers a request about a subject in this order. The first step that applies
decides.

1. **The shape** of the request and **the requester's authentication** (core; T-5):
   `PG_MALFORMED` or an HTTP error, no signed answer.
2. **The subject step** (core): another registry's code and a code this registry does not hold
   are answered as without this extension. Terms never decide them.
3. **The floor and the subject's own refusals**, before anything else about who asks: the profile's
   floor, the opt-out, a provider the subject blocked. These refusals need neither the provider's
   standing at the registry nor accepted terms.
4. The registry's own state of the subject and of the provider.
5. **The exclusions, where no grant covers the use:** a use outside the subject's current
   `rules` (a purpose they do not list, or a category they exclude) gets `deny`,
   `PG_TERMS_EXCLUDED`, whether or not the request carries `terms`. This includes personal
   use. A valid grant decides its own scope, so this step reads the grants first: it is not a
   floor reason, and it holds at this registry only.
6. **Who asks:** the cited `terms` (T-7, T-8): `PG_TERMS_NOT_ACCEPTED`.
7. Everything else: grants, uses, the registry's policy.

**The terms grant nothing.** A use inside the rules still needs whatever the registry and the
profile require (a grant for commercial use, for example); only `allow` permits.

## What a proof shows

From an output alone, anyone verifies **what was signed**: the terms version, the request that
named it, and the registry's answer to that request ([`proof`](proof.md)). **Not whether it
still stands:** a later version, a withdrawal or a change of the subject's state is the
registry's live state, shown on its status page (`lookup`'s `status_url`).

## Registry document

A registry that publishes terms declares `terms` and `lookup` in its `extensions`, and
`"terms": "optional"`: a request may accept a subject's terms, and none is required to.

## Errors

| Code | HTTP | Meaning |
|---|---|---|
| `PG_UNKNOWN_TERMS` | 404 | no terms with this id were ever published here |
| `PG_MALFORMED` | 422 | `terms` without `signers`, a category outside the closed vocabulary, or `terms` sent to a registry that does not declare it |

`PG_TERMS_NOT_ACCEPTED` and `PG_TERMS_EXCLUDED` are answer reasons, not HTTP errors.
