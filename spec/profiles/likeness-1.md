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
| An intimate category (`sexual`, `adult`) without the person's own signature — see below | `PG_PERSONAL_SIGNATURE_REQUIRED` |

## Intimate categories need the person's own signature

An `allow` for an output in the categories `sexual` or `adult` requires all of:
- the subject holds their own key (`custody: self`), so the registry cannot sign for them;
- the subject's level is `verified`;
- a grant signed with that key names those categories in its `use.categories`.

This is not a ban: it is consent the registry cannot fake, where the harm is greatest.

## Other reasons

| Reason | Meaning |
|---|---|
| `PG_NO_LICENSE` | no grant covers this licensee and use |
| `PG_USAGE_LIMIT` | the grant's uses are spent |
| `PG_SCOPE_VIOLATION` | outside the grant's scope |
| `PG_REVIEW_REQUIRED` | with status `review` |
| `PG_NOT_CONNECTED` | this use needs a connected end user |

## Grants under this profile

A grant's `use` is `{purposes, categories?, resale?}`: the purposes it covers, the content
categories it grants explicitly (required for intimate ones), and the resale right
([`catalog`](../extensions/catalog.md)).

## Public persons

A public person is resolved through [`identity`](../extensions/identity.md): by anchor, across
every registry that lists it. By default a client does not generate a public person whose
claim is not confirmed on their own channel (`PG_IDENTITY_UNCONFIRMED`, `PG_IDENTITY_CONFLICT`
— client outcomes, not registry answers).

**A registry may add its own reasons.** A provider treats an unknown reason as a refusal.

## Give-back window

24 hours from `issued_at` ([`limits`](../extensions/limits.md)).
