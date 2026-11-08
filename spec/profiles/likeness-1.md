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

## The closed vocabulary

`adult`, `advertising`, `alcohol`, `cannabis`, `drugs`, `endorsement`, `fashion`, `financial`,
`gambling`, `health`, `political`, `religion`, `sexual`, `tobacco`, `violence`, `weapons`.
A code, once listed, is never removed or renamed.

Each is a language-neutral ASCII code; a registry shows it in the reader's language. A
subject's terms are written only in these codes, and a request that accepts terms
([`terms`](../extensions/terms.md)) declares `categories` only in them: any other word, case,
look-alike letter or hidden character is `PG_MALFORMED`, never normalised and never passed. A
request without `terms` may still use other words in this version.

- **Prohibited for minors:** `sexual`, `adult`, `violence`.
- **Intimate:** `sexual`, `adult`.

Both lists only grow.

## Answer members this profile adds

- **`level`** — `self`, `asserted`, `consented` or `verified`, as defined in
  [`lookup`](../extensions/lookup.md). A claim, not evidence.
- **`obligations`** — a list of `{id, params}`, for example `disclosure`. PRE-GEN never asks
  for a watermark; a legacy `watermark` id is recognised, not used. A registry lists the ids
  it uses in its published policy. A report may name the ids applied (`obligations_applied`).

## The floor — refused before any grant is considered

These refusals are never overridden by a grant, an extension or a registry policy
(`PRE-GEN-SPEC.md` E-1, R-4):

| Case | Reason |
|---|---|
| An opt-out in effect | `PG_SUBJECT_OPTED_OUT` |
| The subject is pending, paused or withdrawn | `PG_SUBJECT_UNAVAILABLE` |
| A fixed protection forbids the use — a minor's likeness in a sexualised or otherwise prohibited category, or in a category outside the closed vocabulary | `PG_PROHIBITED_USE` |
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
| `PG_SUBJECT_DISPUTED` | a complaint about this code is being examined; refused at this registry before any grant, but not a refusal of the person ([`identity`](../extensions/identity.md)) |
| `PG_NOT_CONNECTED` | this use needs a connected end user |
| `PG_TERMS_NOT_ACCEPTED` | the request's `terms` is not the subject's current terms, or the provider cannot accept them ([`terms`](../extensions/terms.md)) |
| `PG_TERMS_EXCLUDED` | no grant covers the use, and the subject's terms exclude it |

## Terms under this profile

A subject's `pg.terms.v1` `rules` are `{purposes, excluded_categories}`: the purposes the
subject allows (at least one) and the categories they refuse (possibly none), both sorted. A
category can only be excluded, so terms never lower the floor. `minor` is whether the registry
knew the subject to be a minor when it signed the version, so that anyone can run the whole
floor from the record. Intimate categories stay on the subject's own-key grant path above; terms
never permit them.

## Grants under this profile

A grant's `use` is `{purposes, categories?, resale?}`: the purposes it covers, the content
categories it grants explicitly (required for intimate ones), and the resale right
([`catalog`](../extensions/catalog.md)).

## Public persons

For a public person, a client asks every registry whose anchor list names the person's
anchor, and decides over those claims with the [`identity`](../extensions/identity.md) rule,
for each generation. With no claim confirmed on the person's own channel, PRE-GEN says
nothing (`not_blocked`, `PG_IDENTITY_UNCONFIRMED`: a client outcome, not a registry answer).
Nothing is permitted; a client generates only on `allow`.

**A registry may add its own reasons.** A provider treats an unknown reason as a refusal.

## Give-back window

24 hours from `issued_at` ([`limits`](../extensions/limits.md)).
