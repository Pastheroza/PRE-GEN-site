# Extension `identity` — one person, several registries

**Solves:** the same public person can be claimed by several registries — by right (they
registered twice), or by an impostor. A name never decides; a refusal by the person must hold
everywhere; **who came first never wins — who proved it does.**

## Anchors

An **anchor** is the person's identifier in an independent public source:
`wikidata:Q11571`, `isni:0000000123456789`, or `domain:example.com`.

- A registry MUST give an anchor for every public person it registers. Registering a public
  person without one is ground for revocation (`PG-CODE.md` §9.1).
- Private persons have no anchor and are never listed.

`GET {api}/v2/anchors` → `pg.anchors.v1`, signed by `registry`:

| Member | Rule |
|---|---|
| `registry` | the registry's prefix |
| `issued_at` | integer time; a client refuses a list more than 24 hours old, so an old copy cannot hide a new opt-out |
| `anchors` | `[{anchor, code, level, proof_url, status}]`; `status` is `active`, `opted_out`, or the subject's unavailable status |

Schema: `schemas/anchors.json`. A client collects every listed registry's list, at least
daily, and for a public person asks **every** code its anchor names.

## Confirmation on the person's own channel

A claim is **confirmed** when the person published the line `PRE-GEN: <code>` on an
official channel that the anchor's source lists for them (Wikidata: official website, X,
Instagram, YouTube channel, TikTok), and `proof_url` points to it. Anyone can check it; an
impostor cannot post there. Registries re-check confirmations at least daily.

## The rule

For one anchor, over the claims that remain after the steward's false claims are removed:

1. **Confirmed claims silence unconfirmed ones.** If any claim is confirmed, only confirmed
   claims count. Codes confirmed by the same person are one person in several registries.
2. **A refusal of the person holds everywhere.** If any counted answer refuses with a floor
   reason (`PG_SUBJECT_OPTED_OUT`, `PG_SUBJECT_UNAVAILABLE`, `PG_PROHIBITED_USE`,
   `PG_IMMUTABLE_DENIAL`, `PG_PERSONAL_SIGNATURE_REQUIRED`), the result is that refusal. "No
   licence here" is not a refusal of the person.
3. **No proof, several claims: freeze.** Two or more unconfirmed claims → `review`,
   `PG_IDENTITY_CONFLICT`. Nobody permits until someone proves it.
4. **No proof, one claim:** `review`, `PG_IDENTITY_UNCONFIRMED`, unless the provider's
   own published policy accepts unconfirmed claims.
5. Otherwise an `allow` from any counted claim permits.

An impostor can at most freeze a person who never confirmed anything; it can never permit.
The libraries implement the rule as `decideIdentity` / `decide_identity`.

## Disputes and false claims

- A registry answers a complaint within **7 days**. While it is examined the code is
  `disputed`, which `likeness/1` refuses (`PG_SUBJECT_UNAVAILABLE`).
- The steward records the outcome in the directory: `false_claims: [{anchor, code, at,
  reason}]`. Clients drop those codes when they load that directory; an entry is never removed. Repeated
  false claims are ground for revoking the registry.
- Disputes are decided by the steward under published rules until an independent panel takes
  over.
