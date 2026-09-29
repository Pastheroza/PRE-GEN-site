# PRE-GEN protocol changelog

Protocol-only. Product/UI changes live in `future_warnings_for_valera.md`'s
"Закрытые" log and git history, not here. Kept from 2026-08-24 onward —
**not** backfilled further back than that; earlier protocol history is
already covered by `docs/PRAMPTA-Protocol-Versions.md` and the mint-site
comments cited throughout `spec/PRE-GEN-SPEC.md`.

See `docs/PROTOCOL-GOVERNANCE.md` for what triggers an entry here.

## 2026-09-28

- PRE-GEN is published as a public standard at https://www.pregen.org,
  copyright Valerii Egorov, Apache-2.0.
- Issuer prefix (`PG-CODE.md` §9): other registries prefix every code they
  issue with exactly four letters — `PG-NWRD-000042=`,
  `PG-NWRD-RND-000042-ZZZZZZJ`. The prefix is part of the checked body.
  Additive: bare codes keep meaning the origin registry forever, and every
  existing vector is byte-identical; new `issuer_*` vectors added.

## 2026-09-23

- Added opt-in `pg.receipt.v3`, which signs the lifecycle `event_type` along
  with the existing receipt fields. v2 stays the default and is not
  deprecated. The API reports whether a provider signature actually bound
  the event type; this is not a royalty settlement or completeness guarantee.
  `Spec-Version` advanced to `2026-09-23.1` for the new signed object shape.

## 2026-08-29

- **Known-limitations section added to the spec** (`spec/PRE-GEN-SPEC.md`
  §8). **Not a protocol change**, and `Spec-Version` is deliberately not
  bumped — §8 documents what the five signed objects cannot currently
  express (one subject per decision; `output_hash` not surviving re-encode;
  no commercial terms in a license; no signed settlement artifact) and
  points at a draft proposal. No object, field, or vector changed;
  `spec/conformance/` is unaffected.
- **Revenue-extension design drafted**
  (`docs/PRE-GEN-Revenue-Extensions-DRAFT.md`) — proposes `pg.revenue.v1`
  and `pg.settlement.v1`, plus additions to License, Decision, Receipt, and
  Assertion, each analyzed against §5.1's per-object versioning rule.
  **Nothing is implemented.** Recorded here because the analysis makes one
  thing concrete: Receipt is the only one of the four that breaks, so the
  dual-accept window built dormant on 2026-08-24 now has a named first use
  if this ever ships.

## 2026-08-24

- **Spec published.** `spec/PRE-GEN-SPEC.md` — normative spec for the 5
  signed protocol objects (Decision, License, Receipt, Evidence bundle,
  Assertion), the canonicalization rule, a generated refusal-code table
  (`spec/REFUSAL-CODES.md`), and a PG-code ABNF grammar + canonical regex.
  Not a protocol change itself — this is the first time the existing
  protocol was written down completely enough for an outside implementer
  to build against it without reading PRAMPTA's source. `Spec-Version:
  2026-08-24`.
- **Governance policy adopted.** `docs/PROTOCOL-GOVERNANCE.md` +
  `SECURITY.md` — deprecation-window policy (License: permanent per-row;
  Receipt: 90-day dual-accept, proposed) and a security-advisory contact.
  Not a protocol change either — a policy for how future ones get
  announced.
- **Dual-accept mechanism added for Receipt** (`backend/app/core/
  receipt_body.py`) — the server can now verify a provider's signature
  against either the current receipt-body shape or a recent prior one, for
  a bounded window, and marks a fallback match with `Deprecation`/`Sunset`
  headers. **No format change**: `pg.receipt.v2` remains the only shape
  that has ever actually existed; this entry records that the mechanism
  now exists, ready for the day a real second shape is added, not that one
  has been.
- **Conformance suite published.** `spec/conformance/` — Level 1 (offline,
  a CLI adapter protocol replaying `vectors.json` against all four named
  implementations) and Level 2 (HTTP scenarios against a live server, a
  representative subset of refusal codes, not all 36). Not a protocol
  change — the first standalone artifact a fifth, unknown implementation
  could point at itself.
- **Publishing pipeline built** (`.github/workflows/release-sdk.yml`) —
  `@prampta/sdk` (npm) and `prampta` (PyPI), OIDC trusted publishing, no
  stored tokens. Not shipped yet — needs a one-time account-side Trusted
  Publisher registration on each registry before the first tag-push
  succeeds (`docs/PROTOCOL-GOVERNANCE.md` "Publishing"). Also fixed:
  `spec/README.md`/`PG-CODE.md`/`PRE-GEN-SPEC.md`/`conformance/README.md`
  all linked their Apache-2.0 claim at the repo-root `/LICENSE`, which is
  actually proprietary (it covers the PRAMPTA service, not the spec) —
  added `spec/LICENSE` with the real Apache-2.0 text `sdk/typescript/
  LICENSE` already had, and fixed the four links. Not a normative change
  either way (a citation fix, not a spec change) — no `Spec-Version` bump.
- **SDK publish pipeline unblocked.** `@prampta/sdk` (npm) and `prampta`
  (PyPI) trusted publishers registered on npmjs.com/pypi.org (founder);
  GitHub Environments `npm-publish`/`pypi-publish` created to match
  `release-sdk.yml` exactly. Still no release tag pushed — that remains a
  separate, deliberate action.
- **PG-code ergonomics (Phase 5).** `spec/PG-CODE.md` §§11–13: a reserved
  subject-serial range (`RESERVED_SUBJECT_SERIAL_FLOOR = 900,000,000`,
  founder-confirmed as a numeric block) so documentation/example/test
  codes can never collide with a real subject or license; a public,
  unauthenticated resolver (`GET /v1/pg/{code}`) that finally implements
  §7's mistyped-vs-not-found distinction, which no running code did
  before this; `GET /.well-known/pg-policy` (RFC 8615); a QR/display
  convention (full resolver URL, not a bare code); homoglyph folding at
  the resolver's input boundary, explicitly non-exhaustive. **`Spec-
  Version` bump (`.1`)**: this is a normative addition — the reserved
  range and the mistyped/not-found split are new, checkable facts about
  the protocol, not just documentation. 5.5 (standalone zero-dependency
  `pg-code` packages) explicitly deferred, stated in `spec/PRE-GEN-
  SPEC.md`'s own intro rather than silently dropped.
- **Fixed a stale §7.** `spec/PRE-GEN-SPEC.md` §7 still called the
  conformance suite "not yet built — Phase 3" a full phase after Phase 3
  actually shipped it — found while touching this file for the Phase 5
  entry above, not a new problem introduced today. Rewritten to describe
  the real suite and link `spec/conformance/README.md`.
- **Property-based and fuzz testing (Phase 6, the last of the six
  originally-scoped phases).** hypothesis (Python,
  `backend/tests/test_property_based.py`) and fast-check (TypeScript,
  `sdk/typescript/tests/property.test.ts`) property-test canonicalization
  (determinism, insertion-order independence, round-tripping) and the
  check-character algorithm (single-substitution/adjacent-transposition
  detection), on both sides of the language boundary, alongside the
  pre-existing exhaustive brute-force tests. Not a protocol change — no
  `Spec-Version` bump.

  Fuzzing (`backend/tests/test_fuzz_no_unhandled_exceptions.py`, a plain
  random-garbage generator against the two public unauthenticated
  surfaces) found and fixed three real robustness bugs, two of them
  Postgres-only — invisible to every prior SQLite-only CI run:
  1. `verify_check_char` raised an unhandled `KeyError` on a body
     containing a Unicode "digit" `str.isdigit()` accepts but the
     Crockford alphabet doesn't (e.g. superscript `²`) — reachable from
     the Phase 5 public resolver with a crafted code string.
  2. A NUL byte in any `POST /v1/verify` string field crashed with
     `asyncpg.CharacterNotInRepertoireError` (Postgres rejects it at the
     driver level; SQLite silently accepts it) — now rejected with a
     clean `422`, not stripped, matching `/verify`'s own fail-closed
     design.
  3. Fixing #2 surfaced a third, more general, pre-existing bug: a
     validator raising a bare `ValueError` can leave a non-JSON-
     serializable object in Pydantic v2's `errors()[].ctx`, which used to
     crash `main.py`'s validation handler outright — turning an intended
     `422` into an unhandled `500`. No validator had ever raised
     `ValueError` in this codebase before #2, so this was invisible until
     now. Fixed with `jsonable_encoder`, the standard fix for this
     Pydantic v2 shape, protecting every future validator, not just #2's.

  None of these are protocol/format changes (§1–§4 of this spec are
  unaffected) — implementation robustness fixes, logged here because
  fuzzing found them during this phase, not because the wire format
  moved. Full detail: `PRAMPTA_STRATEGIC_TRUST_PLAN.md` §17.
