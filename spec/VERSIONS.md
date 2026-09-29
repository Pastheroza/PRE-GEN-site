# PRE-GEN versions

PRE-GEN has one version number, and it is the same everywhere: in this
repository, on https://www.pregen.org and on Zenodo. **Each version is one
Zenodo release** under the concept DOI
[10.5281/zenodo.20129901](https://doi.org/10.5281/zenodo.20129901), which
always resolves to the latest one. (Founder, 2026-09-28: "синхронизировать
версии из zenodo и PRE-GEN который в вебсайте".)

| Version | Date | Title | DOI | Status |
|---|---|---|---|---|
| v1 | 2026-05-12 | Prompt Protocol Version 1 | [10.5281/zenodo.20129902](https://doi.org/10.5281/zenodo.20129902) | historical |
| v2 | 2026-05-12 | Prompt Protocol | [10.5281/zenodo.20132247](https://doi.org/10.5281/zenodo.20132247) | historical |
| v3 | 2026-05-20 | Prompt Protocol | [10.5281/zenodo.20319842](https://doi.org/10.5281/zenodo.20319842) | historical |
| v4 | 2026-06-01 | PRE-GEN — Technical Specification | [10.5281/zenodo.20500208](https://doi.org/10.5281/zenodo.20500208) | historical |
| **v5** | 2026-09-28 | PRE-GEN — Technical Specification | assigned when published on Zenodo | **draft** — current once published |

The "Technical Specification v1.1" addendum (August 2026) was never published
as its own Zenodo version; everything it added is part of v5.

## Rules

1. **A version is a published snapshot.** The number changes only when a new
   Zenodo version is published. Between releases, this text is the draft of the
   next version and says so in the header of `PRE-GEN-SPEC.md`.
2. **Nothing issued ever changes meaning.** A PG code, a signed object or a
   vector valid under one version stays valid under every later one. A later
   version may stop *issuing* something (as v5 stopped issuing STD licences),
   never stop *recognizing* it.
3. **Object markers are separate.** `pg.decision.v1`, `pg.license.v2`,
   `pg.receipt.v3` and the other markers version one signed object each and
   move on their own rules (`PRE-GEN-SPEC.md` §5). A new PRE-GEN version does
   not bump them, and bumping one does not by itself make a new PRE-GEN version.
4. **Each version lists what changed** against the previous one, here and in
   `CHANGELOG.md`, so an implementer of the old one knows what to update.

## v5 against v4

What an implementation of v4 must change:

- **Identifiers.** Subject codes are `PG-<serial><check>` (`PG-000042*`);
  licence ids are `PG-<CLASS>-<subject serial>-<tail><check>`. The mod-37 check
  character catches every single-character typo and adjacent transposition.
  v4's `PG-CLASS-SEQUENCE` form is gone.
- **Licence classes.** `STD` (personal), `RND` (research, education,
  editorial) and `PRM` (commercial). `EDT`, `EST`, `ENT`, `PER` and `OWN` are
  retired forever: existing ids keep resolving, none is issued again.
- **STD is a usage record, not a licence.** Personal use with no licence that
  passes every fixed protection gets `not_blocked`: nothing prohibits it and
  nothing is granted. No new STD licences are issued.
- **Decisions have a disposition**: `allow`, `not_blocked`, `review` or `deny`,
  with `policy_version`, cache scope, revocation epoch and a remediation link.
  `allowed` stays, true only on `allow`.
- **Providers authenticate with their own credential**; end users connect once,
  and a licence can be bound to that user. v4's pair token alone is not enough.
- **Receipts** (`pg.receipt.v2`, opt-in `v3` signing the event type) report
  what was generated after an allow.
- **Observations** (`pg.observation.v1`) report uses that need no licence,
  with an output's lifecycle (`created`, `modified`, `published`, `removed`).
- **Refusal codes** are one versioned registry with hard/soft classification
  (`REFUSAL-CODES.md`).
- **Several registries.** Every registry except the origin one prefixes its
  codes with four letters (`PG-NWRD-000042=`). Registries are listed on
  pregen.org.
- **Published test vectors and a conformance runner** define compatibility.
