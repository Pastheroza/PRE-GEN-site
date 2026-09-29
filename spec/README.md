# PRE-GEN specification

PRE-GEN is an open standard for asking permission before an AI system
generates a real person, brand, voice or work, and for proving the answer
afterwards. Current version: **v5** (28 September 2026, `VERSIONS.md`).
Copyright 2026 Valerii Egorov, licensed under the Apache License
2.0 (`LICENSE`, `NOTICE`). Anyone may implement it, run a registry or build on
it without asking permission.

| File | What it is |
|---|---|
| `PRE-GEN-SPEC.md` | The protocol: signed objects, canonicalization, grammar, versioning |
| `PG-CODE.md` | Identifier format, check character, issuer prefixes (§9) |
| `REFUSAL-CODES.md` | Every `PG_*` reason code, hard or soft |
| `VERSIONS.md` | Every version, numbered as on Zenodo, and what changed |
| `PRE-GEN-v5.pdf` | Version 5 as a paper (source: `paper/`) |
| `CHANGELOG.md` | Protocol changes |
| `test-vectors/vectors.json` | Byte-level vectors every implementation must reproduce |
| `conformance/` | The level-1 runner that replays the vectors against an implementation |

**Normative:** the text of these documents and the test vectors. Where prose
and vectors disagree, the vectors win. References to paths such as
`backend/app/...`, `pg_registry.py` or `sdk/...` name files in the origin
registry's implementation (PRAMPTA) and are **non-normative** examples.

## Checking an implementation

Write an adapter that answers the JSON requests described in
`conformance/README.md`, then:

```sh
python3 spec/conformance/level1/run_conformance.py --adapter "<command that runs your adapter>"
```

Operations an adapter doesn't implement answer `{"unsupported": true}` and are
reported as skipped.

## Running a registry

Ask for a four-letter issuer prefix (`PG-CODE.md` §9) by opening an issue in
this repository. Listed registries: https://www.pregen.org/registries
(machine-readable: `/registries.json`).

## Changing the standard

Open an issue or a pull request in this repository. Changes are additive
wherever possible; an issued PG code, a signed object or its vectors never
change meaning.
