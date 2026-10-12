# PRE-GEN specification

PRE-GEN is an open standard for asking permission before an AI system
generates a real person, brand, voice or work, and for proving the answer
afterwards. Current version: **v5** (12 October 2026, `VERSIONS.md`).

**Start here: [`PRE-GEN-CORE.md`](PRE-GEN-CORE.md)** — the whole core on one page.
Copyright 2026 Valerii Egorov, licensed under the Apache License
2.0 (`LICENSE`, `NOTICE`). Anyone may implement it, run a registry or build on
it without asking permission.

| File | What it is |
|---|---|
| `PRE-GEN-CORE.md` | **The core**: codes, directory, ask, signed answer, generate only on allow — one page |
| `extensions/` | Optional extensions, one page each: reports, provider-keys, limits, jobs, grants, licensee, observe, sandbox, lookup, identity, proof, catalog |
| `profiles/likeness-1.md` | The first profile: a person's likeness and voice |
| `schemas/`, `test-vectors/messages.json` | JSON Schemas and byte vectors for the v5 messages |
| `PRE-GEN-SPEC.md` | Foundations the core builds on (canonical bytes, keys, refusal codes) and the earlier interface (`/v1/verify`, receipts), still valid |
| `PRE-GEN-EXTENSIONS.md` | What a registry adds; the first registry's (PRAMPTA) extensions |
| `PG-CODE.md` | Identifier format, check character, issuer prefixes (§9) |
| `REFUSAL-CODES.md` | The first registry's reason codes, core codes marked |
| `VERSIONS.md` | Every version, numbered as on Zenodo, and what changed |
| `PRE-GEN-v5.pdf` | Version 5 as a paper (source: `paper/`) |
| `CHANGELOG.md` | Protocol changes |
| `test-vectors/vectors.json` | Byte-level vectors every implementation must reproduce |
| `conformance/` | The level-1 runner that replays the vectors against an implementation |

**Normative:** the text of `PRE-GEN-CORE.md`, `PRE-GEN-SPEC.md` and
`PG-CODE.md`, the extensions a party declares, the profile it answers under,
and the test vectors; `PRE-GEN-EXTENSIONS.md` and `REFUSAL-CODES.md` for an
implementation that claims an extension. The text defines the requirements
(written in BCP 14 language, `PRE-GEN-SPEC.md` §0); the vectors are its
conformance test, and a disagreement between them is an erratum, never a
rule (§0.3). References to paths such as `backend/app/...` name files in
the first registry's implementation (PRAMPTA) and are **informative**.

What "conforms to PRE-GEN v5" means — the Verifier, Provider and Registry
profiles, and which requirements the checks do not cover — is
`PRE-GEN-SPEC.md` §8.

## Checking an implementation

Write an adapter that answers the JSON requests described in
`conformance/README.md`, then:

```sh
python3 spec/conformance/level1/run_conformance.py --adapter "<command that runs your adapter>"
```

Operations an adapter doesn't implement answer `{"unsupported": true}` and are
reported as skipped. Passing is necessary for a conformance claim, not
sufficient (`PRE-GEN-SPEC.md` §8.2).

## Running a registry

Ask for a four-letter issuer prefix (`PG-CODE.md` §9) by opening an issue in
this repository. The open reference registry (`packages/registry`, Apache-2.0)
runs a complete registry with `init` and `serve`. Listed registries: https://www.pregen.org/registries
(machine-readable: `/registries.json`).

## Changing the standard

Open an issue or a pull request in this repository. Changes are additive
wherever possible; an issued PG code, a signed object or its vectors never
change meaning.
