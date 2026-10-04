# PG Code — Identifier Format Specification

**Part of:** PRE-GEN v5 ([`VERSIONS.md`](VERSIONS.md)) · **Status:** frozen as of 2026-08-20, issuer prefix added 2026-09-28 · **Vectors:** `spec/test-vectors/vectors.json` (`pg_code` section, vectors v2)  
**License:** Apache License 2.0 — see [`spec/LICENSE`](LICENSE); licensed separately from the PRAMPTA service (the repo root `/LICENSE` is proprietary and covers the service itself — see `spec/README.md`'s note on this).

This document specifies the PRE-GEN identifier format completely enough to
implement from scratch, without reading any PRAMPTA source code. The text is
normative; the `pg_code` vectors are its conformance test, and a
disagreement between them is an erratum, handled as `PRE-GEN-SPEC.md` §0.3
states. *Reference implementation:* `backend/app/core/pg_code.py`.

---

## 1. Why this is frozen

A PG code is assigned once and cited forever — in a licence, a dispute, an
email, a court filing. Once real subjects hold real codes, changing how the
check character is computed would invalidate every code already issued, with
no way to tell an old-but-valid code from a corrupted one.

The check character had property tests before this document existed
("catches every single-character substitution", "catches every adjacent
transposition"). Those are necessary but **not sufficient**: a different,
equally-correct scheme passes all of them while producing different
characters. That is why the exact outputs are pinned as byte-level vectors,
not just described.

---

## 2. Two shapes, and only two

| Shape | Example | Meaning |
|---|---|---|
| `PG-<serial><check>` | `PG-000042*` | A **subject's** permanent registry number |
| `PG-<CLASS>-<serial>-<tail><check>` | `PG-STD-000001-K7M2QX9` | A **licence** identifier |

A subject code carries **no class letters** — a subject has no licence class
of its own; its licences do. This makes the two shapes unambiguous by
construction: a bare `PG-` followed by digits is always a subject, and a
`PG-` followed by letters is always a licence.

### 2.1 Historical subject shapes (permanently valid)

`pg_code` is assigned once and never rewritten, so every shape a subject
could have been given must keep resolving forever:

| Shape | Era |
|---|---|
| `PG-000042*` | current (2026-08-19 onward) |
| `PG-STD-000123` | 2026-08 – 2026-08-19 (shared the STD licence counter) |
| `PG-SUB-000123` | pre-2026-08 (dedicated SUB counter, retired) |

The two legacy shapes have **no check character** — they are all-digits
after the prefix. An implementation must recognise them for resolution, and
must not attempt to validate a check character on them.

---

## 3. Alphabet

```
0123456789ABCDEFGHJKMNPQRSTVWXYZ
```

32 symbols: Crockford base32 — the digits, plus the Latin uppercase letters
**excluding `I`, `L`, `O`, `U`**. The first three are excluded because a
human misreads them off a screenshot (`I`/`1`, `L`/`1`, `O`/`0`); `U` is
excluded by Crockford's convention.

A character's **value** is its zero-based index in that string: `0` → 0,
`9` → 9, `A` → 10, … `Z` → 31.

### 3.1 Check symbols

```
*~$=!
```

Five additional symbols, valid **only in the check position**, never inside
a body. They exist because the modulus is 37 (see §4) while the alphabet
holds only 32 symbols — the five overflow values need somewhere to go. This
mirrors Crockford's own optional check-symbol convention.

All five are URL-path-safe unencoded (RFC 3986 unreserved or sub-delims).

The full check alphabet, indexed 0–36, is therefore:

```
0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=!
```

**The canonical form is ASCII-only.** A human retyping or pasting a code
may end up with a visually-identical character from a different Unicode
block — a Cyrillic letter that looks like a Latin one, a fullwidth digit
from a mobile keyboard. Those are input-method artifacts to fold back to
their ASCII equivalent before validation, never a second valid alphabet
(§13 covers the resolver's own folding step; it is explicitly
non-exhaustive, not a claim of covering every Unicode confusable).

---

## 4. Check character

### 4.1 Algorithm

Given a **body** (a string of alphabet characters, no dashes, no check
character):

```
sum = Σ  value(bodyᵢ) × (i + 1)        for i = 0 … len(body)−1
check = CHECK_ALPHABET[ sum mod 37 ]
```

Positions are **1-based weights** applied left to right: the first character
is multiplied by 1, the second by 2, and so on.

Worked example — body `000042`:

| i | char | value | weight (i+1) | product |
|---|---|---|---|---|
| 0 | `0` | 0 | 1 | 0 |
| 1 | `0` | 0 | 2 | 0 |
| 2 | `0` | 0 | 3 | 0 |
| 3 | `0` | 0 | 4 | 0 |
| 4 | `4` | 4 | 5 | 20 |
| 5 | `2` | 2 | 6 | 12 |

`sum = 32`, `32 mod 37 = 32`, `CHECK_ALPHABET[32] = '*'` → code `PG-000042*`.

### 4.2 Why 37 and not 32

32 is composite (2⁵). A weighted sum modulo a composite has zero divisors:
brute-forcing a naive mod-32 variant against every single-character
substitution in a 13-symbol body found roughly **4% of substitutions it
could not catch** — not bad luck, but pairs of bodies that collide by
construction.

37 is the next prime at or above the alphabet size. The difference any
single substitution makes to the sum is `weight × delta mod 37`; since 37 is
prime and `delta < 32 < 37`, that difference can only be 0 mod 37 if the
weight itself is 0 mod 37. Weights 1 to 36 never are; weight 37 is. The
same argument gives adjacent-transposition detection.

**Maximum body length: 36 characters.** A body longer than 36 characters is
invalid, and a verifier must reject it. At position 37 the weight is 0 mod 37,
so a typo there would not change the check character (found by an external
review, 2026-10-03). Every code issued so far is far shorter; the longest
body today, a licence id, is 19 characters.

**Guarantees** (verified by exhaustive brute force, not asserted), for bodies
of at most 36 characters:
- every single-character substitution changes the check character;
- every adjacent transposition of two *different* characters changes it.

Transposing two *identical* characters does not change the check character —
correctly, since it does not change the code either.

### 4.3 What the check character covers

**Everything meaningful in the code**, concatenated with dashes removed:

| Code | Body fed to the algorithm |
|---|---|
| `PG-000042*` | `000042` |
| `PG-STD-000001-K7M2QX9` | `STD000001K7M2QX` |

For a licence, the class letters are part of the body: a wrong class is
exactly as much "a wrong code" as a wrong serial, so it must trip the same
check. The literal `PG-` prefix is **not** part of the body — it is a fixed
marker, identical in every code, and contributes nothing.

---

## 5. Subject codes

```
PG-<serial padded to at least 6 digits><check>
```

The serial is a positive integer from a registry-wide counter, formatted
with **zero-padding to a minimum of 6 digits**. Six is a minimum, not a
maximum: serial 1 234 567 renders as `1234567` (7 digits), and the format
stays valid. Implementations **must not** assume a fixed length.
The only upper bound is the 36-character body limit of §4.2.

| Serial | Code |
|---|---|
| 1 | `PG-0000016` |
| 42 | `PG-000042*` |
| 99999 | `PG-099999*` |
| 999999 | `PG-9999994` |
| 1000000 | `PG-10000001` |
| 12345678 | `PG-12345678K` |

---

## 6. Licence identifiers

```
PG-<CLASS>-<subject serial padded to at least 6 digits>-<tail><check>
```

- **CLASS** — a three-letter licence class. Currently `STD`, `RND`, `PRM`.
- **subject serial** — the serial of the subject this licence is *for*, so a
  licence id names its subject without a lookup being required to know
  *which* subject it belongs to (the lookup is still required for anything
  else — see §8).
- **tail** — 6 random alphabet characters, drawn from a cryptographically
  secure source. Random rather than sequential specifically so the *number
  of licences on one subject* cannot be inferred from an id.

| Class | Serial | Tail | Licence id |
|---|---|---|---|
| `STD` | 1 | `K7M2QX` | `PG-STD-000001-K7M2QX9` |
| `RND` | 42 | `ZZZZZZ` | `PG-RND-000042-ZZZZZZ1` |
| `PRM` | 999999 | `000000` | `PG-PRM-999999-0000000` |

### 6.1 Retired classes are retired forever

A class code that has ever appeared in an issued licence id is **never**
re-admitted and **never** given a different meaning, no matter how long it
has been unused. Currently retired: `EDT`, `EST`, `ENT`, `PER`, `OWN`.

A human reading an id infers meaning from the class letters. A code whose
meaning depends on *when* it was issued defeats the point of a permanent
citation.

---

## 7. Resolution rules

- **Case-insensitive.** `pg-000042*` and `PG-000042*` are the same code;
  canonical form is uppercase. People retype these from screenshots.
- **Surrounding whitespace is stripped** before matching.
- A code whose check character does not verify must be reported as
  *mistyped*, distinctly from *not found* — the two mean different things to
  whoever is holding the code.

---

## 8. The load-bearing rule: resolved, never parsed

**An identifier is resolved by database lookup. It is never parsed to
extract meaning.**

The serial embedded in a licence id is there so a human can see which
subject it belongs to, and so support can eyeball a mismatch — not so
software can `split('-')` and skip the lookup. Anything derived by parsing
becomes wrong the moment the format widens (a 7-digit serial, a future
issuer prefix), and it will be wrong *silently*.

The reference implementation enforces this on itself with a repository-wide
guard test (`backend/tests/test_pg_code_format.py`), which fails the build
if any code path starts slicing an id.

---

## 9. Issuers: more than one registry

PRE-GEN is an open standard, and any company may run a registry. So that two
registries can never issue the same code, every registry other than the
origin one puts its **issuer prefix** in every code it issues.

| Shape | Example | Meaning |
|---|---|---|
| `PG-<ISSUER>-<serial><check>` | `PG-NWRD-000042=` | A subject in registry `NWRD` |
| `PG-<ISSUER>-<CLASS>-<serial>-<tail><check>` | `PG-NWRD-RND-000042-ZZZZZZJ` | A licence issued by registry `NWRD` |

Rules:

1. **Exactly four letters** from the PG alphabet — `ABCDEFGHJKMNPQRSTVWXYZ`
   (no digits; no `I`, `L`, `O`, `U`). Four, never three, so an issuer can
   never be mistaken for a licence class (`STD`, `RND`, `PRM`) or for the
   legacy `PG-STD-` / `PG-SUB-` subject shapes. 22⁴ = 234 256 possible
   prefixes.
2. **The prefix is part of the checked body.** The check character is
   computed over `ISSUER + serial` for a subject and
   `ISSUER + CLASS + serial + tail` for a licence, so a mistyped prefix is
   reported as mistyped (§7), like any other typo.
3. **Bare codes mean the origin registry, forever.** `PG-000042*` and every
   code issued before this section existed keep their meaning. The origin
   registry (PRAMPTA, the first registry) never uses a prefix.
4. **Prefixes are assigned publicly.** A registry asks for one through the
   public registry list at `https://www.pregen.org/registries`; the signed
   registry directory (§9.1) is the only record of who holds which prefix
   and which keys may sign in it. A prefix is never reassigned, even if its
   registry closes, because codes are cited forever.
5. **The issuer is the one thing software may read from a code** — to know
   which registry to ask. Everything else is still resolved, never parsed
   (§8): the issuer names the registry, the registry answers for the code.

A registry that receives a code with a prefix it does not hold must not
report it as "not found" or "invalid": it answers that the code belongs to
another registry and points to the registry list.

Longer serials remain free as well: the pad width is a minimum, and nothing
breaks at a million subjects. The body, prefix included, still stays within
36 characters (§4.2).

### 9.1 The registry directory: who may issue which codes

A PG code is a string; nothing stops anyone from printing one. What the
standard controls is which codes conforming software **accepts**:
**one namespace, one registry, one set of keys.** The bare namespace (codes
with no prefix, including the legacy `PG-STD-` and `PG-SUB-` shapes) belongs
to the origin registry; each prefix belongs to exactly one other registry.
A code is valid only when a key of the registry that owns its namespace
signed it. The rule is the same for every registry: it keeps other
registries out of the bare namespace exactly as it keeps the origin registry
out of every prefix.

**The directory** is `https://www.pregen.org/registries.json`, a JSON object
signed by the **steward key**:

| Member | Rule |
|---|---|
| `schema` | `"pregen.registries.v2"` |
| `sequence` | integer ≥ 1, increased by every signing |
| `issued_at` | RFC 3339 UTC time of signing (informative) |
| `registries` | array; each entry has `name`, `prefix` (`""` for the origin registry, otherwise four letters of the PG alphabet), `api`, `keys` (the registry's key set URL, `PRE-GEN-SPEC.md` §2.3) and `key_fingerprints` (every operator key the registry has ever signed with, current and retired, plus keys announced for future use, `PRE-GEN-SPEC.md` §2.1) |
| `steward_key_id` | fingerprint of the steward key |
| `signature` | Ed25519 by the steward key over the canonical JSON (`PRE-GEN-SPEC.md` §2) of the object without `signature`, hex |

Other members (`website`, `status`, `providers`, …) are informative and
signed like everything else.

Each registry's `api` and `keys` MUST be HTTPS URLs without credentials,
query or fragment. A directory containing an endpoint that violates this
rule MUST NOT be accepted.

A verifier accepts the directory only if (`PRE-GEN-SPEC.md` V-12):

1. the signature verifies with the **published** steward public key below —
   never with a key taken from the directory itself or from the connection
   that served it;
2. exactly one entry has `prefix: ""`, no prefix appears twice, and every
   entry lists at least one key fingerprint;
3. its `sequence` is not lower than the highest one the verifier has already
   accepted, so an old copy cannot be replayed to undo a listing.

A listing, once made, is never removed or given to another registry; a
registry that changes keys gets a new signing that adds the new fingerprint
and keeps the old ones. A registry SHOULD announce its next operator key
before it signs anything with it: the key is generated and kept offline, and
its fingerprint is added to the directory (and to any verifier that pins the
registry's keys) in advance, so that the day it rotates no verifier has to
change. A listed key that has not signed yet is not an error.

A verifier that keeps the last directory it accepted SHOULD also refuse a
newer one that removes a listed namespace or fingerprint, and one that
differs from it at the same `sequence` (two directories signed with one
number mean the steward key signed twice). A verifier MAY additionally pin
the origin registry's fingerprints and accept a bare code only from a key in
both the directory and its pin, so that a stolen steward key cannot add a
key to the bare namespace; a new origin key then needs a new release of that
verifier. The PRE-GEN verification libraries (`@pregen/verify`, `pregen`)
do both from version 0.2.

**The steward key.** Held offline by the editor of the standard, Valerii
Egorov — not by any registry, including the origin one — and used only to
sign the directory.

- public key: `5cb949aab04186e3e216ec541b847c912fc3f78138c0ec3cb2560b2dad0d1f1b`
- fingerprint: `pg-ed25519:dcdd244659e6d0e2426f2b504cb11590`
- created: 2026-10-03; first directory signed with `sequence` 1

The same values are published in the paper, in the standard's repository
README and as a DNS TXT record at `_pregen-steward.pregen.org`, so that no
single channel can substitute them. The TXT record reads

    pg-steward=1 fp=pg-ed25519:dcdd244659e6d0e2426f2b504cb11590 pk=5cb949aab04186e3e216ec541b847c912fc3f78138c0ec3cb2560b2dad0d1f1b

and a verifier that checks it compares both values with the ones it pinned.
**The successor key.** The steward also keeps a successor key, created in
advance, stored apart from the steward key and never used until it is needed:

- public key: `658544163d6abd5fef046407980d249817875d87d8cf4b67879a2e265fa5612f`
- fingerprint: `pg-ed25519:3e5e20729ce8485eea274c4cb33721d6`

A directory signed by the successor key replaces every directory signed by
the steward key, whatever their `sequence`, and a verifier that has accepted
one refuses directories signed by the old key from then on. A thief holding
only the old key cannot win by raising the sequence. Within the successor's
own line the rules above apply as before. A planned change of steward uses the
same path, and a new successor is published at once. The bare namespace cannot be
reassigned by any steward: rule 3 above is part of the standard.

*Reference implementation:* `spec/tools/pregen_directory.py`; the steward's
signing tool is `spec/tools/steward.py`. The vectors' `namespace` section
fixes the directory checks and the issuer check in both directions.

---

## 10. Conformance

An implementation conforms if it reproduces every case in the `pg_code`
section of `spec/test-vectors/vectors.json`:

- `check_char` — all **37** possible outputs, including all five overflow
  symbols;
- `subject_code` — serials spanning the 6-digit boundary in both directions;
- `license_id` — every current class, plus a serial past the pad width;
- `rejects` — corrupted codes that **must** fail verification.

Regenerate vectors only after an intentional, deliberate format change:

```bash
backend/.venv/bin/python spec/generate_vectors.py
```

The generator imports the reference implementation directly and is fully
deterministic — regenerating without a format change produces a
byte-identical file. **A noisy diff here means the format moved.**

---

## 11. Reserved range

**Status:** added 2026-08-24 (Phase 5 of the standardization effort),
founder-confirmed as a numeric block, RFC 5737/`example.com`-style.

Documentation, worked examples, and test fixtures need codes that can
never collide with a real subject or license — this document's own
worked examples (`PG-000042*`, `PG-STD-000001-K7M2QX9`, …) share the
current format's live serial space with real registrations, so if the
registry ever organically reaches serial 42, that citation stops being a
safe placeholder.

**`RESERVED_SUBJECT_SERIAL_FLOOR = 900,000,000`** — subject serials at or
above this floor are reserved for documentation, examples, and tests.
Because a license id always embeds its subject's own serial
(`format_license_id`, §6), reserving the subject range transitively
reserves every license-id example built on one too; no separate
license-class reservation is needed.

Enforced at the one real allocation choke point,
`backend/app/core/subject_code.py::allocate_subject_code` — refuses
outside `ENVIRONMENT=development`. This is a safety net against the
counter somehow reaching the floor, not a live control (at current
registration rates it will not happen for centuries); stated as such
rather than oversold.

---

## 12. Public resolver and `.well-known/pg-policy`

**`GET /v1/pg/{code}`** — public, unauthenticated, rate-limited existence
+ coarse-status lookup, no account required. Mirrors the one existing
narrow-payload precedent in this codebase, `GET /v1/subjects/{id}/epoch`.
Response is exactly `{"kind": "subject"|"license", "found": true,
"status": <the real status column value>}` — nothing else, no PII.

Distinguishes the three outcomes this document's own §7 already names but
that no running code implemented before this:

- **`400 invalid_format`** — doesn't look like either shape at all.
- **`400 mistyped`** — looks like a shape, but the check character is
  wrong (§4). A legacy `PG-STD-`/`PG-SUB-` code has no check character to
  get wrong, so it skips straight to the next outcome.
- **`404 not_found`** — shape and checksum are valid, but no such code has
  ever been issued.
- **`200`** — found (see response shape above).

**`GET /.well-known/pg-policy`** (RFC 8615) — a static JSON manifest at
the server root (not under the versioned API prefix, per RFC 8615):
issuer, current format version, the resolver's URL template, the reserved
serial floor (§11), and a link back to this document.

## 13. QR encoding and homoglyph protection

**Canonical QR payload: the full resolver URL**
(`https://api2.prampta.com/v1/pg/{code}`), not the bare code. A URL is
directly actionable by any generic QR scanner — it opens a page and shows
the code's status in one action. A bare code requires the scanner to
already be PRAMPTA-aware to do anything useful with the text at all.

**Manual-entry grouping is display-only**, never part of the canonical
wire form — the dash in a subject/license code already means something
specific (§2), so a second grouping character can't reuse it. When
showing a code for a human to retype, group the body in space-separated
triplets, e.g. `PG 000 042 *`; strip the spaces before validation.

**Homoglyph folding**: `backend/app/core/pg_code_confusables.py` folds a
small, explicitly non-exhaustive table of realistic input-method
confusables (Cyrillic look-alikes for the Latin letters that appear in
the Crockford alphabet; fullwidth ASCII letters/digits from mobile/IME
keyboards) to their ASCII equivalent, applied only at the resolver's
input boundary (§12) — never at minting time, since minted codes are
always server-generated ASCII already.
