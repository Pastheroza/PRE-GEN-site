# ToG code (formerly PG code) — identifier format

**Part of:** PRE-GEN, collected for the next version; libraries 0.14.0 ([`CHANGELOG.md`](CHANGELOG.md)) ·
**Status:** draft, unreleased · **Vectors:** [`test-vectors/tog-code.json`](test-vectors/tog-code.json) ·
**Reference model:** [`tools/tog_code.py`](tools/tog_code.py)  
**License:** Apache License 2.0 — see [`LICENSE`](LICENSE).

This document specifies every code written from the switch on: persons, licences, and the codes of acts (an
output generated under a yes, a file approved after it was made). It is complete enough to implement from
scratch. The text is normative; the vectors are its conformance test, and a disagreement between them is an
erratum (`PRE-GEN-SPEC.md` §0.3).

[`PG-CODE.md`](PG-CODE.md) stays frozen. Its check algorithm, its alphabet, its grammar, its v2 directory and
its reserved floor do not change. Its grammar is now read only to understand old input (§7.3). Where any other
document says "PG code", read "ToG code", written in its TOG spelling.

---

## 1. One family, one spelling

1. **"ToG code" is the family's name. `TOG-` is the only written marker.** Every protocol message, record,
   directory, lookup answer, proof, card and screen writes `TOG-`. No registry writes a `PG-` code again.
2. **Every code has one spelling, its TOG spelling.** A `PG-` string is legacy input only: an old signed
   record, a printed card, a QR, a typed string. It folds to its one TOG spelling (`code_key`, §7.3) and is
   never written.
3. **Nothing issued changes meaning.** Every old string still resolves to the same person or licence. Only the
   written spelling changed. A person keeps its number and its check character.
4. **A code is a handle, never proof.** The proof is a signed record that fits the file. A code that does not
   equal the code computed from its record is refused (§6).
5. **The person is never in an act code. The provider is never in any code.** New person numbers are random.

---

## 2. Kinds and shapes

| Thing | Code | Example |
|---|---|---|
| Person (subject) | no kind | `TOG-PRAM-900000037K` |
| Licence | `LIC` | `TOG-LIC-NWRD-PRAM-ZZZZ-84RN-RT04` |
| Generated under a yes before generation | `PG`, or `PG-LIC` under a licence | `TOG-PG-PRAM-ZZZZ-K6X4-RZJB`, `TOG-PG-LIC-NWRD-PRAM-ZZZZ-VGDY-WCWV` |
| Approved after it was made (AFTER-GEN) | `AG`, or `AG-LIC` under a licence | `TOG-AG-PRAM-ZZZZ-T8JE-WDJX`, `TOG-AG-LIC-NWRD-PRAM-ZZZZ-ZJGH-HQH3` |

**The five event kinds.** Five meanings, one spelling each. The kind digit goes into the check (§4.3). The
word is what `lookup` answers (`extensions/lookup.md`).

| Kind | Means | Kind digit | Word | Basis |
|---|---|---|---|---|
| `PG` | generated under the person's standing terms | 1 | `generated` | terms |
| `PG-LIC` | generated under a licence | 2 | `generated` | licence |
| `AG` | approved after generation, under the person's terms | 3 | `approved_after` | terms |
| `AG-LIC` | approved after generation, under a licence | 4 | `approved_after` | licence |
| `LIC` | the licence itself | 5 | `license` | none |

**Shapes.** Exactly one shape matches any valid code. The names are the ones the vectors use.

| Shape | Form | Written? |
|---|---|---|
| `person` | `TOG-<PREFIX>-<9 digits><check>` | yes, every new person |
| `event` | `TOG-<KIND>-<ISSUER>[-<HOME>]-XXXX-XXXX-XXXX` | yes, every licence and act |
| `old_person` | `TOG-<4 PG letters>-<6 or 7 digits><old check>` | a PG-born person, respelled; closed |
| `old_bare_person` | `TOG-<6 or more digits><old check>` | a bare PG-born person, respelled; closed |
| `old_no_check` | `TOG-STD-<digits>`, `TOG-SUB-<digits>` | the two oldest shapes, respelled; closed |
| `pg_person`, `bare_person`, `no_check` | PG-CODE.md §2 | legacy input only; folds by its marker |
| `pg_licence`, `bare_licence` | PG-CODE.md §2, §6 | legacy input only; folds through its record |

**Closed** means no new code is ever minted in that shape. Its codes stay valid forever.

**Lengths.** A person code is 19 characters with a 4-letter prefix, at most 23. An event code with one
4-letter prefix is 26 (`PG`, `AG`), 27 (`LIC`) or 30 (`PG-LIC`, `AG-LIC`); with two, 5 more; at most 43.

---

## 3. Alphabet

- **Serials, tails, secrets and check characters** use the Crockford alphabet of PG-CODE §3:
  `0123456789ABCDEFGHJKMNPQRSTVWXYZ`.
- **Prefixes** use all 26 letters `A`–`Z`. Crockford decoding rules never apply to the marker, a kind or a
  prefix.
- **The TOG value table.** For a TOG body, a character's value is its index in
  `0123456789ABCDEFGHJKMNPQRSTVWXYZILOU`: Crockford keeps 0–31, and `I`, `L`, `O`, `U` take 32–35. This is a
  second table, used for TOG bodies only. The PG table of PG-CODE §3 is unchanged byte for byte, so a PG body
  holding `I`, `L`, `O` or `U` never verifies.
- **Check characters.** A new code ends in a Crockford letter or digit, never a symbol. The five symbols
  `*~$=!` of PG-CODE §3.1 stay valid only in the three respelled shapes.

---

## 4. Check character

### 4.1 Algorithm

Unchanged from PG-CODE §4.1: the sum of each body character's value times its 1-based position, mod 37,
indexed into `0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=!`. Values come from the TOG table (§3) for a TOG body and
from the PG table for a PG body. On every Crockford body the two give the same character.

### 4.2 Limits

A new body is at most 35 characters. At 36 the last body character swapped with the check always passes
(an erratum to PG-CODE §4.2, §17). The longest event body is 30, the longest person body 17.

### 4.3 What the check covers

The marker `TOG-` is outside the body, as `PG-` always was. Dashes are not in the body.

| Shape | Body | Example |
|---|---|---|
| person | prefix + serial | `PRAM900000037` → `TOG-PRAM-900000037K` |
| respelled person | prefix + serial (bare: serial) | `ZYXW1234567` → `TOG-ZYXW-1234567R`, the check of `PG-ZYXW-1234567R` |
| event, one prefix | length of issuer, `0`, kind digit, issuer, tail | `401PRAM` + `ZZZZK6X4RZJ` → `TOG-PG-PRAM-ZZZZ-K6X4-RZJB` |
| event, two prefixes | length of issuer, length of home, kind digit, issuer, home, tail | `442NWRDPRAM` + `ZZZZVGDYWCW` → `TOG-PG-LIC-NWRD-PRAM-ZZZZ-VGDY-WCWV` |

A PG body holds only Crockford symbols, where the two tables agree. So respelling a person never changes its
check.

What the check catches, over every example and edge code (checked by the reference model):

- every single substitution and adjacent transposition;
- every relabel between the five kinds (`PG` and `AG`, `-LIC` added or dropped, `LIC` for an act): it changes
  the kind digit and nothing else;
- every dash moved, dropped or added between issuer and home: it changes only the two length digits, by an
  amount that is never 0 mod 37;
- every insertion or deletion after the prefixes (the widths there are fixed).

**One case the check does not catch.** About 1 in 134 single insertions or deletions in the kind and prefix
part pass the check. Each one keeps the kind and the basis and changes one prefix by one letter. Prefix
admission refuses every such neighbour of a listed prefix (§9.1), so the directory catches it. A verifier with
no directory says "prefix not checked".

---

## 5. Person codes

```
TOG-<PREFIX>-<serial><check>
```

- **The serial is exactly 9 digits**, not starting with 0, drawn at random among the registry's unused
  serials below 900 000 000. A gap means nothing; there is no registration order to read. A dropped or doubled
  digit gives 8 or 10 digits: not a code.
- **The check is a letter or digit.** A registry skips any serial whose check would be a symbol (about 1 in 7).
- **A PG-born person is respelled by its marker only.** `PG-<P>-<serial><check>` is written
  `TOG-<P>-<serial><check>`; `PG-<serial><check>` is written `TOG-<serial><check>`; `PG-STD-…` and `PG-SUB-…`
  are written `TOG-STD-…` and `TOG-SUB-…`. Same serial, same length, same check. A prefixed PG person has 6 or
  7 digits; the bare namespace has 6 or more. These shapes are closed.
- One person never has two codes. A respelling is the same person.

---

## 6. Event codes: licences and acts

```
TOG-<KIND>-<ISSUER>[-<HOME>]-XXXX-XXXX-XXXX
```

- **Kind first.** `PG`, `AG` or `LIC` right after `TOG-`. No kind means a person.
- **The `LIC` marker** comes only after `PG` or `AG`, once. It records a fact fixed at issue: the act named a
  licence when it was signed. The licence's own number is in the record, never in the code.
- **The issuer** is the registry that signed the act. It is always the first prefix, and it is the registry
  to ask.
- **The home** is the person's home registry at the act. It is shown only when the home's countersignature
  says `home_in_code: true`, and never when it equals the issuer.
- **The tail** is the first 55 bits of a message id (`PRE-GEN-CORE.md`, Messages), as 11 Crockford symbols,
  most significant first, then the check: three groups of four. The grouping is the code itself, not a display
  form.

### 6.1 Computing a code from its record

A code is computed from its record and compared, never read. `code_for(act)`:

1. **Kind from the act type:** `pg.grant.v1` and `pg.license.v2` give `LIC`; `pg.answer.v1` (an `allow`) gives
   `PG`; `pg.after_gen.v1` (the AFTER-GEN record) gives `AG`.
2. **`-LIC` from the basis.** An allow or AFTER-GEN record that names a licence (an answer's `basis` of kind
   `grant`, a `pg.grant.v1` or an old `pg.license.v2`) gets `-LIC`. One made under the person's standing terms
   does not. A licence has no basis: a licence act that names one gives no code. When the licence is at hand it
   must be signed by the act's own signer; otherwise there is no code.
3. **Issuer:** the prefix of the act's signer.
4. **With a home countersignature** (the home model, a later extension: an object the home signs for the act,
   with its message id, `home` and `home_in_code`): the tail comes from the countersignature's message id, and
   the home slot from its `home` when `home_in_code` is true.
5. **With none (the flat model):** the signer must be the registry the person's code was born at (for a bare
   code, the first registry, `PRAM`). The tail comes from the act's own message id. Any other signer gives no
   code.
6. **A symbol check, or a tail starting `ZZZZ`, gives no code.** The issuer signs the act again with a changed
   body until it has one. An act signed before the switch is countersigned once by its home instead; the act
   itself is never signed again.

Until the home model is published, every act is in the flat model.

**Rules for issuers and homes.**

- **One allow, one `PG` code.** Ten files under one allow show one code with ten hashes.
- **The home refuses a tail it has already used**, under any kind, and keeps that set for life.
- **The issuer refuses a code it has already issued**, and asks the home to countersign again. At 55 bits the
  tails of two homes can meet under one issuer when the home is hidden; neither home sees the other's.
- **`home_in_code`** is true by default for a published person and false for an unpublished one. The person
  may set it false at any time. So a one-prefix code says "issued by X", never "X is the home".
- **When the home signs the act itself**, the home is the issuer and always shows. Hiding works only when a
  market issues.

Vectors: `code_for`.

### 6.2 Licences

A licence has exactly one code, its `TOG-LIC` code.

- **Every new licence is a `pg.grant.v1`** (`extensions/grants.md`). No registry issues a new `pg.license.v2`.
- **An old `pg.license.v2` is a licence act too.** Its message id is grants.md's "Older licences" id: SHA-256
  over body, subject signature and its PG id. With no countersignature it is the flat model: issuer = its
  signer, tail = that id. If that gives a symbol check or a `ZZZZ` tail (about 1 in 7), the home countersigns
  it once and the code comes from the countersignature. The licence itself is never signed again.
- **The PG licence id stays inside the old signed bytes.** It is read only as legacy input, through the
  registry's record (§7.3).

---

## 7. One code, one string

### 7.1 Grammar

ASCII, upper case, the whole string, nothing before or after it.

```
code    = tog / pg
tog     = "TOG-" prefix "-" serial check                     ; person: no kind
        / "TOG-" kind "-" issuer [ "-" home ] "-" tail       ; event
        / "TOG-" oldpfx "-" 6*7DIGIT oldchk                  ; a PG-born person, respelled (closed)
        / "TOG-" 6*DIGIT oldchk                              ; a bare PG-born person, respelled (closed)
        / "TOG-" ( "STD" / "SUB" ) "-" 6*DIGIT               ; the two oldest shapes, respelled (closed)
kind    = "PG" [ "-LIC" ] / "AG" [ "-LIC" ] / "LIC"
issuer  = prefix
home    = prefix
tail    = 4ALPHA "-" 4ALPHA "-" 3ALPHA check                 ; 11 fingerprint symbols, then the check
prefix  = 4*8 ( "A"-"Z" )        ; never begins or ends with LIC; never 4 letters that are LIC with one added
serial  = NZDIGIT 8DIGIT         ; exactly 9 digits
check   = ALPHA                  ; a new shape never ends in * ~ $ = !
oldpfx  = 4 letters of the PG prefix alphabet (PG-CODE §9)
oldchk  = ALPHA / "*" / "~" / "$" / "=" / "!"
pg      = PG-CODE §7, frozen; legacy input only
ALPHA   = a character of 0123456789ABCDEFGHJKMNPQRSTVWXYZ;  NZDIGIT = "1"-"9"
```

The same as regular expressions (the reference model's `SHAPES`; `C` = `0-9A-HJKMNP-TV-Z`):

| Shape | Regex |
|---|---|
| prefix `P` | `(?!LIC\|L[A-Z]IC(?![A-Z])\|LI[A-Z]C(?![A-Z]))[A-Z]{4,8}(?<!LIC)` |
| `person` | `TOG-(P)-([1-9][0-9]{8})([C])` |
| `event` | `TOG-(LIC\|(?:PG\|AG)(?:-LIC)?)-(P)(?:-(P))?-([C]{4}-[C]{4}-[C]{3})([C])` |
| `old_person` | `TOG-([A-HJKMNP-TV-Z]{4})-([0-9]{6,7})([C*~$=!])` |
| `old_bare_person` | `TOG-()([0-9]{6,})([C*~$=!])` |
| `old_no_check` | `TOG-(STD\|SUB)-([0-9]{6,})` |

- **Shapes are told apart by group lengths.** After `TOG-`: 2–3 letters are a kind or the marker, 4–8
  letters a prefix, 9 digits and a check a person's number. An event always ends in three groups of four.
- **`LIC-PG`, `LIC-AG`, `PG-AG`, a doubled kind and a doubled marker are malformed.** So are two equal
  prefixes and a third prefix (a provider has no slot).
- **New shapes exist only under `TOG-`.** `TOG-` dropped never leaves a code: `AG-…` and `LIC-…` have no
  marker, and a `PG-…` event has five or more groups. The only PG shape with five (a v5 licence) has three
  class letters third, where an event has four symbols. Old and new parsers refuse all of them, and typed
  input does not fold them.

### 7.2 In a message

- **Verifiers and registries never repair a code** (PG-CODE §7). No trimming, case change or look-alike
  folding. A string that does not match is not a code.
- **A registry answers a request whose `subject_ref` is not a code with `PG_MALFORMED`** (HTTP 422), never with
  a signed answer.
- **A PG person string in a message is legacy input, not a repair.** It has exactly one TOG spelling, and the
  registry answers for that code (§7.3).
- A code whose check does not verify is reported as *mistyped*, distinctly from *not found* and from *not a
  code* (*malformed*).

### 7.3 PG input and `code_key`

`code_key(code)` gives the one TOG spelling. **Every comparison, hash key, pointer-log key, anchor-list entry
and refusal check uses it**, so one person never has two chains and a refusal cannot be bypassed by spelling.

- **A TOG code** is its own key.
- **A PG person** (`pg_person`, `bare_person`, `no_check`) folds by its marker: `PG-` becomes `TOG-`, nothing
  else changes. Its check must verify with the PG table, and its TOG spelling must be a valid code.
- **A PG person string with no valid TOG spelling was never issued in any spelling: not a code.** That covers 8
  or more digits under a prefix, a 9-digit one with a symbol check or a leading zero, and a no-check class
  other than `STD` and `SUB`. (This replaces the "PG twin" rule of the design: `PG-PRAM-900000037K` is legacy
  input for `TOG-PRAM-900000037K`.)
- **An old PG licence id** folds through its registry's record: its key is `code_for` of the signed
  `pg.license.v2` whose `license_id` is that id (§6.2). With no record at hand the answer is "ask its
  registry".
- **`code_key` never returns a `PG-` string.**
- **Only prefixes in the frozen v2 directory ever issued PG codes.** A `PG-` code of any other prefix folds
  like any other and goes to that prefix's registry, which has no such person: not found. A client does not
  check the v2 directory for this; directory v3 does not say which prefixes are PG-era.

Vectors: `code_key`, `code_key_with_record`.

### 7.4 Where a person types

Only where a person types, pastes or scans a code (a search box, a form, a resolver URL) may software fold
it, and then show the result as "Did you mean …?". In order:

1. Unicode NFKC (full-width forms); Unicode dashes to `-`; drop invisible characters and a markdown
   backslash; fold Cyrillic and Greek look-alikes (a non-exhaustive table, as PG-CODE §13); trim spaces.
2. A pasted resolver URL: keep the last path segment, drop the fragment.
3. Drop trailing punctuation (`.,;:)]"'`); raise to upper case.
4. Split on dashes and remove spaces inside groups. The display form `PG 000 042 *` folds to `TOG-000042*`
   (a special case for PG-CODE §13's erratum).
5. **By slot:** `O`/`0` and `I`/`L`/`1`. Digits in serials and tails; letters in the marker, kinds and
   prefixes, each `1` and `0` per character (`T11U` reaches `TILU`). The marker typed `L1C`, `LlC` or `1IC`
   reads as `LIC`. In a TOG event the three tail groups get the digit reading only.
6. Keep the readings that are valid codes, then fold each by `code_key`. **Exactly one must remain.** Two
   readings that pass (`TOG-111A-…` is both `IILA` and `LLIA`) are refused with both as hints. None is refused.
7. **More than 4 096 readings are refused at once**, not searched.

A licence is never respelled by its marker: `tog-abcd-prm-1234567-a1b2c3a` is not a code. Typed input is never
folded inside a message. Vectors: `typed`.

---

## 8. Resolved, never parsed

Software may read from a code: its marker, its kind, the `LIC` marker, and its prefixes with their slot. **The
first prefix is always the registry to ask.** For the bare and no-check shapes it is the first registry's bare
namespace. Everything else is resolved, never parsed (PG-CODE §8). The tail is never decoded: it is recomputed
from a record and compared. `issuer_of` reads the shape only, like 0.13.

A string alone claims, it does not prove. Offline, from the string only, a verifier can tell: well-formed or
mistyped; the kind; under a licence or not, as claimed; which registry to ask; that it is an example. It
cannot tell that the act happened, or name any party as a fact.

---

## 9. Prefixes

- **4 to 8 letters `A`–`Z`**, written only under `TOG-`. `LIC` is never at the start or the end of a prefix,
  and no 4-letter prefix is `LIC` with one letter added. One inserted letter could otherwise turn the marker
  into a prefix and change the kind.
- **One prefix per legal entity.** Entities with common owners share a `group` id.
- **GOV both ways.** A government's prefix contains `GOV`; no other prefix does.
- **A prefix is never reassigned**, even when its registry closes or is revoked.
- **No new PG codes:** only prefixes of the frozen v2 directory ever issued them (§7.3).

### 9.1 Admission

The steward refuses a prefix that, after folding visual groups (`VV`→`W`, `RN`→`M`, `CL`→`D`, then the groups
C G O Q D, I J L, U V, M N, P R, E F):

1. is one edit (substitution, insertion, deletion, adjacent swap) from a listed prefix, before or after
   folding, or contains one, or is contained in one (`PRAMPTA`, `OMNIUM`; `NWRDPRAM` is what a dropped dash
   makes of `TOG-PG-NWRD-PRAM-…`). **No exemption for governments** (`KPGOV` next to `KRGOV`);
2. contains `GOV` for a non-government, lacks it for a government, or folds to contain `GOV`;
3. reads as a marker or a kind after folding: it starts with `T`, a letter of C G O Q D, then C, G or Q
   (`TOG`, `TQGAB`, `TOCAB`); with P or R, then C, G or Q (`PG`, `PCLIC`, `RGAB`); with A, then C, G or Q (`AG`,
   `ACLIC`); or with two of I, J, L, then C, G or Q (`LIC`, `LLCA`, `IICO`, `LJCA`). The last letter is C, G or
   Q only, so `TGOV` and `PORTO` stay admissible. Or it ends with two of I, J, L, then C, G or Q (`NLIC`,
   `NLJC`, `ACMELLC`); or it is 4 letters holding I/J/L, I/J/L, C/G/Q in order with at most one letter between
   each (`LGIC`, `LIZC`, `LJGA`); or it ends with `PG` or `TOG` (`TOG-SHOPG-900…` hides `PG-900…`);
4. contains a reserved word, after folding: protocol (`PREGEN`, `AFTERGEN`, `TOGCODE`, `STEWARD`), role
   (`HOME`, `MARKET`, `BRANCH`, `PROVIDER`, `WALLET`), verdict (`ALLOW`, `APPROV`, `AUTHORI`, `VERIF`, `VALID`,
   `LEGAL`, `LAWFUL`, `LICENS`, `OFFICIAL`, `CERTIF`, `GENUIN`, `NOTFAKE`, `TRUST`, `DENIED`, `DENY`, `REFUS`,
   `REVOK`, `BLOCK`, `BANNED`), authority (`POLICE`, `COURT`, `STATE`), sensitive (`ADULT`, `PORN`, `NSFW`,
   `XXX`, `EROTIC`, `NUDE`);
5. is a fixture prefix of this specification or its vectors (§11);
6. is a second prefix for one legal entity; or names another party's mark, an offensive word or a sensitive
   category in other words (human judgement).

Vectors: `admission`. Whether a prefix is refused is normative; the wording of the reason is not.

### 9.2 The directory v3

**Schema `pregen.registries.v3` at `https://www.pregen.org/registries.v3.json`.** The v2 file stays at
`https://www.pregen.org/registries.json` with the PG-era entries only, and the steward re-signs it with every
v3 signing. Clients 0.10–0.13 refuse any schema other than v2 and any prefix other than 4 Crockford letters for
the whole file, so v3 at the old URL would stop every deployed client.

v3 keeps every member and acceptance rule of v2 (PG-CODE §9.1) and adds:

| Member | Rule |
|---|---|
| `prefix` | 4–8 letters `A`–`Z` (§9), or `""` for the first registry's bare namespace |
| `entity` | the legal entity the steward verified. One prefix per legal entity |
| `group` | steward-assigned id of the beneficial owners; entities of one group share it. Compared by id, never by name |
| `roles` | `home`, `market`, `wallet`, `log_operator`, `witness`, each `{from, until}` (`until` null while held). A prefix states no role |
| `government` | true only for a government, proved by its own domain |
| `provider_domains` | provider domains of its group, each `{domain, from, until}`. An undeclared one is ground for revocation |
| `void_from` | set on revocation: the time from which its acts fail. It equals `revoked.at`, or an earlier time after a compromise |
| `closed` | the date a registry stopped; its acts stand; ask the home |
| top-level `resolver` | the steward's neutral resolver for card and recovery QRs (§13) |
| top-level `min_library` | the oldest library version that understands `TOG-` (`0.14.0`) |

**Reading the directory at a time.** A party check reads the directory at the act's time. That time is the
witnessed checkpoint in the home's countersignature bundle (home model), never the record's own `issued_at`.
With no such time a verifier checks the string only. Then a party that was revoked, closed or re-roled is a
fact ("listing ended on D"), never "not a code". With a time, a slot fails only when it names an unlisted party,
a party that did not hold the slot's role then, or a party whose listing was void then. The issuer slot needs
`market` when a home is shown, `home` or `market` when none is shown, and `market` for a one-prefix `LIC`; the
home slot needs `home`; a person code's prefix needs only to be listed. A prefix with `GOV` must be listed as a
government, and one without it must not. Until the home model is published, acts have no witnessed time, and a revoked
registry's bundles still fail (`PRE-GEN-SPEC.md` V-14, `extensions/proof.md`).

**Self-dealing is shown.** Two slots of one group: "issuer and home are one group". A provider domain in the
`provider_domains` of any slot, home included: "X also generated it".

Vectors: `parties` (facts are informative; `ok` is normative).

---

## 10. Conformance

An implementation conforms if it reproduces every case of [`test-vectors/tog-code.json`](test-vectors/tog-code.json):

| Section | What it fixes |
|---|---|
| `alphabet` | the tables, limits, kind digits, reserved floor and tail, fixture prefixes |
| `examples` | every example code of this document, by chain mix |
| `check_char` | bodies with their check under the TOG table and the PG table (null: outside the table, never verifies) |
| `parse` | the one reading of each string: shape, kind, basis, issuer, home, example flag, key |
| `describe` | what a string claims, for support tools (never beside a video, §15) |
| `must_reject` | strings that fail, each `malformed` or `mistyped` (§16) |
| `refused_by_0_13` | strings the 0.13 grammar must refuse: every TOG code, every TOG event code with `TOG-` dropped |
| `code_key`, `code_key_with_record` | the TOG spelling of every published string; old licences through their record |
| `typed` | typed input and its one code, or its refusal (with hints when two readings pass) |
| `code_for` | acts and their codes, or `no_code` |
| `metadata` | readable copies against their record (§14) |
| `lookup` | a registry's answer by number (`extensions/lookup.md`) |
| `parties` | dated party checks against a v3-shaped directory |
| `admission` | prefixes the steward admits or refuses |
| `find_codes` | codes found in free text (§13) |
| `verdict` | what a verifier may say before signatures (§15) |

The file is generated from the reference model, never edited by hand:

```bash
python3 -I spec/tools/tog_code.py        # the model's exhaustive self-check, about 6 s
python3 -I spec/tools/tog_vectors.py > spec/test-vectors/tog-code.json
```

The self-check also tries every substitution, transposition, insertion and deletion over every example and
edge code, every dash between issuer and home over the five kinds, and every relabel between kinds.

---

## 11. Reserved range

- **The floor 900 000 000 of PG-CODE §11 is unchanged** and applies to TOG serials too. For 9 digits it means
  a first digit 9.
- **An event tail starting `ZZZZ` is an example.** It is never issued.
- **Fixture prefixes are reserved forever:** `NWRD`, `HLWD`, `USAD`, `VELR`, `SKAN`, `KAST`, `TGOV`, `HYBR`,
  `OMNI`, `KINO`, `KOBEMK`, `LYONMK`, `RIOMKT`, `PUNEMK`, `OSLOMK`, `ZYXW`, `ABCD`, `TEST`.

---

## 12. Resolver

- **`GET {api}/v2/codes/{code}`** at the registry named by the first prefix (`extensions/lookup.md`).
- **`GET /v1/pg/{code}`** (PG-CODE §12) is frozen. It keeps resolving every printed PG string forever, and its
  answers name the TOG spelling.
- **`/.well-known/pg-policy`** keeps its template and adds the `/v2/codes` one.

---

## 13. Cards, QR codes, display and free text

- **A card's QR** points at the steward's neutral resolver (the directory's `resolver`):
  `{resolver}/v2/codes/{code}`. It is a static page that resolves through the signed directory. No registry host
  is printed on a new card.
- **The private person's secret** is 26 Crockford symbols and a letter-or-digit check (130 bits). It is never
  in a code and never on a shareable surface (card image, card QR, NFC tap, receipt, status page). It is only
  on the paper recovery sheet and in the wallet, labelled "Do not share. This is not your card". The recovery
  QR is `{resolver}/v2/codes/{code}#s={secret}`; the fragment never reaches a server.
- **Display grouping never removes a dash.** The tail's three groups of four are the code itself.
- **Wherever the protocol controls display, a word sits next to the code** ("AI-made with permission ·
  TOG-…"), with a copy button and a QR.
- **Free text** (captions, pages, transcripts): candidates match
  `(?<![A-Za-z0-9-])(?:TOG|PG)-[A-Z0-9]+(?:-[A-Z0-9]+)*[*~$=!]?(?![A-Za-z0-9])`. A candidate that does not
  parse is tried once more without a trailing symbol (it may be markup). A marker inside a word
  (`TOG-SHOPG-900…`) is not a code. A `PG-` string found is legacy input: fold it by `code_key` before comparing
  or showing it.

---

## 14. Readable copies in a file's metadata

Beside the signed record in a file, a file may carry two readable copies: the code of the act, and, when the
basis is a licence, the licence's `TOG-LIC` code.

- **Where:** in a PRE-GEN proof, the members `code` and `licence` of each subject's entry in the C2PA assertion
  `org.pregen.proof` (`extensions/proof.md`). In an AFTER-GEN file, the XMP names `pgag:Code` and
  `pgag:Licence` (namespace `pgag:`).
- **Copies, never authority.** A verifier recomputes both from the signed record (`code_for` on the act, and on
  the licence its basis names) and **refuses the file on any mismatch**. A licence copy without a licence basis
  is a mismatch. A licence copy that cannot be recomputed (the licence is not at hand) is a mismatch.
- **A missing copy is not an error:** the record is enough.
- A tool that reads a copy without the record has a string only (§8).

Vectors: `metadata`.

---

## 15. What a verifier shows

A verifier names a party only from a record that fits the file and whose chain verifies. Outcome words come
from the record type and the licence it names, never from the letters or the caption.

| Found | Shown |
|---|---|
| no code, no record | "No record. This says nothing either way." |
| a person or licence code only | "This code names a subject (a license). It says nothing about this file." |
| an act code, no record at hand | "Unchecked: no record at hand. This says nothing either way." |
| an example code | "Example code from the specification. Never issued." |
| `PG` or `PG-LIC`, record fits | the outcome from the record, with the parties, then always: "It covers the named person only, and says nothing about anyone else in the file." |
| `AG` or `AG-LIC`, record fits | "Approved by the person after it was made, on D. Not a permission before generation." Plus the same coverage line |
| a record for another file | "This code belongs to a different file. It does not show that this video is allowed." No names |
| an edit citing the record's file as its C2PA ingredient | "An editor states this was made from an approved file. Only the editor says so." No names, no coverage line |
| code and record differ | "The code does not match its record." |
| mistyped | "Mistyped code." |
| not a code (a PG person string with no TOG spelling included) | "Not a code." |
| a `PG-` string | read as its TOG spelling; only that is shown |

**A verifier never prints a person's code from a bundle** unless the live lookup says the person is published.
Offline it never prints it. Party names are the directory's full names, never a bare prefix.

Vectors: `verdict`. There, `fits: …` stands for "the record fits this file and this code: now verify the
signatures and the chain, then show the outcome with its parties".

---

## 16. Must-reject list

Each fails with the class shown (vectors: `must_reject`, 62 strings).

**Malformed:** one registry written twice; the old licence shape under `TOG-`; a bare person of 5 digits; a
no-check class other than `STD` and `SUB`, under `TOG-` or `PG-`, and one under a kind; event codes with `TOG-`
dropped; 8 digits under a PG-born prefix; 6 or 7 digits under a 5-letter prefix or one outside the PG alphabet;
PG input with no TOG spelling (over-padded to 8 digits, 9 digits with a symbol check, 10 with a leading zero);
serials of 8, 10, 12 and 13 digits and with a leading zero; 3- and 9-letter prefixes; a digit in a prefix; an
unknown kind; a one-letter kind; the kind after the prefixes; `LIC-PG`, `LIC-AG`, `PG-AG`, `PG-PG`,
`PG-LIC-LIC`, `LIC-LIC`; the marker's dash moved or dropped; a prefix beginning or ending with `LIC`; a letter
inserted into or before the marker (`TOG-PG-NLIC-PRAM-…`, `-LGIC-`, `-LIZC-`, each passing the check); the
marker glued to the kind; the kind glued to the issuer; a third prefix; a tail regrouped 3-4-5, with no dashes,
4-8, or with an extra group; a last group of 3 or 5; `L` in a tail; a symbol check under `TOG-`; lower case, a
leading space, U+200B, `L1C`, a Cyrillic `А` in a message; a QR fragment; a bare secret.

**Mistyped:** a wrong check; `PG` turned into `AG` and back; `PG-OWN-…` under the TOG table.

---

## 17. Old clients and the switch

- **0.13 cannot read `TOG-`.** A lookup, request or answer naming a TOG code fails there: no decision, do not
  generate (fail closed). Vectors: `refused_by_0_13`.
- **One path failed open:** 0.13.0's `verify_anchors` dropped lines of a shape it did not know, so a refusal
  listed as `TOG-` was lost. The 0.13.1 patch refuses the whole list instead (`extensions/identity.md`). It
  ships before any registry writes `TOG-`. 0.14 reads `TOG-` lines and folds `PG-` lines by `code_key`.
- **Order.** 1. The 0.13.1 patch. 2. Libraries learn this document and directory v3 (0.14.0). 3. The steward
  signs v2 (old URL, frozen entries) and v3 (new URL) together; v3 states `min_library`. 4. After a notice
  period, the switch in one release: registries write `TOG-` everywhere (persons respelled, licences by their
  `TOG-LIC` codes, anchor lists in TOG), accept `PG-` as legacy input, mint new persons with 9 digits and new
  licences as `pg.grant.v1`. 5. `PG` and `AG` codes by computation from records. No step breaks an issued
  code, a printed card or a stored reference.
- **Protocol strings keep their names:** `PG_MALFORMED`, `PG_MOVED`, `PG_ALIAS`, `PG-Access`. They are not
  codes.

---

## 18. Errata to PG-CODE.md (informative)

PG-CODE.md is frozen; these are recorded here.

- **§4.2:** at body length 36 the last body character swapped with the check always passes. No issued code is
  near (longest body 19). New shapes stop at 35 (§4.2 here).
- **§13:** the display grouping `PG 000 042 *` removes the dash, so "strip the spaces" gives `PG000042*`, which
  is not a code. Grouping must never remove a dash. Typed input folds that display form as a special case
  (§7.4).
