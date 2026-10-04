# PRE-GEN Protocol Specification

**Version:** PRE-GEN v5 draft (2026-10-04, becomes v5 when published on Zenodo) · Zenodo concept DOI
[10.5281/zenodo.20129901](https://doi.org/10.5281/zenodo.20129901) ·
**Vectors:** `spec/test-vectors/vectors.json`
· **License:** Apache License 2.0 — see [`spec/LICENSE`](LICENSE); licensed
separately from the PRAMPTA service, same as [`spec/README.md`](README.md)
and [`spec/PG-CODE.md`](PG-CODE.md).

The version is the PRE-GEN release number, the same one Zenodo and
pregen.org show ([`spec/VERSIONS.md`](VERSIONS.md)). It changes when a new
version is published; normative changes made after v5 is published mark this
header "v6 draft" until then. [`spec/CHANGELOG.md`](CHANGELOG.md) is the
entry-by-entry record; its dated `Spec-Version` entries up to 2026-09-28 are
the history of v5's drafts.

This document is the PRE-GEN **core**: what every authorization registry,
provider and verifier implements. With [`PG-CODE.md`](PG-CODE.md), the core
refusal codes (§3) and the test vectors it specifies signed objects,
canonical bytes, identifiers, verification, decisions, receipts and key
publication completely enough that a registry, a provider, or an independent
verifier can be built **without reading any registry's source code**.

What a registry adds — its own fields, refusal codes, stricter rules and
services — is an **extension** (§0.5). Extensions used by the origin
registry are in [`PRE-GEN-EXTENSIONS.md`](PRE-GEN-EXTENSIONS.md). How a
registry registers subjects, issues licenses, accepts opt-outs and connects
end users is registry policy, outside the core (§5.1, §8.2).

## 0. Conventions and authority

### 0.1 Requirement language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119),
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when,
they appear in all capitals, as shown here. Numbered requirements (`R-n` for
registries, `P-n` for providers, `V-n` for verifiers) are collected in §8
with the check that covers each one.

### 0.2 What is normative

PRE-GEN v5 consists of four normative parts: this document (the core);
`PG-CODE.md` (identifiers); `test-vectors/vectors.json` (byte-level
examples); and, for an implementation that claims an extension,
`PRE-GEN-EXTENSIONS.md` and the origin registry's code table
`REFUSAL-CODES.md`. The paper
`PRE-GEN-v5.pdf` explains the design and is informative.

Also informative, wherever they appear: rationale, examples, and every
paragraph or pointer marked **Reference implementation** — these name files
in PRAMPTA, the origin registry, so an implementer can compare notes. No
requirement depends on them, and an implementation needs none of them.

### 0.3 When the text and a vector disagree

The requirements are defined by the text. The vectors are computed examples
of it and serve as its conformance test. A disagreement between the two is a
defect — an erratum — and never by itself a rule:

1. It is reported as an issue in the standard's repository
   (https://github.com/Pastheroza/PRE-GEN-site).
2. Until it is resolved, the text governs. An implementation SHOULD NOT
   change its behaviour to match a disputed vector alone.
3. The resolution corrects whichever is wrong, lists the affected vector
   names in [`CHANGELOG.md`](CHANGELOG.md), and republishes the vectors.
   A correction that would change the meaning of anything already issued —
   a PG code, a signed object — is not an erratum; it needs a new version
   (§6).

*Informative:* the v5 vectors are produced by running the reference
implementation (`spec/generate_vectors.py`). That is why this procedure
exists: an implementation bug can produce a wrong vector, and a vector is
evidence of what the text means, not a source of meaning.

### 0.4 Roles and terms

- **Authorization registry** (in this text, **registry**) — holds
  subjects, licenses and opt-outs, answers verification requests with
  signed decisions, and keeps the audit log.
- **Registry operator** (**operator**) — the organization that runs a
  registry, and its signing identity: the operator key set (§2.3).
- **Origin registry** — the directory's origin entry, which issues bare PG
  codes (`PG-CODE.md` §9). Today: PRAMPTA.
- **Steward** — the holder of the key that signs the registry directory
  (`PG-CODE.md` §9.1) and so decides which registries are listed.
- **Provider** — an AI service that asks a registry before generating and
  reports afterwards. It authenticates with a credential the registry issued.
- **Licensee** — the party a license is issued to; typically the provider's
  end user, connected to the provider once (§5.1).
- **Verifier** — anyone checking a signed object offline: a provider, a
  rights-holder, an auditor, a court. A provider is always also a verifier.

### 0.5 Core and extensions

A rule is in the core only if two parties that have never met need it to
work together, every kind of registry needs it, and a verifier can check it.
Everything else a registry does is an extension. The core is deliberately
small; registries differ in their rights holders, how they verify them,
their own rules and their services, not in the core.

- **E-1 Floors only go up.** A registry MAY refuse more than the core
  requires — its own floors, published under E-5 — but no extension may
  turn a decision the core requires to be a refusal (R-1 to R-4, R-7) into
  an allow. *Informative:* whether a later version lets a registry relax a
  floor, and with what safeguards, is left open on purpose (§7).
- **E-2 Extra members.** A registry MAY add members to a decision (§1.1) and
  to a licence body (§1.2). They are inside the signature; a verifier that
  does not use them ignores them. Receipts (§1.3) have a fixed shape.
- **E-3 Critical members.** A decision MAY carry `critical`: an array of
  the names of members a provider must understand to use the decision
  safely. A verifier that does not understand every listed member MUST
  treat the decision as unusable for generation. An obligation (P-8) a
  provider cannot apply has the same effect.
- **E-4 Own refusal codes.** A registry that is not the origin registry
  names its own codes `PG_<ISSUER>_<NAME>`, with its issuer prefix
  (`PG-CODE.md` §9). The origin registry's codes are listed in
  `REFUSAL-CODES.md`. A code a provider does not know is hard (P-6).
- **E-5 Published policy.** A registry SHOULD publish, at a stable URL in
  its documentation: its own floors and refusal codes, the extensions it
  implements, the lifetime of its decisions, its opt-out waiting period,
  its usage-limit rules, and the custody modes it offers (§1.2).
- **E-6 Shared extensions.** An extension that more than one registry
  implements is described in `PRE-GEN-EXTENSIONS.md` under a name, so that
  an implementation can claim it (§8.1).

---

## 1. Protocol objects

Three kinds of object make up the core: the decision, the licence and the
receipt. They share one canonicalization rule (§2) and one primitive
(Ed25519, RFC 8032); what differs is *who* signs, *what's excluded* from the
signed bytes, and how strictly each is versioned. The evidence bundle, the
C2PA assertion and the observation are extensions
(`PRE-GEN-EXTENSIONS.md` X.6 to X.8).

| Object | Version marker field | Current value | Who signs | Additive-safe? |
|---|---|---|---|---|
| §1.1 Decision | `schema_version` | `pg.decision.v1` | Operator | Yes (new optional fields never bump it) |
| §1.2 License | `v` | `pg.license.v2` | Subject, countersigned by Operator | Partially — see §1.2 |
| §1.3 Receipt | `v` | `pg.receipt.v2` (default), `pg.receipt.v3` (opt-in) | Provider (optional), hashed by Operator | No |
| Evidence bundle (extension X.6) | `schema_version` | `pg.evidence.v1` | Operator | Not addressed |
| Assertion (extension X.7) | `schema_version` | `pg.assertion.v1` | Operator | Not addressed |

### 1.1 SignedDecision (`pg.decision.v1`)

**Purpose.** The response to `POST /v1/verify` — a cryptographically signed
statement of whether a specific generation is authorized, that a provider
can verify offline and keep as compliance evidence.

**Signed bytes.** The decision is returned as one JSON object. Its signed
bytes are the canonical JSON (§2) of that object with the single member
`operator_signature` removed. Every other member is signed, including
`operator_key_id` and any member the verifier does not recognize: a
verifier MUST NOT drop unrecognized members before checking the signature
(V-2), even though it ignores them otherwise.

*Reference implementation:* `backend/app/api/verify.py` (`SignedDecision`,
`_build_signed_decision`).

**Core members.** A registry MAY add others (E-2); the origin registry's
are in `PRE-GEN-EXTENSIONS.md` X.2.

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | `pg.decision.v1` |
| `decision_id` | string | unique per decision |
| `nonce` | string | one-time-use token; a consumer must not reuse it |
| `disposition` | string | `"allow"` \| `"not_blocked"` \| `"review"` \| `"deny"` — `not_blocked` (with `PG_STD_TRACKING_ONLY`) is personal use that nothing prohibits and nothing grants |
| `allowed` | boolean | `true` only when `disposition == "allow"`; kept so that a client reading only `allowed` treats the other three as not-allowed (fail-closed) |
| `reason` | string \| null | a refusal code (§3, E-4), or null on allow |
| `policy_version` | string | which version of the registry's rules produced this decision — independent of `schema_version`: the *rules* can change without the *envelope shape* changing |
| `subject_id` | string | |
| `licensee_id` | string | |
| `provider_id` | string | |
| `license_id` | string \| null | |
| `prompt_hash` | string | |
| `model` | string | |
| `modality` | string | |
| `intended_use` | object | echoes the request's `intended_use` |
| `obligations` | object | obligations the licensee must satisfy (watermarking, disclosure, …) |
| `subject_authority` | string | how well the registry has established who holds the subject's rights: `self` (the registrant's own claim), `agency_asserted` (an agent's claim), `consented` (the subject's documented consent), `verified` (the registry checked identity and authority). Distinct from whether a licence exists. A provider MAY refuse to generate commercially on anything below `verified` |
| `generation_id` | string | echoed from the request |
| `issued_at` | integer | Unix seconds |
| `expires_at` | integer | Unix seconds; hard signature lifetime, at most 900 seconds after `issued_at` |
| `critical` | array of strings \| absent | E-3 |
| `operator_key_id` | string | the operator key fingerprint (§2.1) used to sign |
| `operator_signature` | string | Ed25519 signature, hex — **excluded from the signed bytes** |

**Additive safety.** New *optional* fields never bump `schema_version` —
`generation_id`, `detection_id`, `provider_user_binding`, and `remediation`
were all added this way, and every extension member (E-2) is added this way. A consumer MUST ignore the meaning of members it
does not recognize (while still signing over them, above) and treat an
expected optional member that is absent as its default. `schema_version`
changes only if a member is removed or its *meaning* changes.

### 1.2 LicenseBody (`pg.license.v2`)

**Purpose.** The terms a subject's owner grants a licensee — signed by the
subject's key over exactly these terms and countersigned by the operator
(proving the registry issued it under that license id). What the subject
signature proves depends on custody — see "Custody and consent" below.

**Signatures.** Let `body` be the license body defined below and
`B = canonical_json(body)` (§2).

1. The **subject signature** is Ed25519 by the subject's key over `B`
   (64 bytes, hex on the wire).
2. The **operator countersignature** is Ed25519 by an operator key over the
   byte concatenation `B || S || L`, where `S` is the 64 raw bytes of the
   subject signature and `L` is the license id (`PG-CODE.md`) encoded as
   ASCII. The countersignature therefore binds the id: the same terms under
   another id do not verify.
3. A verifier (V-9) MUST check both, the subject signature against the
   subject's public key and the countersignature against the operator key
   named by the license's `signing_key_fingerprint`, and MUST treat a
   license failing either as forged (`PG_INVALID_SIGNATURE`), not absent.

The vector `license_countersignature` fixes these bytes.

**The licence envelope.** A licence travels as an object with these
members, and a verifier checks it from them alone, without knowing the
registry's licence fields:

| Member | Type | Notes |
|---|---|---|
| `license_id` | string | the PG licence id (`PG-CODE.md`) |
| `signed_body` | object | the body exactly as signed: `B` is its canonical JSON |
| `subject_public_key_hex` | string | the subject key the subject signature is checked against |
| `subject_signature` | string | hex |
| `operator_signature` | string | the countersignature, hex |
| `signing_key_fingerprint` | string | the operator key that countersigned (§2.1) |

**Core body members.** Every body carries `v` (the licence marker,
`pg.license.v2` today), `subject_id`, `licensee_id`, `contract_start`,
`expires_at` and `scope`. Everything else in the body — classes, territories,
channels, usage limits, prices — is the registry's (E-2); the origin
registry's body is described in `PRE-GEN-EXTENSIONS.md` X.5, including the
licences minted before markers existed, which carry no `v` and stay valid.
A verifier MUST refuse (`PG_INVALID_SIGNATURE`) a licence whose marker it
does not recognize. A marker that changes what a member *means* is a new
value of `v`, never a silent change to v2.

**Who answers for the rights.** The licence format proves who signed what.
Whether the subject's rights holder is real is the responsibility of the
registry that registered it; whether a registry is trusted at all is decided
by the steward, who lists it in the directory and can remove it
(`PG-CODE.md` §9.1). A licence from a registry the directory does not list
for its namespace is invalid (V-10).

**Custody and consent.** A subject's key is held by the subject (`self`)
or encrypted by the registry and used on the subject's behalf (`managed`);
the registry publishes each subject's custody mode (subject record and
certificate, `key_custody`). The two modes do not give the same guarantee:

- **self**: the subject signature is the subject's own act. A compromised
  operator cannot produce a license without it.
- **managed**: the subject signature proves only that the registry used the
  subject's key (`backend/app/core/license_mint.py::finalize_license_signatures`).
  The evidence that the subject agreed is the registry's audit record of the
  instruction — the authenticated account and the terms approved, or the
  automatic-approval rule the subject set in advance
  (`backend/app/api/license_requests.py`). A compromised operator can forge
  both. A verifier that needs proof of the subject's own act MUST require
  `self` custody. A registry offering `managed` custody MUST publish each
  subject's custody mode (R-12).

### 1.3 ReceiptBody (`pg.receipt.v2` / `pg.receipt.v3`)

**Purpose.** A provider's attestation that a generation actually happened,
bound to a specific decision — what a registry compares against the
decisions it issued. Submission rules are in §5.5.

*Reference implementation:* `backend/app/core/receipt_body.py` (`_build_v2`,
`_build_v3`), `backend/app/api/receipts.py` (`submit_receipt`).

**This is the one signed object the operator does not sign at all.** The
operator only computes `receipt_hash = sha256(canonical_json(receipt_body))`
— a content hash, not a signature. The **provider** optionally signs
`canonical_json(receipt_body)` with its own registered Ed25519 key; this is
mandatory only when the provider organization has registered a signing key
(`Organization.signing_public_key_hex`), and the provider's signature is
never itself embedded inside `receipt_body` — it travels alongside it and
is checked against it.

**All fields are always present** (a plain dict literal, no conditional
inclusion — the one signed object where every field is unconditional):

| Field | Type |
|---|---|
| `v` | string, `"pg.receipt.v2"` or `"pg.receipt.v3"` |
| `decision_id` | string |
| `subject_id` | string, from the bound decision's audit metadata |
| `licensee_id` | string, from the `X-Licensee-ID` header |
| `provider_id` | string, from the `X-Provider-ID` header |
| `prompt_hash` | string |
| `output_hash` | string — mandatory proof a generation actually happened |
| `model` | string |
| `obligations_applied` | object |
| `watermark_embedded` | boolean |
| `generated_at` | integer, Unix seconds |

`pg.receipt.v2` is the default when neither `v` nor `schema_version` is sent.
It **does not sign `event_type`**, even if that request field is supplied.
An operator may record the reported event type, but cannot claim that its
value was covered by the provider's v2 signature.

`pg.receipt.v3` is opt-in: send `"schema_version": "pg.receipt.v3"` (or
`"v": "pg.receipt.v3"`) in the request. The signed body has all v2 fields,
with `v` set to `"pg.receipt.v3"`, plus one mandatory field:

| Field | Type |
|---|---|
| `event_type` | one of `preview`, `output_accepted`, `output_delivered`, `output_published` |

If both request version fields are present, they must agree. An unsupported
version is rejected. A provider with a registered signing key must sign the
canonical JSON of the selected version. For v3, a v2 signature is **never**
accepted as fallback, because that would leave `event_type` unsigned. The
response and audit event include `provider_signed_event_type`, true only
when a registered provider key verified a v3 signature. v2 remains accepted
without a sunset date; it is not deprecated by this opt-in addition. Even a
v3 signature attests a provider's claim, not output existence, reporting
completeness, legal compliance, or settlement. The `output_hash` is a file
identifier/commitment, not independent proof of generation.

**Fixed shape.** Every member is always present, so any change of shape is
a new marker, introduced with the window of §7. `pg.receipt.v3` is
RECOMMENDED for new integrations; `pg.receipt.v2` stays accepted.

### 1.4 – 1.6 Evidence bundle, assertion, observation

Moved to `PRE-GEN-EXTENSIONS.md` (X.6 evidence bundle, X.7 C2PA assertion,
X.8 observation). They are extensions: a registry or provider that offers
one MUST implement it as specified there.

## 2. Canonicalization

Every signed object above is turned into bytes the same way before hashing
or signing. Get this wrong and nothing else in this document matters — two
implementations that agree on every field but disagree on canonicalization
produce different signatures over what a human would call "the same
object."

1. **Serialize as JSON** (RFC 8259) with:
   - Object members sorted by key, comparing keys as sequences of Unicode
     code points. (Not UTF-16 code units: the two orders differ for keys
     containing characters outside the Basic Multilingual Plane.)
   - No insignificant whitespace: `,` between members and elements, `:`
     between key and value, nothing else.
   - Strings: `"` and `\` escaped as `\"` and `\\`; U+0008, U+0009,
     U+000A, U+000C, U+000D as `\b`, `\t`, `\n`, `\f`, `\r`; every other
     code point below U+0020 as `\u00xx` with lowercase hex. Every other
     character, including `/`, U+007F and all non-ASCII characters, is
     written as itself, never escaped.
   - `true`, `false`, `null` as literals.
   - Numbers in a signed body are **integers only**, written in decimal
     without a leading `+`, leading zeros or exponent, and within
     ±(2^53 − 1). A signed object never contains a non-integer number,
     because float formatting is not portable across languages.
2. **Encode the result as UTF-8 bytes.**
3. **Hash** with SHA-256, rendered as lowercase hex.
4. **Sign** with Ed25519 (RFC 8032, deterministic — the same message and
   key always produce the same signature bytes) over the canonical JSON
   bytes of the body, **with the signature field itself excluded** from
   what gets signed (each §1 subsection above states exactly how its
   object excludes its own signature field).

*Reference implementation:* `backend/app/core/crypto.py` (`canonical_json`,
equivalent to Python `json.dumps(obj, sort_keys=True, separators=(",", ":"),
ensure_ascii=False)`).

**⚠ Unicode is NOT normalized.** Two visually-identical strings in
different Unicode normalization forms (NFC vs. NFD — e.g. an accented
character as one composed code point vs. a base character plus a combining
mark) canonicalize to **different bytes** and therefore sign differently.
This is deliberate, not an oversight: `spec/test-vectors/vectors.json`'s
`canonical_json` section carries an explicit NFC/NFD pair proving they hash
differently (`spec/generate_vectors.py`, function `_canonical_cases`) — an
implementation that silently normalizes Unicode before canonicalizing will
produce byte-identical output for two inputs this protocol considers
distinct, and will fail that vector case.

### 2.1 Key fingerprint

`pg-ed25519:` followed by the first 32 hex characters of
`SHA-256(raw 32-byte Ed25519 public key)`, lowercase. The same rule names
operator keys, subject keys and provider keys. The vectors' `operator_key`
entry fixes one example.

### 2.2 Audit chain

An audit event is signed over the canonical JSON of exactly these members:
`event_id`, `action`, `entity_type`, `entity_id`, `actor`, `timestamp`
(ISO 8601 in UTC with an explicit `+00:00` offset), `metadata` (an object,
`{}` when empty) and `prev_hash`. Its `event_hash` is the SHA-256 of those
bytes, and its `signature` is the operator's Ed25519 signature over them,
named by `signing_key_id`.

`prev_hash` is the `event_hash` of the previous event **in the same chain**;
the first event of a chain has the literal string `"genesis"`. A registry
MAY keep several chains (the reference implementation keeps one per subject
for verification traffic and one for everything else); each chain is
independently verifiable. The registry's Merkle root over event hashes
(informative; paper §10) covers the events of all chains. The vectors `audit_event_genesis` and
`audit_event_chained` fix the bytes.

### 2.3 Signed key set

`GET /keys` (at the registry's API origin, not under `/v1`) returns

```json
{"current_key_id": "pg-ed25519:…",
 "keys": [{"key_id": "pg-ed25519:…", "public_key_hex": "…", "activated_at": 0,
           "deactivated_at": null, "status": "active", "is_ephemeral": false}],
 "signature": "…"}
```

`keys` is the full history, current and retired; `signature` is the current
key's Ed25519 signature over the canonical JSON of the object without
`signature`. A retired key stays listed so that everything it ever signed
remains verifiable. Which keys may sign in which PG-code namespace is not a
registry's own statement: it is fixed by the signed registry directory
(`PG-CODE.md` §9.1).

The key set is **self-signed**: it proves the list is consistent, not that
it is authentic, because anyone can sign a list that includes their own key.
A provider therefore MUST obtain at least one operator public key out of
band — from the registry's published listing (`registries.json` `keys`
field), its documentation, or a pinned configuration — and MUST NOT trust a
key it learns only from the same connection that serves decisions (V-1).

*Reference implementation:* `backend/app/core/keystore.py` (`get_key_set`);
operational procedure in `docs/Operator-Key-Rotation-Runbook.md`.

---

## 3. Refusal codes

A refusal carries a reason code. These are the **core codes**: every
registry that refuses for one of these reasons MUST use the code with this
meaning. **Hard** means no retry, reshaped request or licence fixes it;
**soft** means a different request, licence or provider might succeed.

| Code | Kind | Meaning |
|---|---|---|
| `PG_MISSING_PROMPT_HASH` | soft | the request has no `prompt_hash` (R-1) |
| `PG_NO_PAIR` | soft | the caller is not authenticated for this provider and licensee (§5.1) |
| `PG_NO_SUBJECT` | soft | this registry holds no such subject — not a prohibition (P-5) |
| `PG_SUBJECT_OPTED_OUT` | hard | an opt-out in effect refuses this use (R-2) |
| `PG_SUBJECT_PENDING` | soft | the subject awaits the registry's review (R-3) |
| `PG_SUBJECT_PAUSED` | soft | the subject's owner paused licensing (R-3) |
| `PG_SUBJECT_DISPUTED` | hard | a dispute is open on the subject (R-3) |
| `PG_SUBJECT_WITHDRAWN` | hard | the subject was withdrawn (R-3) |
| `PG_PROHIBITED_USE` | hard | a fixed protection, such as for minors, forbids this use (R-4) |
| `PG_NO_LICENSE` | soft | no valid, live licence covers this licensee and use |
| `PG_INVALID_SIGNATURE` | hard | the licence found does not verify (R-7) |
| `PG_LICENSE_REVOKED` | hard | the licence was revoked |
| `PG_SCOPE_VIOLATION` | soft | the request falls outside the licence's scope |
| `PG_IMMUTABLE_DENIAL` | hard | the use matches a denial the licence can never grant |
| `PG_USAGE_LIMIT` | soft | the licence's usage limit is spent |
| `PG_STD_TRACKING_ONLY` | soft | personal use: not blocked, nothing granted (R-6) |
| `PG_HELD_FOR_REVIEW` | soft | held for a human; disposition `review` |

A registry MAY refuse for other reasons with its own codes (E-4). The
origin registry's full table, generated from its policy registry, is
[`REFUSAL-CODES.md`](REFUSAL-CODES.md); its core rows match this table.
A provider MUST treat a code it does not know as hard (P-6): failing closed
is the safer wrong answer.

---

## 4. PG-code grammar

The full identifier specification — alphabet, check-character algorithm,
worked examples, and the "resolved, never parsed" resolution rule — lives
in **[`spec/PG-CODE.md`](PG-CODE.md)**. This section adds a formal grammar
on top of that prose: an ABNF (RFC 5234) definition of the two current
shapes plus the two permanently-valid legacy shapes, and one canonical
regular expression meant to accept the same strings.

**Scope.** The grammar describes *shape* only. Whether the check character
is right is a separate arithmetic check (`PG-CODE.md` §4), so a mistyped
code can be told apart from an unknown one (`PG-CODE.md` §7). Every vector
in `pg_code.rejects` is shape-valid and checksum-invalid on purpose.

### 4.1 ABNF (RFC 5234)

Assumes canonical (uppercase, whitespace-stripped) input — apply
`.strip().upper()` first, matching `subject_code.py::normalize_subject_code`.

```abnf
pg-code             = subject-code / license-id / legacy-subject-code
                      / issuer-subject-code / issuer-license-id

prefix              = %s"PG-"

digit               = %x30-39                 ; "0"-"9"
alpha-upper         = %x41-5A                  ; "A"-"Z"

; Crockford base32 body alphabet: digits plus A-Z minus I(%x49), L(%x4C),
; O(%x4F), U(%x55) -- see PG-CODE.md §3 for why those four.
alphabet-char       = digit / %x41-48 / %x4A-4B / %x4D-4E / %x50-54 / %x56-5A

; Five symbols valid ONLY in the check position (PG-CODE.md §3.1) -- the
; overflow values a mod-37 sum can take that the 32-symbol alphabet has no
; room for.
check-extra         = "*" / "~" / "$" / "=" / "!"
check-char          = alphabet-char / check-extra

; Zero-padded to a MINIMUM of 6 decimal digits; no maximum -- widens freely
; past 999999 without invalidating anything already issued (PG-CODE.md §9).
subject-serial      = 6*digit

subject-code        = prefix subject-serial check-char

; Shape only. PG-CODE.md §6 names the closed, append-only set of values a
; conformant implementation may actually ISSUE (currently STD/RND/PRM) and
; the permanently-retired set (EDT/EST/ENT/PER/OWN) that must keep
; resolving but must never be re-admitted or issued again.
license-class       = 3alpha-upper

; 6 random characters from the body alphabet -- random, not sequential, so
; the number of licenses on one subject is never inferable from an id.
license-tail        = 6alphabet-char

license-id          = prefix license-class "-" subject-serial "-"
                       license-tail check-char

; Another registry's codes (PG-CODE.md §9): exactly four letters from the
; body alphabet, never a digit. The prefix is part of the checked body.
issuer-letter       = %x41-48 / %x4A-4B / %x4D-4E / %x50-54 / %x56-5A
issuer              = 4issuer-letter

issuer-subject-code = prefix issuer "-" subject-serial check-char

issuer-license-id   = prefix issuer "-" license-class "-" subject-serial "-"
                       license-tail check-char

; Two permanently-valid historical shapes (PG-CODE.md §2.1) -- no check
; character (all-digits after the prefix), any digit count. Must keep
; resolving forever; must never be newly issued.
legacy-subject-code = prefix ("STD-" / "SUB-") 1*digit
```

### 4.2 Canonical regex

Equivalent to the ABNF above on the vector corpus (§4, scope note above) —
operates on canonical (uppercase, stripped) input:

```
^PG-(?:[A-HJKMNP-TV-Z]{4}-)?(?:[0-9]{6,}[0-9A-HJ-KM-NP-TV-Z*~$=!]|[A-Z]{3}-[0-9]{6,}-[0-9A-HJ-KM-NP-TV-Z]{6}[0-9A-HJ-KM-NP-TV-Z*~$=!])$|^PG-(?:STD|SUB)-[0-9]+$
```

An optional four-letter issuer prefix (PG-CODE.md §9) in front of the two
current shapes — `subject-code` / `issuer-subject-code` and `license-id` /
`issuer-license-id` — then, separately, `legacy-subject-code`, which never
carries a prefix.

---

## 5. Operations

Paths are relative to the registry's API base, which the registry publishes
(`registries.json`, member `api`; PRAMPTA: `https://api2.prampta.com`).
Operations live under `/v1`, except `GET /keys` (§2.3). Bodies are JSON.

### 5.1 Authentication

A provider sends, on every operation below:

- `X-Provider-ID` — its provider identifier; REQUIRED.
- `Authorization: Bearer <credential>` — the credential the registry issued
  to it; REQUIRED. A registry MUST refuse a request whose credential does not
  match the provider identifier (`PG_NO_PAIR` on `/v1/verify`, HTTP 401
  elsewhere).
- `X-Licensee-ID` — the connected end user the provider acts for. When it
  is absent the request is **provider-level**: it can only ever end in
  `not_blocked` for declared personal use (R-6), because licenses belong to
  a licensee.

How an end user is connected to a provider (a one-time authorization code,
in the manner of OAuth 2.0) is registry policy in v5, not a wire
requirement. *Reference implementation:* `docs/licensing-integration.md`.

### 5.2 Verification request — `POST /v1/verify`

| Member | Type | Rule |
|---|---|---|
| `subject_id` | string | the subject: a PG code or the registry's subject id; REQUIRED |
| `prompt_hash` | string | SHA-256 hex of the prompt; REQUIRED. The prompt text MUST NOT be sent |
| `model` | string | the provider's model identifier |
| `modality` | string | `image`, `video`, `audio`, `voice`, `text`, … |
| `intended_use` | object | `use_case` (`personal` \| `educational` \| `research` \| `editorial` \| `commercial`), `channel`, `territory`, `categories` (array), `modality`, `rights` (array; empty means output generation only) — all optional unless stated; a registry MAY accept more (E-2) |
| `generation_id` | string | the provider's own id for this attempt; echoed. The same id across the decisions for one output (P-9) |
| `license_id` | string | optional hint; narrows candidate licenses, never widens them |

A registry MAY accept further members (E-2); the origin registry's are in
`PRE-GEN-EXTENSIONS.md` X.2.

The response is always HTTP 200 with a signed decision (§1.1), whether the
answer is allow or a refusal; HTTP errors mean the request itself could not
be processed (malformed body, rate limit).

### 5.3 Evaluation — registry requirements

- **R-1** A request without `prompt_hash` MUST be refused with
  `PG_MISSING_PROMPT_HASH`; an unknown subject with `PG_NO_SUBJECT`.
- **R-2** An opt-out **in effect** (its `effective_from` has passed) whose
  scope is `all_modalities` or equals the request's `modality` MUST produce
  `PG_SUBJECT_OPTED_OUT`, and MUST be evaluated before the caller is
  authenticated and before any license is consulted. A pending opt-out has
  no effect until `effective_from`.
- **R-3** A subject that is pending, paused, disputed or withdrawn MUST be
  refused with its own code (`PG_SUBJECT_PENDING`, `PG_SUBJECT_PAUSED`,
  `PG_SUBJECT_DISPUTED`, `PG_SUBJECT_WITHDRAWN`) before license resolution.
- **R-4** No license may override an opt-out in effect, a subject status of
  R-3, an immutable denial, or a fixed protection for minors.
- **R-5** A registry MUST NOT answer `allow` unless (a) a license whose both
  signatures verify (§1.2), whose `contract_start` ≤ now < `expires_at`,
  which is not revoked, and whose scope covers the request, applies to the
  licensee; or (b) the registry's published policy grants the use without a
  license, and the decision says so by its reason code
  (the origin registry's example: `PG_ORG_INTERNAL_USE`, extension X.2).
  An allow MUST carry `allowed: true` and
  `disposition: "allow"`.
- **R-6** `not_blocked` MAY be answered only when no license applies,
  `intended_use.use_case` is `personal`, and nothing prohibits the use; it
  MUST carry `allowed: false` and `PG_STD_TRACKING_ONLY`. It grants nothing.
- **R-7** When the only candidate license fails signature verification the
  answer MUST be `PG_INVALID_SIGNATURE`, not `PG_NO_LICENSE`.
- **R-8** Every decision — allow or refusal — MUST be signed (§1.1), MUST
  carry a fresh `nonce` and an `expires_at`, MUST echo `subject_id`,
  `provider_id`, `licensee_id`, `prompt_hash`, `model`, `modality` and
  `intended_use` as received, and MUST be recorded in the audit log (§2.2).
- **R-9** (extension, `PRE-GEN-EXTENSIONS.md` X.3.)

R-1 to R-4 and R-7 are the **fixed floor**: no extension may answer `allow`
where they require a refusal (E-1).

The remaining order of checks is registry policy. A registry SHOULD follow
the reference order: caller and sandbox limits; subject status, provider
vetoes and fixed prohibitions; personal use; license resolution; scope
(immutable denials, deny categories, license class, channel, territory,
modality, granted rights); typed extensions, usage and concurrency limits,
and human review (`PG_HELD_FOR_REVIEW`, disposition `review`).
*Reference implementation:* `backend/app/core/verify_engine.py`
(`run_verify`).

### 5.4 Using a decision — provider and verifier requirements

- **V-1** The operator key that verifies a decision MUST be one the provider
  trusts out of band (§2.3). In pinned mode an unknown `operator_key_id`
  MUST fail closed.
- **V-2** The signature MUST be verified over the canonical JSON of the
  decision exactly as received minus `operator_signature` (§1.1), with the
  key named by `operator_key_id`.
- **V-3** A decision without a positive integer `expires_at`, whose
  `issued_at` is not earlier than `expires_at`, or whose `expires_at` has
  passed MUST NOT be used.
- **V-4** Each echoed member of R-8 MUST equal what the provider sent
  (members of `intended_use` it did not send appear with their empty
  defaults); a mismatch MUST be treated as an invalid decision, so that an
  allow for one product, project or user cannot be replayed for another.
- **P-5** A provider MUST generate on the registry's authority only when
  `disposition` is `allow`. On `not_blocked` it MAY generate under its own
  policy but MUST NOT present the output as licensed. On `review` and `deny`
  it MUST NOT generate for this request, with one exception: `PG_NO_SUBJECT`
  says only that this registry holds no such subject. It is not a
  prohibition — the user may hold rights the registry does not record (a
  direct contract, their own work, another registry) — so the provider MAY
  proceed under its own policy, as for `not_blocked`, and MUST NOT present
  the output as licensed by this registry.
- **P-6** A reason code the provider does not know (§3, E-4) MUST be
  treated as hard.
- **P-7** A decision authorizes the one generation it answers. It MAY be
  reused only as the registry's extension permits (origin: X.3), and never
  after `expires_at`.
- **P-8** Obligations returned in `obligations` (watermark, disclosure, …)
  MUST be applied to an output generated under an allow, and reported in the
  receipt (§5.5).
- **V-9** A license MUST be checked as §1.2 states: both signatures, the
  countersignature over body, subject signature and license id.
- **V-10** For every signed object that carries a PG code — a license (its
  `license_id`), or a decision naming a license — the verifier MUST look up
  the code's namespace (`PG-CODE.md` §9 rule 5) in the registry directory
  and MUST check that the signing operator key is one of the
  `key_fingerprints` of the registry that owns it. Otherwise the object is
  invalid (`PG_ISSUER_MISMATCH`, or `PG_ISSUER_UNKNOWN` when no registry
  holds the namespace) — a verification failure like a bad signature, not a
  refusal code a registry returns.
- **V-11** A subject code MUST be resolved only at the registry that owns
  its namespace (the directory entry's `api`); an answer about it from any
  other registry MUST be ignored.
- **V-12** The registry directory MUST be accepted only as `PG-CODE.md`
  §9.1 states: the published steward key's signature, its invariants, and a
  `sequence` no lower than one already accepted.
- **V-13** (extension, `PRE-GEN-EXTENSIONS.md` X.4.)
- **V-14** A decision, licence or other object signed by a key of a revoked
  registry, or by a key listed in `revoked_keys` (`PG-CODE.md` §9.1), MUST
  NOT be used to authorize a generation, whatever its `issued_at`. As
  evidence it is reported as signed by a revoked key; its own `issued_at`
  does not show that it was signed before the revocation.
- **P-10** When the provider learns that the same person, brand or work is
  held by more than one listed registry — it asked several, or found the
  subject in several subject indexes — it MUST NOT generate on the
  registries' authority unless every registry it asked answers `allow`. A
  hard refusal from any of them prevails over an allow from another.
- **P-9** When one output involves several subjects — a person, a voice, a
  brand, a work — the provider MUST ask for each subject, with one
  `generation_id` for all of them, MUST NOT generate on the registries'
  authority unless every decision is an `allow`, and SHOULD file one receipt
  per decision. A subject answered `PG_NO_SUBJECT` is handled as P-5
  states.

### 5.5 Receipts — `POST /v1/receipts`

After generating under an allow, the provider SHOULD file one receipt. The
request carries `decision_id`, `prompt_hash`, `output_hash` (SHA-256 hex of
the output; REQUIRED), `model`, `obligations_applied` (object),
`watermark_embedded` (boolean), `generated_at` (Unix seconds), optionally
`schema_version` / `v` (`pg.receipt.v2` default, `pg.receipt.v3`) and
`event_type` (v3), and `provider_signature` (hex).

- **R-10** A registry MUST accept at most one receipt per decision (HTTP 409
  for a second), MUST refuse a receipt whose decision was not an allow issued
  to the same provider and licensee (HTTP 400 / 403), and MUST refuse a
  `prompt_hash` that differs from the decision's (HTTP 400).
- **R-11** If the provider has registered a signing key, the receipt MUST
  carry `provider_signature` over the canonical JSON of the receipt body of
  the selected version (§1.3), and the registry MUST verify it; for v3 a v2
  signature MUST NOT be accepted.

Later stages of a receipted output (lifecycle events) are an extension
(`PRE-GEN-EXTENSIONS.md` X.9).

### 5.6 Observations

An extension (`PRE-GEN-EXTENSIONS.md` X.8).

### 5.7 Registry publication

- **R-12** A registry MUST publish its key set (§2.3); MUST publish each
  subject's custody mode where it offers `managed` custody (§1.2); and, if
  it is not the origin registry, MUST issue codes with its assigned issuer
  prefix (`PG-CODE.md` §9).
- **R-13** A registry that receives a code with an issuer prefix it does not
  hold MUST answer that the code belongs to another registry, not that it
  was not found (`PG-CODE.md` §9).
- **R-14** A registry MUST issue PG codes only in the namespace the registry
  directory assigns to it, and MUST NOT issue codes before it is listed.
  Only the directory's origin entry may issue bare codes. Every key it signs
  with MUST be listed in its entry's `key_fingerprints` before first use.
- **R-15** A registry that learns that another listed registry holds the
  same person, brand or work SHOULD tell that registry and the steward, and
  SHOULD stop issuing new licences for the subject, answering
  `PG_SUBJECT_DISPUTED`, until the two agree who holds the rights. An
  opt-out filed at either applies to the subject at both.

---

## 6. Versioning and compatibility

A **PRE-GEN version** (v5) is one published release of these documents
(`VERSIONS.md`). Each signed object also carries its own **marker**, which
changes on the rules below and independently of the PRE-GEN version.

### 6.1 Per-object rules

- **Decision (`schema_version`).** Bumps only when a field is *removed* or
  an existing field's *meaning* changes. Adding a new optional field never
  bumps it (§1.1) — this is the strongest additive-safety guarantee in the
  protocol.
- **License (`v`).** Optional members are included only when set (§1.2),
  so a new optional member never breaks an old signature. A license signed
  before markers existed has no `v` and is reconstructed without one,
  permanently. A marker that changes what a member *means* is a new value
  of `v` with its own reconstruction rule.
- **Receipt (`v`).** Every member is always present (§1.3), so any change
  of shape is a new marker (`pg.receipt.v3` was added that way), handled by
  the window of §7.
- **Evidence bundle / Assertion (`schema_version`, extensions X.6, X.7).** Both are minted fresh
  at read/issue time rather than re-serving a pre-existing signed body, so
  neither carries the same retroactive-invalidation risk License does — no
  additive-safety convention has been needed yet.

### 6.2 Policy version (distinct from schema version)

`policy_version` (§1.1, §3) versions the *rules* `/verify` applies —
independent of `schema_version`, which versions the *shape* of the decision
envelope. A decision can always be read against the exact rule set that
produced it, even long after the rules have changed, because both are
stamped on it. The list of policy versions is append-only and published in
`REFUSAL-CODES.md` ("Policy version history").

### 6.3 What "stays valid" means

Two different promises are made about old material, and they must not be
confused:

- **As evidence, forever.** A signed object is verified against the rules
  and keys that applied when it was signed. A decision, license, receipt,
  evidence bundle or audit event that verified then MUST still verify
  under every later version, and a PG code once issued keeps resolving to
  the same thing. Retired keys stay in the key set (§2.3) for this reason.
- **As authority, only while current.** Nothing old grants anything new by
  itself. A decision authorizes only the request it answers and only until
  `expires_at`; a license authorizes only within its own term, while it is
  neither revoked nor overridden (R-2, R-3, R-4), and only under the rules
  in force at the time of the new request. A key or algorithm that is
  retired or compromised stops producing new valid signatures; what it
  signed before remains readable as historical evidence, and a registry MAY
  mark such evidence as signed by a compromised key.

---

## 7. Governance and errata

- **Editor.** PRE-GEN is edited by its author, Valerii Egorov. Changes are
  proposed as issues or pull requests in the standard's repository
  (https://github.com/Pastheroza/PRE-GEN-site).
- **Errata** follow §0.3 and are listed in `CHANGELOG.md`. An erratum
  corrects text or vectors to what was always meant; it does not change the
  version number.
- **Additive changes** — a new optional member, a new refusal code, a new
  optional feature — may be made in the next version without breaking any
  conforming implementation (§1.1, §6.1).
- **Breaking changes** — removing a member, changing a meaning — need a new
  version and a new object marker (§6), are announced in `CHANGELOG.md` and
  `VERSIONS.md` with what an implementation must change, and, where a
  registry keeps accepting the old form for a while, are signalled with
  `Deprecation` and `Sunset` HTTP headers during that window. Nothing
  already issued changes meaning (§6.3).
- **Receipts.** Because a receipt is verified once, at submission, a
  registry MAY accept a provider signature over either the current or the
  previous receipt shape during an announced window; `pg.receipt.v2` and
  `pg.receipt.v3` currently coexist with no sunset date.
- **Security.** A vulnerability in the standard itself is reported
  privately to the editor through GitHub private vulnerability reporting
  (`github.com/Pastheroza/PRE-GEN-site/security/advisories/new`) before public disclosure;
  a vulnerability in a registry's implementation is reported to that
  registry (PRAMPTA: security@prampta.com).

*Reference implementation:* PRAMPTA's own compatibility policy is in
`docs/PROTOCOL-GOVERNANCE.md`, its dual-accept window in
`backend/app/core/receipt_body.py`.

---

## 8. Conformance

### 8.1 Profiles

An implementation claims conformance to one or more profiles of
**PRE-GEN v5**, by name:

- **PRE-GEN v5 Verifier** — V-1 to V-4, V-9 to V-12, V-14, E-3; §2 and §2.1
  exactly; PG codes parsed and checked as `PG-CODE.md` states.
- **PRE-GEN v5 Provider** — everything in Verifier, plus P-5 to P-10 and
  §5.1–§5.2 on the wire. Receipts (§5.5) are RECOMMENDED.
- **PRE-GEN v5 Registry** — R-1 to R-8, R-10 to R-14, E-1, E-4; decisions
  (§1.1), licences (§1.2), the audit chain (§2.2), the key set (§2.3) and
  receipts (§5.5) exactly; the core refusal codes (§3).

**Extensions** (`PRE-GEN-EXTENSIONS.md`) are claimed by name on top of a
profile: the origin decision members and request members (X.2), decision
reuse (X.3, with R-9 and the origin P-7), end-user binding (X.4, with V-13),
evidence bundles (X.6), C2PA assertions (X.7), observations (X.8),
lifecycle events (X.9), `pg.receipt.v3`. An implementation that offers an
extension MUST implement it as specified.

A claim names the profile and the extensions, e.g. "PRE-GEN v5 Registry,
with evidence bundles and observations".

A conformance run that claims a profile MUST NOT skip an operation required
by that profile. An unsupported or skipped required operation is a failure,
not a successful check. The release runner's `--require-op` selects the
required operations; optional unsupported operations are reported as skips.

### 8.2 What the published checks cover

Passing the checks is necessary for a claim, **not sufficient**. The checks
are the vectors (`test-vectors/vectors.json`), replayed by the Level 1
runner, and the Level 2 HTTP scenarios (`conformance/`). Everything marked
"not checked" below rests on the implementer's reading of the text.

| Requirement | Checked by |
|---|---|
| §2 canonical JSON, §2.1 fingerprint | Level 1: `canonical_json`, `signing` vectors |
| V-2 decision signature | Level 1: `signing_verify:signed_decision_v1` |
| V-9 / §1.2 license signatures | Level 1: `license_countersignature` (subject + operator, and that the countersignature binds the id) |
| §2.2 audit event bytes and chaining | Level 1: `audit_event_genesis`, `audit_event_chained`; Level 2: `10_audit_chain_valid` |
| `PG-CODE.md` formatting and check character | Level 1: `pg_code` vectors |
| V-10, V-12, V-14 (who may issue which codes; the signed directory; revocation) | Level 1: `namespace` vectors — both directions of the issuer check, replayed and tampered directories, a revoked registry and a revoked key |
| R-1 | Level 2: `02_refusal_missing_prompt_hash`, `04_refusal_no_subject` |
| §5.1 caller authentication | Level 2: `03_refusal_no_pair` |
| R-3 (withdrawn only) | Level 2: `05_refusal_subject_withdrawn` |
| R-5 (allow with a license), scope | Level 2: `01_happy_path_verify`, `06_refusal_no_license`, `07_refusal_immutable_denial`, `08_refusal_scope_violation` |
| R-10 (accepting a receipt) | Level 2: `09_receipt_recorded` |
| R-2 opt-out priority; R-3 other statuses; R-4; R-6; R-7; R-8 echo; R-11; R-12; R-13; R-14; R-15; E-1; E-4 | **not checked** |
| V-1, V-3, V-4, V-11, E-3; P-5 to P-10; extension V-13 | **not checked** by the published Level 1/2 checks (client behaviour; local SDK regression tests are not a portable conformance operation) |
| §8.1 no skipped required operation | Runner `--require-op`; unsupported required operations fail, optional skips are counted separately |
| Extensions X.6 to X.9, `pg.receipt.v3` | **not checked** |

Level 2 sets up its subjects, licenses and connections through the origin
registry's own management endpoints, which v5 does not standardize. Against
another registry the setup steps have to be adapted; the checked requests
and answers are the standard's.

### 8.3 Independent implementation

PRE-GEN v5 has one production registry (PRAMPTA) and clients written
alongside it. No implementation built only from this text by another team
has yet passed the checks. Until one has, compatibility between independent
implementations is specified but **not demonstrated**.

*Informative:* how to run the checks is in
[`conformance/README.md`](conformance/README.md); CI runs them against the
four implementations in this repository.

---

## 9. Reference implementation status (informative)

What the origin registry, PRAMPTA, offers today — so that nothing in this
document is read as a claim about it. PRAMPTA implements the core and every
extension in `PRE-GEN-EXTENSIONS.md`; its policy (E-5) is summarised in X.1.

- **Custody.** Both custody modes are specified (§1.2). PRAMPTA registers
  new subjects in `managed` custody only; `self` custody registration is
  retired, and licenses signed under `self` custody earlier still verify.
- **C2PA.** PRAMPTA issues `pg.assertion.v1` (extension X.7). No end-to-end
  integration with a C2PA manifest has been tested.
- **Namespace.** PRAMPTA is the directory's origin entry and issues bare
  codes. The steward key is published (`PG-CODE.md` §9.1, 2026-10-03) and
  the directory on pregen.org is signed; at the time of writing it is at
  `sequence` 2, which adds the next PRAMPTA operator key and the successor
  steward key. The verification libraries `@pregen/verify` (npm) and
  `pregen` (PyPI) check it with the steward key built in (0.3.0 or later;
  0.4.0 adds the offline simulator; 0.5.0 checks revocation, V-14, and
  `critical`, E-3). `@prampta/sdk` 0.7.0 and later uses
  them through its opt-in `pregenDirectory` option (V-10 to V-12); it
  requires pinned operator keys and does not auto-discover a root. 0.8.0
  adds `generateAuthorized`, which follows P-9 for several subjects.
  Current versions are listed on pregen.org/docs/sdk. No registry or key is
  revoked, and no registry sends `critical`. The directory does not define
  freshness. Namespace membership is not evidence of rights-holder
  authority.
- **Anchoring.** Audit roots are submitted about hourly to public
  OpenTimestamps calendars, best effort (§10).
- **Opt-out cooling.** 14 days (`COOLING_PERIOD_DAYS`); a subject pause
  takes effect immediately.
- **Level 1 and Level 2** pass against PRAMPTA in CI.

---

## 10. Known limitations and planned extensions (non-normative)

**Nothing in this section is a requirement.** It states what v5 cannot do,
and what might be added later; proposed objects and fields named here exist
in no version, no vector and no check. An implementer building against
§§0–9 today is unaffected by everything below.

It is here because an implementer deserves to know where the edges are
before hitting one in production.

**Current limitations of the signed objects in §1:**

- **One subject per decision.** `SignedDecision.subject_id` (§1.1) and
  `ReceiptBody.subject_id` (§1.3) are each a single string. An output with
  several subjects is handled by several decisions sharing one
  `generation_id` (P-9); no single signed object states the whole set, and
  nothing splits rights or revenue between the subjects.
- **`output_hash` does not survive re-encoding.** It is a SHA-256 (§1.3),
  which is correct for proving a specific byte sequence was produced and
  useless for recognizing the same work after a transcode, crop, or
  platform re-encode. `watermark_embedded` records *that* a watermark was
  applied but never what it contains, so there is nothing to resolve
  against. C2PA's term for the durable form is a *soft binding*; PRE-GEN
  has no field for one.
- **A license cannot express commercial terms.** `pg.license.v2` (§1.2)
  carries scope, term, and obligations, but no rate, floor, or settlement
  terms — so commercial terms cannot be bound to the moment a decision was
  signed, only recorded elsewhere.
- **A decision is not single-use.** One receipt is accepted per decision
  (R-10), which limits what can be *reported* against it, not how many
  generations a provider runs under it. After the receipt, lifecycle events
  (§5.5) record later stages of the same output, but they are not signed by
  the provider, and there is no chain across several outputs or edits from
  one decision, which video and multi-step workflows need. Observations
  (extension X.8) chain events by `output_id` but are unsigned by the provider and
  carry no authorization.
- **Several registries may disagree.** Issuer prefixes (`PG-CODE.md` §9)
  prevent code collisions, not rights conflicts. When a provider knows that
  two registries hold the same person, a refusal from either prevails
  (P-10), and registries that find out SHOULD freeze new licences (R-15).
  But nothing tells a provider that two registries hold the same person:
  there is no shared identifier across registries, so the rule applies only
  when the provider finds it out.
- **An opt-out waits before it takes effect.** A new opt-out is `pending`
  for the registry's cooling period (reference: `COOLING_PERIOD_DAYS` = 14)
  and has no effect on decisions until `effective_from`
  (`backend/app/core/verify_engine.py`); providers are notified at
  registration. The immediate path is a subject pause (`paused`, refused
  before license resolution); protections for minors and immutable denials
  never depend on an opt-out. The two differ in who may use them: anyone
  claiming authority over a subject can file an opt-out, which is why it
  waits; only the subject's owner or the registry operator can pause it.
- **An opt-out or pause stops new decisions, not issued ones.** From its
  effective time every new decision for the subject refuses. A decision
  issued earlier stays usable until its `expires_at` (reference:
  `DECISION_TTL_SECONDS` = 300) and a cached plain allow up to
  `max_cache_age_seconds` (P-7), never past its `expires_at` (V-3); a provider learns a new `revocation_epoch`
  only from its next decision. Another registry holding the same person is
  not bound by it.
- **Self custody prevents a forged license, not a false allow.** A provider
  verifies the decision (V-2), not the license it names. A compromised
  registry can sign an `allow` naming a license that does not exist or that
  the subject never signed. Without a verifiable license and a trusted
  binding of the subject's key, such an allow cannot be independently
  confirmed. An evidence bundle (extension X.6) without a subject-signed license shows
  only that the bundle does not support the allow, not that no license ever
  existed; a compromised registry may withhold the bundle, and the subject
  key's binding is the registry's own statement. Preventing or proving such
  an allow needs mechanisms v5 does not specify.
- **Revocation reaches only verifiers that refresh.** The steward can
  revoke a registry or a key (`PG-CODE.md` §9.1, V-14), but a verifier
  learns of it only from a directory it fetches, and v5 does not say how
  often. An object's own `issued_at` does not show that it was signed before
  a theft, so everything a revoked key signed loses its authority, the
  genuine included; proving "signed before" with external timestamps is
  future work. Admission is the steward's judgement on the registry, not a
  check of each rights holder.
- **Legal overrides have no format.** A court may order generation despite
  an opt-out; v5 defines no record, decision, refusal code or conformance
  status for such an override, and the reference registry implements none.
- **Personal use is not linked to its decision.** A `not_blocked` decision
  has no receipt, and an observation may name a decision only if that
  decision has the provider's receipt (extension X.8), so an observation of personal
  use cannot point at the decision that answered it.
- **External anchoring is best effort.** Signed roots are submitted to
  OpenTimestamps calendars about hourly (`backend/app/core/anchor_publish.py`);
  an event is anchored only once a later accepted root includes it, and an
  outage leaves a root unpublished.
- **Managed custody proves key use, not consent** (§1.2, "Custody and
  consent").
- **Settlement has no signed object.** A decision dispute resolves against
  `pg.evidence.v1` (extension X.6). A disagreement about what was *owed* has no
  equivalent artifact.

**Proposed extensions.** A draft design addressing all four —
`pg.revenue.v1` (reporter-signed revenue attestation) and
`pg.settlement.v1` (operator-signed reconciliation statement), plus field
additions to License, Decision, Receipt, and Assertion — is in
[`docs/PRE-GEN-Revenue-Extensions-DRAFT.md`](../docs/PRE-GEN-Revenue-Extensions-DRAFT.md),
along with a per-object analysis against §6.1's versioning rules. One point
from it is worth stating here because it is a fact about *this* document
rather than about the proposal: of the four objects that would change, only
**Receipt** breaks. It is the one object with no additive-safety convention
(§1.3), so adding any field to it would be the first real use of the
dual-accept window §7 describes as built-but-dormant — with the
`Deprecation`/`Sunset` headers, `CHANGELOG` entry, and new PRE-GEN version
that §7 requires.
