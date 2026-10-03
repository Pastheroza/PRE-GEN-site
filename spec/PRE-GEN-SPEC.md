# PRE-GEN Protocol Specification

**Version:** PRE-GEN v5 draft (2026-10-03, becomes v5 when published on Zenodo) · Zenodo concept DOI
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

This document, with [`PG-CODE.md`](PG-CODE.md),
[`REFUSAL-CODES.md`](REFUSAL-CODES.md) and the test vectors, specifies the
PRE-GEN core — signed objects, canonical bytes, identifiers, verification,
decisions, receipts and key publication — completely enough that a
registry, a provider, or an independent verifier can be built **without
reading any registry's source code**. How a registry registers subjects,
issues licenses, accepts opt-outs and connects end users is registry policy
in v5, outside this core (§5.1, §8.2).

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

PRE-GEN v5 consists of four normative parts: this document; `PG-CODE.md`
(identifiers); `REFUSAL-CODES.md` (reason codes); and
`test-vectors/vectors.json` (byte-level examples). The paper
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

- **Registry** — holds subjects, licenses and opt-outs, answers
  verification requests with signed decisions, and keeps the audit log.
  **Operator** is the registry's signing identity (its Ed25519 key set, §2.3).
- **Provider** — an AI service that asks a registry before generating and
  reports afterwards. It authenticates with a credential the registry issued.
- **Licensee** — the party a license is issued to; typically the provider's
  end user, connected to the provider once (§5.1).
- **Verifier** — anyone checking a signed object offline: a provider, a
  rights-holder, an auditor, a court. A provider is always also a verifier.

---

## 1. Protocol objects

Five kinds of object are cryptographically signed in PRE-GEN. All five
share one canonicalization rule (§2) and one primitive (Ed25519, RFC 8032)
— what differs between them is *who* signs, *what's excluded* from the
signed bytes, and how strictly each is versioned.

| Object | Version marker field | Current value | Who signs | Additive-safe? |
|---|---|---|---|---|
| §1.1 Decision | `schema_version` | `pg.decision.v1` | Operator | Yes (new optional fields never bump it) |
| §1.2 License | `v` | `pg.license.v2` | Subject, countersigned by Operator | Partially — see §1.2 |
| §1.3 Receipt | `v` | `pg.receipt.v2` (default), `pg.receipt.v3` (opt-in) | Provider (optional), hashed by Operator | No |
| §1.4 Evidence bundle | `schema_version` | `pg.evidence.v1` | Operator | Not addressed |
| §1.5 Assertion | `schema_version` | `pg.assertion.v1` | Operator | Not addressed |

§1.6 Observation (`pg.observation.v1`) is a sixth, unsigned request object: the
registry signs only its own audit record of it.

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

**Field table:**

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | `pg.decision.v1` |
| `decision_id` | string | unique per decision |
| `nonce` | string | one-time-use token; a consumer must not reuse it |
| `allowed` | boolean | `true` only when `disposition == "allow"` |
| `disposition` | string | `"allow"` \| `"not_blocked"` \| `"review"` \| `"deny"` — `not_blocked` (with `PG_STD_TRACKING_ONLY`) is personal use that nothing prohibits and nothing grants; `allowed` stays a boolean, `true` only on `allow`, so an older client that only reads `allowed` treats the other three as not-allowed (fail-closed) |
| `policy_version` | string | which entry of the refusal-code registry (§6.2) produced this decision — independent of `schema_version`: the *rules* can change without the *envelope shape* changing |
| `reason` | string \| null | a `PG_*` code from §3, or null on allow |
| `subject_id` | string | |
| `licensee_id` | string | |
| `provider_id` | string | |
| `license_id` | string \| null | |
| `prompt_hash` | string | |
| `model` | string | |
| `modality` | string | |
| `intended_use` | object | echoes the request's `IntendedUse` |
| `obligations` | object | obligations the licensee must satisfy (watermarking, disclosure, …) |
| `rules_text` | string | display-only rights-holder text (never itself enforced — see `README.md`'s "Security notes") |
| `rules_text_hash` | string | SHA-256 hex of `rules_text`, empty string when `rules_text` is empty |
| `subject_authority` | string | `self` \| `agency_asserted` \| `consented` \| `verified` — how well the subject's real-world rights are proven, distinct from whether a license exists at all |
| `watermark_payload` | string \| null | |
| `is_hard_refusal` | boolean | from the refusal-code registry (§3) — `false` on allow |
| `issued_at` | integer | Unix seconds |
| `expires_at` | integer | Unix seconds; hard signature lifetime |
| `revocation_epoch` | integer | the subject's revocation counter at issuance; `0` on subject-less refusals |
| `max_cache_age_seconds` | integer | `0` for anything not a plain allow; shorter for a high-risk commercial allow than a routine one |
| `cache_scope` | string | `"exact_request"` (only a plain allow) \| `"not_cacheable"` |
| `provider_user_binding` | string | `"unbound"` \| `"verified"` \| `"invalid"` |
| `provider_identity_link_id` | string | |
| `generation_id` | string | echoed from the request |
| `detection_id` | string | echoed from the request |
| `operator_key_id` | string | the operator key fingerprint (§2.1) used to sign |
| `operator_signature` | string | Ed25519 signature, hex — **excluded from the signed bytes** |
| `remediation` | object \| null | populated only on `PG_NO_LICENSE`: where and how to fix exactly this refusal |

**Additive safety.** New *optional* fields never bump `schema_version` —
`generation_id`, `detection_id`, `provider_user_binding`, and `remediation`
were all added this way. A consumer MUST ignore the meaning of members it
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

**Not in the body.** The signatures themselves, the subject public key, the
operator key fingerprint, the license status, the issue time, and the
license id are carried beside the body and never inside it.

*Reference implementation:* `backend/app/core/license_body.py`
(`license_model_dump_for_signature`), `backend/app/core/license_mint.py`
(`finalize_license_signatures`).

**Always-present fields:**

| Field | Type |
|---|---|
| `subject_id` | string |
| `licensee_id` | string |
| `license_class` | string |
| `scope` | array of strings |
| `deny_categories` | array of strings |
| `immutable_denials` | array of strings |
| `required_obligations` | object |
| `expires_at` | integer |
| `contract_start` | integer |
| `product_name` | string |
| `project_name` | string |
| `purpose` | object |
| `extensions` | array of objects |
| `rules_text` | string |

**Conditionally-present fields** — included only when the underlying value
is not `None` (an additive-safe convention: a license row minted before a
field existed keeps verifying byte-for-byte, because the field is simply
absent from its signed body, not present-as-null):
`asset_visual_description` (only if non-empty after trimming to 4000
characters), `allowed_channels`, `allowed_territories`, `billing_terms`,
`entitlement_id`, `provider_identity_link_id`, `allowed_providers`,
`blocked_providers`, `allowed_modalities`, `allowed_regions_v2`,
`max_uses`, `concurrency_limit`, `transferability`, `sublicensing`,
`attribution_required`, `granted_rights`, `output_survives_termination`.

**The version marker is the body member `"v"`**, distinct from the
`schema_version` member of the API response that carries the license, so
the marker inside the signed bytes is never confused with response metadata.
It is the one exception to the conditional-inclusion rule above:

- A license signed before version markers existed has **no** `"v"` member,
  permanently. A verifier MUST reconstruct it without one.
- A current license has `"v": "pg.license.v2"`.
- A verifier MUST refuse (`PG_INVALID_SIGNATURE`) a license whose marker it
  does not recognize, rather than reconstructing it as either of the above.

A future marker that changes what a member *means* is a new value of `"v"`
with its own reconstruction rule, never a silent addition to v2.

**Version marker on the API response** is a different member,
`schema_version`, on the license detail response. It reports the same value
as `v` but is not signed; it describes the response, not the license.

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

**This object is NOT additive-safe today.** Unlike License, there is no
`if value is not None` inclusion convention here — every field is
unconditional, and a field that changes this dict's shape still ships live
the moment the change merges. What §7 now provides is not additive safety
itself, but a **migration mechanism** for when the shape does change: a
bounded dual-accept window (`backend/app/core/receipt_body.py`) during
which the server verifies a provider's signature against either the
current shape or a recent prior one, marking a fallback match with
`Deprecation`/`Sunset` headers — see §7 for the policy and
`docs/PROTOCOL-GOVERNANCE.md` for why Receipt gets a temporary window where
License gets a permanent per-row rule instead. *Informative:* a test worth
naming for any implementer building a receipt client:
`backend/tests/test_receipts.py::test_receipt_provider_signature_verified`
constructs its own independent copy of `receipt_body` (simulating a real
external provider, not sharing PRAMPTA's own construction code) — if your
client's `receipt_body` shape ever silently disagrees with the server's,
this is the kind of test that catches it, and is exactly why PRAMPTA keeps
its own copy of that test independent rather than importing a shared
helper.

### 1.4 EvidenceBundle (`pg.evidence.v1`)

**Purpose.** A self-contained, signed archive for one decision — everything
needed to independently verify it offline, for litigation or compliance
review: the decision itself, the license it resolved against (if any),
every audit event tied to it, a Merkle inclusion proof when one exists, and
the operator key material to check every signature.

Served at `GET /v1/audit/evidence/{decision_id}`. *Reference
implementation:* `backend/app/api/audit.py` (`get_decision_evidence`).

**What's excluded from the signed bytes.** `evidence_hash`,
`operator_signature`, and `operator_key_id` — these are computed from
`canonical_json(evidence)` and only added to the dict *afterward*, so
the signed bytes are the canonical JSON of the bundle without those three
members.

**Field table:**

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | `pg.evidence.v1` — genuinely signed, since this whole object is minted fresh at read time, not a pre-existing signed body being re-served |
| `decision_id` | string | |
| `policy_version` | string | from the decision's own audit metadata |
| `decision_event` | object | `event_id`, `action`, `metadata`, `timestamp`, `signature`, `signing_key_id` |
| `license` | object \| null | present only if the decision resolved against one; `null` on a subject-less or license-less refusal. When present it MUST carry `license_id`, `signed_body` (the exact license body of §1.2, or `null` for a license whose marker cannot be reconstructed), `subject_public_key_hex`, `subject_signature`, `operator_signature` and `signing_key_fingerprint`, so that both license signatures verify offline (V-9) |
| `related_events` | array of objects | every audit event tied to this decision, chronological |
| `inclusion_proof` | object \| null | Merkle inclusion proof when the audit anchor exists and is intact; degrades to `null` on a corrupted anchor chain **without** invalidating the rest of the bundle — the license/event evidence is independently useful even without a Merkle proof attached |
| `operator_keys` | object | the full signed key set (§2.3), so every signature in the bundle can be checked entirely offline |
| `evidence_hash` | string | SHA-256 hex of the canonicalized bundle — **excluded from the signed bytes** |
| `operator_signature` | string | **excluded from the signed bytes** |
| `operator_key_id` | string | **excluded from the signed bytes** |

### 1.5 Assertion (`pg.assertion.v1`)

**Purpose.** A signed statement a provider embeds inside its own C2PA
manifest. The registry produces only this statement; building and signing
the C2PA manifest is the provider's job, and PRE-GEN v5 does not specify
how the statement is placed in it. Deliberately bound to an
*existing* `GenerationReceipt` rather than a bare provider-submitted
output hash, so an assertion and its receipt can never disagree about what
was actually produced.

Issued at `POST /v1/assertions` for a decision that has a receipt. It is
idempotent: a repeated request MUST return the byte-identical original,
never a re-signed copy with a new `issued_at`. *Reference implementation:*
`backend/app/api/assertions.py` (`create_assertion`).

**Signed bytes.** The canonical JSON of the assertion without `signature`
and `signing_key_id`.

**All fields are always present:**

| Field | Type |
|---|---|
| `schema_version` | string, constant `"pg.assertion.v1"` |
| `assertion_id` | string |
| `decision_id` | string |
| `subject_id` | string |
| `license_id` | string \| null |
| `provider_id` | string |
| `model_id` | string |
| `decision` | string, hardcoded literal `"allow"` — only an allowed decision can ever have a receipt to bind to |
| `purpose` | string, derived from the bound decision's `intended_use.use_case` |
| `rules_snapshot_hash` | string, the hash of the exact rule inputs that produced the bound decision |
| `output_hash` | string, from the bound receipt |
| `issued_at` | string, ISO 8601 |

---

### 1.6 Observation (`pg.observation.v1`)

A usage report for an output that needs no license — personal use answered
`not_blocked` (`PG_STD_TRACKING_ONLY`), or an output the provider's own
detectors link to a subject. `POST /v1/observations`, with the provider's
credential (§5.1). **An observation never authorizes anything** and is not a
receipt. *Reference implementation:* `backend/app/api/observations.py`.

| Field | Type | Rule |
|---|---|---|
| `schema_version` | string | `"pg.observation.v1"` |
| `event_id` | string | `[A-Za-z0-9_.:-]{1,100}`, provider-unique; idempotency key |
| `output_id` | string | same charset; shared by every event of one output |
| `subject_id` | string | PG code or subject id |
| `event_type` | string | `output.created` \| `output.modified` \| `output.published` \| `publication.removed` |
| `output_hash` | string | 64 lowercase hex (SHA-256 of the output bytes) |
| `occurred_at` | RFC 3339 with offset | not more than 5 minutes in the future |
| `declared_purpose` | string | `personal` \| `commercial` \| `educational` \| `research` \| `editorial` \| `unknown` (default) |
| `parent_output_hash` | string \| absent | required on `output.modified`, differs from `output_hash`; forbidden otherwise |
| `publication_url` | string \| absent | required on the two publication events, forbidden otherwise; `https`, no credentials, query or fragment; never fetched by the registry |
| `decision_id` | string \| absent | accepted only if that decision already has this provider's receipt |
| `visual_match` | object \| absent | the provider's own look-alike finding: `method`, `confidence` 0–1, `basis`, `reference_ids` |

Unknown fields are rejected. Resending an `event_id` with the same payload
returns the existing record; with a different payload, `409`. The lifecycle
of one output is the set of its events sharing `output_id`, ordered by
`occurred_at`; `output.modified` links versions by hash.

The provider does not sign observations. The registry appends an
`observation_received` audit event, signed with its operator key, over the
SHA-256 of the canonical payload (§2), with `record_kind:
"usage_observation"` and `authorization: "not_granted_by_this_record"`. A
record whose audit event does not verify is reported as an integrity failure
(`PG_OBSERVATION_INTEGRITY_FAILED`), never shown as evidence. An observation
proves what the provider reported and when the registry received it, not that
the output exists or matches.

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

Every `PG_*` code `POST /v1/verify` can return as a `SignedDecision`'s
`reason` is documented in a companion, **generated** file:
**[`spec/REFUSAL-CODES.md`](REFUSAL-CODES.md)**.

The table is normative. A registry MUST use each code only with the
meaning the table gives it, and MUST add a new code to the table (§7)
before issuing it. No code count is stated here; count from the table.

*Reference implementation:* the table is generated from
`backend/app/core/policy_registry.py` (`RULES`) by
`spec/generate_refusal_table.py`, and a test fails if the two diverge.

Each entry carries: the code, its category (`request` / `identity` /
`subject_trust` / `license` / `review`), whether it's a **hard** refusal
(no retry, reshaped request, or license change fixes it) or **soft** (a
different request, license, or provider might succeed), the policy version
it was introduced in, and a plain-language description. A provider MUST
treat a code it does not find in the table as hard (P-6): failing closed is
the safer wrong answer.

---

## 4. PG-code grammar

The full identifier specification — alphabet, check-character algorithm,
worked examples, and the "resolved, never parsed" resolution rule — lives
in **[`spec/PG-CODE.md`](PG-CODE.md)**. This section adds a formal grammar
on top of that prose: an ABNF (RFC 5234) definition of the two current
shapes plus the two permanently-valid legacy shapes, and one canonical
regular expression meant to accept the same strings.

**Scope, stated precisely so as not to overclaim:** this grammar describes
*shape* — which strings look like a well-formed PG code. It does **not**,
and by construction **cannot**, capture check-character *validity* — the
check character is a weighted sum modulo 37 (`PG-CODE.md` §4), an
arithmetic property no regular expression can test. A string can be
shape-valid and still carry a wrong check character (a mistyped digit, a
transposed pair) — telling those two failure modes apart (`PG-CODE.md` §7:
"mistyped", distinctly from "not found") is exactly why resolution is a
two-step process: shape first, then a separate arithmetic check
(`app/core/pg_code.py::verify_check_char`). `backend/tests/
test_pg_code_grammar_matches_implementation.py` demonstrates precisely this
split — every vector in `vectors.json`'s `pg_code.rejects` section is
shape-valid (the regex matches it) *and* checksum-invalid (`verify_check_char`
returns `false` for it), on purpose.

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
| `intended_use` | object | `use_case` (`personal` \| `educational` \| `research` \| `editorial` \| `commercial`), `channel`, `product_name`, `project_name`, `territory`, `categories` (array), `modality`, `rights` (array; empty means output generation only), `campaign_id` — all optional strings unless stated |
| `generation_id` | string | the provider's own id for this attempt; echoed |
| `provider_user_id` / `provider_identity_link_id` | string | which connected user the provider acts for; if given, MUST resolve to a link the registry verified, and a license bound to another user is refused (`PG_IDENTITY_MISMATCH`) |
| `license_id` | string | optional hint; narrows candidate licenses, never widens them |
| `detection_id` | string | optional link to an earlier detection record; echoed, never used to decide |
| `idempotency_key` | string | echoed |
| `return_url` | string | where a `PG_NO_LICENSE` remediation link returns the user |

The response is always HTTP 200 with a signed decision (§1.1), whether the
answer is allow or a refusal; HTTP errors mean the request itself could not
be processed (malformed body, rate limit). A caller MAY send
`X-Prampta-Expected-Schema-Version: pg.decision.v1`; a registry that signs a
different decision schema MUST then answer HTTP 409 instead of a decision.
(The header name carries the origin registry's name for compatibility with
existing clients.)

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
  (`PG_ORG_INTERNAL_USE`: a member of the organization that itself holds a
  non-person subject). An allow MUST carry `allowed: true` and
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
- **R-9** `cache_scope` MUST be `not_cacheable` and `max_cache_age_seconds`
  `0` on anything other than a plain allow.

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
  it MUST NOT generate for this request.
- **P-6** A reason code absent from `REFUSAL-CODES.md` MUST be treated as
  hard.
- **P-7** A decision MAY be reused only for the identical request, only
  when `cache_scope` is `exact_request`, and only within
  `max_cache_age_seconds`.
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
- **V-13** If the provider sent `provider_user_id` or
  `provider_identity_link_id`, an `allow` is valid only when
  `provider_user_binding` is `"verified"` and `provider_identity_link_id`
  is a non-empty string. Otherwise the decision MUST be rejected.

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

**Later lifecycle events.** `POST /v1/receipts/{decision_id}/events` with
`event_type` (one of `preview`, `output_accepted`, `output_delivered`,
`output_published`) and optionally `output_hash` records a later stage of
the same receipted output. A registry MUST treat a repeated event as
already recorded, MUST refuse an `output_hash` that differs from the
receipt's (HTTP 409), and records the event in its audit log. Lifecycle
events are not signed by the provider.

### 5.6 Observations — `POST /v1/observations`

Uses that need no license are reported as observations (§1.6).

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
- **Evidence bundle / Assertion (`schema_version`).** Both are minted fresh
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
  privately to the editor (Pastheroza@gmail.com) before public disclosure;
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

- **PRE-GEN v5 Verifier** — V-1, V-2, V-3, V-4, V-9 to V-13; §2 and §2.1 exactly;
  PG codes parsed and checked as `PG-CODE.md` states.
- **PRE-GEN v5 Provider** — everything in Verifier, plus P-5, P-6, P-7,
  P-8, and §5.1–§5.2 on the wire. Receipts (§5.5) are RECOMMENDED;
  `pg.receipt.v3`, lifecycle events, observations (§1.6) and assertions
  (§1.5) are OPTIONAL features, each claimed by name.
- **PRE-GEN v5 Registry** — R-1 to R-14; decisions (§1.1), licenses
  (§1.2), the audit chain (§2.2), the key set (§2.3) and receipts (§5.5)
  exactly. Evidence bundles (§1.4), assertions (§1.5), observations (§1.6)
  and external anchoring are OPTIONAL features, each claimed by name; a
  registry that offers one MUST implement it as specified.

A claim names the profile and the optional features, e.g. "PRE-GEN v5
Registry, with evidence bundles and observations".

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
| V-10, V-12 (who may issue which codes; the signed directory) | Level 1: `namespace` vectors — both directions of the issuer check, replayed and tampered directories |
| R-1 | Level 2: `02_refusal_missing_prompt_hash`, `04_refusal_no_subject` |
| §5.1 caller authentication | Level 2: `03_refusal_no_pair` |
| R-3 (withdrawn only) | Level 2: `05_refusal_subject_withdrawn` |
| R-5 (allow with a license), scope | Level 2: `01_happy_path_verify`, `06_refusal_no_license`, `07_refusal_immutable_denial`, `08_refusal_scope_violation` |
| R-10 (accepting a receipt) | Level 2: `09_receipt_recorded` |
| R-2 opt-out priority; R-3 other statuses; R-4; R-6; R-7; R-8 echo; R-9; R-11; R-12; R-13; R-14 | **not checked** |
| V-1, V-3, V-4, V-11, V-13; P-5 to P-8 | **not checked** by the published Level 1/2 checks (client behaviour; local SDK regression tests are not a portable conformance operation) |
| §8.1 no skipped required operation | Runner `--require-op`; unsupported required operations fail, optional skips are counted separately |
| §1.4, §1.5, §1.6, lifecycle events, `pg.receipt.v3` | **not checked** |

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
document is read as a claim about it:

- **Custody.** Both custody modes are specified (§1.2). PRAMPTA registers
  new subjects in `managed` custody only; `self` custody registration is
  retired, and licenses signed under `self` custody earlier still verify.
- **C2PA.** PRAMPTA issues `pg.assertion.v1` (§1.5). No end-to-end
  integration with a C2PA manifest has been tested.
- **Namespace.** PRAMPTA is the directory's origin entry and issues bare
  codes. The TypeScript SDK source now provides an opt-in verified directory
  snapshot and namespace/endpoint checks (V-10 to V-12). It requires pinned
  operator keys plus an independently obtained steward key; it does not
  auto-discover a root. This is not yet a published SDK rollout. Python
  clients still rely on per-registry operator pins. The steward key is
  published (`PG-CODE.md` §9.1, 2026-10-03) and the directory on pregen.org
  is signed (`sequence` 1). The verification libraries `@pregen/verify`
  (npm) and `pregen` (PyPI) 0.1.0 check it with the steward key built in;
  the unpublished `@prampta/sdk` 0.7.0 uses them through its opt-in
  `pregenDirectory` option. v2 does not define freshness or key
  revocation. Namespace membership is not evidence of rights-holder authority.
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

- **One subject per decision.** `SignedDecision.subject_id` (§1.1),
  `ReceiptBody.subject_id` (§1.3), and `Assertion.subject_id` (§1.5) are
  each a single string. An output derived from more than one registered
  subject cannot be represented — not as a split, not as a fact. Any
  implementation that needs this today must model it outside the protocol.
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
  (§1.6) chain events by `output_id` but are unsigned by the provider and
  carry no authorization.
- **Several registries may disagree.** Issuer prefixes (`PG-CODE.md` §9)
  prevent code collisions, not rights conflicts: two registries can hold
  the same person and answer differently, and v5 defines no rule for which
  answer prevails, no shared opt-out, and no dispute freeze.
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
  confirmed. An evidence bundle (§1.4) without a subject-signed license shows
  only that the bundle does not support the allow, not that no license ever
  existed; a compromised registry may withhold the bundle, and the subject
  key's binding is the registry's own statement. Preventing or proving such
  an allow needs mechanisms v5 does not specify.
- **A stolen key cannot be revoked.** A stolen operator or steward key keeps
  producing valid signatures. Announcing the next key (`PG-CODE.md` §9.1)
  prepares a planned rotation; it does not stop the old key, v5 defines no
  revoked status for a listed key, and an object's own `issued_at` does not
  show that it was signed before a theft.
- **Legal overrides have no format.** A court may order generation despite
  an opt-out; v5 defines no record, decision, refusal code or conformance
  status for such an override, and the reference registry implements none.
- **Personal use is not linked to its decision.** A `not_blocked` decision
  has no receipt, and an observation may name a decision only if that
  decision has the provider's receipt (§1.6), so an observation of personal
  use cannot point at the decision that answered it.
- **External anchoring is best effort.** Signed roots are submitted to
  OpenTimestamps calendars about hourly (`backend/app/core/anchor_publish.py`);
  an event is anchored only once a later accepted root includes it, and an
  outage leaves a root unpublished.
- **Managed custody proves key use, not consent** (§1.2, "Custody and
  consent").
- **Settlement has no signed object.** A decision dispute resolves against
  `pg.evidence.v1` (§1.4). A disagreement about what was *owed* has no
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
