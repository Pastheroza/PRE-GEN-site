# PRE-GEN Protocol Specification

**Version:** PRE-GEN v5 (2026-09-28) · Zenodo concept DOI
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

This document specifies PRE-GEN's signed protocol objects, its
canonicalization rule, its refusal codes, and its identifier format,
completely enough that an implementer can build a compatible client or
server **without reading PRAMPTA's source code**. Every claim below cites
its normative source in the reference implementation (a file and a function
name, not a line number, since line numbers move and this doc shouldn't go
stale over a refactor that doesn't change behavior) — where this prose and
`spec/test-vectors/vectors.json` disagree, **the vectors win**, the same
rule [`spec/PG-CODE.md`](PG-CODE.md) already states for itself.

This is **Phase 6**, the last of the six-phase standardization effort as
originally scoped. What exists today: this document, the refusal-code
table and PG-code grammar (Phase 1), a compatibility/deprecation policy
plus a security-advisory process (§6, Phase 2), a standalone conformance
suite (§7, Phase 3), a released SDK pipeline (Phase 4,
`docs/PROTOCOL-GOVERNANCE.md` "Publishing"), PG-code ergonomics — a
reserved range, a public resolver, `.well-known` policy, QR/homoglyph
guidance (`spec/PG-CODE.md` §§11–13, Phase 5) — and property-based +
fuzz testing (Phase 6: hypothesis/fast-check property tests for
canonicalization and the check-character algorithm, plus fuzzing that
found and fixed three real robustness bugs — see
`PRAMPTA_STRATEGIC_TRUST_PLAN.md` §17 for the detail). One item remains
explicitly deferred rather than silently dropped: standalone
zero-dependency `pg-code` packages (Phase 5.5) — neither SDK has any
pg-code logic today, and building real packages with their own
vector-replay tests is a deliverable on the scale of Phase 4 repeated,
not a small addition. Property-based coverage of license-term/policy
combinations (as opposed to the crypto layer underneath them) is
similarly real, separate, tracked work, not claimed as done here.

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

**Normative source.** `backend/app/api/verify.py`, class `SignedDecision`
and function `_build_signed_decision`. The Pydantic model IS the signed
body — there is no separate wire-format struct; every field below is both
signed and returned to the caller.

**What's excluded from the signed bytes.** Exactly one field:
`operator_signature` itself, via `decision.model_dump(exclude=
{"operator_signature"})` before signing. Every other field, including
`operator_key_id` (set before signing), is part of the signed bytes.

**Field table:**

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | `pg.decision.v1` |
| `decision_id` | string | unique per decision |
| `nonce` | string | one-time-use token; a consumer must not reuse it |
| `allowed` | boolean | `true` only when `disposition == "allow"` |
| `disposition` | string | `"allow"` \| `"not_blocked"` \| `"review"` \| `"deny"` — `not_blocked` (with `PG_STD_TRACKING_ONLY`) is personal use that nothing prohibits and nothing grants; `allowed` stays a boolean, `true` only on `allow`, so an older client that only reads `allowed` treats the other three as not-allowed (fail-closed) |
| `policy_version` | string | which entry of the refusal-code registry (§5.2) produced this decision — independent of `schema_version`: the *rules* can change without the *envelope shape* changing |
| `reason` | string \| null | a `PG_*` code from §5, or null on allow |
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
| `is_hard_refusal` | boolean | from the refusal-code registry (§5) — `false` on allow |
| `issued_at` | integer | Unix seconds |
| `expires_at` | integer | Unix seconds; hard signature lifetime |
| `revocation_epoch` | integer | the subject's revocation counter at issuance; `0` on subject-less refusals |
| `max_cache_age_seconds` | integer | `0` for anything not a plain allow; shorter for a high-risk commercial allow than a routine one |
| `cache_scope` | string | `"exact_request"` (only a plain allow) \| `"not_cacheable"` |
| `provider_user_binding` | string | `"unbound"` \| `"verified"` \| `"invalid"` |
| `provider_identity_link_id` | string | |
| `generation_id` | string | echoed from the request |
| `detection_id` | string | echoed from the request |
| `operator_key_id` | string | the operator key fingerprint (§2.4) used to sign |
| `operator_signature` | string | Ed25519 signature, hex — **excluded from the signed bytes** |
| `remediation` | object \| null | populated only on `PG_NO_LICENSE`: where and how to fix exactly this refusal |

**Additive safety.** New *optional* fields never bump `schema_version` —
`generation_id`, `detection_id`, `provider_user_binding`, and `remediation`
were all added this way. An implementation must ignore fields it doesn't
recognize and default fields it expects but doesn't find. `schema_version`
only changes if a field is removed or its *meaning* changes.

### 1.2 LicenseBody (`pg.license.v2`)

**Purpose.** The terms a subject's owner grants a licensee — signed by the
subject (proving the rights holder agreed to exactly these terms) and
countersigned by the operator (proving PRAMPTA issued it).

**Normative source.** `backend/app/core/license_body.py`, function
`license_model_dump_for_signature(license_row)` — reconstructs the exact
signed body from a stored license row. This is the function both mint time
(to sign) and verify time (to re-verify) call; there is no separate
"build" path that could drift from the "reconstruct" path.

**What's excluded from the signed bytes.** The License database row has
several columns that never enter the signed dict at all:
`subject_signature`, `subject_public_key_hex`, `operator_signature`,
`signing_key_fingerprint`, `status`, `issued_at`, the internal `id`, and
`license_id` itself.

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

**The version marker field is named `"v"`, not `"schema_version"`** — a
deliberate naming split from the response wrapper (see below), made so a
future implementation can never confuse "the field named `schema_version`
on the API response" with "the field that's actually inside the signed
bytes." Its inclusion rule is the **one deliberate exception** to the
additive-safe convention above:

```
if license_row.schema_version is None:
    # legacy: pre-versioning row. Reconstructs WITHOUT "v" — permanently,
    # not as a migration-in-progress placeholder. Real historical fact
    # about that specific row.
    pass
elif license_row.schema_version == "pg.license.v2":
    body_dict["v"] = license_row.schema_version
else:
    # A value this code doesn't recognize (typo, corruption, or a real
    # future v3) refuses rather than silently reconstructing as legacy.
    raise UnsupportedSchemaVersion(license_row.schema_version)
```

A future `v3` — one that changes what a field *means*, not just adds a new
one — gets its own explicit branch in this same function, not a bare field
addition. An implementer building a v3 parser should look for exactly this
branch point.

**Version marker on the API response** is a *different* field,
`schema_version`, on the `/v1/licenses/{id}` detail response — reports the
same value as `v` today, but is not itself part of the signed bytes; it's
metadata about the response, not the license.

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
  both. A verifier that needs proof of the subject's own act must require
  `self` custody.

### 1.3 ReceiptBody (`pg.receipt.v2` / `pg.receipt.v3`)

**Purpose.** A provider's attestation that a generation actually happened,
bound to a specific decision — the compliance measurement PRAMPTA compares
against decisions issued (decisions-vs-receipts ratio).

**Normative source.** `backend/app/core/receipt_body.py`, functions
`_build_v2` and `_build_v3`, selected by `backend/app/api/receipts.py`'s
`submit_receipt`.

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
the moment the change merges. What §6 now provides is not additive safety
itself, but a **migration mechanism** for when the shape does change: a
bounded dual-accept window (`backend/app/core/receipt_body.py`) during
which the server verifies a provider's signature against either the
current shape or a recent prior one, marking a fallback match with
`Deprecation`/`Sunset` headers — see §6 for the policy and
`docs/PROTOCOL-GOVERNANCE.md` for why Receipt gets a temporary window where
License gets a permanent per-row rule instead. A test worth naming
explicitly for any implementer building a receipt client:
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

**Normative source.** `backend/app/api/audit.py`, handler
`get_decision_evidence` (`GET /v1/audit/evidence/{decision_id}`).

**What's excluded from the signed bytes.** `evidence_hash`,
`operator_signature`, and `operator_key_id` — these are computed from
`canonical_json(evidence)` and only added to the dict *afterward*, so
they're excluded by construction order, not an explicit exclusion list (a
different mechanism from Decision's `.model_dump(exclude=...)`, worth
knowing if you're implementing this from the Python source rather than this
doc).

**Field table:**

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | `pg.evidence.v1` — genuinely signed, since this whole object is minted fresh at read time, not a pre-existing signed body being re-served |
| `decision_id` | string | |
| `policy_version` | string | from the decision's own audit metadata |
| `decision_event` | object | `event_id`, `action`, `metadata`, `timestamp`, `signature`, `signing_key_id` |
| `license` | object \| null | present only if the decision resolved against one; `null` on a subject-less or license-less refusal |
| `related_events` | array of objects | every audit event tied to this decision, chronological |
| `inclusion_proof` | object \| null | Merkle inclusion proof when the audit anchor exists and is intact; degrades to `null` on a corrupted anchor chain **without** invalidating the rest of the bundle — the license/event evidence is independently useful even without a Merkle proof attached |
| `operator_keys` | object | the full signed key set (§2.4), so every signature in the bundle can be checked entirely offline |
| `evidence_hash` | string | SHA-256 hex of the canonicalized bundle — **excluded from the signed bytes** |
| `operator_signature` | string | **excluded from the signed bytes** |
| `operator_key_id` | string | **excluded from the signed bytes** |

### 1.5 Assertion (`pg.assertion.v1`)

**Purpose.** A signed statement a provider embeds inside its own C2PA
manifest — PRAMPTA does not implement C2PA itself; this endpoint produces
only the signed statement the manifest carries. Deliberately bound to an
*existing* `GenerationReceipt` rather than a bare provider-submitted
output hash, so an assertion and its receipt can never disagree about what
was actually produced.

**Normative source.** `backend/app/api/assertions.py`, function
`create_assertion`, the `body` dict (`POST /v1/assertions`). Idempotent —
re-requesting the assertion for an already-receipted decision returns the
byte-identical original, never re-signed with a new `issued_at`.

**What's excluded from the signed bytes.** `signature` and `signing_key_id`
— never added to the `body` dict before signing, the same construction-
order exclusion pattern as EvidenceBundle.

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
credential (`Authorization: Bearer`, `X-Provider-Id`). Source:
`backend/app/api/observations.py::ObservationRequest`. **An observation never
authorizes anything** and is not a receipt.

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

**Normative source.** `backend/app/core/crypto.py`, function
`canonical_json`.

1. **Serialize as JSON** with:
   - Object keys sorted (Python: `sort_keys=True` — lexicographic by
     Unicode code point).
   - No whitespace: comma and colon separators with no padding
     (`separators=(",", ":")`).
   - Non-ASCII *characters* left as raw UTF-8, never `\uXXXX`-escaped
     (`ensure_ascii=False`).
   - Numbers in a signed body are **integers only** — floats are never
     serialized in a signed object anywhere in this protocol, because
     float-to-string formatting is not portable across languages.
2. **Encode the result as UTF-8 bytes.**
3. **Hash** with SHA-256, rendered as lowercase hex.
4. **Sign** with Ed25519 (RFC 8032, deterministic — the same message and
   key always produce the same signature bytes) over the canonical JSON
   bytes of the body, **with the signature field itself excluded** from
   what gets signed (each §1 subsection above states exactly how its
   object excludes its own signature field — the mechanism differs
   between objects, the principle doesn't).

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
`SHA-256(raw 32-byte Ed25519 public key)`. Normative source:
`backend/app/core/crypto.py`, class `OperatorKeyStore`, property
`fingerprint`.

### 2.2 Audit chain

Each audit event's `prev_hash` is the SHA-256 of the previous event's
canonical JSON bytes; the very first event in the chain uses the literal
string `"genesis"`, not a hash of anything.

### 2.3 Signed key set

`GET /v1/keys` returns the full history of operator keys (current plus
retired), itself canonicalized and signed by the *current* key — so a
client polling for rotation can verify the rotation announcement itself,
not just trust an unsigned HTTP response. See
`docs/Operator-Key-Rotation-Runbook.md` for the operational procedure this
protects.

---

## 3. Refusal codes

Every `PG_*` code `POST /v1/verify` can return as a `SignedDecision`'s
`reason` is documented in a companion, **generated** file:
**[`spec/REFUSAL-CODES.md`](REFUSAL-CODES.md)**.

That file is produced by `spec/generate_refusal_table.py` directly from
`backend/app/core/policy_registry.py`'s `RULES` registry — the same
"backend is the source of truth" discipline `spec/generate_vectors.py`
already applies to the crypto vectors. `backend/tests/
test_refusal_table_matches_registry.py` regenerates the table on every test
run and fails if it disagrees with the committed file, so a new refusal
code registered without regenerating the table is a build failure, not a
silent doc drift.

**Deliberately no code count is stated in this prose** — count from the
table itself; a number written here would go stale the moment one more
code is registered, which is exactly the kind of doc/code drift this whole
phase exists to eliminate.

Each entry carries: the code, its category (`request` / `identity` /
`subject_trust` / `license` / `review`), whether it's a **hard** refusal
(no retry, reshaped request, or license change fixes it) or **soft** (a
different request, license, or provider might succeed), the policy version
it was introduced in, and a plain-language description. An **unregistered**
code is treated as hard by `policy_registry.is_hard_refusal()` — fail
closed on the safer wrong answer, never silently retryable-by-default.

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

## 5. Versioning rules

What bumps a version marker, per object — condensed from
`docs/PRAMPTA-Protocol-Versions.md`'s fuller treatment (that document also
covers surfaces outside this spec's current scope, like Identity Assertion
and Entitlement's shared `audience` check).

### 5.1 Per-object rules

- **Decision (`schema_version`).** Bumps only when a field is *removed* or
  an existing field's *meaning* changes. Adding a new optional field never
  bumps it (§1.1) — this is the strongest additive-safety guarantee in the
  protocol.
- **License (`v`).** Everything except `v` itself follows the
  `if value is not None` additive convention (§1.2) — a new optional field
  never breaks an old signature. `v` itself is the deliberate exception: a
  row with `schema_version IS NULL` (signed before this marker existed)
  permanently reconstructs *without* `v`, forever — not a migration window,
  a real historical fact about that row. A `v3` that changes a field's
  *meaning* (not just adds one) gets an explicit new branch in
  `license_model_dump_for_signature`, never a silent addition to the `v2`
  branch.
- **Receipt (`v`).** Not additive-safe today (§1.3) — any change to
  `receipt_body`'s shape ships live the moment it merges. §6 (stub) is
  where a deprecation window and dual-accept mechanism for this object are
  planned.
- **Evidence bundle / Assertion (`schema_version`).** Both are minted fresh
  at read/issue time rather than re-serving a pre-existing signed body, so
  neither carries the same retroactive-invalidation risk License does — no
  additive-safety convention has been needed yet.

### 5.2 Policy version (distinct from schema version)

`policy_version` (§1.1, §3) versions the *rules* `/verify` applies —
independent of `schema_version`, which versions the *shape* of the decision
envelope. A decision can always be read against the exact rule set that
produced it, even long after the rules have changed, because both are
stamped on it. Normative source: `backend/app/core/policy_registry.py`'s
append-only `POLICY_HISTORY` — `spec/REFUSAL-CODES.md`'s "Policy version
history" table is generated from the same list.

---

## 6. Governance

Full policy: [`docs/PROTOCOL-GOVERNANCE.md`](../docs/PROTOCOL-GOVERNANCE.md).
Summary:

- **Deprecation windows differ by object**, matching each object's
  retroactive-invalidation risk (§1): License changes a meaning-bump
  permanently, per row (`schema_version IS NULL` reconstructs without `v`
  forever — not a migration window, a historical fact about that row).
  Receipt gets a **bounded, proposed 90-day dual-accept window**
  (`backend/app/core/receipt_body.py`) instead, since a receipt is verified
  once at submission and never re-verified later — the server can afford
  to accept a signature over either the current or a recent prior shape
  for a while, and say so.
- **Announcing a breaking change** moves three things together:
  `Deprecation`/`Sunset` response headers during the window, a
  [`spec/CHANGELOG.md`](CHANGELOG.md) entry, and the next PRE-GEN version
  ([`spec/VERSIONS.md`](VERSIONS.md)) saying what an implementation must change.
- **Security advisories**: [`/SECURITY.md`](../SECURITY.md) — contact,
  scope (the spec itself is explicitly in scope, not just running code),
  and response SLA.

The dual-accept mechanism is tested, but v2 and opt-in v3 currently coexist
without deprecation. The 90-day sunset remains a proposal, not an active
deadline. A future breaking retirement must follow
`docs/PROTOCOL-GOVERNANCE.md` and announce a real sunset date.

---

## 7. Conformance

**[`spec/conformance/`](conformance/README.md)** — a standalone artifact,
separate from any single implementation's own internal test suite. Two
independent levels, stated there in full: if your implementation passes
Level 1 (offline, a CLI adapter protocol replaying `vectors.json`), it's
compatible at the crypto/pg-code layer; if it also passes Level 2 (HTTP
scenarios against a live server — a representative subset of refusal
codes, not all 36, stated honestly rather than overclaimed), it's
compatible as a service. Wired into CI
(`.github/workflows/ci.yml`'s `conformance` job) against all four
implementations named in `spec/README.md`.

---

## 8. Known limitations and planned extensions (non-normative)

**Nothing in this section is normative.** No object or field named here
exists in the reference implementation, in `spec/test-vectors/vectors.json`,
or in `spec/conformance/`. This section is not a normative change and needs
no new version: describing what the protocol cannot currently do is not one. An
implementer building against §§1–7 today is unaffected by everything below.

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
  (§1.3), which limits what can be *reported* against it, not how many
  generations a provider runs under it. A receipt names one lifecycle
  event; there is no signed chain from decision to generation to output to
  its later events (preview, edit, publication), which video and
  multi-step workflows need. Observations (§1.6) chain events by
  `output_id` but are unsigned by the provider and carry no authorization.
- **Several registries may disagree.** Issuer prefixes (`PG-CODE.md` §9)
  prevent code collisions, not rights conflicts: two registries can hold
  the same person and answer differently, and v5 defines no rule for which
  answer prevails, no shared opt-out, and no dispute freeze.
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
along with a per-object analysis against §5.1's versioning rules. One point
from it is worth stating here because it is a fact about *this* document
rather than about the proposal: of the four objects that would change, only
**Receipt** breaks. It is the one object with no additive-safety convention
(§1.3), so adding any field to it would be the first real use of the
dual-accept window §6 describes as built-but-dormant — with the
`Deprecation`/`Sunset` headers, `CHANGELOG` entry, and new PRE-GEN version
that §6 requires.
