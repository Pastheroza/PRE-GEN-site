# PRE-GEN extensions

**Version:** PRE-GEN v5 draft (2026-10-04) · companion to
[`PRE-GEN-SPEC.md`](PRE-GEN-SPEC.md) · Apache License 2.0.

The core (`PRE-GEN-SPEC.md`) is what every authorization registry,
provider and verifier implements. This document holds what a registry
**adds**: the rules any extension must follow are in the core (§0.5, E-1 to
E-6); the extensions themselves are here. An implementation claims an
extension by name (core §8.1); one that claims none is fully conformant.

Every requirement keeps the identifier it had before the core was
separated (2026-10-04), so references in code and documents stay valid.
`§n` refers to a section of the core document, `X.n` to this one.

## X.1 The origin registry profile (PRAMPTA)

PRAMPTA, the origin registry, implements every extension below. Its
refusal codes beyond the core set are the origin rows of
[`REFUSAL-CODES.md`](REFUSAL-CODES.md). Its published policy (core E-5):
decisions live 300 seconds; an opt-out waits 14 days, a pause is
immediate; on a licence with `max_uses` every `allow` counts, and an unused
one can be given back before a receipt and within 24 hours
(`POST /v1/receipts/{decision_id}/release`, recorded in the audit log); new
subjects are registered in `managed` custody only.

## X.2 Decision members

Optional members the origin registry adds to every decision (core §1.1,
E-2). Each is signed; a verifier that does not use one ignores it.

| Field | Type | Notes |
|---|---|---|
| `rules_text` | string | display-only rights-holder text, never itself enforced |
| `rules_text_hash` | string | SHA-256 hex of `rules_text`, empty string when `rules_text` is empty |
| `watermark_payload` | string \| null | |
| `is_hard_refusal` | boolean | from the refusal-code table — `false` on allow |
| `revocation_epoch` | integer | the subject's revocation counter at issuance; `0` on subject-less refusals |
| `max_cache_age_seconds` | integer | X.3 |
| `cache_scope` | string | X.3 |
| `provider_user_binding` | string | `"unbound"` \| `"verified"` \| `"invalid"` (X.4) |
| `provider_identity_link_id` | string | X.4 |
| `detection_id` | string | echoed from the request |
| `remediation` | object \| null | populated only on `PG_NO_LICENSE`: where and how to fix exactly this refusal |

Request members the origin registry accepts in addition to the core ones
(core §5.2): `provider_user_id` / `provider_identity_link_id` (X.4),
`detection_id` (an earlier detection record; echoed, never used to decide),
`idempotency_key` (echoed), `return_url` (where a `PG_NO_LICENSE`
remediation link returns the user), and `intended_use` members
`product_name`, `project_name`, `campaign_id`. A caller MAY send
`X-Prampta-Expected-Schema-Version: pg.decision.v1`; the registry then
answers HTTP 409 if it signs a different decision schema.

Organization-internal use (`PG_ORG_INTERNAL_USE`) is an origin policy grant
under core R-5(b): a member of the organization that itself holds a
non-person subject, never a person's likeness or voice.

## X.3 Reusing a decision (cache)

The core lets a decision be reused only as an extension permits (core
P-7). The origin registry permits it this way:

- **R-9** `cache_scope` MUST be `not_cacheable` and `max_cache_age_seconds`
  `0` on anything other than a plain allow.
- **P-7 (origin)** A decision MAY be reused only for the identical request,
  only when `cache_scope` is `exact_request`, only within
  `max_cache_age_seconds`, and never past `expires_at`.

`revocation_epoch` is the subject's counter at issuance; comparing it with
`GET /v1/subjects/{id}/epoch` tells a provider cheaply whether anything
happened since.

## X.4 End-user binding

A provider may say which connected end user it acts for
(`provider_user_id` or `provider_identity_link_id`). If given, it MUST
resolve to a link the registry verified, and a license bound to another
user is refused (`PG_IDENTITY_MISMATCH`).

- **V-13** If the provider sent `provider_user_id` or
  `provider_identity_link_id`, an `allow` is valid only when
  `provider_user_binding` is `"verified"` and `provider_identity_link_id`
  is a non-empty string. Otherwise the decision MUST be rejected.

How an end user is connected to a provider (a one-time authorization code,
in the manner of OAuth 2.0) is described in PRAMPTA's
`docs/licensing-integration.md`.

## X.5 How the origin registry builds a licence body

The core verifies a licence over its body as carried (core §1.2). This is
how the origin registry builds that body, which matters only to an
implementation that rebuilds bodies from stored records.

**Always-present members:** `subject_id`, `licensee_id`, `license_class`,
`scope`, `deny_categories`, `immutable_denials`, `required_obligations`,
`expires_at`, `contract_start`, `product_name`, `project_name`, `purpose`,
`extensions`, `rules_text`.

**Members present only when set** (so a licence minted before a member
existed keeps verifying byte for byte, because the member is absent from its
signed body, not present as null): `asset_visual_description` (only if
non-empty after trimming to 4000 characters), `allowed_channels`,
`allowed_territories`, `billing_terms`, `entitlement_id`,
`provider_identity_link_id`, `allowed_providers`, `blocked_providers`,
`allowed_modalities`, `allowed_regions_v2`, `max_uses`,
`concurrency_limit`, `transferability`, `sublicensing`,
`attribution_required`, `granted_rights`, `output_survives_termination`.

**The version marker** `v` is the one exception: a licence signed before
markers existed has no `v` member, permanently, and is rebuilt without one;
a current licence has `"v": "pg.license.v2"`. The licence detail response
also reports the value as `schema_version`, unsigned.

*Reference implementation:* `backend/app/core/license_body.py`,
`backend/app/core/license_mint.py`.

### X.6 EvidenceBundle (`pg.evidence.v1`)

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


### X.7 Assertion (`pg.assertion.v1`)

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


### X.8 Observation (`pg.observation.v1`)

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


## X.9 Receipt lifecycle events

**Later lifecycle events.** `POST /v1/receipts/{decision_id}/events` with
`event_type` (one of `preview`, `output_accepted`, `output_delivered`,
`output_published`) and optionally `output_hash` records a later stage of
the same receipted output. A registry MUST treat a repeated event as
already recorded, MUST refuse an `output_hash` that differs from the
receipt's (HTTP 409), and records the event in its audit log. Lifecycle
events are not signed by the provider.


## X.10 Registering a new extension

An extension used by more than one registry is added to this document with
a name, its members, its requirements and the registries that implement it
(core E-6). A registry's private extension needs only its published policy
(core E-5).
