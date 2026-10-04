<!-- GENERATED FILE — do not hand-edit. Regenerate with: -->
<!--   backend/.venv/bin/python spec/generate_refusal_table.py -->
<!-- Source of truth: backend/app/core/policy_registry.py -->

# PRE-GEN refusal codes

Every `PG_*` code `POST /v1/verify` can return as a decision's `reason`,
generated from the live policy registry so this table cannot drift from
what the server actually does. **Do not hand-edit** — see
`spec/generate_refusal_table.py`.

Current policy version: `2026-09-22`. `policy_version` on a signed
decision names the exact rule set in force when it was made — see
`spec/PRE-GEN-SPEC.md` §5 for what bumps it.

An unregistered code is treated as a HARD refusal by
`policy_registry.is_hard_refusal()` — fail-closed on the safer wrong
answer, not on retryable-by-default.

| Code | Category | Hard/Soft | Introduced | Description |
|---|---|---|---|---|
| `PG_CONCURRENCY_LIMIT` | license | Soft | 2025-05-01 | The license's concurrent in-flight generation cap is reached. |
| `PG_ENTITLEMENT_INACTIVE` | identity | Hard | 2025-06-01 | The purchase (entitlement) backing this request is no longer active — reversed or expired. |
| `PG_EXTENSION_REFUSED` | license | Soft | 2025-05-01 | A license extension (e.g. a region rider) evaluated and refused this request. |
| `PG_HELD_FOR_REVIEW` | review | Soft | 2026-07-24 | A commercial generation of a high-risk subject that would otherwise be ALLOWED is held for a human (opt-in, REVIEW_HIGH_RISK_COMMERCIAL). |
| `PG_IDENTITY_MISMATCH` | identity | Soft | 2026-07-26 | The licence belongs to a different end user than the one the caller is acting for — cross-user reuse. Also raised when a request supplies both a link id and a provider user id that describe different people. |
| `PG_IDENTITY_REQUIRED` | identity | Soft | 2026-07-26 | The licence is bound to a specific end user, and REQUIRE_PROVIDER_USER_BINDING is on, so the caller must say which user it is acting for. Supply provider_user_id or provider_identity_link_id. |
| `PG_IDENTITY_REVOKED` | identity | Hard | 2025-06-01 | The provider disowned this end user's identity link (Identity v2 §7). |
| `PG_IDENTITY_UNKNOWN` | identity | Soft | 2026-07-26 | The caller asserted an end-user identity that does not resolve to any live identity link for this provider — the user has not completed the PRAMPTA connect flow, or the link was deleted. |
| `PG_IMMUTABLE_DENIAL` | license | Hard | 2025-01-01 | The request's declared category matches one of the license's immutable (never-grantable) denials. |
| `PG_INSUFFICIENT_AUTHORITY` | subject_trust | Soft | 2025-10-01 | The subject's authority/verification tier does not meet the bar this request needs. |
| `PG_INVALID_SIGNATURE` | license | Hard | 2025-01-01 | A license was found but its signature does not verify. |
| `PG_LICENSE_REVOKED` | license | Hard | 2025-09-15 | A live revocation (full or partial — this provider/modality/channel/region) withdraws this license (A7). |
| `PG_MISSING_CONTEXT` | license | Soft | 2025-04-01 | The license restricts a dimension (modality/channel/territory/use case) and the request omitted it — fail-closed rather than let an omission bypass a restriction. |
| `PG_MISSING_PROMPT_HASH` | request | Soft | 2025-01-01 | The request did not include a prompt_hash to bind the decision to. |
| `PG_NO_LICENSE` | license | Soft | 2025-01-01 | No valid, live license authorizes this licensee for this subject. |
| `PG_NO_PAIR` | identity | Soft | 2025-01-01 | No live provider↔licensee pair authorizes this caller. |
| `PG_NO_SUBJECT` | subject_trust | Soft | 2025-01-01 | No registered subject matches subject_id. Not a prohibition: this registry knows nothing about the subject, so the provider decides under its own policy and must not present the output as licensed (spec P-5). |
| `PG_ORG_INTERNAL_USE` | grant | Soft | 2026-09-25 | ALLOWED without a licence: the connected user is an owner, admin or creator of the organization that itself holds this character, brand or work (never a person's likeness or voice). Ends when they leave the organization or lose the role. core/authz.py::org_internal_user. |
| `PG_OWNER_NOT_VERIFIED` | subject_trust | Soft | 2026-08-19 | Commercial use also requires the subject's owning account itself to be verified (identity-verified user, or domain/kyc-tier organization) — the subject alone reaching commercial_enabled is not sufficient. |
| `PG_PRODUCT_MISMATCH` | license | Soft | 2025-04-01 | The license is bound to a specific product and this request names a different one. |
| `PG_PROHIBITED_USE` | subject_trust | Hard | 2026-06-01 | A permanently-denied use for a high-risk subject (16.9) — e.g. a sexualized category for a minor. |
| `PG_PROJECT_MISMATCH` | license | Soft | 2025-04-01 | The license is bound to a specific project and this request names a different one. |
| `PG_PROVIDER_NOT_ALLOWED` | identity | Soft | 2025-06-01 | This license's allow/block list excludes the calling provider. |
| `PG_PROVIDER_VETOED` | subject_trust | Hard | 2025-07-01 | The rights holder blocked this specific provider — no license changes that. |
| `PG_REFERENCE_ONLY` | subject_trust | Hard | 2025-01-01 | The subject is registered as reference-only and never licenses. |
| `PG_REGION_BLOCKED` | license | Soft | 2025-06-01 | The request's territory falls outside the license's allowed regions (Identity v2 scope). |
| `PG_RIGHTS_NOT_GRANTED` | license | Soft | 2026-06-01 | The request exercises a rights dimension (16.8 — e.g. model_training) the license never granted. |
| `PG_SANDBOX_SUBJECT_ONLY` | subject_trust | Hard | 2025-08-01 | A sandbox (Tier 1) provider credential may only verify against synthetic test subjects. |
| `PG_SCOPE_VIOLATION` | license | Soft | 2025-01-01 | The request's modality, channel, or territory falls outside what the license scopes. |
| `PG_STD_TRACKING_ONLY` | tracking | Soft | 2026-09-21 | Personal use with no licence: the fixed floor (opt-out, status, minors, scope, deny) passed, so PRAMPTA does not block it — but grants nothing. disposition=not_blocked. |
| `PG_SUBJECT_DISPUTED` | subject_trust | Hard | 2025-09-01 | A dispute is open on this subject (A5, §9) — licensing is frozen pending outcome. |
| `PG_SUBJECT_NOT_LICENSABLE` | subject_trust | Hard | 2025-10-01 | The subject's trust-lifecycle state (suspended/disputed/revoked/archived) permits no licensing at all. |
| `PG_SUBJECT_OPTED_OUT` | subject_trust | Hard | 2025-01-01 | The subject's rules_text refuses this request's category outright. |
| `PG_SUBJECT_PAUSED` | subject_trust | Soft | 2025-01-01 | The subject's owner temporarily paused licensing. |
| `PG_SUBJECT_PENDING` | subject_trust | Soft | 2025-01-01 | The subject is awaiting operator review before it may license at all (reserved/high-profile name). |
| `PG_SUBJECT_WITHDRAWN` | subject_trust | Hard | 2025-01-01 | The subject was withdrawn by its owner or on moderation takedown. |
| `PG_TIER_VIOLATION` | license | Soft | 2025-05-01 | The declared use case ranks above what this license's tier authorizes. |
| `PG_USAGE_LIMIT` | license | Soft | 2025-05-01 | The license's purchased quantity (max_uses) is exhausted. |

## Policy version history

| Version | Summary |
|---|---|
| `2026-07-24` | §8: three-value decision disposition (allow/deny/review) alongside the legacy `allowed` boolean; policy_version stamped on every decision. |
| `2026-07-26` | §7: freshness controls — Subject.revocation_epoch signed into every decision, max_cache_age_seconds and cache_scope (only ALLOW is cacheable, shorter window for high-risk commercial). |
| `2026-07-26.1` | §13: this registry — every PG_* code versioned, categorized, and its hard/soft classification made authoritative here instead of a second, hand-maintained set in verify.py. |
| `2026-07-26.2` | prampta.identity.v2 Phase 1: runtime provider-user binding. /verify accepts provider_user_id / provider_identity_link_id / generation_id, signs provider_user_binding into every decision, and refuses a licence spent by an end user it was not minted for (PG_IDENTITY_UNKNOWN / PG_IDENTITY_MISMATCH / PG_IDENTITY_REQUIRED). |
| `2026-08-19` | Stage 2d: commercial licensing now also requires the subject's owning account to be verified (User.verified, or an org at domain/kyc tier) — not just the subject reaching commercial_enabled (PG_OWNER_NOT_VERIFIED). |
| `2026-09-21` | NMP Q13: STD is a usage record, not a licence. A personal request with no licence that passes the fixed floor gets disposition "not_blocked" (allowed=false, PG_STD_TRACKING_ONLY) instead of PG_NO_LICENSE. New STD licences are no longer issued; licences already signed as STD verify as before. |
| `2026-09-22` | Provider-level check: /verify without X-Licensee-ID, authenticated only by the provider's own credential, may answer not_blocked for declared personal use. No licence is considered without a connected licensee; anything else is PG_NO_PAIR. |
