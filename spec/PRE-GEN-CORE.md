# PRE-GEN Core

**Ask before you generate. Get a signed answer anyone can check.**

Draft, part of PRE-GEN v5 (2026-10-12). Normative once v5 is published on Zenodo.
Apache License 2.0.

---

## The idea

Before a generative system produces an output that uses a protected **subject** — a
person's likeness or voice, a character, a work — it asks the registry that speaks for
that subject. The registry answers, and signs the answer.

That signed answer:
- **proves itself** — anyone can check it later, offline, without asking anyone;
- **is bound to the exact question** — it cannot be reused for another;
- **is signed by a key the public directory lists** — so a fake registry is rejected.

Everything else in PRE-GEN is an optional extension that builds on this.

## The core, in five rules

**1. A code names the subject and its registry.**
A subject has a PG code (`PG-CODE.md`): `PG-<prefix>-<number><check>`.
- The four-letter prefix names the registry; a code with no prefix belongs to the origin
  registry.
- Software may read the prefix, and nothing else, from a code.

**2. The directory says whom to trust.**
The steward signs one directory (`PG-CODE.md` §9.1). It maps each prefix to a registry's
address and signing keys. A verifier checks the directory with the published steward key.
A verifier accepts a registry's signature only for the prefix the directory gives that
registry.

**3. Ask.**
The provider sends the registry one request about one subject.
- **Endpoint:** `POST {api}/v2/requests`.
- **Headers:** `X-Provider-ID`, and `Authorization: Bearer <credential>` issued by that
  registry.
- **Body:** an unsigned envelope:

```json
{"type": "pg.request.v1", "signatures": [],
 "body": {"subject_ref": "PG-TEST-000001…", "provider_id": "frame-ai",
          "profile": "likeness/1", "use": {"purpose": "commercial"},
          "job_id": "job-8841", "job_hash": "<sha-256 of what the provider fixed about the job>"}}
```

- **`use` is defined by the profile** (rule 5).
- **`job_hash` is the provider's fingerprint of the job.** The prompt and the output never
  leave the provider.
- **The request id** is the request's message id (§Messages).

**4. A signed answer.**
The registry replies `{"answer": <envelope>}`:

```json
{"type": "pg.answer.v1",
 "body": {"signers": [{"role": "registry", "key_id": "pg-ed25519:…"}],
          "request_id": "<message id of the request>", "profile": "likeness/1",
          "status": "allow", "basis": {"kind": "policy", "rule": "…"},
          "issued_at": 1791800000, "expires_at": 1791800300},
 "signatures": ["<ed25519 hex>"]}
```

- **`status`** is one of:
  - `allow` — permitted, with a `basis`;
  - `deny` — refused, with a `reason`;
  - `review` — held for a human, with a `reason`;
  - `not_blocked` — nothing prohibits the use and nothing grants it, with a `reason`.

  **Only `allow` permits.**
- **`basis`** is `{"kind": "policy", "rule"}` or `{"kind": "grant", "grant": {"format",
  "id", …}}`.
- **Lifetime:** `expires_at − issued_at` is between 1 and 900 seconds.

**5. Generate only on a valid allow, and keep it.**
A provider generates only when every subject of the job has an `allow` that is valid at
that moment. It keeps the answers with the output: they are its proof. **An output made
without a valid `allow` is never presented as permitted.**

**A valid answer** passes all of these checks:
- its signature verifies with a key the directory lists for the subject's prefix, and the
  key is not revoked;
- `request_id` is the id of the request sent;
- `profile` is the one asked for;
- `issued_at` is not more than 60 seconds in the future;
- it has not expired.

A provider that does exactly this, and nothing more, implements PRE-GEN.

## Messages

Every message is `{type, body, signatures}`.

| Element | Rule |
|---|---|
| **Signing input** | `"PREGEN-V5" || 0x00 || type || 0x00 || canonical(body)` |
| **Signature** | Ed25519, hex. The body's `signers` list names each signer's `role` and `key_id`, in order |
| **Message id** | SHA-256 hex of `"PREGEN-V5-ID" || 0x00 || type || 0x00 || canonical(body)`. Signatures are not part of it |
| **Canonical JSON** | `PRE-GEN-SPEC.md` §2. Numbers are integers; times are Unix seconds |
| **Unknown members** | Rejected, unless defined by the profile or by an extension the registry declares. `ext` holds registry extensions; `critical` lists those a receiver must understand |

JSON Schemas: `schemas/`. Byte vectors: `test-vectors/messages.json`.

## Errors

**A refusal about the subject is a signed answer, not an error.** HTTP errors carry
`{"error", "error_description"}`.

| Code | HTTP | Meaning |
|---|---|---|
| `PG_MALFORMED` | 422 | the request does not follow this document |
| `PG_NOT_AUTHENTICATED` | 401 | credential or `provider_id` not accepted |
| `PG_PROFILE_UNSUPPORTED` | 422 | the registry does not answer under this profile |

**Two codes are answer reasons**, not HTTP errors:
- `PG_UNKNOWN_SUBJECT` — the registry holds no such subject. This is not a prohibition.
- `PG_OTHER_REGISTRY` — the code's prefix belongs to another registry.

**A provider treats any reason it does not know as a refusal.**

## What a registry publishes

- **`GET {api}/keys`** — its signing keys (`PRE-GEN-SPEC.md` §2.3).
- **`GET {api}/.well-known/pregen-registry.json`** — a document listing:
  - `prefix`, `name`;
  - `profiles` and `extensions`;
  - `policy` — the URL of its published policy;
  - `complaints` — a contact for complaints;
  - `sandbox`.

**A client sends members of an extension only to a registry that declares it.**

## Profiles make it universal

The core knows nothing about faces, voices or licences. A **profile** says what `use`
contains, which reasons and obligations exist, and which refusals no grant can override.
- `profiles/likeness-1.md` is the first profile: a person's likeness and voice.
- Works, characters and other subjects are profiles to come. The core does not change.

## Extensions

Each extension is one page, solves one problem, is optional, and **only adds**. No
extension may turn a refusal the core or a profile requires into a permission.

| Extension | Solves |
|---|---|
| [`reports`](extensions/reports.md) | "What happened?" A signed report after generation, and a signed acknowledgement |
| [`provider-keys`](extensions/provider-keys.md) | Provider signing keys: first key, rotation, recovery |
| [`limits`](extensions/limits.md) | Grants with a number of uses: reserve, count, give back |
| [`jobs`](extensions/jobs.md) | One generation with several subjects; never generating twice |
| [`grants`](extensions/grants.md) | Licences as signed objects: `pg.grant.v1` |
| [`licensee`](extensions/licensee.md) | Answers for a connected end user |
| [`observe`](extensions/observe.md) | Trial mode: generate and record, without blocking |
| [`sandbox`](extensions/sandbox.md) | Standard test subjects and a test directory |
| [`lookup`](extensions/lookup.md) | Public lookup of a code |

The earlier interface (`PRE-GEN-SPEC.md` §1, §5: `pg.decision.v1`, `/v1/verify`,
receipts) stays valid. Everything issued under it keeps its meaning (`VERSIONS.md`).
