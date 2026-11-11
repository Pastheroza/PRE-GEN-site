# PRE-GEN Core

**Ask before you generate. Get a signed answer anyone can check.**

PRE-GEN v5 · 12 October 2026 · Apache License 2.0.
The one page every provider, registry and verifier starts from.

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
A subject has a ToG code (`TOG-CODE.md`): `TOG-<prefix>-<number><check>`, for example
`TOG-TEST-000001N`.
- The prefix (4 to 8 letters) names the registry. Every registry has one, and every new code
  carries it.
- **Every code is written `TOG-`.** PG codes are retired and not compatible: a `PG-` string is
  not a code anywhere (`TOG-CODE.md` §1). Each registry migrates its own people once, inside the
  registry (`TOG-CODE.md` §5); a person's ToG code is the one their registry shows them.
- Codes without a prefix (`TOG-000042*`) were issued before v5 by the first registry. They
  keep their meaning forever; no registry issues new ones.
- Software may read the marker, the kind and the prefixes, and nothing else, from a code.
  The first prefix is the registry to ask.

**2. The directory says whom to trust.**
The steward signs one directory, `https://www.pregen.org/registries.v3.json` (`TOG-CODE.md`
§9.2); the PG-era v2 file at `https://www.pregen.org/registries.json` stays frozen for older
clients. Each entry maps
a prefix to a registry: `name`, `prefix`, `api`, `keys` (its key set URL) and
`key_fingerprints`. A verifier:
- accepts the directory only if its `signature` verifies with the **published steward
  key** (below), never with a key from the directory itself, and its `sequence` is not lower
  than one it already accepted;
- loads it again **at least once every 24 hours**, preferably from pregen.org, and accepts
  no answer on a copy it loaded earlier than that. The signature proves a copy authentic,
  not current: a stale copy from a mirror or an attacker can hide a newer revocation until
  the verifier fetches a current one;
- accepts a registry's signature only for the **prefix** the directory gives that registry;
- refuses a registry marked `revoked` and a key listed in `revoked_keys`;
- takes the public key from the registry's key set (`GET {api}/keys`) and checks that it
  hashes to a listed fingerprint.

A registry not in the directory is not refused by anyone's opinion; it simply cannot sign
anything a verifier accepts. Steward key: `pg-ed25519:dcdd244659e6d0e2426f2b504cb11590`,
public key `5cb949aab04186e3e216ec541b847c912fc3f78138c0ec3cb2560b2dad0d1f1b`, also in DNS
at `_pregen-steward.pregen.org`. Admission, revocation and key handover: `PG-CODE.md` §9.1;
prefixes and directory v3: `TOG-CODE.md` §9.

**3. Ask.**
The provider sends the registry one request about one subject.
- **Endpoint:** `POST {api}/v2/requests`.
- **Headers:** `X-Provider-ID`, and `Authorization: Bearer <credential>` issued by that
  registry. A provider known by its domain sends no credential and signs the request
  instead (`extensions/provider-identity.md`).
- **Body:** an unsigned envelope (signed under `provider-identity`):

```json
{"type": "pg.request.v1", "signatures": [],
 "body": {"subject_ref": "TOG-TEST-000001…", "provider_id": "frame-ai",
          "profile": "likeness/1", "use": {"purpose": "commercial"},
          "job_id": "job-8841", "job_hash": "<sha-256 of what the provider fixed about the job>"}}
```

- **`use` is defined by the profile** (rule 5).
- **`job_hash` is the provider's fingerprint of the job.** The prompt and the output never
  leave the provider.
- **The request id** is the request's message id (§Messages).
- **A request may accept the subject's terms:** `terms`, their message id, in a signed
  request (`extensions/terms.md`).

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
  "id", …}}`. `rule` names the registry's rule (for example `minors-never`); it is never a
  hash or a version of any text. A grant `id` names one signed grant, as `request_id` names
  one request.
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

A provider that does exactly this, and nothing more, implements PRE-GEN. The libraries do
rules 2 and 5 in one call: `checkAnswer` in `@pregen/verify`, `check_answer` in `pregen`.

## Messages

Every message is `{type, body, signatures}`.

| Element | Rule |
|---|---|
| **Canonical JSON** | UTF-8; object members sorted by key in code point order; no whitespace; strings escape only `"`, `\`, `\b \t \n \f \r` and other code points below U+0020 (as `\u00xx`, lowercase); no Unicode normalization; numbers are integers within ±(2^53 − 1); times are Unix seconds |
| **Signing input** | `"PREGEN-V5" || 0x00 || type || 0x00 || canonical(body)` |
| **Signature** | Ed25519 (RFC 8032), lowercase hex. The body's `signers` list names each signer's `role` and `key_id`, in order; `signatures` follow the same order. A public key that is a small-order point, in any encoding, or is not canonically encoded (y ≥ p) is refused wherever a key is recorded, and nothing verifies under it: anyone could sign under such a key (`test-vectors/small-order-keys.json`) |
| **Key id** | `pg-ed25519:` + the first 32 hex characters of SHA-256 of the raw 32-byte public key |
| **Key set** | `GET {api}/keys` → `{"keys": [{"key_id", "public_key_hex", …}], …}`, current and retired keys |
| **Message id** | SHA-256 hex of `"PREGEN-V5-ID" || 0x00 || type || 0x00 || canonical(body)`. Signatures are not part of it |
| **Unknown members** | Rejected, unless defined by the profile or by an extension the registry declares. `ext` holds registry extensions; `critical` lists those a receiver must understand |

JSON Schemas: `schemas/`. Byte vectors: `test-vectors/messages.json`.

## Errors

**A refusal about the subject is a signed answer, not an error.** HTTP errors carry
`{"error", "error_description"}`.

| Code | HTTP | Meaning |
|---|---|---|
| `PG_MALFORMED` | 422 | the request does not follow this document |
| `PG_NOT_AUTHENTICATED` | 401 | credential, signature or `provider_id` not accepted |
| `PG_PROFILE_UNSUPPORTED` | 422 | the registry does not answer under this profile |

**Two codes are answer reasons**, not HTTP errors:
- `PG_UNKNOWN_SUBJECT` — the registry holds no such subject. This is not a prohibition.
- `PG_OTHER_REGISTRY` — the code's prefix belongs to another registry.

**A provider treats any reason it does not know as a refusal.**

## What a registry publishes

- **`GET {api}/keys`** — its signing keys (Messages, Key set).
- **`GET {api}/.well-known/pregen-registry.json`** — a document listing:
  - `prefix`, `name`, `api`, `keys`, `spec`;
  - `profiles` and `extensions`;
  - `policy` — the URL of its published policy;
  - `complaints` — a contact for complaints;
  - `sandbox`;
  - `providers`: `open` when providers known by their domain are accepted
    (`extensions/provider-identity.md`), `registered` when it issues its own credentials;
  - `bind`: its `authorize` and `token` endpoints, if it declares `bind`;
  - `terms`: `optional`, if it declares `terms`.
- **`GET {api}/v2/codes/{code}`** — what a code names, if it declares `lookup`.
- **`GET {api}/v2/terms/{id}`** — every version of a subject's terms it ever published, if it
  declares `terms`.

**A client sends members of an extension only to a registry that declares it.**

## Profiles make it universal

The core knows nothing about faces, voices or licences. A **profile** says what `use`
contains, which reasons and obligations exist, and which refusals no grant can override. A
profile's name is fixed: it names a vocabulary of uses, never a version of anyone's policy, and
it is compared only as a name. A new vocabulary is a new name. An answer carries nothing that
names a version, hash or counter of a registry's rules. A subject's terms (`terms`) are a
signed record the request names by its message id, not a version of the registry's rules: the
answer covers them through `request_id`.
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
| [`jobs`](extensions/jobs.md) | One generation with several subjects; with the provider's job rules, never generating twice |
| [`grants`](extensions/grants.md) | Licences as signed objects: `pg.grant.v1` |
| [`licensee`](extensions/licensee.md) | Answers for a connected end user |
| [`observe`](extensions/observe.md) | Trial mode: generate and record, without blocking |
| [`sandbox`](extensions/sandbox.md) | Standard test subjects and a test directory |
| [`lookup`](extensions/lookup.md) | Public lookup of a code, with the subject's current terms |
| [`identity`](extensions/identity.md) | One person, one home registry: anchors, confirmation on the person's own channel, "who proved it, not who came first", the stricter answer for a duplicate, disputes |
| [`proof`](extensions/proof.md) | The signed record travels with the output (C2PA manifest and the file's SHA-256); platforms check it |
| [`catalog`](extensions/catalog.md) | Providers sell what registries offer: catalog, resale right, billing by issued allows |
| [`provider-identity`](extensions/provider-identity.md) | A provider known by its domain and key: party document at `/.well-known/pregen-party.json`, signed requests, no account at any registry |
| [`bind`](extensions/bind.md) | A person connects their licences to an app: OAuth 2.0 code + PKCE at their registry, a per-app `licensee_id` |
| [`terms`](extensions/terms.md) | A person's terms of generation: a public, signed, versioned `pg.terms.v1`; a provider accepts them by signing its request |

## The earlier interface

New implementations use only this document. The earlier interface (`PRE-GEN-SPEC.md` §1,
§5: `pg.decision.v1`, `/v1/verify`, receipts) is **legacy**: what was issued under it stays
valid and verifiable forever (`VERSIONS.md`), and it gets no new features.
