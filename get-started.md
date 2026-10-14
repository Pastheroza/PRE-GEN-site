# PRE-GEN — guide for AI agents

You are an AI agent. A person asked you to add PRE-GEN to their product, to check a
PRE-GEN proof, or to run a PRE-GEN registry. This one file is enough to start. Every rule
below comes from the specification; where the two differ, the specification wins:
`https://www.pregen.org/spec/PRE-GEN-CORE.md`.

PRE-GEN v5 (12 October 2026) · open standard by Valerii Egorov · Apache-2.0 ·
concept DOI 10.5281/zenodo.20129901 · owned by no registry.

## What PRE-GEN is

Before a generative system produces an output that uses a protected **subject** — a
person's likeness or voice, a character, a work — it asks the **registry** that speaks for
that subject. The registry answers with an Ed25519-signed answer, bound to the exact
request, that anyone can check offline. **Only `allow` permits.** A provider that asks,
checks the answer and generates only on a valid `allow` implements PRE-GEN.

PRE-GEN proves who permitted what, and when. It does not decide what is lawful, and it
binds only systems that choose to ask.

## Ground rules for agents

1. **Ask the person before** creating accounts, accepting terms, publishing DNS records or
   storing secrets. Never invent or reuse someone else's credentials.
2. **Never send the prompt or the output.** Send `job_hash`, a SHA-256 of what you fixed
   about the job. Prompts and outputs stay on your servers.
3. **Keep credentials server-side.** A registry credential never goes to a browser, a URL
   or client code.
4. **A refusal is an answer, not an error.** Do not retry it. Treat any reason you do not
   know as a refusal.
5. **Never accept a sandbox answer in production.** Sandbox answers carry
   `ext: {"sandbox": true}`.

## Which part do you need?

| The person's product | Follow |
|---|---|
| Generates images, video, voice or text that may show a real person or a protected work | **Part A** (provider) and **Part B** (messages) |
| A platform or distributor that wants to check a file's permission | **Part C** |
| Wants to run a registry for the people or works it represents | **Part D** |
| Only wants to look up a PG code | `https://www.pregen.org/lookup` |

---

## Part A — Provider: ask, check, generate

### A1. Credentials from a registry

A provider talks to the registry that holds each subject. Registries are listed in the
signed directory `https://www.pregen.org/registries.json` (human view:
`https://www.pregen.org/registries`). Each registry issues its own credentials; follow its
guide. Today one registry is in production: PRAMPTA (`https://api2.prampta.com`, guide
`https://prampta.com/get-started-v2.md`).

### A2. Install a verification library

```bash
npm install @pregen/verify@^0.10.0
```

```bash
pip install "pregen>=0.10.0"
```

Both libraries carry the steward key, load and check the directory, and check answers and
proofs. They pin no registry by default; you may pin any registry's keys yourself
(`pinnedKeys` / `pinned_keys`).

### A3. Load the directory

```js
import { loadDirectory } from "@pregen/verify";
const directory = await loadDirectory({ previous: saved });  // saved = the last one you accepted
saved = directory.toJSON();                                   // keep it; reload at least every 24 hours
```

```python
import pregen
directory = pregen.load_directory(previous=saved)
saved = directory.to_json()
```

The directory is accepted only if the published steward key signed it and its `sequence`
is not lower than one you already accepted. Answers on a directory loaded more than 24
hours ago are refused.

### A4. Find the registry for a subject

A PG code looks like `PG-<prefix>-<number><check>`, e.g. `PG-TEST-000001N`. The four-letter
prefix names the registry; it is the only part of a code software may read. Codes without
a prefix (`PG-000042*`) were issued before v5 by the first registry.

```js
const entry = directory.registryFor("PG-TEST-000001N");   // null = no listed registry holds it
const api = entry.api;
```

### A5. Ask

```
POST {api}/v2/requests
Authorization: Bearer <credential from that registry>
X-Provider-ID: <your provider id>
Content-Type: application/json

{"type": "pg.request.v1", "signatures": [],
 "body": {"subject_ref": "PG-TEST-000001N", "provider_id": "<your provider id>",
          "profile": "likeness/1", "use": {"purpose": "commercial"},
          "job_id": "job-8841", "job_hash": "<sha-256 hex of what you fixed about the job>"}}
```

- These six members are all the core requires. Add others only if the profile or an
  extension the registry declares defines them.
- **`use` under `likeness/1`:** `{purpose, rights?, territory?, channel?, categories?}`;
  `purpose` is `personal`, `educational`, `research`, `editorial` or `commercial`.
  Declare `categories` honestly (e.g. `political`, `violence`): fixed protections are
  checked against them.
- One request per subject. A job with several subjects asks each one (extension `jobs`).
- The request id is the request's message id (Part B).

### A6. Check the answer

```js
import { checkAnswer } from "@pregen/verify";
const { answer } = await res.json();
await checkAnswer(answer, request, { directory });   // throws with the reason, or you may generate
```

```python
pregen.check_answer(answer, request, directory)      # raises with the reason, or you may generate
```

`status` is one of:

| `status` | Meaning | Do |
|---|---|---|
| `allow` | Permitted, with a `basis` (a policy rule or a grant) | Generate, applying any `obligations` |
| `deny` | Refused, with a `reason` | Do not generate |
| `review` | Held for a person, with a `reason` | Do not generate now |
| `not_blocked` | Nothing prohibits it and nothing grants it | Not a permission |

An answer is valid when its signature verifies with a key the directory lists for the
subject's prefix (not revoked), `request_id` is the id of your request, `profile` matches,
`issued_at` is not more than 60 seconds in the future, and it has not expired (an answer
lives 1 to 900 seconds).

### A7. Generate only on a valid allow, and keep it

Generate only when **every** subject of the job has a valid `allow` at that moment. Keep
the answers with the output: they are your proof. An output made without a valid `allow`
is never presented as permitted.

### A8. Report (when the registry declares `reports`)

After generating, sign a `pg.report.v1` with your own key and send it to
`POST {api}/v2/reports`; the registry returns a signed acknowledgement. Register your key
once with `POST {api}/v2/keys` (extension `provider-keys`).

```
body: {signers: [{role: "provider", key_id}], request_id, answer: <answer's message id>,
       job_id, outcome: "generated" | "not_generated",
       output_hash: <sha-256 of the output, or "">, occurred_at: <unix seconds>}
```

A report counts as filed only when an acknowledgement for exactly its message id verifies.
The identical report again returns the stored acknowledgement; a different one is
`PG_REPORT_CONFLICT`.

### A9. Try it without blocking (when the registry declares `observe`)

Send `"mode": "observe"` in the request and the report: you generate whatever the answers
are and report every generation. Nothing is permitted by the mode; switching to
`"enforce"` (the default) is one setting.

### Errors

A refusal about the subject is a signed answer. HTTP errors carry
`{"error", "error_description"}`:

| Code | HTTP | Meaning |
|---|---|---|
| `PG_MALFORMED` | 422 | the request does not follow the core |
| `PG_NOT_AUTHENTICATED` | 401 | credential or `provider_id` not accepted |
| `PG_PROFILE_UNSUPPORTED` | 422 | the registry does not answer under this profile |

Answer reasons you will meet: `PG_UNKNOWN_SUBJECT` (the registry holds no such subject —
not a prohibition), `PG_OTHER_REGISTRY` (the code belongs to another registry: ask that
one), `PG_NO_LICENSE`, `PG_USAGE_LIMIT`, `PG_SCOPE_VIOLATION`, `PG_REVIEW_REQUIRED`, and the
fixed protections no grant overrides: `PG_SUBJECT_OPTED_OUT`, `PG_SUBJECT_UNAVAILABLE`,
`PG_PROHIBITED_USE`, `PG_IMMUTABLE_DENIAL`, `PG_PERSONAL_SIGNATURE_REQUIRED` (intimate
categories need the person's own signed grant).

### Testing

- **A registry's sandbox.** A registry whose document says `"sandbox": true` publishes eight
  standard test subjects on its prefix (`…000001` allows; `…000002`–`…000007` refuse,
  hold or answer `not_blocked`; `…000008` is unknown). Check its answers with
  `checkAnswer(answer, request, { directory, testing: true })`.
- **The open reference registry** runs the same sandbox on your machine, to test request
  and answer shapes:

  ```bash
  pip install "git+https://github.com/Pastheroza/PRE-GEN-site#subdirectory=packages/registry"
  pregen-registry init --dir ./data --prefix TEST --name "My sandbox" --api http://127.0.0.1:8000 --sandbox
  pregen-registry serve --dir ./data
  curl -X POST http://127.0.0.1:8000/v2/sandbox/access     # a provider id and token, no account
  ```

  Its keys are not in the real directory, so `checkAnswer` refuses its signatures; that is
  expected. A shared test directory signed by a separate test steward key is specified
  (`extensions/sandbox.md`) but not online yet.
- **Bytes.** `spec/test-vectors/messages.json` gives eight messages with their canonical
  body, signing input, message id and signatures. Reproduce every one.

### You are done when

- [ ] The directory is loaded, kept, and reloaded at least every 24 hours
- [ ] Every generation of a registered subject is preceded by a request to the registry that holds it
- [ ] `checkAnswer` passes before generating; every subject of the job has a valid `allow`
- [ ] Answers are kept with the output; reports are filed where the registry declares `reports`
- [ ] Refusals are shown to the user and never retried; unknown reasons are refusals
- [ ] No prompt, output or credential leaves your servers

---

## Part B — Messages

Every message is `{type, body, signatures}`.

| Element | Rule |
|---|---|
| Canonical JSON | UTF-8; object members sorted by key in code point order; no whitespace; strings escape only `"`, `\`, `\b \t \n \f \r` and other code points below U+0020 (as `\u00xx`, lowercase); no Unicode normalization; integers within ±(2^53 − 1); times are Unix seconds |
| Signing input | `"PREGEN-V5" \|\| 0x00 \|\| type \|\| 0x00 \|\| canonical(body)` |
| Signature | Ed25519 (RFC 8032), lowercase hex. `body.signers` lists each signer's `role` and `key_id` in order; `signatures` follow the same order |
| Key id | `pg-ed25519:` + the first 32 hex characters of SHA-256 of the raw 32-byte public key |
| Key set | `GET {api}/keys` → `{"keys": [{"key_id", "public_key_hex", …}], …}`, current and retired keys |
| Message id | SHA-256 hex of `"PREGEN-V5-ID" \|\| 0x00 \|\| type \|\| 0x00 \|\| canonical(body)`; signatures are not part of it |
| Unknown members | Rejected unless the profile or an extension the registry declares defines them; `ext` holds registry extensions, `critical` lists those a receiver must understand |

The libraries export `canonicalJson` / `canonical_json` and `messageId` / `message_id`.
JSON Schemas: `https://github.com/Pastheroza/PRE-GEN-site/tree/main/spec/schemas`.

---

## Part C — Platform or distributor: check a proof

A file made under PRE-GEN can carry a proof bundle `pg.proof.v1`: for every subject of the
job, the request, the answer, the provider's report and the registry's acknowledgement,
each exactly as signed.

- **Where to find it:** a C2PA manifest assertion labelled `org.pregen.proof`; or a
  watermark payload `<prefix>:<16 hex>`, from which you fetch the registry's part with
  `GET {api}/v2/proofs/{16 hex}`.
- **How to check it:**

  ```js
  import { checkProof } from "@pregen/verify";
  const result = await checkProof(bundle, { directory, outputSha256 });  // throws with the reason
  ```

  ```python
  result = pregen.check_proof(bundle, directory, output_sha256=sha)
  ```

  It passes when every answer was a valid `allow` **at the time the output was made**,
  every acknowledgement is signed by the subject's registry and names that report and
  answer, all reports name one output and one job, and the file's hash matches (after
  re-encoding, a soft binding instead).
- A bundle from a revoked registry fails, old ones included. A bundle shows who permitted
  what and when; whether you keep, label or remove the content stays your decision.

---

## Part D — Run a registry

Any company or person can run a registry on the same terms; the first one has no special
rights.

1. **Run one.** The open reference registry:
   `pip install "git+https://github.com/Pastheroza/PRE-GEN-site#subdirectory=packages/registry"`,
   then `pregen-registry init --dir ./data --prefix ABCD --name "…" --api https://… --policy https://… --complaints mailto:…`.
   Or implement the core yourself from `PRE-GEN-CORE.md`.
2. **Publish:** `GET {api}/keys` (your signing keys) and
   `GET {api}/.well-known/pregen-registry.json` (`prefix`, `name`, `profiles`,
   `extensions`, `policy`, `complaints`, `sandbox`).
3. **Apply for a four-letter prefix** (`ABCDEFGHJKMNPQRSTVWXYZ`, no digits, no I, L, O, U):
   open a "Registry application" issue at
   `https://github.com/Pastheroza/PRE-GEN-site/issues/new?template=registry-application.md`.
   Bring a named operator with a public address and a complaints contact answered within
   7 days; a published policy, including how you verify rights holders and an anchor
   (Wikidata, ISNI or a domain) for every public person; acceptance of the core's fixed
   protections; your key fingerprints, also sent to the steward by a second channel; your
   next key announced.
4. **Listed** means the steward signed a new directory with your prefix and keys. A listing
   can be revoked; a prefix is never reassigned.

**One person in several registries** (extension `identity`): a claim the person confirmed
on their own official channel silences unconfirmed claims; a refusal of the person holds in
all their registries; several unconfirmed claims freeze. A matching name is never evidence.
The libraries implement this as `decideIdentity` / `decide_identity`.

---

## Links

- Core (one page): `https://www.pregen.org/spec/PRE-GEN-CORE.md`
- Specification PDF: `https://www.pregen.org/spec/PRE-GEN-v5.pdf`
- Profile `likeness/1` and the twelve extensions:
  `https://github.com/Pastheroza/PRE-GEN-site/tree/main/spec`
- Signed registry directory: `https://www.pregen.org/registries.json`
- Implementation kit and test vectors: `https://www.pregen.org/docs/implement`
- Questions and errata: `https://github.com/Pastheroza/PRE-GEN-site/issues`
- Short index for LLMs: `https://www.pregen.org/llms.txt`
