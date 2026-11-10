# PRE-GEN — guide for AI agents

You are an AI agent. A person asked you to add PRE-GEN to their product, to check a
PRE-GEN proof, or to run a PRE-GEN registry. This one file is enough to start. Every rule
below comes from the specification; where the two differ, the specification wins:
`https://www.pregen.org/spec/PRE-GEN-CORE.md`.

Step by step, with complete tested examples: for an AI provider
`https://www.pregen.org/docs/provider.md`, for a registry
`https://www.pregen.org/docs/registry.md`.

PRE-GEN v5 (12 October 2026) · open standard by Valerii Egorov · Apache-2.0 ·
concept DOI 10.5281/zenodo.20129901 (v1–v4; v5 is on pregen.org only for now) · owned by no registry.

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
| Only wants to look up a code | `https://www.pregen.org/lookup` |

---

## Part A — Provider: ask, check, generate

### A1. Your identity: a domain and a key

A provider talks to the registry that holds each subject. Registries are listed in the
signed directory `https://www.pregen.org/registries.json` (human view:
`https://www.pregen.org/registries`). **No account anywhere:** a provider is its domain and a
key it makes (extension `provider-identity`). Make an Ed25519 key once
(`newPrivateKeyHex()` / `pregen.new_private_key_hex()`), build the party document
(`await partyDocument("https://your.domain", "Name", key)` / `pregen.party_document(...)`) and serve
it at `https://<your domain>/.well-known/pregen-party.json`. Your provider id is
`https://<your domain>`, the registrable domain itself (no `www.`, path or port); every request and report is signed with the key. A registry that says
`"providers": "registered"` in its document still issues its own credential; a registry that
says `"open"` answers you with no credential. Until it vets you under its published procedure, it
answers only about subjects it publishes (their refusals included) and licences a person
connected to your app (`bind`). Everything else is `deny` `PG_PROVIDER_NOT_ACCEPTED` (provider-identity P-5a). Today one registry is in production: PRAMPTA
(`https://api2.prampta.com`). It accepts apps by their domain and answers an app it has not vetted only about published subjects (refusals included) and about licences connected with `bind`; anything else, a floor refusal of a private subject included, gets the answer of an unknown code. The complete
guide, with tested examples: `https://www.pregen.org/docs/provider.md`.

### A2. Install a verification library

```bash
npm install @pregen/verify@^0.13.0
```

```bash
pip install "pregen>=0.13.0"
```

Both libraries carry the steward key, load and check the directory, and check answers and
proofs. They pin no registry by default. You may pin any registry's keys yourself: fetch the directory
and pass it to `verifyDirectory(json, { previous, pinnedKeys })` /
`pregen.verify_directory(json, previous=saved, pinned_keys=...)` (`loadDirectory` takes no pins).

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

A person's code looks like `TOG-<prefix>-<number><check>`, e.g. `TOG-TEST-000001N`. The prefix
names the registry; it is the only part of a code software may read. Codes without a prefix
(`TOG-000042*`) were issued before v5 by the first registry. PG codes are retired: a `PG-` string
is not a code anywhere. Use the ToG code your registry shows you.

```js
const entry = directory.registryFor("TOG-TEST-000001N");   // null = no listed registry holds it
const api = entry.api;
```

### A5. Ask

```
POST {api}/v2/requests
X-Provider-ID: https://your.domain
Content-Type: application/json

{"type": "pg.request.v1", "signatures": ["<ed25519 hex, by your current key>"],
 "body": {"signers": [{"role": "provider", "key_id": "pg-ed25519:…"}],
          "subject_ref": "TOG-TEST-000001N", "provider_id": "https://your.domain",
          "profile": "likeness/1", "use": {"purpose": "commercial"},
          "job_id": "job-8841", "job_hash": "<sha-256 hex of what you fixed about the job>"}}
```

- `await signEnvelope("pg.request.v1", body, key)` / `pregen.sign_envelope(..., key)` makes it. On the
  credential path (a `registered` registry) the request is unsigned, has no `signers`, and
  carries `Authorization: Bearer <credential>` with the registry's provider id.
- The six members after `signers` are all the core requires. Add others only if the profile or an
  extension the registry declares defines them.
- **`use` under `likeness/1`:** `{purpose, rights?, territory?, channel?, categories?}`;
  `purpose` is `personal`, `educational`, `research`, `editorial` or `commercial`.
  Declare `categories` honestly (e.g. `political`, `violence`): fixed protections are
  checked against them. A registry cannot see the output: your server, never the end user's own
  claim, determines the subject and the use, and renders exactly the inputs fixed in `job_hash`.
  A false declaration is your signed statement and your liability.
- One request per subject. A job with several subjects asks each one (extension `jobs`).
- The request id is the request's message id (Part B).

### A5a. A person's own licence (when the registry declares `bind`)

The person connects their licences to your app at their registry. This is OAuth 2.0
authorization code + PKCE against `bind.authorize` / `bind.token` from the registry document.
`client_id` is your provider URL; `redirect_uri` is one of the `redirect_uris` in your party
document. The registry returns a signed `pg.binding.v1`. Send its `licensee_id` only for codes
among the binding's grants (`GET {api}/v2/grants?licensee_id=…`); for any other code leave it out
and rest on your own grant. Spec: `https://www.pregen.org/spec/extensions/bind.md`.

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
`POST {api}/v2/reports`; the registry returns a signed acknowledgement. Your key is in your
party document (A1); on the credential path, register it once with `POST {api}/v2/keys`
(extension `provider-keys`).

```
body: {signers: [{role: "provider", key_id}], request_id, answer: <answer's message id, or null with the full request body in "request">,
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
| `PG_NOT_AUTHENTICATED` | 401 | credential, signature or `provider_id` not accepted (no party document, a key that is not current, a chain that does not extend the pin, or a credential sent beside a provider URL) |
| `PG_NOT_BOUND` | 403 | this licensee has not connected (or has revoked) their licences for your app: show "connect your licence", not a refusal |
| `PG_REPORT_CONFLICT` | 409 | a different report for the same answer |
| `PG_PROFILE_UNSUPPORTED` | 422 | the registry does not answer under this profile |

Answer reasons you will meet: `PG_UNKNOWN_SUBJECT` (the registry holds no such subject —
not a prohibition), `PG_OTHER_REGISTRY` (the code belongs to another registry: ask that
one), `PG_PROVIDER_NOT_ACCEPTED` (an open registry has not vetted your app yet: a refusal, not a
permission; get vetted or have the person connect their licence), `PG_NO_LICENSE`,
`PG_NOT_CONNECTED` (this use needs a connected end user), `PG_USAGE_LIMIT`, `PG_SCOPE_VIOLATION`, `PG_REVIEW_REQUIRED`, and the
fixed protections no grant overrides: `PG_SUBJECT_OPTED_OUT`, `PG_SUBJECT_UNAVAILABLE`,
`PG_PROHIBITED_USE`, `PG_IMMUTABLE_DENIAL`, `PG_PERSONAL_SIGNATURE_REQUIRED` (intimate
categories need the person's own signed grant).

### Testing

- **A registry's sandbox.** A registry whose document says `"sandbox": true` publishes the
  standard test subjects on its prefix (`…000001` allows; `…000002`–`…000007` refuse,
  hold or answer `not_blocked`; `…000008` is unknown; `…000009` tests payment, `…000010` a
  person's terms, `…000011` a minor, `…000012` a creator's licence through `bind`; table below). Check its answers against the test
  directory, never the real one:
  `const testDir = await loadDirectory({ url: "https://www.pregen.org/test/registries.json", stewardPublicKeyHex: "78c95e45a79c5e271fdec762b92c2ec1b27d6d08e512b7a94779de2429868ef0" })`
  / `pregen.load_directory("https://www.pregen.org/test/registries.json", steward_public_key_hex="78c95e45a79c5e271fdec762b92c2ec1b27d6d08e512b7a94779de2429868ef0")`,
  then `checkAnswer(answer, request, { directory: testDir, testing: true })`. With the real
  directory, `testing: true` throws.
- **The open reference registry** runs the same sandbox on your machine, to test request
  and answer shapes:

  ```bash
  pip install "pregen-registry>=0.4.0"
  pregen-registry init --dir ./data --prefix TEST --name "My sandbox" --api http://127.0.0.1:8000 --sandbox
  pregen-registry serve --dir ./data
  curl -X POST http://127.0.0.1:8000/v2/sandbox/party -H 'Content-Type: application/json' --data @pregen-party.json   # your party document, by post
  ```

  Its keys are not in the real directory, so `checkAnswer` refuses its signatures; that is
  expected. The shared test directory is online: `https://www.pregen.org/test/registries.json`,
  signed by the test steward key `78c95e45a79c5e271fdec762b92c2ec1b27d6d08e512b7a94779de2429868ef0`. It lists PRE-GEN's own
  sandbox, the PRE-GEN Test Registry (`https://sandbox.pregen.org`, prefix `TEST`, codes
  `TOG-TEST-000001N` to `TOG-TEST-0000123`): with it, `checkAnswer(…, { directory: testDir, testing: true })`
  accepts sandbox answers end to end. Post your party document to
  `https://sandbox.pregen.org/v2/sandbox/party` first (an `https://<domain>` id: lower case, no path, query or trailing slash; a sandbox also
  takes a port, and on your machine `https://<32 hex of your key id>.localhost:<port>`, which
  `sandboxProviderUrl(KEY, port)` / `pregen.sandbox_provider_url(KEY, port)` builds), then ask
  with signed requests.
- **What to test.** One job (a new `job_id`) per row, `purpose: "research"` unless the row
  says otherwise. Codes at the PRE-GEN Test Registry:

  | Code | Tests | Ask | Answer |
  |---|---|---|---|
  | `TOG-TEST-000001N` | the whole flow | ask, check, generate, report, proof | `allow` |
  | `TOG-TEST-000002Z` | no licence | ask | `deny` `PG_NO_LICENSE` |
  | `TOG-TEST-0000034` | an opt-out | ask | `deny` `PG_SUBJECT_OPTED_OUT` |
  | `TOG-TEST-000004E` | a used-up grant | ask | `deny` `PG_USAGE_LIMIT` |
  | `TOG-TEST-000005R` | a fixed protection | ask | `deny` `PG_PROHIBITED_USE` |
  | `TOG-TEST-000006$` | held for a person | ask | `review` `PG_REVIEW_REQUIRED` |
  | `TOG-TEST-0000077` | nothing blocks, nothing grants | ask | `not_blocked` `PG_NO_LICENSE` |
  | `TOG-TEST-000008H` | a code no one holds | ask | `deny` `PG_UNKNOWN_SUBJECT` |
  | `TOG-TEST-000009V` | payment: buy first | ask before buying | `deny` `PG_NO_LICENSE` |
  | `TOG-TEST-000009V` | one use per purchase | buy one use, then ask; ask again | `allow`; then `deny` `PG_USAGE_LIMIT` |
  | `TOG-TEST-000009V` | a race | buy one use, then two jobs at once | one `allow`, one `deny` `PG_USAGE_LIMIT` |
  | `TOG-TEST-000009V` | a give-back | after an allow, report `not_generated`, then ask | `allow` again |
  | `TOG-TEST-000010M` | the person's terms | no `terms`, or `terms` = the current id | `deny` `PG_NO_LICENSE`: terms grant nothing |
  | `TOG-TEST-000010M` | a stale id | `terms` = any other id, or any id on the credential path | `deny` `PG_TERMS_NOT_ACCEPTED` |
  | `TOG-TEST-000010M` | an excluded use | `purpose: "commercial"`, or `categories: ["advertising"]` | `deny` `PG_TERMS_EXCLUDED` |
  | `TOG-TEST-000011Y` | a minor: the floor | no `categories`, or `["fashion"]` | `allow` |
  | `TOG-TEST-000011Y` | a minor: the floor | `["violence"]`, `["sexual"]`, `["adult"]`, or an unknown word such as `["nsfw-art"]` | `deny` `PG_PROHIBITED_USE` |
  | `TOG-TEST-0000123` | a creator's licence, through `bind` | connect (`bind`), then ask with the binding's `licensee_id` | `allow`; `ext.bind` names the binding |
  | `TOG-TEST-0000123` | outside the licence | the same, `purpose: "commercial"` | `deny` `PG_SCOPE_VIOLATION` |
  | `TOG-TEST-0000123` | not connected | no `licensee_id` | `deny` `PG_NO_LICENSE` |
  | `TOG-TEST-0000123` | a `licensee_id` not bound to you | another app's, a replaced or revoked one, or a made-up one | HTTP 403 `PG_NOT_BOUND`: show "connect your licence", not a refusal |

  To buy, `POST https://sandbox.pregen.org/v2/sandbox/purchases` with the same signed
  `pg.request.v1` you would ask with (any `job_id`): HTTP 200 `{"grant": …}`, one use, yours
  only, no money. Then ask under a new `job_id`. For code 12, connect first (`bind`, OAuth code + PKCE): the
  sandbox's test creator approves with no password. The details: `https://www.pregen.org/docs/provider.md`, step 9;
  a working app: https://github.com/Pastheroza/PRE-GEN-site/tree/main/examples/reference-provider.
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

- **Where to find it:** a C2PA manifest assertion labelled `org.pregen.proof`.
- **How to check it:**

  ```js
  import { checkProof } from "@pregen/verify";
  const result = await checkProof(bundle, { directory, outputSha256 });  // throws with the reason
  ```

  ```python
  result = pregen.check_proof(bundle, directory, output_sha256=sha)
  ```

  It passes when every answer was a valid `allow` **at the time the output was made**,
  every acknowledgement is signed by the subject's registry, names that report and answer,
  and was received no later than 24 hours after the allow expired; every report says
  `generated`; all reports name one output and one job; and, when you pass the file's
  SHA-256, it equals `output_hash`. `checkProof` does not match re-encoded files: a soft
  binding (`bindings`) is matched with that algorithm's own tooling, outside PRE-GEN.
- A bundle from a revoked registry fails, old ones included. A bundle shows who permitted
  what and when; whether you keep, label or remove the content stays your decision.

---

## Part D — Run a registry

Any company or person can run a registry on the same terms; the first one has no special
rights.

1. **Run one.** The open reference registry:
   `pip install "pregen-registry>=0.4.0"`,
   then `pregen-registry init --dir ./data --prefix ABCD --name "…" --api https://… --policy https://… --complaints mailto:… --open-providers`
   (`--open-providers`: answer any provider known by its domain and key, with no credential).
   Step by step: `https://www.pregen.org/docs/registry.md`. Or implement the core yourself
   from `PRE-GEN-CORE.md`.
2. **Publish:** `GET {api}/keys` (your signing keys) and
   `GET {api}/.well-known/pregen-registry.json` (`prefix`, `name`, `profiles`,
   `extensions`, `policy`, `complaints`, `sandbox`, `providers`).
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
all their registries; an unconfirmed claim neither permits nor refuses (with no confirmed claim:
`not_blocked`, `PG_IDENTITY_UNCONFIRMED`). A matching name is never evidence.
The libraries implement this as `decideIdentity` / `decide_identity`.

---

## Links

- Core (one page): `https://www.pregen.org/spec/PRE-GEN-CORE.md`
- Specification PDF: `https://www.pregen.org/spec/PRE-GEN-v5.pdf`
- Profile `likeness/1` and the fourteen extensions:
  `https://github.com/Pastheroza/PRE-GEN-site/tree/main/spec`
- Signed registry directory: `https://www.pregen.org/registries.json`
- Implementation kit and test vectors: `https://www.pregen.org/docs/implement`
- Questions and errata: `https://github.com/Pastheroza/PRE-GEN-site/issues`
- Short index for LLMs: `https://www.pregen.org/llms.txt`
