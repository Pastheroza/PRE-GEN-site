# PRE-GEN for AI providers: ask, check, generate, report, prove

You run a generative AI product. Before it generates an output that shows a protected
person (or work), it **asks** the registry that holds them, **checks** the signed answer,
generates **only on a valid `allow`**, **reports** the output, and keeps a **proof** anyone
can check offline. This guide gives every step in Python and JavaScript, with what each
step returns. Where it and the specification differ, the specification wins:
`https://www.pregen.org/spec/PRE-GEN-CORE.md`.

**You need:** Python 3.9+ or Node.js 20+, and credentials from each registry you ask (step 1).

## Ground rules

1. **Only `allow` permits.** `deny`, `review`, `not_blocked`, an error, a timeout, an
   unknown status or reason: do not generate. Never retry a refusal to get another answer.
2. **Never send the prompt or the output.** You send `job_hash`: a SHA-256 of what you
   fixed about the job. Prompts and outputs stay on your servers.
3. **Secrets stay server-side:** registry tokens and your private key never go to a browser,
   a URL, a log or client code.
4. **A sandbox answer is never accepted in production.** It carries `ext: {"sandbox": true}`;
   the libraries refuse it unless you pass `testing`.
5. **Ask the person** who runs the product before you create accounts, accept terms or
   store secrets.

## 1. Credentials from each registry

The directory (`https://www.pregen.org/registries.json`, human view
`https://www.pregen.org/registries`) lists every registry with its prefix and `api`. Each
registry gives you, privately, a **provider id** and a **token**. Keep one pair per
registry, for example:

```json
{"ABCD": {"provider_id": "frame-ai", "token": "<secret>"},
 "EFGH": {"provider_id": "frame-ai", "token": "<secret>"}}
```

A registry's sandbox gives test credentials without an account:
`curl -s -X POST {sandbox api}/v2/sandbox/access` → `{"provider_id": "sbx-…", "token": "…"}`.

## 2. Install the library

```bash
pip install "pregen>=0.11.0"
```

```bash
npm install @pregen/verify@^0.11.0
```

Both carry the PRE-GEN steward key, check the directory, answers and proofs, and sign your
messages. Neither needs anything else.

## 3. Your provider key: make it once, register it at each registry

Reports are signed with **your** key, so a registry can tell your reports from anyone
else's. Make the key once and keep it with your other secrets:

```python
import pregen
key = pregen.new_private_key_hex()          # 64 hex: the private key. Store it, never log it.
pub = pregen.public_key_hex(key)            # 64 hex: the public key
key_id = pregen.fingerprint(pub)            # "pg-ed25519:<32 hex>"
```

```js
import { newPrivateKeyHex, publicKeyHex, fingerprint } from "@pregen/verify";
const key = newPrivateKeyHex();
const pub = await publicKeyHex(key);
const keyId = await fingerprint(pub);
```

Register it once at **each** registry, with that registry's credential:

```python
keyset = pregen.sign_envelope("pg.keyset.v1", {
    "signers": [{"role": "provider", "key_id": key_id}],
    "kind": "first", "provider_id": PROVIDER_ID, "previous": None, "recovery_registry": "",
    "keys": [{"key_id": key_id, "public_key_hex": pub, "status": "current"}]}, key)
# POST {api}/v2/keys with this envelope as the JSON body (headers: step 5)
```

The registry answers HTTP 200 `{"keyset": …}`; sending the same keyset again returns the same.

## 4. Load the directory

```python
directory = pregen.load_directory(previous=saved)     # saved: the last one you accepted, or None
saved = directory.to_json()                           # keep it; load again at least every 24 hours
```

```js
import { loadDirectory } from "@pregen/verify";
const directory = await loadDirectory({ previous: saved });
saved = directory.toJSON();
```

It is accepted only when the PRE-GEN steward signed it and its `sequence` is not lower than
one you accepted before. Answers checked against a directory loaded more than 24 hours ago
are refused.

**Testing:** a test directory is signed by a test steward key. Load it with
`pregen.load_directory(url, steward_public_key_hex=TEST_STEWARD)` or
`loadDirectory({ url, stewardPublicKeyHex: TEST_STEWARD })`. Never in production.

## 5. Ask

A person's code looks like `PG-ABCD-000001G`; its four letters name the registry.
`directory.registry_for(code)` / `directory.registryFor(code)` gives that registry's entry
(`None` / `null`: no listed registry holds it, so PRE-GEN says nothing about it).

```
POST {api}/v2/requests
Content-Type: application/json
X-Provider-ID: <provider id from that registry>
Authorization: Bearer <token from that registry>

{"type": "pg.request.v1", "signatures": [],
 "body": {"subject_ref": "PG-ABCD-000001G", "provider_id": "<provider id>",
          "profile": "likeness/1", "use": {"purpose": "commercial"},
          "job_id": "job-8841", "job_hash": "<sha-256 hex of what you fixed about the job>"}}
```

- These six members are all a request needs. `use.purpose` is `personal`, `educational`,
  `research`, `editorial` or `commercial`; add `territory`, `channel` and `categories`
  (for example `["political"]`) when they apply, honestly: fixed protections are checked
  against them.
- **One request per person.** A job with two people asks twice, under the same `job_id`,
  each at the registry that holds them. **Every job has a new `job_id`** (random, not a
  timestamp): once a job is reported, asking again under its id is refused (`PG_ASK_CLOSED`).
- `pregen.sign_envelope("pg.request.v1", body)` / `signEnvelope("pg.request.v1", body)`
  makes the envelope (no key: `signatures` stays empty; the token authenticates you).
- Copy codes exactly. A code with another case, a space or an invisible character is
  refused with HTTP 422 `PG_MALFORMED`. Its last character is a check character that may
  be `*`, `~`, `$`, `=` or `!`: quote codes in a shell (`'PG-ABCD-000001$'`) and encode them
  in a URL path (`%24` for `$`).

The registry answers HTTP 200 `{"answer": {"type": "pg.answer.v1", "body": {…}, "signatures": […]}}`.

## 6. Check the answer

```python
pregen.check_answer(answer, request, directory)     # raises PregenError with the reason
```

```js
import { checkAnswer } from "@pregen/verify";
await checkAnswer(answer, request, { directory });  // throws PregenError with the reason
```

It passes only when a key the directory lists for the code's prefix signed the answer, the
answer names exactly your request and profile, it is within its lifetime, it is not a
sandbox answer (unless `testing`), and its `status` is `allow`. The statuses:

| `status` | Meaning | Do |
|---|---|---|
| `allow` | permitted, with a `basis` (a policy rule or a grant) | generate, applying any `obligations` |
| `deny` | refused, with a `reason` | do not generate |
| `review` | held for a person | do not generate now |
| `not_blocked` | nothing grants it | not a permission: do not generate on it |

## 7. Generate, only on a valid allow for every person

Generate only when **every** person in the job has a checked `allow` at that moment. Note
the time you checked: the report's `occurred_at` is when generation **began** (step 8), even
if rendering ends later. Hash the output: `output_hash = sha256(file bytes)` in hex.

## 8. Report the output

For each person's answer, sign a report with your key and send it to the same registry:

```python
report = pregen.sign_envelope("pg.report.v1", {
    "signers": [{"role": "provider", "key_id": key_id}],
    "request_id": pregen.message_id("pg.request.v1", request["body"]),
    "answer": pregen.message_id("pg.answer.v1", answer["body"]),
    "job_id": request["body"]["job_id"], "outcome": "generated",
    "output_hash": output_hash, "occurred_at": checked_at}, key)
# POST {api}/v2/reports with this envelope → HTTP 200 {"ack": <signed pg.report_ack.v1>}
```

If you decided not to generate after an `allow`, report `"outcome": "not_generated"` with
`"output_hash": ""`, so the use is given back. The same report sent again returns the same
acknowledgement; a different report for the same answer is refused (`PG_REPORT_CONFLICT`).
Send reports soon: a proof needs the registry to have received the report **within 24 hours
of the answer's expiry**; a later one is recorded but proves nothing.

## 9. Keep the proof with the output

The proof is the four signed messages for every person in the job, exactly as signed:

```python
bundle = {"format": "pg.proof.v1", "subjects": [
    {"request": request, "answer": answer, "report": report, "ack": ack},   # one per person
]}
pregen.check_proof(bundle, directory, output_sha256=output_hash)   # raises if anything is off
```

Store it with the file: a C2PA manifest assertion labelled `org.pregen.proof`, or alongside
it. **An output made without a valid `allow` is never presented as permitted.**

**Checking someone's proof** (a platform, a distributor, an auditor):

```python
result = pregen.check_proof(bundle, directory, output_sha256=sha256_of_the_file)
```

```js
import { checkProof } from "@pregen/verify";
const result = await checkProof(bundle, { directory, outputSha256 });
```

It returns `{output_hash, job_id, subjects: [{code, level, basis}]}` / `{outputHash, jobId,
subjects}` or raises with the reason. It passes when every answer was a valid `allow` at
the moment generation began, each acknowledgement is signed by that person's registry and
names that report and answer, it was received in time, all reports name one output and one
job, and the file's hash matches.

**Offline:** while online, save the directory and each listed registry's key set
(`GET {keys}` for every entry). Later, check with no network by giving the library what you
saved:

```python
directory = pregen.verify_directory(saved_directory)          # add steward_public_key_hex for a test directory
result = pregen.check_proof(bundle, directory, get_json=lambda url: saved_key_sets[url],
                            output_sha256=sha256_of_the_file)
```

```js
import { verifyDirectory, checkProof } from "@pregen/verify";
const directory = await verifyDirectory(savedDirectory);      // add { stewardPublicKeyHex } for a test directory
const fetch = async (url) => ({ ok: url in savedKeySets, status: url in savedKeySets ? 200 : 404,
                                json: async () => savedKeySets[url] });
const result = await checkProof(bundle, { directory, fetch, outputSha256 });
```

A retired registry key stays in its key set, so old proofs keep verifying after a key change.
A proof from a revoked registry fails, old ones included.

## 10. Try it in a sandbox first

Ask a registry for its sandbox `api`, the sandbox's eight test codes, and its test
directory (the URL and the test steward key). Take credentials from
`{sandbox api}/v2/sandbox/access`. The test subjects are `PG-<sandbox prefix>-000001…` to
`…000008`: `1` allows; `2`–`7` refuse, hold or say `not_blocked`; `8` is unknown. Check sandbox answers and proofs with `testing`:
`check_answer(…, testing=True)`, `check_proof(…, testing=True)` /
`{ testing: true }`. Your provider key needs registering at the sandbox too (step 3).

## Complete example (Python)

One job, one or more people, each at their own registry. Fill in the four constants.

```python
import hashlib
import json
import secrets
import time
import urllib.error
import urllib.request

import pregen

CREDENTIALS = {"ABCD": {"provider_id": "frame-ai", "token": "<secret>"}}   # one per registry (step 1)
KEY = "<your private key hex>"                                             # step 3, from your secret store
DIRECTORY_URL, TEST_STEWARD = pregen.DIRECTORY_URL, None                    # testing: the test directory and its key
CODES = ["PG-ABCD-000001G"]                                                # the people in this job

pub = pregen.public_key_hex(KEY)
key_id = pregen.fingerprint(pub)
directory = pregen.load_directory(DIRECTORY_URL, **({"steward_public_key_hex": TEST_STEWARD} if TEST_STEWARD else {}))


def post(entry, path, envelope):
    cred = CREDENTIALS[entry["prefix"]]
    req = urllib.request.Request(entry["api"] + path, data=json.dumps(envelope).encode(), method="POST", headers={
        "Content-Type": "application/json", "X-Provider-ID": cred["provider_id"],
        "Authorization": "Bearer " + cred["token"]})
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            return json.loads(res.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{path}: HTTP {e.code} {e.read().decode()}") from None


def register_key(entry):                                                  # step 3: once per registry
    post(entry, "/v2/keys", pregen.sign_envelope("pg.keyset.v1", {
        "signers": [{"role": "provider", "key_id": key_id}], "kind": "first",
        "provider_id": CREDENTIALS[entry["prefix"]]["provider_id"], "previous": None, "recovery_registry": "",
        "keys": [{"key_id": key_id, "public_key_hex": pub, "status": "current"}]}, KEY))


job_id = "job-" + secrets.token_hex(8)                                   # new for every job
job_hash = hashlib.sha256(b"what you fixed about this job").hexdigest()
asked = []
for code in CODES:                                                        # steps 5 and 6
    entry = directory.registry_for(code)
    if entry is None:
        raise SystemExit(f"{code}: no listed registry holds it; PRE-GEN says nothing: do not generate on it")
    register_key(entry)
    request = pregen.sign_envelope("pg.request.v1", {
        "subject_ref": code, "provider_id": CREDENTIALS[entry["prefix"]]["provider_id"], "profile": "likeness/1",
        "use": {"purpose": "commercial"}, "job_id": job_id, "job_hash": job_hash})
    answer = post(entry, "/v2/requests", request)["answer"]
    pregen.check_answer(answer, request, directory)                      # raises unless a valid allow
    asked.append((entry, request, answer, int(time.time())))

output = b"<the generated file>"                                          # step 7: generate only now
output_hash = hashlib.sha256(output).hexdigest()

subjects = []
for entry, request, answer, checked_at in asked:                          # step 8
    report = pregen.sign_envelope("pg.report.v1", {
        "signers": [{"role": "provider", "key_id": key_id}],
        "request_id": pregen.message_id("pg.request.v1", request["body"]),
        "answer": pregen.message_id("pg.answer.v1", answer["body"]), "job_id": job_id, "outcome": "generated",
        "output_hash": output_hash, "occurred_at": checked_at}, KEY)
    subjects.append({"request": request, "answer": answer, "report": report,
                     "ack": post(entry, "/v2/reports", report)["ack"]})

bundle = {"format": "pg.proof.v1", "subjects": subjects}                  # step 9
print(pregen.check_proof(bundle, directory, output_sha256=output_hash))
```

It prints `{'output_hash': '…', 'job_id': 'job-…', 'subjects': [{'code': 'PG-ABCD-000001G',
'level': 'verified', 'basis': {'kind': 'grant', …}}]}`. Registering the key again on the next
job is harmless: the registry returns the stored keyset.

## Complete example (JavaScript)

The same, in Node.js 20+ (save as `job.mjs`):

```js
import { createHash } from "node:crypto";
import { loadDirectory, signEnvelope, checkAnswer, checkProof, messageId, publicKeyHex, fingerprint,
  DIRECTORY_URL } from "@pregen/verify";

const CREDENTIALS = { ABCD: { provider_id: "frame-ai", token: "<secret>" } };   // one per registry (step 1)
const KEY = "<your private key hex>";                                          // step 3, from your secret store
const [url, TEST_STEWARD] = [DIRECTORY_URL, null];                              // testing: the test directory and its key
const CODES = ["PG-ABCD-000001G"];                                              // the people in this job

const pub = await publicKeyHex(KEY);
const keyId = await fingerprint(pub);
const directory = await loadDirectory(TEST_STEWARD ? { url, stewardPublicKeyHex: TEST_STEWARD } : { url });

async function post(entry, path, envelope) {
  const cred = CREDENTIALS[entry.prefix];
  const res = await fetch(entry.api + path, { method: "POST", body: JSON.stringify(envelope), headers: {
    "Content-Type": "application/json", "X-Provider-ID": cred.provider_id, Authorization: `Bearer ${cred.token}` } });
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status} ${await res.text()}`);
  return res.json();
}

const jobId = `job-${crypto.randomUUID()}`;                                     // new for every job
const jobHash = createHash("sha256").update("what you fixed about this job").digest("hex");
const asked = [];
for (const code of CODES) {                                                     // steps 5 and 6
  const entry = directory.registryFor(code);
  if (!entry) throw new Error(`${code}: no listed registry holds it; PRE-GEN says nothing: do not generate on it`);
  const providerId = CREDENTIALS[entry.prefix].provider_id;
  await post(entry, "/v2/keys", await signEnvelope("pg.keyset.v1", {                 // step 3: once per registry
    signers: [{ role: "provider", key_id: keyId }], kind: "first", provider_id: providerId, previous: null,
    recovery_registry: "", keys: [{ key_id: keyId, public_key_hex: pub, status: "current" }] }, KEY));
  const request = await signEnvelope("pg.request.v1", { subject_ref: code, provider_id: providerId,
    profile: "likeness/1", use: { purpose: "commercial" }, job_id: jobId, job_hash: jobHash });
  const { answer } = await post(entry, "/v2/requests", request);
  await checkAnswer(answer, request, { directory });                            // throws unless a valid allow
  asked.push({ entry, request, answer, checkedAt: Math.floor(Date.now() / 1000) });
}

const output = Buffer.from("<the generated file>");                             // step 7: generate only now
const outputHash = createHash("sha256").update(output).digest("hex");

const subjects = [];
for (const { entry, request, answer, checkedAt } of asked) {                    // step 8
  const report = await signEnvelope("pg.report.v1", { signers: [{ role: "provider", key_id: keyId }],
    request_id: await messageId("pg.request.v1", request.body), answer: await messageId("pg.answer.v1", answer.body),
    job_id: jobId, outcome: "generated", output_hash: outputHash, occurred_at: checkedAt }, KEY);
  const { ack } = await post(entry, "/v2/reports", report);
  subjects.push({ request, answer, report, ack });
}
const bundle = { format: "pg.proof.v1", subjects };                             // step 9
console.log(await checkProof(bundle, { directory, outputSha256: outputHash }));
```

## Errors

A refusal about a person is a signed answer (step 6). HTTP errors carry
`{"error", "error_description"}`:

| Code | HTTP | Meaning |
|---|---|---|
| `PG_MALFORMED` | 422 | the request does not follow the core (a member, a type, a code's spelling) |
| `PG_NOT_AUTHENTICATED` | 401 | the provider id or token is not accepted, or no provider key is registered yet (reports) |
| `PG_PROFILE_UNSUPPORTED` | 422 | the registry does not answer under this profile |
| `PG_KEYSET_CONFLICT` | 409 | a different first keyset was already registered: rotate instead (`spec/extensions/provider-keys.md`) |
| `PG_REPORT_CONFLICT` | 409 | another report for the same answer was already filed |
| `PG_ASK_CLOSED` | 409 | this person in this job was already reported: use a new `job_id` for a new job |

Answer reasons you will meet: `PG_UNKNOWN_SUBJECT` (this registry holds no such person:
not a prohibition, and not a permission), `PG_OTHER_REGISTRY`, `PG_NO_LICENSE`,
`PG_USAGE_LIMIT`, `PG_SCOPE_VIOLATION`, and the fixed protections no grant overrides:
`PG_SUBJECT_OPTED_OUT`, `PG_SUBJECT_UNAVAILABLE`, `PG_PROHIBITED_USE`,
`PG_IMMUTABLE_DENIAL`, `PG_PERSONAL_SIGNATURE_REQUIRED`. Treat any reason you do not know as
a refusal.

## You are done when

- [ ] The directory is loaded, kept, and loaded again at least every 24 hours
- [ ] Your provider key is in your secret store and registered at every registry you ask
- [ ] Every generation of a listed person is preceded by a request to the registry that holds them
- [ ] `check_answer` / `checkAnswer` passes for every person in the job before generating
- [ ] Every generation is reported, with `occurred_at` when generation began; refusals are never retried
- [ ] The proof bundle is checked with `check_proof` / `checkProof` and kept with the output
- [ ] Nothing in production accepts a sandbox answer; no prompt, output, token or key leaves your servers
