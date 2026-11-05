# PRE-GEN for AI providers: ask, check, generate, report, prove

You run a generative AI product. Before it generates an output that shows a protected
person (or work), it **asks** the registry that holds them, **checks** the signed answer,
generates **only on a valid `allow`**, **reports** the output, and keeps a **proof** anyone
can check offline. This guide gives every step in Python and JavaScript, with what each
step returns. Where it and the specification differ, the specification wins:
`https://www.pregen.org/spec/PRE-GEN-CORE.md`.

**You need:** Python 3.9+ or Node.js 20+, and credentials from each registry you ask (step 1).

## Ground rules

1. **Only `allow` permits.** `deny`, `review`, `not_blocked`, an unknown status or reason,
   or no valid answer at all: do not generate. Never ask again to get another answer to a
   refusal. (A new job for a new output, with a new `job_id`, is not asking again.)
2. **No answer is not a refusal and not a permission.** After a timeout or an HTTP 5xx you
   may send the **identical** request again (same `job_id`, same bytes): a registry answers
   it with the answer it already gave. The same goes for a connection error with no HTTP
   response. Wait 10 s for an answer, resend at most 3 times, 3 s apart; after that, you
   have no allow for that person. Skipping the resend can leave an allow you never saw
   counted against the grant.
3. **Never send the prompt or the output.** You send `job_hash`: a SHA-256 of what you
   fixed about the job: `hashlib.sha256(pregen.canonical_json(job_input)).hexdigest()`, where
   `job_input` is a dict of the prompt and settings (`canonical_json` returns bytes; in JS,
   `canonicalJson` returns a string to hash). Keep that input with the job, so you can show
   later what the hash stands for.
4. **Keep your clock synced** with your system's time service (NTP: `timedatectl`, `chronyc
   tracking`, or Windows Time): answers live minutes, and one issued more than 60 s in your
   future is refused.
5. **Secrets stay server-side:** registry tokens and your private key never go to a browser,
   a URL, a log or client code. Your secret store is wherever only your servers can read
   them: a secrets manager, environment variables, or a file readable only by the service.
6. **A sandbox answer is never accepted in production.** It carries `ext: {"sandbox": true}`;
   the libraries refuse it unless you pass `testing`.
7. **Copy codes exactly.** A person's code ends with a check character that may be `*`, `~`,
   `$`, `=` or `!`: quote codes in a shell (`'PG-ABCD-000001$'`) and encode them in a URL
   path (`%24` for `$`).
8. **Ask the person** who runs the product before you create accounts, accept terms or
   store secrets. Their request to integrate PRE-GEN covers what this guide makes: the
   sandbox credential and your provider key.

## 1. Credentials from each registry

Do the steps in this order: install (step 2), load the directory (step 4), then this step
and step 3; every `api` below comes from the directory. The directory (`https://www.pregen.org/registries.json`, human view
`https://www.pregen.org/registries`) lists every registry with its prefix and `api`. Each
registry gives you, privately, a **provider id** and a **token**. Always send to the
`api` in the registry's directory entry; if one a registry gave you differs, ask it before
sending anything. If a registry sends a token
without its provider id, ask for the id: do not guess (a wrong one is 401
`PG_NOT_AUTHENTICATED`). Keep one pair per registry, keyed by its prefix, for example:

```json
{"ABCD": {"provider_id": "frame-ai", "token": "<secret>"},
 "EFGH": {"provider_id": "frame-ai", "token": "<secret>"}}
```

A registry's sandbox gives test credentials without an account:
`curl -s -X POST {sandbox api}/v2/sandbox/access` → `{"provider_id": "sbx-…", "token": "…",
"registry": "<the sandbox api>", "note": "…"}` (Python: `json.loads(urllib.request.urlopen(
urllib.request.Request(sandbox_api + "/v2/sandbox/access", data=b"", method="POST")).read())`;
JS: `await (await fetch(sandboxApi + "/v2/sandbox/access", { method: "POST" })).json()`).
The token is shown once: store the pair at once, under the sandbox's prefix (the four
letters of its test codes). Once you have loaded the test directory (step 4), check that
`registry` equals `directory.registry_for(<test code 1>)["api"]`. A directory entry does not
say it is a sandbox; the registry's document does (`GET {api}/.well-known/pregen-registry.json`
→ `"sandbox": true`). Use the credential like any other.

## 2. Install the library

```bash
pip install "pregen>=0.11.0"
```

```bash
npm init -y && npm pkg set type=module    # in your project folder, if it has no package.json yet
npm install @pregen/verify@^0.11.0
```

Both carry the PRE-GEN steward key, check the directory, answers and proofs, and sign your
messages. Neither needs anything else.

## 3. Your provider key: make it once, register it once per registry

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

Register it **once at each registry**, with that registry's credential, before your first
request there (a report without a registered key is refused with 401, and the allow would
stay counted), and remember which registries are done. `PROVIDER_ID` is the provider id
that registry gave you; for JavaScript, see the complete example:

```python
keyset = pregen.sign_envelope("pg.keyset.v1", {
    "signers": [{"role": "provider", "key_id": key_id}],
    "kind": "first", "provider_id": PROVIDER_ID, "previous": None, "recovery_registry": "",
    "keys": [{"key_id": key_id, "public_key_hex": pub, "status": "current"}]}, key)
# POST {api}/v2/keys with this envelope as the JSON body (headers: step 5)
```

The registry answers HTTP 200 `{"keyset": …}`, and the same keyset again returns the same.
A *different* first keyset is refused (409 `PG_KEYSET_CONFLICT`): to change your key later,
send a `rotation` keyset (`spec/extensions/provider-keys.md`).

## 4. Load the directory

```python
directory = pregen.load_directory(previous=saved)     # saved: the last one you accepted, or None
saved = directory.to_json()                           # the full signed document: store it as JSON
```

```js
import { loadDirectory } from "@pregen/verify";
const directory = await loadDirectory({ previous: saved });
saved = directory.toJSON();
```

It is accepted only when the PRE-GEN steward signed it and its `sequence` is not lower than
the one you saved (so no one can serve you an older one). Load it again at least every 24
hours: answers checked against a directory object older than that are refused.

**Testing:** a test directory is signed by a test steward key. Load it with
`pregen.load_directory(url, previous=saved, steward_public_key_hex=TEST_STEWARD)` or
`loadDirectory({ url, previous: saved, stewardPublicKeyHex: TEST_STEWARD })`, where `url` is
the test directory's URL (without it, the public directory is loaded). Never in production.
A test directory is only about who signed the directory: answers from a non-sandbox registry
listed in it are checked without `testing`. `testing` is for sandbox answers only (step 10).

**A registry's new key:** if `check_answer` refuses with `… may not sign …: issuer_mismatch`,
the registry may have just been listed with a new key: load the directory again (with
`previous`) and check the same answer once more. If it still fails, it is not an answer.

## 5. Ask

A person's code looks like `PG-ABCD-000001G`; its four letters name the registry.
`directory.registry_for(code)` / `directory.registryFor(code)` gives that registry's entry
(`prefix`, `api`, `keys` = the URL of its key set, `key_fingerprints`, …). If it gives
`None` / `null`, no listed registry holds the code: you have no `allow`: do not generate
that person.

```
POST {api}/v2/requests
Content-Type: application/json
X-Provider-ID: <provider id from that registry>
Authorization: Bearer <token from that registry>

{"type": "pg.request.v1", "signatures": [],
 "body": {"subject_ref": "PG-ABCD-000001G", "provider_id": "<provider id>",
          "profile": "likeness/1", "use": {"purpose": "commercial"},
          "job_id": "job-8841", "job_hash": "<sha-256 hex of what you fixed about the job>",
          "licensee_id": "frame-ai:user-1"}}
```

- The first six members are required; `licensee_id` and the others below are optional. `use.purpose` is what the output is for, not
  its medium (an ad, image or video, is `commercial`; if you do not know what your customer
  will use it for, ask them, or send `commercial`): `personal`, `educational`,
  `research`, `editorial` or `commercial`; add `territory`, `channel` and `categories`
  (for example `["political"]`) when they apply, honestly: fixed protections are checked
  against them.
- **`licensee_id`** (optional, a member of `body` beside `job_id`): your end customer's id,
  when you generate on their behalf and the registry connected that customer to you
  (extension `licensee`). Leave it out otherwise. Some grants cover
  only one licensee. Send exactly the licensee id the registry gave you. An id the registry
  did not connect to you is refused (401 `PG_NOT_AUTHENTICATED`).
- **One request per person.** A job with two people asks twice, under the same `job_id`,
  each at the registry that holds them. **Every job has a new `job_id`** (random, not a
  timestamp), and `job_input` holds everything you fixed, the customer included (for example
  `{"prompt": …, "settings": …, "customer": "<licensee id, or null>"}`): once a
  person in a job is reported, asking again under that id is refused
  (409 `PG_ASK_CLOSED`, which carries the acknowledgement you were given before: keep it if
  you lost yours; otherwise nothing to do). Within one job, every request carries the same `job_hash`; a reused `job_id`
  with a different `job_hash` gets 409 `PG_JOB_CONFLICT` first. Both mean no answer.
- `pregen.sign_envelope("pg.request.v1", body)` / `signEnvelope("pg.request.v1", body)`
  makes the envelope (no key: `signatures` stays empty; the token authenticates you).

The registry answers HTTP 200 `{"answer": {"type": "pg.answer.v1", "body": {…}, "signatures": […]}}`.

## 6. Check the answer

```python
pregen.check_answer(answer, request, directory)     # raises PregenError; str(e) is the reason
```

```js
import { checkAnswer } from "@pregen/verify";
await checkAnswer(answer, request, { directory });  // throws PregenError; e.message is the reason
```

It passes only when a key the directory lists for the code's prefix signed the answer (and
was not retired before it signed), the answer names exactly your request and profile, it is
within its lifetime, it is not a sandbox answer (unless `testing`), and its `status` is
`allow`. An answer that fails the check is not an answer: never generate on it. If its body
says `allow` all the same (expired, badly signed, for another request), still report
`not_generated` for it (step 8), so a registry that did issue it frees the use; one that did
not refuses the report: log that and go on. To log why a valid answer refused, the same
arguments to `pregen.verify_answer(answer, request, directory)` /
`await verifyAnswer(answer, request, { directory })` (plus `testing` for a sandbox answer)
return the checked body whatever its status: read `body["reason"]` there. The statuses:

| `status` | Meaning | Do |
|---|---|---|
| `allow` | permitted, with a `basis` (a policy rule or a grant) | generate, applying any `obligations` (`[]` or missing: none); if one is listed that you do not understand, do not generate |
| `deny` | refused, with a `reason` (with `PG_UNKNOWN_SUBJECT`: this registry holds no such person) | do not generate |
| `review` | held for a person | do not generate in this job; a later job (new `job_id`) may ask again |
| `not_blocked` | nothing grants it | not a permission: do not generate on it |

`check_answer` does not look at `obligations`: you must. If an allow lists obligations your
product does not apply, do not generate, and give the allow back.

## 7. Generate, only on a valid allow for every person

An answer lives a short time (`expires_at`, at most 15 minutes; often 5). Generate only when
**every** person in the job has a checked `allow` whose `expires_at` has not passed. Take
one time, `began`, right before generation starts: it is the `occurred_at` of every report
in the job (step 8), even if rendering ends later. If generation cannot start before the
earliest `expires_at`, ask again under a new `job_id` and give back the old allows (step 8).
Hash the output: `output_hash = sha256(file bytes)` in hex.

## 8. Report the output

For each person's allow, sign a report with your key and send it to the same registry:

```python
report = pregen.sign_envelope("pg.report.v1", {
    "signers": [{"role": "provider", "key_id": key_id}],
    "request_id": pregen.message_id("pg.request.v1", request["body"]),
    "answer": pregen.message_id("pg.answer.v1", answer["body"]),
    "job_id": request["body"]["job_id"], "outcome": "generated",
    "output_hash": output_hash, "occurred_at": began}, key)
# POST {api}/v2/reports with this envelope → HTTP 200 {"ack": <signed pg.report_ack.v1>}
```

- **Give back what you did not use.** If the job stops after any `allow` (a later person
  refused, an error, you changed your mind, the allows expired), report
  `"outcome": "not_generated"` with `"output_hash": ""` and `occurred_at` = when you gave it
  up, for **every** allow already received in that job, soon (within 24 hours of the
  answer's expiry). Otherwise the use stays counted. Name your own request and the answer
  you received, even when that answer was for another request.
- **Keep the signed report** you sent. If a report gets no answer, send the **same bytes**
  again: you get the same acknowledgement. A different report for the same answer is
  refused (409 `PG_REPORT_CONFLICT`).
- **Send reports soon:** a proof needs the registry to have received the report within 24
  hours of the answer's expiry; a later one is recorded but proves nothing.

## 9. Keep the proof with the output

The proof is the four signed messages for every person in the job, exactly as signed:

```python
bundle = {"format": "pg.proof.v1", "subjects": [
    {"request": request, "answer": answer, "report": report, "ack": ack},   # one per person
]}
pregen.check_proof(bundle, directory, output_sha256=output_hash)   # raises if anything is off
```

Store it with the file: alongside it as JSON, or in the file's C2PA manifest as an assertion
labelled `org.pregen.proof`. **An output made without a valid `allow` is never presented as
permitted.**

**Checking someone's proof** (a platform, a distributor, an auditor):

```python
result = pregen.check_proof(bundle, directory, output_sha256=sha256_of_the_file)
```

```js
import { checkProof } from "@pregen/verify";
const result = await checkProof(bundle, { directory, outputSha256 });
```

**Always pass the SHA-256 of the file you hold.** Without it, the check says nothing about
that file, and its result must never be shown as a label on it. It returns `{output_hash,
job_id, subjects: [{code, level, basis}]}` / `{outputHash, jobId, subjects}`, or raises with
the reason (`str(e)` / `e.message`). Without `output_sha256` it still runs, but says nothing
about any file. It passes when every answer was a valid `allow` at the
`occurred_at` the provider reported (the registry bounds it: the report reached it within
24 hours of the allow's expiry), each acknowledgement is signed by that person's registry
and names that report and answer, all reports name one output and one job, and the file's
hash matches. `level` is how far the registry established who holds the person's rights:
`self` (the registrant's own claim), `asserted` (an agent's claim), `consented` (the
person's documented consent), `verified` (the registry checked identity and authority).
Show it with your label, and decide which levels your label requires; below `consented`, no
one but the registrant vouched, and a strict default is `verified`. `check_proof` does not
look at `obligations`: they are in each `answer.body`, and were the provider's to apply;
show them if your label cares. The result does not name a licensee; a licensee-only grant shows as `licensee_id`
in that person's `request.body`. With no file to hash, record the proof as not checked: it
is never a label. A proof made in a sandbox passes only with `testing` and is never a label.

**Offline:** while online, save the directory (`directory.to_json()` / `toJSON()`) and the key
set of every registry it lists: `GET` each entry's `keys` URL and keep the JSON, keyed by that
exact URL. They are required: `check_proof` reads each registry's key set on every check,
so offline it fails without them. Save both every time you load the directory, at least
every 24 hours while you label, replacing the old copies (a key set keeps its retired keys,
so the newest copy verifies old proofs too):

```python
saved_directory = directory.to_json()
for r in directory.registries:                       # saved_key_sets: the previous copy, or {}
    try:
        saved_key_sets[r["keys"]] = json.loads(urllib.request.urlopen(r["keys"], timeout=10).read())
    except Exception as e:
        print("kept the previous key set for", r["keys"], e)
```

```js
const savedDirectory = directory.toJSON();
for (const r of directory.registries) {              // savedKeySets: the previous copy, or {}
  try {
    const res = await fetch(r.keys, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    savedKeySets[r.keys] = await res.json();
  } catch (e) { console.log("kept the previous key set for", r.keys, e.message); }
}
```

If one registry does not answer, keep its previous copy and go on. Keep the directory in
one JSON file, and all key sets in another, as one object keyed by URL; a test directory's
steward key is a constant you keep with them. Save key sets as they come: at check time the
library uses only keys whose ids the directory lists, and refuses small-order keys. It does
not check the provider's signature on a report: it relies on the registry's signed
acknowledgement, which names that report. If your saved copy is more than 24 hours old, do
not label: go online, load and save again.

Later, check with no network:

```python
directory = pregen.verify_directory(saved_directory)       # test directory: steward_public_key_hex=TEST_STEWARD
result = pregen.check_proof(bundle, directory, get_json=lambda url: saved_key_sets.get(url, {}),
                            output_sha256=sha256_of_the_file)          # a sandbox proof: testing=True
```

```js
import { verifyDirectory, checkProof } from "@pregen/verify";
const directory = await verifyDirectory(savedDirectory);    // test directory: verifyDirectory(savedDirectory, { stewardPublicKeyHex: TEST_STEWARD })
const offlineFetch = async (url) => ({ ok: url in savedKeySets, status: url in savedKeySets ? 200 : 404,
                                       json: async () => savedKeySets[url] });
const result = await checkProof(bundle, { directory, fetch: offlineFetch, outputSha256 });
```

The check fetches only through the `get_json` / `fetch` you pass. A retired registry key stays
in its key set, so old proofs keep verifying after a key change.
A proof from a revoked registry fails, old ones included (the directory marks a revoked
registry `"revoked": true`, and lists revoked keys in `revoked_keys`). An offline check can only be as
current as what you saved: a revocation published after that is invisible to it. Use
`verify_directory(saved)` only for offline proof checks: it counts the saved copy as loaded
now. For answers, always `load_directory(previous=saved)`.

## 10. Try it in a sandbox first

From the registry, get its sandbox `api`, the sandbox's eight test codes, and the test
directory (its URL and test steward key). A sandbox is its own registry with its own prefix
(for example `ABCE` beside `ABCD`): take credentials from `{sandbox api}/v2/sandbox/access`,
store them under that prefix in `CREDENTIALS`, and register your key there (step 3). Copy
the eight test codes the registry gives you (code `N` is `PG-<prefix>-00000N` plus a check
character that cannot be guessed). Each answers one way:

| Code | Answer |
|---|---|
| `1` | `allow` |
| `2` | `deny` `PG_NO_LICENSE` |
| `3` | `deny` `PG_SUBJECT_OPTED_OUT` |
| `4` | `deny` `PG_USAGE_LIMIT` |
| `5` | `deny` `PG_PROHIBITED_USE` |
| `6` | `review` `PG_REVIEW_REQUIRED` |
| `7` | `not_blocked` `PG_NO_LICENSE` (nothing blocks it, and nothing grants it) |
| `8` | `deny` `PG_UNKNOWN_SUBJECT` |

Ask each in a job of its own, and take code `1` through the whole flow (ask, check,
generate, report, proof), as in production: the complete examples below do, with
`TESTING = True` / `const TESTING = true`. Keep sandbox outputs and proofs apart from
production ones: they are never labels. Check sandbox answers
and proofs with `testing`: `check_answer(answer, request, directory, testing=True)`,
`check_proof(…, testing=True)`; JS `checkAnswer(answer, request, { directory, testing: true })`.

## Complete example (Python)

One job, one or more people, each at their own registry. Fill in the six constants.

```python
import hashlib
import json
import os
import secrets
import time
import urllib.error
import urllib.request

import pregen

CREDENTIALS = {"ABCD": {"provider_id": "frame-ai", "token": "<secret>"}}   # one per registry (step 1)
KEY = "<your private key hex>"                                             # step 3, from your secret store
DIRECTORY_URL, TEST_STEWARD = pregen.DIRECTORY_URL, None                    # testing: the test directory and its key
CODES = ["PG-ABCD-000001G"]                                                # the people in this job
SAVED = "directory.json"                                                   # where the last directory is kept
TESTING = False                                                            # True only against a sandbox (step 10)

pub = pregen.public_key_hex(KEY)
key_id = pregen.fingerprint(pub)
saved = json.load(open(SAVED)) if os.path.exists(SAVED) else None
directory = pregen.load_directory(DIRECTORY_URL, previous=saved,
                                  **({"steward_public_key_hex": TEST_STEWARD} if TEST_STEWARD else {}))
json.dump(directory.to_json(), open(SAVED, "w"))


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


REGISTERED = set()                             # keep this with your secrets in a real product


def register_key(entry):                       # step 3: once per registry
    if entry["prefix"] in REGISTERED:
        return
    post(entry, "/v2/keys", pregen.sign_envelope("pg.keyset.v1", {
        "signers": [{"role": "provider", "key_id": key_id}], "kind": "first",
        "provider_id": CREDENTIALS[entry["prefix"]]["provider_id"], "previous": None, "recovery_registry": "",
        "keys": [{"key_id": key_id, "public_key_hex": pub, "status": "current"}]}, KEY))
    REGISTERED.add(entry["prefix"])


def report(entry, request, answer, outcome, output_hash, began):   # step 8
    env = pregen.sign_envelope("pg.report.v1", {
        "signers": [{"role": "provider", "key_id": key_id}],
        "request_id": pregen.message_id("pg.request.v1", request["body"]),
        "answer": pregen.message_id("pg.answer.v1", answer["body"]), "job_id": request["body"]["job_id"],
        "outcome": outcome, "output_hash": output_hash, "occurred_at": began}, KEY)
    return env, post(entry, "/v2/reports", env)["ack"]


def give_back(items, when):                                              # step 8: not_generated, one by one
    for entry, request, answer in items:
        try:
            report(entry, request, answer, "not_generated", "", when)
        except Exception as e:                                           # e.g. a registry that never issued it
            print("give-back refused:", e)


job_id = "job-" + secrets.token_hex(8)                                   # new for every job
job_input = {"prompt": "<the prompt>", "settings": {"model": "<model>", "seed": 1}}   # keep it with the job
job_hash = hashlib.sha256(pregen.canonical_json(job_input)).hexdigest()
allowed = []                                                              # every answer whose body says allow
try:
    for code in CODES:                                                    # steps 5 and 6
        entry = directory.registry_for(code)
        if entry is None:
            raise RuntimeError(f"{code}: no listed registry holds it, so no allow: do not generate")
        register_key(entry)
        request = pregen.sign_envelope("pg.request.v1", {
            "subject_ref": code, "provider_id": CREDENTIALS[entry["prefix"]]["provider_id"], "profile": "likeness/1",
            "use": {"purpose": "commercial"}, "job_id": job_id, "job_hash": job_hash})
        answer = post(entry, "/v2/requests", request)["answer"]
        if answer.get("body", {}).get("status") == "allow":
            allowed.append((entry, request, answer))                      # given back below if anything fails
        pregen.check_answer(answer, request, directory, testing=TESTING)  # raises unless a valid allow
        if answer["body"].get("obligations"):                             # this product applies none, so any listed one stops it
            raise RuntimeError(f"{code}: an allow with obligations this product does not apply")
except Exception:
    give_back(allowed, int(time.time()))
    raise

began = int(time.time())                                                  # step 7: generation begins now
if began >= min(a["body"]["expires_at"] for _, _, a in allowed):          # an allow ran out: give all back, ask again
    give_back(allowed, began)
    raise RuntimeError("an allow expired before generation began: ask again under a new job_id")
try:
    output = b"<the generated file>"                                      # your generation
except Exception:
    give_back(allowed, int(time.time()))                                  # it failed: free every use
    raise
output_hash = hashlib.sha256(output).hexdigest()

subjects = []
for entry, request, answer in allowed:                                    # step 8
    rep, ack = report(entry, request, answer, "generated", output_hash, began)
    subjects.append({"request": request, "answer": answer, "report": rep, "ack": ack})

bundle = {"format": "pg.proof.v1", "subjects": subjects}                  # step 9
print(pregen.check_proof(bundle, directory, output_sha256=output_hash, testing=TESTING))
```

It prints `{'output_hash': '…', 'job_id': 'job-…', 'subjects': [{'code': 'PG-ABCD-000001G',
'level': 'verified', 'basis': {'kind': 'grant', …}}]}`. Not shown, in either example: the
identical resend of rule 2, the directory reload on `issuer_mismatch` (step 4), and
`verify_answer` to log why a refusal refused (step 6).

## Complete example (JavaScript)

The same, in Node.js 20+ (save as `job.mjs`):

```js
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { loadDirectory, signEnvelope, checkAnswer, checkProof, messageId, publicKeyHex, fingerprint,
  canonicalJson, DIRECTORY_URL } from "@pregen/verify";

const CREDENTIALS = { ABCD: { provider_id: "frame-ai", token: "<secret>" } };   // one per registry (step 1)
const KEY = "<your private key hex>";                                          // step 3, from your secret store
const [url, TEST_STEWARD] = [DIRECTORY_URL, null];                              // testing: the test directory and its key
const CODES = ["PG-ABCD-000001G"];                                              // the people in this job
const SAVED = "directory.json";                                                 // where the last directory is kept
const TESTING = false;                                                          // true only against a sandbox (step 10)

const pub = await publicKeyHex(KEY);
const keyId = await fingerprint(pub);
const previous = existsSync(SAVED) ? JSON.parse(readFileSync(SAVED, "utf8")) : undefined;
const directory = await loadDirectory({ url, previous, ...(TEST_STEWARD ? { stewardPublicKeyHex: TEST_STEWARD } : {}) });
writeFileSync(SAVED, JSON.stringify(directory.toJSON()));

async function post(entry, path, envelope) {
  const cred = CREDENTIALS[entry.prefix];
  const res = await fetch(entry.api + path, { method: "POST", body: JSON.stringify(envelope), signal: AbortSignal.timeout(10000), headers: {
    "Content-Type": "application/json", "X-Provider-ID": cred.provider_id, Authorization: `Bearer ${cred.token}` } });
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status} ${await res.text()}`);
  return res.json();
}

async function report(entry, request, answer, outcome, outputHash, began) {      // step 8
  const env = await signEnvelope("pg.report.v1", { signers: [{ role: "provider", key_id: keyId }],
    request_id: await messageId("pg.request.v1", request.body), answer: await messageId("pg.answer.v1", answer.body),
    job_id: request.body.job_id, outcome, output_hash: outputHash, occurred_at: began }, KEY);
  return { report: env, ack: (await post(entry, "/v2/reports", env)).ack };
}

async function giveBack(items, when) {                                          // step 8: not_generated, one by one
  for (const { entry, request, answer } of items) {
    try { await report(entry, request, answer, "not_generated", "", when); }
    catch (e) { console.log("give-back refused:", e.message); }                 // e.g. a registry that never issued it
  }
}

const registered = new Set();                                                   // keep this with your secrets in a real product
const jobId = `job-${crypto.randomUUID()}`;                                     // new for every job
const jobInput = { prompt: "<the prompt>", settings: { model: "<model>", seed: 1 } };   // keep it with the job
const jobHash = createHash("sha256").update(canonicalJson(jobInput)).digest("hex");
const allowed = [];                                                             // every answer whose body says allow
try {
  for (const code of CODES) {                                                   // steps 5 and 6
    const entry = directory.registryFor(code);
    if (!entry) throw new Error(`${code}: no listed registry holds it, so no allow: do not generate`);
    const providerId = CREDENTIALS[entry.prefix].provider_id;
    if (!registered.has(entry.prefix)) {                                        // step 3: once per registry
      await post(entry, "/v2/keys", await signEnvelope("pg.keyset.v1", {
        signers: [{ role: "provider", key_id: keyId }], kind: "first", provider_id: providerId, previous: null,
        recovery_registry: "", keys: [{ key_id: keyId, public_key_hex: pub, status: "current" }] }, KEY));
      registered.add(entry.prefix);
    }
    const request = await signEnvelope("pg.request.v1", { subject_ref: code, provider_id: providerId,
      profile: "likeness/1", use: { purpose: "commercial" }, job_id: jobId, job_hash: jobHash });
    const { answer } = await post(entry, "/v2/requests", request);
    if (answer?.body?.status === "allow") allowed.push({ entry, request, answer }); // given back below if anything fails
    await checkAnswer(answer, request, { directory, testing: TESTING });       // throws unless a valid allow
    if (answer.body.obligations?.length) throw new Error(`${code}: an allow with obligations`); // this product applies none
  }
} catch (e) {
  await giveBack(allowed, Math.floor(Date.now() / 1000));
  throw e;
}

const began = Math.floor(Date.now() / 1000);                                    // step 7: generation begins now
if (began >= Math.min(...allowed.map(({ answer }) => answer.body.expires_at))) { // an allow ran out: give all back
  await giveBack(allowed, began);
  throw new Error("an allow expired before generation began: ask again under a new job_id");
}
let output;
try {
  output = Buffer.from("<the generated file>");                                 // your generation
} catch (e) {
  await giveBack(allowed, Math.floor(Date.now() / 1000));                       // it failed: free every use
  throw e;
}
const outputHash = createHash("sha256").update(output).digest("hex");

const subjects = [];
for (const { entry, request, answer } of allowed) {                             // step 8
  const { report: rep, ack } = await report(entry, request, answer, "generated", outputHash, began);
  subjects.push({ request, answer, report: rep, ack });
}
const bundle = { format: "pg.proof.v1", subjects };                             // step 9
console.log(await checkProof(bundle, { directory, outputSha256: outputHash, testing: TESTING }));
```

## Errors

A refusal about a person is a signed answer (step 6). HTTP errors carry
`{"error", "error_description"}`:

| Code | HTTP | Meaning |
|---|---|---|
| `PG_MALFORMED` | 422 | the request does not follow the core (a member, a type, a code's spelling) |
| `PG_NOT_AUTHENTICATED` | 401 | the provider id, token or licensee is not accepted, or no provider key is registered yet (reports) |
| `PG_PROFILE_UNSUPPORTED` | 422 | the registry does not answer under this profile |
| `PG_KEYSET_CONFLICT` | 409 | a different first keyset was already registered: rotate instead (step 3) |
| `PG_REPORT_CONFLICT` | 409 | another report for the same answer was already filed: resend the report you kept |
| `PG_ASK_CLOSED` | 409 | this person in this job was already reported: use a new `job_id` for a new job |
| `PG_ASK_CONFLICT` | 409 | this person in this job was asked with a different request: resend the identical one |
| `PG_JOB_CONFLICT` | 409 | this `job_id` was already used with another `job_hash`: use a new `job_id` |
| any other code | any | no answer: do not generate; if it refused a give-back, log it and go on |

Answer reasons you will meet: `PG_UNKNOWN_SUBJECT` (this registry holds no such person:
not a prohibition, and not a permission), `PG_OTHER_REGISTRY`, `PG_NO_LICENSE`,
`PG_USAGE_LIMIT`, `PG_SCOPE_VIOLATION` (the grant does not cover this purpose or use),
`PG_REVIEW_REQUIRED` (held for a person), and
the fixed protections no grant overrides: `PG_SUBJECT_OPTED_OUT`, `PG_SUBJECT_UNAVAILABLE`,
`PG_PROHIBITED_USE`, `PG_IMMUTABLE_DENIAL`, `PG_PERSONAL_SIGNATURE_REQUIRED`. Treat any
reason you do not know as a refusal.

## You are done when

- [ ] The directory is saved after every load, and loaded again (with `previous`) at least every 24 hours
- [ ] Your provider key is in your secret store and registered at every registry you ask
- [ ] Every generation of a listed person is preceded by a request to the registry that holds them
- [ ] `check_answer` / `checkAnswer` passes for every person in the job before generating
- [ ] Every allow is reported: `generated` with `occurred_at` = when generation began, or `not_generated`
- [ ] The proof bundle is checked with `check_proof` / `checkProof` and kept with the output
- [ ] Nothing in production accepts a sandbox answer; no prompt, output, token or key leaves your servers
