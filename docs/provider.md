# PRE-GEN for AI providers: ask, check, generate, report, prove

You run a generative AI product. Before it generates an output that shows a protected
person (or work), it **asks** the registry its code names, **checks** the signed answer,
generates **only on a valid `allow`**, **reports** the output, and keeps a **proof** anyone
can check offline. This guide gives every step in Python and JavaScript, with what each
step returns. Where it and the specification differ, the specification wins:
`https://www.pregen.org/spec/PRE-GEN-CORE.md`.

**You need:** Python 3.9+ or Node.js 20+, and credentials from each registry you ask (step 3).

## Ground rules

1. **Only `allow` permits.** `deny`, `review`, `not_blocked`, an unknown status or reason,
   or no valid answer at all: do not generate. Never ask again to get another answer to a
   refusal. (A new job for a different output is not asking again; the same `job_input`
   under a new `job_id` after a `deny` is, unless something you can name changed since: a new
   grant you were told of, the customer connected, a different purpose.)
2. **No answer is not a refusal and not a permission.** After a timeout or an HTTP 5xx you
   may send the **identical** request again (same `job_id`, same bytes): a registry answers
   it with the answer it already gave (after that answer expires, the same bytes get a new
   answer, which counts again: give back any allow you do not use). The same goes for a connection error with no HTTP
   response, and for `/v2/keys` and `/v2/reports`. Wait 10 s for an answer; on none, wait
   3 s and send the same bytes again, up to 3 more times (4 sends in all). Any 4xx is final
   for those bytes: no answer; do not resend them unless the Errors table says to. After
   that, you have no allow for
   that person. Skipping the resend can leave an allow you never saw
   counted against the grant.
3. **Never send the prompt or the output.** You send `job_hash`: a SHA-256 of what you
   fixed about the job: `hashlib.sha256(pregen.canonical_json(job_input)).hexdigest()`, where
   `job_input` is a dict of the prompt and settings (`canonical_json` returns bytes; in JS,
   `canonicalJson` returns a string to hash). Keep that input with the job, so you can show
   later, to whoever you choose (never a registry), what the hash stands for.
4. **Keep your clock synced** with your system's time service (NTP: `timedatectl`, `chronyc
   tracking`, `sntp time.apple.com` on macOS, or Windows Time; without a time server, compare
   with a registry's HTTP `Date` header, `curl -s -o /dev/null -D - {api}/keys | grep -i '^date'`):
   answers live minutes, and one issued more than 60 s in your future is refused.
5. **Secrets stay server-side:** registry tokens and your private key never go to a browser,
   a URL, a log or client code. Your secret store is wherever only your servers can read
   them: a secrets manager, environment variables, or a file readable only by the service.
6. **A sandbox answer is never accepted in production.** It carries `ext: {"sandbox": true}`;
   the libraries refuse it unless you pass `testing`.
7. **Copy codes exactly.** A person's code ends with a check character that may be `*`, `~`,
   `$`, `=` or `!`: quote codes in a shell (`'PG-ABCD-000001$'`) and encode them in a URL
   path (`%24` for `$`).
8. **Ask the person** who runs the product before you create accounts, accept terms or
   store secrets. Their request to integrate PRE-GEN covers what this guide makes and
   stores: the sandbox credential, the tokens registries give you, and your provider key.

## 1. Install the library

```bash
pip install "pregen>=0.11.0"
```

```bash
npm init -y && npm pkg set type=module    # in your project folder, if it has no package.json yet
npm install @pregen/verify@^0.11.0
```

Both carry the PRE-GEN steward key, check the directory, answers and proofs, and sign your
messages. Neither needs anything else.

## 2. Load the directory

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
Keep a saved test directory in its own file: passed as `previous` to the real directory, it is
refused (`sequence … is older` / `namespace … was removed`).
A test directory is only about who signed the directory: answers from a non-sandbox registry
listed in it are checked without `testing`. `testing` is for sandbox answers only (step 10).

**A registry's new key:** if `check_answer` refuses with `… may not sign …: issuer_mismatch`,
the registry may have just been listed with a new key: load the directory again (with
`previous`) and check the same answer once more. If it still fails, it is not an answer.

## 3. Credentials from each registry

Every `api` below comes from the directory you loaded in step 2. The directory
(`https://www.pregen.org/registries.json`, human view
`https://www.pregen.org/registries`) lists every registry with its prefix and `api`. Each
registry gives you, privately, a **provider id** and a **token**. Always send to the
`api` in the registry's directory entry; if one a registry gave you differs, ask it before
sending anything (compare them as exact strings). If a registry sends a token
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
JS: `const res = await fetch(sandboxApi + "/v2/sandbox/access", { method: "POST" }); if (!res.ok)
throw new Error(`HTTP ${res.status}`); const access = await res.json()`).
Never resend this call: each one mints a new credential (at most 10 an hour per address, then
429). The token is shown once: store the pair at once, under the sandbox's prefix (the four
letters of its test codes). Once you have loaded the test directory (step 2), check that
`registry` equals `directory.registry_for(<test code 1>)["api"]` (by prefix: `next(r for r in directory.registries if
r["prefix"] == "ABCE")["api"]`); if it differs, delete the
stored pair and ask the registry before using it. A directory entry does not
say it is a sandbox; the registry's document does (`GET {api}/.well-known/pregen-registry.json`
→ `"sandbox": true`; if it says `false`, it is not a sandbox: do not use `testing` with it).
Use the credential like any other.

## 4. Your provider key: make it once, register it once per registry

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
stay counted), and remember which registries are done (persist that list with your secrets,
and each job's `job_id` and `job_input` with the job record, saved before its first request,
so a resend after a crash is the identical request). `PROVIDER_ID` is the provider id
that registry gave you; anything but HTTP 200 with `keyset` means: do not ask that registry. In JavaScript, `await signEnvelope("pg.keyset.v1", { …the same body… },
KEY)` (the complete example has it in full):

```python
keyset = pregen.sign_envelope("pg.keyset.v1", {
    "signers": [{"role": "provider", "key_id": key_id}],
    "kind": "first", "provider_id": PROVIDER_ID, "previous": None, "recovery_registry": "",
    "keys": [{"key_id": key_id, "public_key_hex": pub, "status": "current"}]}, key)
# POST {api}/v2/keys with this envelope as the JSON body (headers: step 5)
```

The registry answers HTTP 200 `{"keyset": …}`, and the same keyset again returns the same.
`recovery_registry: ""` means only the registry that holds your key set may co-sign a
recovery if you lose your key (`https://www.pregen.org/spec/extensions/provider-keys.md`). A *different* first
keyset is refused (409 `PG_KEYSET_CONFLICT`): to change your key later,
send a `rotation` keyset (`https://www.pregen.org/spec/extensions/provider-keys.md`).

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

- The first six members are required; `licensee_id` and the others below are optional.
  `profile` is the fixed name of a vocabulary of uses (`likeness/1`: a person's likeness and
  voice), never a version of a registry's policy: the answer must name the same profile,
  compared as a name. No answer carries a version, hash or counter of a registry's rules. `use.purpose` is what the output is for, not
  its medium (an ad, image or video, is `commercial`; if you do not know what your customer
  will use it for, ask them, or send `commercial`): `personal`, `educational`,
  `research`, `editorial` or `commercial`; add `territory`, `channel` and `categories`
  (for example `["political"]`) when they apply, honestly: fixed protections are checked
  against them.
- **`licensee_id`** (optional, a member of `body` beside `job_id`): your end customer's id,
  when you generate on their behalf and the registry connected that customer to you
  (extension `licensee`). Leave it out otherwise. A licensee id belongs to one registry: send it
  only to the registry that connected it, and none to the other registries in the job. Some grants cover
  only one licensee. Send exactly the licensee id the registry gave you. An id the registry
  did not connect to you is refused (401 `PG_NOT_AUTHENTICATED`).
- **Rule out what you can locally first** (no listed registry, no credential, a failed anchor
  list), then ask in any order you like and stop at the first refusal, giving back every allow
  received before it.
- **One request per code.** A job with two people asks twice, under the same `job_id`,
  each code at the registry its prefix names (a public person: see below). **Every job has a new `job_id`** (random, not a
  timestamp), and `job_input` holds everything you fixed, the customer included (for example
  `{"prompt": …, "settings": …, "customer": "<the licensee_id you send, or null>"}`): once a
  person in a job is reported, asking again under that id is refused
  (409 `PG_ASK_CLOSED`, whose body's `ack` member is the acknowledgement you were given before: keep it if
  you lost yours; otherwise nothing to do). Within one job, every request carries the same `job_hash`; a reused `job_id`
  with a different `job_hash` gets 409 `PG_JOB_CONFLICT` first. Both mean no answer.
- `pregen.sign_envelope("pg.request.v1", body)` / `signEnvelope("pg.request.v1", body)`
  makes the envelope (no key: `signatures` stays empty; the token authenticates you).

The registry answers HTTP 200 `{"answer": {"type": "pg.answer.v1", "body": {…}, "signatures": […]}}`.

**A public person** (extension `identity`, `https://www.pregen.org/spec/extensions/identity.md`) may be claimed by
several registries. A refusal of the person (`PG_SUBJECT_OPTED_OUT`, `PG_SUBJECT_UNAVAILABLE`,
`PG_PROHIBITED_USE`, `PG_IMMUTABLE_DENIAL`, `PG_PERSONAL_SIGNATURE_REQUIRED`) by any registry
whose claim the person confirmed holds everywhere; "no licence here" does not. So:

1. At least daily, fetch every listed registry's anchor list and check it:

   ```python
   anchors, failed = {}, set()                       # anchor -> [{code, proof_url, …}]; prefixes whose list failed
   for r in directory.registries:
       if r.get("revoked") or not r["prefix"]:
           continue                                  # revoked, or the legacy bare namespace
       try:
           env = json.loads(urllib.request.urlopen(r["api"] + "/v2/anchors", timeout=10).read())
           for e in pregen.verify_anchors(env, r["prefix"], directory):   # refuses a list over a day old
               anchors.setdefault(e["anchor"], []).append(e)
       except urllib.error.HTTPError as e:
           try:                                      # 404 is "no list" only from a registry without identity
               declared = "identity" in json.loads(urllib.request.urlopen(
                   r["api"] + "/.well-known/pregen-registry.json", timeout=10).read()).get("extensions", [])
           except Exception:
               declared = True
           if e.code != 404 or declared:
               failed.add(r["prefix"])               # item 5
       except Exception:
           failed.add(r["prefix"])
   ```

   In JS (`fetch` does not throw on a 404):

   ```js
   const anchors = {}, failed = new Set();
   for (const r of directory.registries) {
     if (r.revoked || !r.prefix) continue;
     try {
       const res = await fetch(r.api + "/v2/anchors", { signal: AbortSignal.timeout(10000) });
       if (res.status === 404) {                                         // "no list" only without identity
         const doc = await (await fetch(r.api + "/.well-known/pregen-registry.json")).json();
         if ((doc.extensions ?? []).includes("identity")) failed.add(r.prefix);
         continue;
       }
       if (!res.ok) throw new Error(`HTTP ${res.status}`);
       for (const e of await verifyAnchors(await res.json(), r.prefix, { directory })) (anchors[e.anchor] ??= []).push(e);
     } catch { failed.add(r.prefix); }                                    // item 5
   }
   ```

   An entry's
   `status` (`active`, `opted_out`, …) is information only: ask the code anyway.
2. If a person's code is in a list, ask **every** code listed under the same anchor, each at
   its registry, in the same job.
3. For each code, decide whether the person confirmed it on their own channel:
   `pregen.check_channel_proof(code, entry["proof_url"], pregen.wikidata_official_urls(anchor),
   get_text)`, where `get_text(url)` returns the page's text (JS: `await checkChannelProof(code,
   proofUrl, await wikidataOfficialUrls(anchor, { fetch }), getText)`, with `getText` an
   `async (url) => string`). `confirmed` is the boolean it returns. Only `wikidata:` anchors have
   a defined list of official channels today: for any other anchor, `confirmed` is `False` (do
   not call `wikidata_official_urls`, which raises). Both complete examples below do all of
   step 5. In Python, pass `get_text` (and a `get_json` if you fetch
   yourself) that send a `User-Agent: <product> (<contact URL>)` header: Wikidata answers 403
   to an anonymous client (the library's own fetcher sends one). In JS, pass a `fetch` that sends
   it to `wikidataOfficialUrls`, and send it from `getText`.
4. Combine: `pregen.decide_identity([{"code": c, "confirmed": …, "answer":
   pregen.verify_answer(answer, request, directory)}, …])` / `decideIdentity([...])` (synchronous;
   `answer` is the checked body `verify_answer` / `await verifyAnswer` returns) gives
   `{status, reason, code}`. A confirmation may be reused until the next daily anchor fetch,
   while the entry's `proof_url` is unchanged. Generate only if its `status` is `allow`. With no confirmed claim
   it is `not_blocked` (`PG_IDENTITY_UNCONFIRMED`): no permission. `check_answer` must pass for
   the code it returns; `verify_answer` must pass for every other code whose claim the person
   confirmed. Report
   as `generated`, and put in the proof, the allow of the code it returns and every other allow
   from a claim the person confirmed; give back (step 8) allows from unconfirmed claims. Apply
   step 6's obligations rule to every allow you report. Codes that did not answer `allow` are
   neither reported nor put in the proof. If the status is not `allow`, give back every allow.
5. **Unknown is not unconfirmed.** If any listed registry's anchor list fails (anything but
   404, or `verify_anchors` raises), if a proof page or Wikidata cannot be read, or if any code
   under the anchor **whose claim the person confirmed** gets no valid answer (no credentials
   there, a 4xx, or `verify_answer` raises), you have no decision for this person: do not
   generate them, and give back their allows. A failure at an unconfirmed claim changes nothing:
   `decide_identity` ignores it. While any registry's anchor list (except a 404) has not verified within the last 24
   hours (`failed` above), generate no one whose code has that registry's prefix, and no public
   person at all (no code that is in any anchor list): the failed list may hold their opt-out.
   Everyone else may go on. A code the steward recorded as a false claim
   (`directory.is_false_claim(code)`) is never generated, and the libraries refuse its answers.

## 6. Check the answer

If you learn of another registry's claim to the same person only later, apply step 5's
public-person rule then: keep every answer, and never present the output as permitted while a
refusal of the person stands.

```python
pregen.check_answer(answer, request, directory)     # raises pregen.PregenError (a ValueError); str(e) is the reason
```

```js
import { checkAnswer, PregenError } from "@pregen/verify";
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
`await verifyAnswer(answer, request, { directory })` (for a sandbox answer,
`verify_answer(answer, request, directory, testing=True)` / `verifyAnswer(answer, request, {
directory, testing: true })`)
return the checked body whatever its status: read `body["reason"]` there. Like `check_answer`,
they raise when the answer itself is not valid; then log that reason. The statuses:

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
**every** person in the job has a checked `allow` (for a public person, `decide_identity`'s
`allow`, step 5) whose `expires_at` has not passed. Take
one time, `began` (whole Unix seconds, `int(time.time())`), right before generation starts:
it is the `occurred_at` of every report
in the job (step 8), even if rendering ends later. If generation cannot start before the
earliest `expires_at`, ask again under a new `job_id` and give back the old allows (step 8).
Write the output only after every check passed and `began` is taken. Hash it:
`output_hash` = SHA-256, in hex, of the exact bytes you write or deliver (read back from the
file if you write one).

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
  answer's `issued_at`). Otherwise the use stays counted. Name your own request and the answer
  you received, even when that answer was for another request.
- **Keep the signed report** you sent. If a report gets no answer, send the **same bytes**
  again: you get the same acknowledgement. A different report for the same answer is
  refused (409 `PG_REPORT_CONFLICT`). If the `generated` report is refused or never
  acknowledged, the output has no proof: keep it unlabelled, and never send a different report.
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
Show it with your label. By default require `verified`; accept less only under a policy of your
own that you publish (below `consented`, no one but the registrant vouched). `check_proof` does not
look at `obligations`: they are in each `answer.body`, and were the provider's to apply;
show them if your label cares. The result does not name a licensee; a licensee-only grant shows as `licensee_id`
in that person's `request.body`. With no file to hash, do not run the check: record it as not
accepted, reason "no file: not checked"; it is never a label. A proof covers only the people
it lists; it says nothing about anyone else the file shows, nor that every registry claiming a
public person was asked. If any `answer.body.obligations` is non-empty, show them with the label
or do not label. A proof made in a sandbox passes only with `testing` and is never a label.

**Offline:** while online, save the directory (`directory.to_json()` / `toJSON()`) and the key
set of every registry it lists: `GET` each entry's `keys` URL and keep the JSON, keyed by that
exact URL. They are required for offline checks: `check_proof` reads each registry's key set on every check,
so offline it fails without them. Save both every time you load the directory, at least
every 24 hours while you label, replacing the old copies (a key set keeps its retired keys,
so the newest copy verifies old proofs too):

Production and testing each keep their own folder, so a test file can never stand in for a
production one: `pregen/`, or `pregen-test/` with the test steward key beside the rest.

```python
FOLDER = "pregen-test" if TEST_STEWARD else "pregen"
os.makedirs(FOLDER, exist_ok=True)
path = lambda name: os.path.join(FOLDER, name)
saved_key_sets = json.load(open(path("key_sets.json"))) if os.path.exists(path("key_sets.json")) else {}
for r in directory.registries:
    try:
        saved_key_sets[r["keys"]] = json.loads(urllib.request.urlopen(r["keys"], timeout=10).read())
    except Exception as e:
        print("kept the previous key set for", r["keys"], e)
json.dump(directory.to_json(), open(path("directory.json"), "w"))
json.dump(saved_key_sets, open(path("key_sets.json"), "w"))
json.dump({"saved_at": int(time.time())}, open(path("saved_at.json"), "w"))
if TEST_STEWARD:
    json.dump({"steward_public_key_hex": TEST_STEWARD}, open(path("test_steward.json"), "w"))
```

```js
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
const FOLDER = TEST_STEWARD ? "pregen-test" : "pregen";
mkdirSync(FOLDER, { recursive: true });
const path = (name) => `${FOLDER}/${name}`;
const savedKeySets = existsSync(path("key_sets.json")) ? JSON.parse(readFileSync(path("key_sets.json"), "utf8")) : {};
for (const r of directory.registries) {
  try {
    const res = await fetch(r.keys, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    savedKeySets[r.keys] = await res.json();
  } catch (e) { console.log("kept the previous key set for", r.keys, e.message); }
}
writeFileSync(path("directory.json"), JSON.stringify(directory.toJSON()));
writeFileSync(path("key_sets.json"), JSON.stringify(savedKeySets));
writeFileSync(path("saved_at.json"), JSON.stringify({ saved_at: Math.floor(Date.now() / 1000) }));
if (TEST_STEWARD) writeFileSync(path("test_steward.json"), JSON.stringify({ steward_public_key_hex: TEST_STEWARD }));
```

**A proof checked against a test directory is never a label, sandbox or not.** If one registry
does not answer, keep its previous copy and go on. Save key sets as they come: at check time the
library uses only keys whose ids the directory lists, and refuses small-order keys; the
directory never removes a listed key id (the libraries refuse a directory that does), a key is
only ever revoked, so old proofs keep their keys. It does not check the provider's signature on
a report: it relies on the registry's signed acknowledgement, which names that report. The
library cannot tell when you saved: `saved_at.json` does, and if it is more than 24 hours old,
do not label: go online, load and save again.

Later, check with no network (`verify_directory` / `verifyDirectory` fetch nothing):

```python
FOLDER = "pregen"                                    # "pregen-test" only when testing
path = lambda name: os.path.join(FOLDER, name)
test = json.load(open(path("test_steward.json")))["steward_public_key_hex"] if os.path.exists(path("test_steward.json")) else None
saved_key_sets = json.load(open(path("key_sets.json")))
if time.time() - json.load(open(path("saved_at.json")))["saved_at"] > 86_400:
    raise SystemExit("the saved copy is more than 24 hours old: go online, load and save again")
directory = pregen.verify_directory(json.load(open(path("directory.json"))),
                                    **({"steward_public_key_hex": test} if test else {}))
result = pregen.check_proof(bundle, directory, get_json=lambda url: saved_key_sets.get(url, {}),
                            output_sha256=sha256_of_the_file)          # a sandbox proof: testing=True
```

```js
import { existsSync, readFileSync } from "node:fs";
import { verifyDirectory, checkProof } from "@pregen/verify";
const FOLDER = "pregen";                                                       // "pregen-test" only when testing
const read = (name) => JSON.parse(readFileSync(`${FOLDER}/${name}`, "utf8"));
const TEST = existsSync(`${FOLDER}/test_steward.json`) ? read("test_steward.json").steward_public_key_hex : null;
const savedKeySets = read("key_sets.json");
if (Date.now() / 1000 - read("saved_at.json").saved_at > 86_400) {
  throw new Error("the saved copy is more than 24 hours old: go online, load and save again");
}
const directory = await verifyDirectory(read("directory.json"), TEST ? { stewardPublicKeyHex: TEST } : {});
const offlineFetch = async (url) => ({ ok: url in savedKeySets, status: url in savedKeySets ? 200 : 404,
                                       json: async () => savedKeySets[url] });
const result = await checkProof(bundle, { directory, fetch: offlineFetch, outputSha256 });   // a sandbox proof: testing: true
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
store them under that prefix in `CREDENTIALS`, and register your key there (step 4; the same
provider key for sandbox and production is fine). Copy
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

A registry may give you more codes (9 and up) for its own test grants, and tells you what each
answers: ask them like the others. Ask each in a job of its own, and take code `1` through the whole flow (ask, check,
generate, report, proof), as in production: the complete examples below do, with
`TESTING = True` / `const TESTING = true`. Keep sandbox outputs and proofs apart from
production ones: they are never labels. Check sandbox answers
and proofs with `testing`: `check_answer(answer, request, directory, testing=True)`,
`check_proof(…, testing=True)`; JS `checkAnswer(answer, request, { directory, testing: true })`.

## Complete example (Python)

One job, one or more people (private or public), each at their own registry. Fill in the eight constants.

```python
import hashlib
import http.client
import json
import os
import secrets
import time
import urllib.error
import urllib.request

import pregen

CREDENTIALS = {"ABCD": {"provider_id": "frame-ai", "token": "<secret>"}}   # one per registry (step 3)
KEY = "<your private key hex>"                                             # step 4, from your secret store
DIRECTORY_URL, TEST_STEWARD = pregen.DIRECTORY_URL, None                    # testing: the test directory and its key
CODES = ["PG-ABCD-000001G"]                                                # the people in this job
SAVED = "directory-test.json" if TEST_STEWARD else "directory.json"          # never a test directory as previous to the real one
TESTING = False                                                            # True only against a sandbox (step 10)
UA = {"User-Agent": "frame-ai (https://frame-ai.example/contact)"}        # who you are: Wikidata refuses anonymous clients
LICENSEES = {}                                                             # prefix -> the licensee_id that registry gave this customer

pub = pregen.public_key_hex(KEY)
key_id = pregen.fingerprint(pub)
saved = json.load(open(SAVED)) if os.path.exists(SAVED) else None
directory = pregen.load_directory(DIRECTORY_URL, previous=saved,
                                  **({"steward_public_key_hex": TEST_STEWARD} if TEST_STEWARD else {}))
json.dump(directory.to_json(), open(SAVED, "w"))


def get_json(url):
    return json.loads(urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=10).read())


def get_text(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=10).read().decode()


ANCHOR_OF, CLAIMS, FAILED = {}, {}, set()                                  # step 5.1 (refresh at least daily)
for r in directory.registries:
    if r.get("revoked") or not r["prefix"]:
        continue                                                          # revoked, or the legacy bare namespace
    try:
        for e in pregen.verify_anchors(get_json(r["api"] + "/v2/anchors"), r["prefix"], directory):
            ANCHOR_OF[e["code"]] = e["anchor"]
            CLAIMS.setdefault(e["anchor"], []).append(e)
    except urllib.error.HTTPError as e:                                   # 404 is "no list" only without identity
        try:
            declared = "identity" in get_json(r["api"] + "/.well-known/pregen-registry.json").get("extensions", [])
        except Exception:
            declared = True
        if e.code != 404 or declared:
            FAILED.add(r["prefix"])
    except Exception:
        FAILED.add(r["prefix"])


def post(entry, path, envelope, member):                                  # rule 2: the same bytes, at most 4 sends
    cred, data = CREDENTIALS[entry["prefix"]], json.dumps(envelope).encode()
    for _ in range(4):
        req = urllib.request.Request(entry["api"] + path, data=data, method="POST", headers={
            "Content-Type": "application/json", "X-Provider-ID": cred["provider_id"],
            "Authorization": "Bearer " + cred["token"]})
        try:
            with urllib.request.urlopen(req, timeout=10) as res:
                body = json.loads(res.read())
            if member not in body:
                raise RuntimeError(f"{path}: HTTP 200 without {member}: no answer")
            return body[member]
        except urllib.error.HTTPError as e:
            if e.code < 500 and e.code != 429:                            # any other 4xx is final for these bytes
                raise RuntimeError(f"{path}: HTTP {e.code} {e.read().decode()}") from None
            if e.code == 429:
                time.sleep(min(int(e.headers.get("Retry-After") or 3), 60))
                continue
        except (urllib.error.URLError, OSError, http.client.HTTPException):
            pass                                                          # no answer: send the same bytes again
        time.sleep(3)
    raise RuntimeError(f"{path}: no answer after 4 sends")


REGISTERED = set()                             # keep this with your secrets in a real product


def register_key(entry):                       # step 4: once per registry
    if entry["prefix"] in REGISTERED:
        return
    post(entry, "/v2/keys", pregen.sign_envelope("pg.keyset.v1", {
        "signers": [{"role": "provider", "key_id": key_id}], "kind": "first",
        "provider_id": CREDENTIALS[entry["prefix"]]["provider_id"], "previous": None, "recovery_registry": "",
        "keys": [{"key_id": key_id, "public_key_hex": pub, "status": "current"}]}, KEY), "keyset")
    REGISTERED.add(entry["prefix"])


def report(entry, request, answer, outcome, output_hash, began):   # step 8
    env = pregen.sign_envelope("pg.report.v1", {
        "signers": [{"role": "provider", "key_id": key_id}],
        "request_id": pregen.message_id("pg.request.v1", request["body"]),
        "answer": pregen.message_id("pg.answer.v1", answer["body"]), "job_id": request["body"]["job_id"],
        "outcome": outcome, "output_hash": output_hash, "occurred_at": began}, KEY)
    return env, post(entry, "/v2/reports", env, "ack")


def give_back(items, when):                                              # step 8: not_generated, one by one
    for entry, request, answer in items:
        try:
            report(entry, request, answer, "not_generated", "", when)
        except Exception as e:                                           # e.g. a registry that never issued it
            print("give-back refused:", e)


job_id = "job-" + secrets.token_hex(8)                                   # new for every job
job_input = {"prompt": "<the prompt>", "settings": {"model": "<model>", "seed": 1}, "customer": LICENSEES or None}   # keep it
job_hash = hashlib.sha256(pregen.canonical_json(job_input)).hexdigest()
allowed = []                                                              # every answer whose body says allow


def ask(code):                                                            # step 5: one code, in this job
    entry = directory.registry_for(code)
    register_key(entry)
    request = pregen.sign_envelope("pg.request.v1", {
        "subject_ref": code, "provider_id": CREDENTIALS[entry["prefix"]]["provider_id"], "profile": "likeness/1",
        "use": {"purpose": "commercial"}, "job_id": job_id, "job_hash": job_hash,
        **({"licensee_id": LICENSEES[entry["prefix"]]} if entry["prefix"] in LICENSEES else {})})
    answer = post(entry, "/v2/requests", request, "answer")
    if answer.get("body", {}).get("status") == "allow":
        allowed.append((entry, request, answer))                          # given back below if anything fails
    return answer, request


for code in CODES:                                                        # rule out locally first (step 5)
    entry = directory.registry_for(code)
    if entry is None or entry["prefix"] in FAILED or (code not in ANCHOR_OF and entry["prefix"] not in CREDENTIALS):
        raise SystemExit(f"{code}: no listed registry, no credential there, or its anchor list failed")
    if directory.is_false_claim(code):
        raise SystemExit(f"{code}: the steward recorded it as a false claim")
    if code in ANCHOR_OF and FAILED:
        raise SystemExit(f"{code}: a public person while an anchor list failed: no decision (step 5)")

try:
    for code in CODES:                                                    # steps 5 and 6
        anchor = ANCHOR_OF.get(code)
        if anchor is None:                                                # a private person: one code
            pregen.check_answer(*ask(code), directory, testing=TESTING)  # raises unless a valid allow
            continue
        official = pregen.wikidata_official_urls(anchor, get_json=get_json) if anchor.startswith("wikidata:") else []
        claims, asked = [], {}                                            # a public person: every code under the anchor
        for e in CLAIMS[anchor]:
            confirmed = bool(official) and pregen.check_channel_proof(e["code"], e["proof_url"], official, get_text)
            try:
                asked[e["code"]] = ask(e["code"])
                body = pregen.verify_answer(*asked[e["code"]], directory, testing=TESTING)
            except Exception:
                if confirmed:
                    raise                                                 # a confirmed claim with no answer: no decision
                body = {}                                                 # an unconfirmed claim changes nothing
            claims.append({"code": e["code"], "answer": body, "confirmed": confirmed})
        verdict = pregen.decide_identity(claims)
        if verdict["status"] != "allow":
            raise RuntimeError(f"{code}: {verdict['status']} {verdict['reason']}")
        pregen.check_answer(*asked[verdict["code"]], directory, testing=TESTING)
        unconfirmed = {c["code"] for c in claims if not c["confirmed"]}   # their allows go back, not into the proof
        give_back([a for a in allowed if a[1]["body"]["subject_ref"] in unconfirmed], int(time.time()))
        allowed[:] = [a for a in allowed if a[1]["body"]["subject_ref"] not in unconfirmed]
    for entry, request, answer in allowed:                                # step 6: this product applies no obligations
        if answer["body"].get("obligations"):
            raise RuntimeError(f"{request['body']['subject_ref']}: an allow with obligations")
except Exception:
    give_back(allowed, int(time.time()))
    raise

began = int(time.time())                                                  # step 7: generation begins now
if began >= min(a["body"]["expires_at"] for _, _, a in allowed):          # an allow ran out: give all back, ask again
    give_back(allowed, began)
    raise RuntimeError("an allow expired before generation began: ask again under a new job_id")
try:
    open("output.bin", "wb").write(b"<the generated file>")               # your generation
except Exception:
    give_back(allowed, int(time.time()))                                  # it failed: free every use
    raise
output_hash = hashlib.sha256(open("output.bin", "rb").read()).hexdigest()  # the bytes delivered

subjects, unreported = [], []
for entry, request, answer in allowed:                                    # step 8: every report, one by one
    try:
        rep, ack = report(entry, request, answer, "generated", output_hash, began)
        subjects.append({"request": request, "answer": answer, "report": rep, "ack": ack})
    except Exception as e:
        unreported.append(request["body"]["subject_ref"])
        print("report refused:", e)

if unreported:                                                            # no proof: keep the output unlabelled
    raise SystemExit(f"no proof for {unreported}: keep output.bin unlabelled")
bundle = {"format": "pg.proof.v1", "subjects": subjects}                  # step 9
print(pregen.check_proof(bundle, directory, output_sha256=output_hash, testing=TESTING))
```

It prints `{'output_hash': '…', 'job_id': 'job-…', 'subjects': [{'code': 'PG-ABCD-000001G',
'level': 'verified', 'basis': {'kind': 'grant', …}}]}`. Not shown, in either example: the
identical resend of rule 2, the directory reload on `issuer_mismatch` (step 2),
`verify_answer` to log why a refusal refused (step 6), and saving the key sets for offline
checks (step 9).

## Complete example (JavaScript)

The same, in Node.js 20+ (save as `job.mjs`):

```js
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { loadDirectory, signEnvelope, checkAnswer, verifyAnswer, checkProof, messageId, publicKeyHex, fingerprint,
  canonicalJson, verifyAnchors, wikidataOfficialUrls, checkChannelProof, decideIdentity, DIRECTORY_URL } from "@pregen/verify";

const CREDENTIALS = { ABCD: { provider_id: "frame-ai", token: "<secret>" } };   // one per registry (step 3)
const KEY = "<your private key hex>";                                          // step 4, from your secret store
const [url, TEST_STEWARD] = [DIRECTORY_URL, null];                              // testing: the test directory and its key
const CODES = ["PG-ABCD-000001G"];                                              // the people in this job
const SAVED = TEST_STEWARD ? "directory-test.json" : "directory.json";         // never a test directory as previous to the real one
const TESTING = false;                                                          // true only against a sandbox (step 10)
const UA = "frame-js (https://frame-js.example/contact)";                       // who you are: Wikidata refuses anonymous clients
const LICENSEES = {};                                                           // prefix -> the licensee_id that registry gave this customer

const pub = await publicKeyHex(KEY);
const keyId = await fingerprint(pub);
const previous = existsSync(SAVED) ? JSON.parse(readFileSync(SAVED, "utf8")) : undefined;
const directory = await loadDirectory({ url, previous, ...(TEST_STEWARD ? { stewardPublicKeyHex: TEST_STEWARD } : {}) });
writeFileSync(SAVED, JSON.stringify(directory.toJSON()));

const fetchUA = (u, o = {}) => fetch(u, { ...o, signal: AbortSignal.timeout(10000), headers: { ...o.headers, "User-Agent": UA } });
const getText = async (u) => { const res = await fetchUA(u); if (!res.ok) throw new Error(`${u}: HTTP ${res.status}`); return res.text(); };

const ANCHOR_OF = new Map(), CLAIMS = new Map(), FAILED = new Set();            // step 5.1 (refresh at least daily)
for (const r of directory.registries) {
  if (r.revoked || !r.prefix) continue;                                         // revoked, or the legacy bare namespace
  try {
    const res = await fetchUA(r.api + "/v2/anchors");
    if (res.status === 404) {                                                   // "no list" only without identity
      const doc = await fetchUA(r.api + "/.well-known/pregen-registry.json").then((d) => d.json()).catch(() => null);
      if (!doc || (doc.extensions ?? []).includes("identity")) FAILED.add(r.prefix);
      continue;
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    for (const e of await verifyAnchors(await res.json(), r.prefix, { directory })) {
      ANCHOR_OF.set(e.code, e.anchor);
      if (!CLAIMS.has(e.anchor)) CLAIMS.set(e.anchor, []);
      CLAIMS.get(e.anchor).push(e);
    }
  } catch { FAILED.add(r.prefix); }
}

async function post(entry, path, envelope, member) {                          // rule 2: the same bytes, at most 4 sends
  const cred = CREDENTIALS[entry.prefix], data = JSON.stringify(envelope);
  for (let i = 0; i < 4; i++) {
    let res, body;
    try {
      res = await fetch(entry.api + path, { method: "POST", body: data, signal: AbortSignal.timeout(10000), headers: {
        "Content-Type": "application/json", "X-Provider-ID": cred.provider_id, Authorization: `Bearer ${cred.token}` } });
      body = res.ok ? await res.json() : await res.text();
    } catch { await new Promise((r) => setTimeout(r, 3000)); continue; }        // no answer: send the same bytes again
    if (res.ok) {
      if (!(member in body)) throw new Error(`${path}: HTTP 200 without ${member}: no answer`);
      return body[member];
    }
    if (res.status < 500 && res.status !== 429) throw new Error(`${path}: HTTP ${res.status} ${body}`);
    const wait = res.status === 429 ? Math.min(Number(res.headers.get("Retry-After")) || 3, 60) : 3;
    await new Promise((r) => setTimeout(r, wait * 1000));
  }
  throw new Error(`${path}: no answer after 4 sends`);
}

async function report(entry, request, answer, outcome, outputHash, began) {      // step 8
  const env = await signEnvelope("pg.report.v1", { signers: [{ role: "provider", key_id: keyId }],
    request_id: await messageId("pg.request.v1", request.body), answer: await messageId("pg.answer.v1", answer.body),
    job_id: request.body.job_id, outcome, output_hash: outputHash, occurred_at: began }, KEY);
  return { report: env, ack: await post(entry, "/v2/reports", env, "ack") };
}

async function giveBack(items, when) {                                          // step 8: not_generated, one by one
  for (const { entry, request, answer } of items) {
    try { await report(entry, request, answer, "not_generated", "", when); }
    catch (e) { console.log("give-back refused:", e.message); }                 // e.g. a registry that never issued it
  }
}

const registered = new Set();                                                   // keep this with your secrets in a real product
const jobId = `job-${crypto.randomUUID()}`;                                     // new for every job
const jobInput = { prompt: "<the prompt>", settings: { model: "<model>", seed: 1 }, customer: Object.keys(LICENSEES).length ? LICENSEES : null };   // keep it
const jobHash = createHash("sha256").update(canonicalJson(jobInput)).digest("hex");
const allowed = [];                                                             // every answer whose body says allow

async function ask(code) {                                                      // step 5: one code, in this job
  const entry = directory.registryFor(code);
  const providerId = CREDENTIALS[entry.prefix].provider_id;
  if (!registered.has(entry.prefix)) {                                          // step 4: once per registry
    await post(entry, "/v2/keys", await signEnvelope("pg.keyset.v1", {
      signers: [{ role: "provider", key_id: keyId }], kind: "first", provider_id: providerId, previous: null,
      recovery_registry: "", keys: [{ key_id: keyId, public_key_hex: pub, status: "current" }] }, KEY), "keyset");
    registered.add(entry.prefix);
  }
  const request = await signEnvelope("pg.request.v1", { subject_ref: code, provider_id: providerId,
    profile: "likeness/1", use: { purpose: "commercial" }, job_id: jobId, job_hash: jobHash,
    ...(entry.prefix in LICENSEES ? { licensee_id: LICENSEES[entry.prefix] } : {}) });
  const answer = await post(entry, "/v2/requests", request, "answer");
  if (answer?.body?.status === "allow") allowed.push({ entry, request, answer }); // given back below if anything fails
  return { answer, request };
}

for (const code of CODES) {                                                     // rule out locally first (step 5)
  const entry = directory.registryFor(code);
  if (!entry || FAILED.has(entry.prefix) || (!ANCHOR_OF.has(code) && !CREDENTIALS[entry.prefix])) {
    throw new Error(`${code}: no listed registry, no credential there, or its anchor list failed`);
  }
  if (directory.isFalseClaim(code)) throw new Error(`${code}: the steward recorded it as a false claim`);
  if (ANCHOR_OF.has(code) && FAILED.size) throw new Error(`${code}: a public person while an anchor list failed: no decision (step 5)`);
}

try {
  for (const code of CODES) {                                                   // steps 5 and 6
    const anchor = ANCHOR_OF.get(code);
    if (!anchor) {                                                              // a private person: one code
      const { answer, request } = await ask(code);
      await checkAnswer(answer, request, { directory, testing: TESTING });     // throws unless a valid allow
      continue;
    }
    const official = anchor.startsWith("wikidata:") ? await wikidataOfficialUrls(anchor, { fetch: fetchUA }) : [];
    const claims = [], asked = new Map();                                       // a public person: every code under the anchor
    for (const e of CLAIMS.get(anchor)) {
      const confirmed = official.length > 0 && await checkChannelProof(e.code, e.proof_url, official, getText);
      let body = {};                                                            // an unconfirmed claim changes nothing
      try {
        const { answer, request } = await ask(e.code);
        asked.set(e.code, { answer, request });
        body = await verifyAnswer(answer, request, { directory, testing: TESTING });
      } catch (err) { if (confirmed) throw err; }                               // a confirmed claim with no answer: no decision
      claims.push({ code: e.code, answer: body, confirmed });
    }
    const verdict = decideIdentity(claims);
    if (verdict.status !== "allow") throw new Error(`${code}: ${verdict.status} ${verdict.reason}`);
    const chosen = asked.get(verdict.code);
    await checkAnswer(chosen.answer, chosen.request, { directory, testing: TESTING });
    const unconfirmed = new Set(claims.filter((c) => !c.confirmed).map((c) => c.code));   // their allows go back
    const back = allowed.filter((a) => unconfirmed.has(a.request.body.subject_ref));
    await giveBack(back, Math.floor(Date.now() / 1000));
    allowed.splice(0, allowed.length, ...allowed.filter((a) => !back.includes(a)));
  }
  for (const { request, answer } of allowed) {                                  // step 6: this product applies no obligations
    if (answer.body.obligations?.length) throw new Error(`${request.body.subject_ref}: an allow with obligations`);
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
try {
  writeFileSync("output.bin", Buffer.from("<the generated file>"));             // your generation
} catch (e) {
  await giveBack(allowed, Math.floor(Date.now() / 1000));                       // it failed: free every use
  throw e;
}
const outputHash = createHash("sha256").update(readFileSync("output.bin")).digest("hex");   // the bytes delivered

const subjects = [], unreported = [];
for (const { entry, request, answer } of allowed) {                             // step 8: every report, one by one
  try {
    const { report: rep, ack } = await report(entry, request, answer, "generated", outputHash, began);
    subjects.push({ request, answer, report: rep, ack });
  } catch (e) { unreported.push(request.body.subject_ref); console.log("report refused:", e.message); }
}
if (unreported.length) throw new Error(`no proof for ${unreported}: keep output.bin unlabelled`);
const bundle = { format: "pg.proof.v1", subjects };                             // step 9
console.log(await checkProof(bundle, { directory, outputSha256: outputHash, testing: TESTING }));
```

## Errors

A refusal about a person is a signed answer (step 6). HTTP errors carry
`{"error", "error_description"}`:

| Code | HTTP | Meaning |
|---|---|---|
| `PG_MALFORMED` | 422 | the request does not follow the core (a member, a type, a code's spelling) |
| `PG_NOT_AUTHENTICATED` | 401 | the provider id, token or licensee is not accepted, or no provider key is registered yet (reports: register it, step 4, then send the same report again) |
| `PG_PROFILE_UNSUPPORTED` | 422 | the registry does not answer under this profile |
| `PG_KEYSET_CONFLICT` | 409 | a different first keyset was already registered: rotate instead (step 4) |
| `PG_REPORT_CONFLICT` | 409 | another report for the same answer was already filed: resend the report you kept |
| `PG_ASK_CLOSED` | 409 | this person in this job was already reported: use a new `job_id` for a new job |
| `PG_ASK_CONFLICT` | 409 | this person in this job was asked with a different request: resend the identical one |
| `PG_JOB_CONFLICT` | 409 | this `job_id` was already used with another `job_hash`: use a new `job_id` |
| `PG_RATE_LIMITED` | 429 | not answered yet: wait (`Retry-After` if sent), then send the same bytes again |
| any other code | any | no answer: do not generate; if it refused a give-back, log it and go on |
| HTTP 200 without `answer` / `ack` / `keyset` | 200 | no answer, as a 4xx |

Answer reasons you will meet: `PG_UNKNOWN_SUBJECT` (this registry holds no such person:
not a prohibition, and not a permission), `PG_OTHER_REGISTRY`, `PG_NO_LICENSE`, `PG_NOT_CONNECTED`
(only a connected end user's grant would do: show "connect your account"),
`PG_USAGE_LIMIT`, `PG_SCOPE_VIOLATION` (the grant does not cover this purpose or use),
`PG_REVIEW_REQUIRED` (held for a person), and
the fixed protections no grant overrides: `PG_SUBJECT_OPTED_OUT`, `PG_SUBJECT_UNAVAILABLE`,
`PG_PROHIBITED_USE`, `PG_IMMUTABLE_DENIAL`, `PG_PERSONAL_SIGNATURE_REQUIRED`. Treat any
reason you do not know as a refusal.

## You are done when

- [ ] The directory is saved after every load, and loaded again (with `previous`) at least every 24 hours
- [ ] Your provider key is in your secret store and registered at every registry you ask
- [ ] If you check proofs offline, the directory and every key set are saved with `saved_at`, at least every 24 hours
- [ ] Every generation of a listed person is preceded by a request for each of their codes, to the registry each code names
- [ ] A public person is asked at every code their anchor names, and generated only on `decide_identity`'s `allow`
- [ ] `check_answer` / `checkAnswer` passes for every private person, and for the code `decide_identity` names for each public person, before generating
- [ ] Every allow is reported: `generated` with `occurred_at` = when generation began, or `not_generated`
- [ ] The proof bundle is checked with `check_proof` / `checkProof` and kept with the output
- [ ] Nothing in production accepts a sandbox answer; no prompt, output, token or key leaves your servers
