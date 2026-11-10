# PRE-GEN for AI providers: a domain, a key, the library

You run a generative AI product. Before it generates an output that shows a protected
person (or work), it **asks** the registry its code names, **checks** the signed answer,
generates **only on a valid `allow`**, **reports** the output, and keeps a **proof** anyone
can check offline. This guide gives every step in Python and JavaScript, with what each
step returns. Where it and the specification differ, the specification wins:
`https://www.pregen.org/spec/PRE-GEN-CORE.md`.

**You need:** Python 3.9+ or Node.js 20+, and a domain you control. **No account anywhere:**
your identity is your domain and a key you make (step 2). Every registry listed in the
directory answers you on the same terms. Selling licences is a registry's own, optional
business, joined later and separately (the section "Selling and connected users").

## Ground rules

1. **Only `allow` permits.** `deny`, `review`, `not_blocked`, an unknown status or reason,
   or no valid answer at all: do not generate. Never ask again to get another answer to a
   refusal; an answer that fails `check_answer` is no answer, not a refusal. (A new job for a
   different output is not asking again; the same `job_input`
   under a new `job_id` after a `deny` is, unless something you can name changed since: a new
   grant you were told of, the customer connected, a different purpose.)
2. **No answer is not a refusal and not a permission.** After a timeout or an HTTP 5xx you
   may send the **identical** request again (same `job_id`, same bytes): while its answer is
   open, a registry answers it with the answer it already gave. The same goes for a connection error with no HTTP
   response, and for `/v2/keys` and `/v2/reports`. Wait 10 s for an answer; on none, wait
   3 s and send the same bytes again, up to 3 more times (4 sends in all). Any 4xx is final
   for those bytes: no answer; do not resend them unless the Errors table says to. After
   that, you have no allow for that person, and **you never send that request again**: once
   its answer had expired, the same bytes would get a new answer and count a second use.
   Instead, give back an allow you may never have seen: once any answer would have expired (never
   earlier than your actual last send, Retry-After waits included, plus its 10 s timeout, plus the
   registry's answer lifetime, 900 s if you do not know it, plus 60 s for clocks), report `"outcome": "not_generated"` with
   `"answer": null` and your `request` (step 7). The registry gives back every expired allow of
   that request and closes it (`extensions/limits.md`). Skipping it can leave an allow you never
   saw counted against the grant.
3. **Never send the prompt or the output.** You send `job_hash`: a SHA-256 of what you
   fixed about the job: `hashlib.sha256(pregen.canonical_json(job_input)).hexdigest()`, where
   `job_input` is a dict of the prompt and settings (`canonical_json` returns bytes; in JS,
   `canonicalJson` returns a string to hash). It accepts only strings, booleans, null, lists,
   objects and whole numbers from −(2^53 − 1) to 2^53 − 1: write every other number as a string
   (`"temperature": "0.7"`, `"seed": "18446744073709551615"`). Keep that input with the job, so you can show
   later, to whoever you choose (never a registry), what the hash stands for.
4. **Keep your clock synced** with your system's time service (NTP: `timedatectl`, `chronyc
   tracking`, `sntp time.apple.com` on macOS, or Windows Time; without a time server, compare
   with a registry's HTTP `Date` header, `curl -s -o /dev/null -D - {api}/keys | grep -i '^date'`):
   answers live minutes, and one issued more than 60 s in your future is refused.
5. **Secrets stay server-side:** your private key (and any registry token, on the credential
   path) never goes to a browser, a URL, a log or client code. Your secret store is wherever only your servers can read
   them: a secrets manager, environment variables, or a file readable only by the service.
6. **A sandbox answer is never accepted in production.** It carries `ext: {"sandbox": true}`;
   the libraries refuse it unless you pass `testing`.
7. **Copy codes exactly.** An older person's code may end with a check character `*`, `~`,
   `$`, `=` or `!`: quote codes in a shell (`'TOG-TEST-000006$'`) and encode them in a URL
   path (`%24` for `$`).
8. **Ask the person** who runs the product before you accept terms or store secrets. Their
   request to integrate PRE-GEN covers what this guide makes and stores: your provider key,
   your party document, and the copy of it a sandbox keeps. This guide creates no account.
9. **An `allow` is a registry's signed answer, not legal advice.** It records what that
   registry decided under its own published policy; you stay responsible under the law
   that applies to you (`https://www.pregen.org/legal.html`).

## 1. Install the library

```bash
pip install "pregen>=0.13.0"
```

```bash
npm init -y && npm pkg set type=module    # in your project folder, if it has no package.json yet
npm install @pregen/verify@^0.13.0
```

Both carry the PRE-GEN steward key, check the directory, answers and proofs, and sign your
messages. Neither needs anything else.

## 2. Your identity: a domain, a key, the party document

A provider is known by its **domain** and signs with its **key**. Nothing is issued to you,
nowhere to sign up (extension `provider-identity`,
`https://www.pregen.org/spec/extensions/provider-identity.md`).

**Your provider id** is `https://` and your registrable domain, nothing else: the name you
registered (eTLD+1 under the Public Suffix List), `https://frame.example`, never
`https://app.frame.example` or `https://www.frame.example`. It is lower case, with no subdomain,
path, port or trailing slash, and at most 100 characters; only a sandbox also takes a port, step 9.
The libraries and a sandbox accept a subdomain. Checking the registrable domain is the registry's
job: a production registry that does it refuses a subdomain (401 `PG_NOT_AUTHENTICATED`); the
reference registry does not check it. It goes in every request as `provider_id` and in the `X-Provider-ID`
header. Pick the domain the product owns and keep it: changing it is becoming a new provider.

**Make the key once** and keep it with your other secrets:

```python
import json, os
import pregen
if not os.path.exists("provider.key"):      # once: never overwrite a key a registry has pinned
    fd = os.open("provider.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # or your secret store; the complete examples read this file
    with os.fdopen(fd, "w") as f:
        f.write(pregen.new_private_key_hex())   # 64 hex: the private key. Never log it.
key = open("provider.key").read().strip()
pub = pregen.public_key_hex(key)            # 64 hex: the public key
key_id = pregen.fingerprint(pub)            # "pg-ed25519:<32 hex>"
```

```js
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { newPrivateKeyHex, publicKeyHex, fingerprint, partyDocument } from "@pregen/verify";
if (!existsSync("provider.key")) writeFileSync("provider.key", newPrivateKeyHex(), { mode: 0o600, flag: "wx" });   // once; never overwrite
const key = readFileSync("provider.key", "utf8").trim();
const pub = await publicKeyHex(key);
const keyId = await fingerprint(pub);
```

**Build the party document** (who you are and your key, signed by the key) and serve it as a
static file at `https://<your domain>/.well-known/pregen-party.json`:

```python
doc = pregen.party_document("https://frame.example", "Frame", key)   # the same key: the same document
json.dump(doc, open("pregen-party.json", "w"))                       # publish it at /.well-known/pregen-party.json
```

```js
const doc = await partyDocument("https://frame.example", "Frame", key);
writeFileSync("pregen-party.json", JSON.stringify(doc));             // publish it at /.well-known/pregen-party.json
```

Check it: `curl -s https://frame.example/.well-known/pregen-party.json | python3 -m json.tool`
prints `party_id`, `name`, `roles` and one `keysets` entry.

To let people connect licences (`bind`, see Selling below), list your callback:
`pregen.party_document("https://frame.example", "Frame", key, redirect_uris=["https://frame.example/pregen/callback"])`
/ `partyDocument(url, name, key, { redirectUris: ["https://frame.example/pregen/callback"] })`.
Each is HTTPS on your own host (or a native app's reversed-domain scheme).
 The file must answer over HTTPS
without a redirect and without a login. If your site sends `example.com` to `www.example.com`, exempt
`/.well-known/pregen-party.json` from that redirect. A registry reads it the first time you ask, pins your
key chain, and reads it again at least daily; **whoever takes over your domain does not get
your key**: a later document must extend the chain (a `rotation` keyset signed by the old key,
`https://www.pregen.org/spec/extensions/provider-keys.md`), or it is refused.

**Before you have a domain** (or to test from a laptop), a sandbox takes the document by post
and accepts a test id with a port too, or on your machine one bound to your key,
`pregen.sandbox_provider_url(KEY, port)` / `await sandboxProviderUrl(KEY, port)`: step 9. Nothing else changes.

**A registry that still wants its own credential** says `"providers": "registered"` in its
document, or has no `providers` member (`GET {api}/.well-known/pregen-registry.json`); the
credential path for it is at the end of this guide. Only a registry that says
`"providers": "open"` (and lists `provider-identity`) answers you as you are.

## 3. Load the directory

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
The public test directory is `https://www.pregen.org/test/registries.json`, signed by the test
steward key `78c95e45a79c5e271fdec762b92c2ec1b27d6d08e512b7a94779de2429868ef0`.
Keep a saved test directory in its own folder (`pregen-test/`, step 8): passed as `previous` to
the real directory, it is refused (`sequence … is older` / `namespace … was removed`).
A test directory is only about who signed the directory: answers from a non-sandbox registry
listed in it are checked without `testing`. `testing` is for sandbox answers only (step 9).

**A registry's new key:** if `check_answer` refuses with `… may not sign …: issuer_mismatch`,
the registry may have just been listed with a new key: load the directory again (with
`previous`) and check the same answer once more. If it still fails, it is not an answer.
`unknown_issuer` means no registry in that directory holds the code's prefix: it is not an
answer, and reloading will not help. A test directory that fails to load is no test directory:
stop, never check sandbox answers without it, and report it through the steward's issue tracker.

## 4. Ask

A person's code looks like `TOG-ABCD-418207365E`; its letters name the registry. Old `PG-` codes are still
accepted and become `TOG-` (`PG-TEST-000001N` is `TOG-TEST-000001N`).
`directory.registry_for(code)` / `directory.registryFor(code)` gives that registry's entry
(`prefix`, `api`, `keys` = the URL of its key set, `key_fingerprints`, …). If it gives
`None` / `null`, no listed registry holds the code: you have no `allow`: do not generate
that person.

```
POST {api}/v2/requests
Content-Type: application/json
X-Provider-ID: https://frame.example

{"type": "pg.request.v1", "signatures": ["<ed25519 hex, by your current key>"],
 "body": {"signers": [{"role": "provider", "key_id": "pg-ed25519:…"}],
          "subject_ref": "TOG-ABCD-418207365E", "provider_id": "https://frame.example",
          "profile": "likeness/1", "use": {"purpose": "commercial"},
          "job_id": "job-8841", "job_hash": "<sha-256 hex of what you fixed about the job>",
          "licensee_id": "<the licensee id that registry gave your customer>"}}
```

- `signers` names your current key, and the one signature is by it: that is your whole
  authentication (no `Authorization` header). The next six members are required; `licensee_id` and the others below are optional.
  `profile` is the fixed name of a vocabulary of uses (`likeness/1`: a person's likeness and
  voice), never a version of a registry's policy: the answer must name the same profile,
  compared as a name. No answer carries a version, hash or counter of a registry's rules. `use.purpose` is what the output is for, not
  its medium (an ad, image or video, is `commercial`; if you do not know what your customer
  will use it for, ask them, or send `commercial`): `personal`, `educational`,
  `research`, `editorial` or `commercial`; add `territory`, `channel` and `categories`
  (for example `["political"]`) when they apply, honestly: fixed protections are checked
  against them.
- The use is yours to fix, not your user's to claim. A registry cannot see the output. If
  a user says "research" and leaves out a restricted category, the registry signs an `allow` for
  what you declared. That is the trust model: the signed request is your own statement, and the
  proof keeps it. So your server determines the subject and the use (`purpose`, `categories`)
  from what it will render, never from the end user's own claim, and renders exactly the inputs
  it fixed in `job_hash`. A false declaration is your signed statement and your liability.
- **`licensee_id`** (optional, a member of `body` beside `job_id`): your end customer's id,
  when you generate on their behalf and the registry connected that customer to you
  (extension `licensee`). Send it **only when the request rests on that customer's licence**:
  under `bind`, a code among the binding's grants (`GET {api}/v2/grants?licensee_id=…`,
  "Selling" below); under a registry's own connect (extension `licensee`), the codes that registry
  told you the customer's licence covers. For any other code leave it out and rest on your own grant. Your own grant
  covers your customers only with the resale right (`extensions/catalog.md`), so a `licensee_id`
  sent where the customer holds nothing turns an allow into a refusal. A licensee id belongs to one registry: send it
  only to the registry that connected it, and none to the other registries in the job. Some grants cover
  only one licensee. Send exactly the licensee id the registry gave you. An id that is not connected to you is
  refused: HTTP 403 `PG_NOT_BOUND` at a registry that uses `bind` (show "connect your licence",
  not a refusal), or 401 `PG_NOT_AUTHENTICATED` at a registry that connects licensees itself
  (extension `licensee`).
- **Rule out what you can locally first** (no listed registry, a failed anchor list), then ask in any order you like and stop at the first refusal of a private person, or
  the first `decide_identity` verdict that is not `allow`, giving back every allow received before it.
- **One request per code.** A job with two people asks twice, under the same `job_id`,
  each code at the registry its prefix names (a public person: see below). **Every job has a new `job_id`** (random, not a
  timestamp), and `job_input` holds everything you fixed, the customer included (for example
  `{"prompt": …, "settings": …, "customer": <the prefix → licensee_id map you send, or null>}`): once a
  person in a job is reported, asking again under that id is refused
  (409 `PG_ASK_CLOSED`, whose body's `ack` member is the acknowledgement you were given before: keep it if
  you lost yours; otherwise nothing to do). Within one job, every request carries the same `job_hash`; a reused `job_id`
  with a different `job_hash` gets 409 `PG_JOB_CONFLICT` first. Both mean no answer.
- `pregen.sign_envelope("pg.request.v1", body, KEY)` / `await signEnvelope("pg.request.v1",
  body, KEY)` makes the envelope, with `body["signers"] = [{"role": "provider", "key_id":
  key_id}]`. A registry that has not vetted you (its own published procedure) answers
  `deny` `PG_PROVIDER_NOT_ACCEPTED` for everything except a subject it publishes (its refusals
  included) and a grant your own connected customer holds; a refusal of a private subject is
  masked too: a refusal, so nothing to
  generate; ask the registry how it vets providers, or use its sandbox meanwhile (step 9).

The registry answers HTTP 200 `{"answer": {"type": "pg.answer.v1", "body": {…}, "signatures": […]}}`.

**A public person** (extension `identity`, `https://www.pregen.org/spec/extensions/identity.md`) may be claimed by
several registries. A refusal of the person (`PG_SUBJECT_OPTED_OUT`, `PG_SUBJECT_UNAVAILABLE`,
`PG_PROHIBITED_USE`, `PG_IMMUTABLE_DENIAL`, `PG_PERSONAL_SIGNATURE_REQUIRED`) by any registry
whose claim the person confirmed holds everywhere; "no licence here" does not, and neither does a
dispute (`PG_SUBJECT_DISPUTED`, which holds only at the registry examining it). So:

1. At least daily, fetch every listed registry's anchor list and check it:

   ```python
   anchors, failed = {}, set()                       # anchor -> [{code, proof_url, …}]; prefixes whose list failed
   for r in directory.registries:
       if r.get("revoked") or not r["prefix"]:
           continue                                  # revoked (item 5 keeps its last entries), or the legacy bare namespace
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
     if (r.revoked || !r.prefix) continue;                              // revoked (item 5 keeps its last entries), or the legacy bare namespace
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

   Keep each registry's last verified entries (not the envelope: a list over a day old no
   longer verifies); item 5 uses them. An entry's
   `status` (`active`, `opted_out`, …) is information only: ask the code anyway.
2. If a person's code is in a list, ask **every** code listed under the same anchor, each at
   its registry, in the same job.
3. For each code, decide whether the person confirmed it on their own channel:
   `pregen.check_channel_proof(code, entry["proof_url"], pregen.wikidata_official_urls(anchor),
   get_text)` (JS: `await checkChannelProof(code, proofUrl, await wikidataOfficialUrls(anchor,
   { fetch }), getText)`). `get_text(url)` / `async getText(url)` returns, for a website's
   `/.well-known/pregen`, the page's text as a string; for a post or the profile of an account,
   `{"author": …, "text": …}`, where both come from the platform's own record of who wrote it
   (its API), never from the page's HTML. A string confirms only `/.well-known/pregen`. The
   complete examples leave that part to you (`account_post` / `accountPost`, one per platform);
   until you write it, every claim on an account stays unconfirmed there, so an opt-out posted
   only on an account is missed: write it before you generate public persons. `confirmed` is
   the boolean it returns, and comes only from it: never
   set it by hand or on anyone's word, a person's look included (a cached result of
   `check_channel_proof` may be reused as item 4 says; item 5 if it cannot run). A `proof_url`
   whose path has a `.` or `..` segment (or `%2e`, or an encoded slash) confirms nothing, and so
   does one with a `?` or `#`. `get_text` must not follow redirects: treat a 3xx like a 404
   (unconfirmed); the complete examples show how. Only the fixed places of `identity.md` confirm
   (the official website's `https://<host>/.well-known/pregen`, or a post or the profile of the
   person's own account, as the platform records who wrote it), on channels from current
   Wikidata statements (not deprecated, not ended).
   Only `wikidata:` anchors have
   a defined list of official channels today: for any other anchor, `confirmed` is `False` (do
   not call `wikidata_official_urls`, which raises). Both complete examples below do all of
   step 4. In Python, pass `get_text` (and a `get_json` if you fetch
   yourself) that send a `User-Agent: <product> (<contact URL>)` header: Wikidata answers 403
   to an anonymous client (the library's own fetcher sends one). In JS, pass a `fetch` that sends
   it to `wikidataOfficialUrls`, and send it from `getText`.
4. Combine. Each claim is `{"code", "confirmed", "settled", "refusal_only", "answer"}`. A claim
   confirmed only on a channel that has not stood on Wikidata for 7 days refuses but does not
   permit: only a `settled` claim's allow permits, and a missing `settled` means not settled. A
   refusal from a claim you saw confirmed in the last 7 days, or whose line stands at a channel
   Wikidata dropped this week, still counts after its channel or line goes: that is
   `refusal_only`. Keep, for 7 days, which claims you saw confirmed (`seen_this_week`). For one
   claim:

   ```python
   now_urls = pregen.wikidata_official_urls(anchor, get_json=get_json)
   then_urls = pregen.wikidata_official_urls(anchor, get_json=get_json, at=int(time.time()) - pregen.SETTLED_AFTER)
   confirmed = pregen.check_channel_proof(code, proof_url, now_urls, get_text, seen_confirmed=seen_this_week)
   settled = confirmed and pregen.check_channel_proof(code, proof_url, [u for u in now_urls if u in then_urls], get_text)
   gone = [u for u in then_urls if u not in now_urls]          # removed, replaced or ended this week
   refusal_only = not confirmed and (seen_this_week or pregen.check_channel_proof(code, proof_url, gone, get_text))
   ```

   ```js
   const nowUrls = await wikidataOfficialUrls(anchor, { fetch });
   const thenUrls = await wikidataOfficialUrls(anchor, { fetch, at: Math.floor(Date.now() / 1000) - SETTLED_AFTER });
   const confirmed = await checkChannelProof(code, proofUrl, nowUrls, getText, { seenConfirmed: seenThisWeek });
   const settled = confirmed && await checkChannelProof(code, proofUrl, nowUrls.filter((u) => thenUrls.includes(u)), getText);
   const gone = thenUrls.filter((u) => !nowUrls.includes(u));   // removed, replaced or ended this week
   const refusal_only = !confirmed && (seenThisWeek || await checkChannelProof(code, proofUrl, gone, getText));
   ```

   `answer` is the checked body `pregen.verify_answer(answer, request, directory)` / `await
   verifyAnswer(answer, request, { directory })` returns, or `None` / `null` when there is none.
   Then `pregen.decide_identity(claims, frozen=directory.frozen(anchor))` /
   `decideIdentity(claims, { frozen: directory.frozen(anchor) })` (synchronous) gives
   `{status, reason, code}`. While the steward freezes the person, it is `deny`
   `PG_SUBJECT_UNAVAILABLE`. A confirmation may be reused until the next daily anchor fetch,
   while the entry's `proof_url` is unchanged.
   Generate only if its `status` is `allow`. With no confirmed claim
   it is `not_blocked` (`PG_IDENTITY_UNCONFIRMED`): no permission. `check_answer` must pass for
   the code it returns; `verify_answer` must pass for every other code whose claim the person
   confirmed. Report
   as `generated`, and put in the proof, the allow of the code it returns and every other allow
   from a claim the person confirmed; give back (step 7) allows from unconfirmed claims. Apply
   step 5's obligations rule to every allow you report. Codes that did not answer `allow` are
   neither reported nor put in the proof. If the status is not `allow`, give back every allow.
5. **Unknown is not unconfirmed, and not a freeze either.** If Wikidata cannot be read, if the
   proof page of a claim **you saw confirmed in the last 7 days** cannot be read (a timeout, a
   connection error, 403, 429 or 5xx), or if any code under the anchor **whose claim the person
   confirmed** gets no valid answer (a 4xx, or `verify_answer` raises), you have no decision for
   this person: do not generate them, and give back their allows. An unreadable proof page of a
   claim you never saw confirmed makes it unconfirmed (a 404 or 410 means the page and its line
   are gone, so that claim is unconfirmed too): an impostor's broken link freezes nobody. A
   failure at an unconfirmed claim changes nothing: `decide_identity` ignores it. While a
   registry's anchor list (except a 404 from a registry whose document does not list `identity`)
   has not verified within the last 24 hours (`failed` above), generate none of that registry's
   own codes, and pass the entries of its last verified list to `decide_identity` with `"answer":
   None` (JS `null`), not asked: no one who confirmed a claim there is generated, since the
   failed list may hold their opt-out. Everyone else may go on, people that list also named
   included. A revoked registry is never asked either, but its refusals keep counting: keep its
   last verified entries, pass one whose `status` is `opted_out` or `paused` with `"answer":
   {"status": "deny", "reason": "PG_SUBJECT_OPTED_OUT"}` (or `"PG_SUBJECT_UNAVAILABLE"`), and
   drop the rest. Like every claim, these count only while the person confirms them. A code
   the steward recorded as a false claim (`directory.is_false_claim(code)`) is never generated, and the libraries refuse its answers.

If you learn of another registry's claim to the same person only later, apply step 4's
public-person rule then: keep every answer, and never present the output as permitted while a
refusal of the person stands.

## 5. Check the answer

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
`not_generated` for it (step 7), so a registry that did issue it frees the use where it can
(the reference registry refuses a give-back for an answer bound to another request); a refused
give-back is logged, and you go on. To log why a valid answer refused, the same
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

## 6. Generate, only on a valid allow for every person

An answer lives a short time (`expires_at`, at most 15 minutes; often 5). Generate only when
**every** person in the job has a checked `allow` (for a public person, `decide_identity`'s
`allow`, step 4) whose `expires_at` has not passed. Take
one time, `began` (whole Unix seconds, `int(time.time())`), right before generation starts:
it is the `occurred_at` of every report
in the job (step 7), even if rendering ends later. If generation cannot start before the
earliest `expires_at`, ask again under a new `job_id` and give back the old allows (step 7).
Write the output only after every check passed and `began` is taken. Hash it:
`output_hash` = SHA-256, in hex, of the exact bytes you write or deliver (read back from the
file if you write one).

## 7. Report the output

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
- **An answer you never received** (ground rule 2): once it would have expired, send the same
  report with `"answer": None` / `answer: null` and `"request": request["body"]` beside
  `request_id`. It gives back every expired allow of that request; the request is closed from
  then on (409 `PG_ASK_CLOSED`). Send it once; never send the request itself again.
- **Keep the signed report** you sent. If a report gets no answer, send the **same bytes**
  again: you get the same acknowledgement. A different report for the same answer is
  refused (409 `PG_REPORT_CONFLICT`). If the `generated` report is refused or never
  acknowledged, the output has no proof: keep it unlabelled, and never send a different report.
- **Send reports soon:** a proof needs the registry to have received the report within 24
  hours of the answer's expiry; a later one is recorded but proves nothing.

## 8. Keep the proof with the output

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

**Checking someone's proof** (a platform, a distributor, an auditor; if that is all you do, you
need steps 1, 3 and 8 only):

```python
result = pregen.check_proof(bundle, directory, output_sha256=sha256_of_the_file)
```

```js
import { checkProof } from "@pregen/verify";
const result = await checkProof(bundle, { directory, outputSha256 });
```

**Always pass the SHA-256 of the file you hold.** Without it, the check says nothing about
that file, and its result must never be shown as a label on it. It returns `{output_hash,
job_id, subjects: [{code, level, basis, terms, terms_assent}]}` / `{outputHash, jobId, subjects}` (`terms`: the section
"Accepting a person's terms"), or raises with
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

Run the snippets from your product's own folder; the save snippet follows step 3's
`load_directory`. Production and testing each keep their own folder, so a test file can never stand in for a
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

**A proof checked against a test directory is never a label, sandbox or not.** The verdict, in
this order: 1. no file: `no file: not checked`; 1b. a saved copy over 24 hours old: `saved copy
over 24 hours old: not checked`; 2. the check raises: its message; 3. a level
below your policy (levels rank `self` < `asserted` < `consented` < `verified`): `level <x>`; 4.
obligations you do not show: `obligations not shown: not a label`; 5. a test directory or
sandbox: `test directory: never a label` (which means every check passed); 6. otherwise
`accepted: true`, reason `label`. If one registry
does not answer, keep its previous copy and go on. Save key sets as they come: at check time the
library uses only keys whose ids the directory lists, and refuses small-order keys; the
directory never removes a listed key id (the libraries refuse a directory that does), a key is
only ever revoked, so old proofs keep their keys. It does not check the provider's signature on
a report: it relies on the registry's signed acknowledgement, which names that report. The
library cannot tell when you saved: `saved_at.json` does, and if it is more than 24 hours old,
do not label (reason `saved copy over 24 hours old: not checked`): go online, load and save again.

Later, check with no network (`verify_directory` / `verifyDirectory` fetch nothing):

```python
import hashlib, json, os, time
import pregen

FOLDER, MIN_LEVEL = "pregen", "self"                 # "pregen-test" for sandbox proofs; your policy's lowest level
RANK = ["self", "asserted", "consented", "verified"]
path = lambda name: os.path.join(FOLDER, name)
bundle = json.load(open("output.bin.proof.json"))
output_sha256 = hashlib.sha256(open("output.bin", "rb").read()).hexdigest()
test = json.load(open(path("test_steward.json")))["steward_public_key_hex"] if os.path.exists(path("test_steward.json")) else None
saved_key_sets = json.load(open(path("key_sets.json")))
if time.time() - json.load(open(path("saved_at.json")))["saved_at"] > 86_400:
    raise SystemExit("saved copy over 24 hours old: not checked")
directory = pregen.verify_directory(json.load(open(path("directory.json"))),
                                    **({"steward_public_key_hex": test} if test else {}))
sandbox = any(s["answer"]["body"].get("ext", {}).get("sandbox") for s in bundle["subjects"])
try:
    result = pregen.check_proof(bundle, directory, get_json=lambda url: saved_key_sets.get(url, {}),
                                output_sha256=output_sha256, testing=bool(test) and sandbox)
    low = [s["level"] for s in result["subjects"] if RANK.index(s["level"]) < RANK.index(MIN_LEVEL)]
    if low:
        verdict = f"level {low[0]}"
    elif any(s["answer"]["body"].get("obligations") for s in bundle["subjects"]):
        verdict = "obligations not shown: not a label"                  # unless you show them
    else:
        verdict = "test directory: never a label" if test else "label"
except pregen.PregenError as e:
    verdict = str(e)
print({"accepted": verdict == "label", "reason": verdict})
```

```js
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { verifyDirectory, checkProof } from "@pregen/verify";
const FOLDER = "pregen", MIN_LEVEL = "self";               // "pregen-test" for sandbox proofs; your policy's lowest level
const RANK = ["self", "asserted", "consented", "verified"];
const bundle = JSON.parse(readFileSync("output.bin.proof.json", "utf8"));
const outputSha256 = createHash("sha256").update(readFileSync("output.bin")).digest("hex");
const read = (name) => JSON.parse(readFileSync(`${FOLDER}/${name}`, "utf8"));
const TEST = existsSync(`${FOLDER}/test_steward.json`) ? read("test_steward.json").steward_public_key_hex : null;
const savedKeySets = read("key_sets.json");
if (Date.now() / 1000 - read("saved_at.json").saved_at > 86_400) {
  throw new Error("saved copy over 24 hours old: not checked");
}
const directory = await verifyDirectory(read("directory.json"), TEST ? { stewardPublicKeyHex: TEST } : {});
const offlineFetch = async (url) => ({ ok: url in savedKeySets, status: url in savedKeySets ? 200 : 404,
                                       json: async () => savedKeySets[url] });
const sandbox = bundle.subjects.some((s) => s.answer.body.ext?.sandbox);
let verdict;
try {
  const result = await checkProof(bundle, { directory, fetch: offlineFetch, outputSha256, testing: Boolean(TEST) && sandbox });
  const low = result.subjects.map((s) => s.level).filter((l) => RANK.indexOf(l) < RANK.indexOf(MIN_LEVEL));
  if (low.length) verdict = `level ${low[0]}`;
  else if (bundle.subjects.some((s) => s.answer.body.obligations?.length)) verdict = "obligations not shown: not a label";
  else verdict = TEST ? "test directory: never a label" : "label";
} catch (e) { verdict = e.message; }
console.log({ accepted: verdict === "label", reason: verdict });
```

The check fetches only through the `get_json` / `fetch` you pass. A retired registry key stays
in its key set, so old proofs keep verifying after a key change.
A proof from a revoked registry fails, old ones included (the directory marks a revoked
registry `"revoked": true`, and lists revoked keys in `revoked_keys`). An offline check can only be as
current as what you saved: a revocation published after that is invisible to it. Use
`verify_directory(saved)` only for offline proof checks: it counts the saved copy as loaded
now. For answers, always `load_directory(previous=saved)`.

## 9. Try it on the public test network first

The test network is a sandbox registry and a test directory, open to everyone:

- **Test directory:** `https://www.pregen.org/test/registries.json`, signed by the test steward
  key `78c95e45a79c5e271fdec762b92c2ec1b27d6d08e512b7a94779de2429868ef0` (step 3). It lists
  sandboxes only. Never in production.
- **The PRE-GEN Test Registry:** prefix `TEST`, `api` `https://sandbox.pregen.org`, codes 1 to 12:
  `TOG-TEST-000001N` `TOG-TEST-000002Z` `TOG-TEST-0000034` `TOG-TEST-000004E` `TOG-TEST-000005R`
  `TOG-TEST-000006$` `TOG-TEST-0000077` `TOG-TEST-000008H` `TOG-TEST-000009V` `TOG-TEST-000010M`
  `TOG-TEST-000011Y` `TOG-TEST-0000123` (copy them; the last character is a check character). Any registry's own sandbox works the same way: a separate registry with its
  own prefix (`ABCE` beside `ABCD`), listed in the test directory, whose document says
  `"sandbox": true`.

**Introduce yourself by post.** A laptop has no domain to serve a document on, so a sandbox
takes your party document as a request body, and accepts a test id of your own
(make it random, such as `https://test-k7q2x9.example`, so nobody else's test has already taken it) with the key you made in step 2:

```python
doc = pregen.party_document(PROVIDER, NAME, KEY)
urllib.request.urlopen(urllib.request.Request(sandbox_api + "/v2/sandbox/party", method="POST",
    data=json.dumps(doc).encode(), headers={"Content-Type": "application/json"}), timeout=10)   # → 200 {"party_id": …}
```

```js
const res = await fetch(sandboxApi + "/v2/sandbox/party", { method: "POST", body: JSON.stringify(doc),
  headers: { "Content-Type": "application/json" }, signal: AbortSignal.timeout(10000) });     // → 200 {"party_id": …}
```

Posting the same document again is harmless. A different first keyset under an id someone
else already pinned is refused (401): pick another id, for example
`https://test-<random>.example`. From then on you ask the sandbox exactly as you would any
registry: signed requests, `X-Provider-ID`, no credential. A production registry reads the
same document from your domain instead, and nothing is ever posted to it.

What to test. Each row is one job (a new `job_id`) with `purpose: "research"` unless the row
says otherwise. The complete example sends `commercial`, which code 10 refuses: change it in `ask`
for code 10, and add `categories` there for the code 11 rows.

| Code | Tests | Ask | Answer |
|---|---|---|---|
| `1` | the whole flow | ask, check, generate, report, proof | `allow` |
| `2` | no licence | ask | `deny` `PG_NO_LICENSE` |
| `3` | an opt-out | ask | `deny` `PG_SUBJECT_OPTED_OUT` |
| `4` | a used-up grant | ask | `deny` `PG_USAGE_LIMIT` |
| `5` | a fixed protection | ask | `deny` `PG_PROHIBITED_USE` |
| `6` | held for a person | ask | `review` `PG_REVIEW_REQUIRED` |
| `7` | nothing blocks, nothing grants | ask | `not_blocked` `PG_NO_LICENSE` |
| `8` | a code no one holds | ask | `deny` `PG_UNKNOWN_SUBJECT` |
| `9` | payment: buy first | ask before buying | `deny` `PG_NO_LICENSE` |
| `9` | one use per purchase | buy one use, then ask; ask again | `allow`; then `deny` `PG_USAGE_LIMIT` |
| `9` | a race | buy one use, then two jobs at once | one `allow`, one `deny` `PG_USAGE_LIMIT` |
| `9` | a give-back | after an allow, report `not_generated`, then ask | `allow` again |
| `9` | purchases are yours | another provider id asks | `deny` `PG_NO_LICENSE` |
| `10` | the person's terms | no `terms`, or `terms` = the current id | `deny` `PG_NO_LICENSE`: terms grant nothing |
| `10` | a stale id | `terms` = any other id, or any id on the credential path | `deny` `PG_TERMS_NOT_ACCEPTED` |
| `10` | an excluded use | `purpose: "commercial"`, or `categories: ["advertising"]` | `deny` `PG_TERMS_EXCLUDED` |
| `11` | a minor: the floor | no `categories`, or `["fashion"]` | `allow` |
| `11` | a minor: the floor | `["violence"]`, `["sexual"]`, `["adult"]`, or a word outside the vocabulary such as `["nsfw-art"]` | `deny` `PG_PROHIBITED_USE` |
| `12` | a creator's licence, through `bind` | connect (`bind`), then ask with the binding's `licensee_id` | `allow`; `ext.bind` names the binding |
| `12` | outside the licence | the same, `purpose: "commercial"` | `deny` `PG_SCOPE_VIOLATION` |
| `12` | not connected | no `licensee_id` | `deny` `PG_NO_LICENSE` |
| `12` | a `licensee_id` not bound to you | another app's, a replaced or revoked one, or a made-up one | HTTP 403 `PG_NOT_BOUND`: show "connect your licence", not a refusal |

To buy (code 9), sign the same `pg.request.v1` envelope `ask` builds, with any `job_id`, and
`POST {sandbox api}/v2/sandbox/purchases` with `X-Provider-ID`. In the complete example:
`post(entry, "/v2/sandbox/purchases", request, "grant")`. It returns HTTP 200 `{"grant": …}`:
one use, for you only. No money moves. Each purchase adds one use. A give-back counts only
within the give-back window. `GET {sandbox api}/v2/statement`, with the headers of "The
credential path" item 4, then shows that grant `billed` 1, `given_back` 1. Code 11 holds a grant for every purpose
and category, signed by the person, yet still refuses: a minor's protection comes first. The
code 10 terms are at `GET {sandbox api}/v2/codes/TOG-TEST-000010M` (section "Accepting a
person's terms").

Code 12 is a creator's licence that only the creator's own connection reaches. List a callback in
your party document (`redirect_uris`), then connect as in "Selling" below: the sandbox's consent page
signs in its test creator, with no password, and each consent gives that creator a new licence on
code 12 (research, three uses), so no two apps share it. A working app that does all of this, and a
self-check that runs your own integration through codes 1 to 12, is the reference provider:
https://github.com/Pastheroza/PRE-GEN-site/tree/main/examples/reference-provider. It runs against a local reference registry with one command.

`testing` is only ever used with a test directory (`TEST_STEWARD` set): there it is true for a
code whose registry's document says `"sandbox": true`, and for `check_proof` (offline included)
when any `answer.body.ext.sandbox` is true. With the real directory it is always false, whatever
a registry's document says, and the libraries refuse it there. A sandbox proof is never a label.
A registry may give you more codes (12 and up) for its own test grants, and tells you what each
answers (if not, `GET {sandbox api}/v2/codes/<code>`: the name says): ask them like the others.
Ask each in a job of its own: run the complete example once per code (`CODES = [that code]`).
For a refusal it stops at the check: the example raises, exits with code 1, and the last line
of the traceback, `not an allow: <status> <reason>`, is the outcome to compare with the table
(nothing was allowed, so nothing to give back). That is the example working, not a bug. Take code
`1` through the whole flow (ask, check, generate, report, proof), as in production: the complete
examples below do, with `TESTING = True` / `const TESTING = true`. Keep sandbox outputs and
proofs apart from production ones: they are never labels (record `accepted: false`, reason
`test directory: never a label`, step 8). A sandbox accepts a `licensee_id` only as
production does: a binding to your app (`bind`, code 12) or one the operator connected. A
registered sandbox credential cannot test a person's licence on a sandbox you do not run; only an
app known by its domain can, through `bind`.
Check sandbox answers and proofs with `testing`: `check_answer(answer, request, directory,
testing=True)`, `check_proof(…, testing=True)`; JS `checkAnswer(answer, request, { directory,
testing: true })`. Every sandbox answer carries `ext: {"sandbox": true}`, and the libraries
refuse it outside testing.

**You are integrated** when the complete example below ends with the proof printed for code
`1`, with `not an allow: …` for codes 2 to 8, and with the answers in the table for codes 9 to 11. Then switch `DIRECTORY_URL` to the real
directory, `TEST_STEWARD` to `None`, `TESTING` to `False`, and `PROVIDER` to your domain, with
the party document served on it.

## Before production

1. Every path that can start a render (your API, queues, retries, batch jobs, internal and admin
   tools) goes through the same server-side ask and check. No path generates around it.
2. You have a policy for identifying who an output depicts and classifying its use, uploaded
   reference images and voice samples included. PRE-GEN does not recognise faces or voices: it
   answers only for the codes you ask about.
3. Each job has a durable record (`job_id`, `job_input`, the answers) written before you ask.
   A worker claims a job atomically, so two workers never render one job on one allow.
4. You keep every signed report and acknowledgement, and attach the proof to the exact file you
   deliver. Its `output_hash` is of those bytes: a re-encoded or cropped copy does not match it.
5. You sign with a production identity: your own domain serving the party document, and a key
   in your secret store. The sandbox key and test id are throwaway. A real registry, such as
   PRAMPTA, reads your document from your domain and answers that key only.

## Accepting a person's terms

A registry whose document lists `terms` in `extensions` publishes some people's terms of
generation: the purposes they allow and the categories they exclude, as a signed `pg.terms.v1`
that keeps every version (`https://www.pregen.org/spec/extensions/terms.md`). You accept them by
naming them in your signed request. Nothing else changes: the answer has the same shape, and a
request without `terms` is answered as before.

1. **Look them up.** `GET {api}/v2/codes/{code}` gives `"terms": {"id", "url"}` for a person who
   has terms; `GET` the `url` for `{"terms": <pg.terms.v1>}`. Check it before you rely on it:

   ```python
   terms = pregen.check_terms(envelope, code, directory)   # raises unless it is this person's, signed by their registry
   assert pregen.message_id("pg.terms.v1", terms) == lookup["terms"]["id"]
   ```

   ```js
   const terms = await checkTerms(envelope, code, { directory });
   if ((await messageId("pg.terms.v1", terms)) !== lookup.terms.id) throw new Error("not the current terms");
   ```

   `terms["rules"]` is `{purposes, excluded_categories}`. `pregen.forbids(terms["rules"], use)` /
   `forbids(terms.rules, use)` names the first part of your use they rule out, or returns `None` /
   `null`; `pregen.floor(use, terms["minor"])` / `floor(use, terms.minor)` names a fixed protection
   the use reaches. Either one means: do not ask for this use.
2. **Accept.** Put the id in the body as `terms`, beside `job_hash`, and sign the request with
   your key (step 4). Your signature is the acceptance, so only a provider known by its domain can
   give it; on the credential path, leave `terms` out. A request that carries `terms`:
   - names `use.categories` only in the closed vocabulary (`pregen.CATEGORIES` / `CATEGORIES`),
     spelled exactly: `adult`, `advertising`, `alcohol`, `cannabis`, `drugs`, `endorsement`,
     `fashion`, `financial`, `gambling`, `health`, `political`, `religion`, `sexual`, `tobacco`,
     `violence`, `weapons`. Any other word, a capital, a look-alike letter or a hidden character gets
     422 `PG_MALFORMED` and no answer;
   - goes only to a registry whose document lists `terms`.
3. **Read the answer** as in step 5. Its `request_id` is the message id of the body you signed, so
   the registry's signature covers the version you accepted. Two refusals are new:
   - `PG_TERMS_NOT_ACCEPTED`: the id is not the person's current terms (they changed since you
     looked, or the id is someone else's), or you asked with a registry credential. Look the terms
     up again and ask again under the same `job_id` with the current id: a refused id binds nothing,
     so this is no conflict, spends nothing, and is not asking again for another answer (ground
     rule 1: the terms changed).
   - `PG_TERMS_EXCLUDED`: no licence covers this use, and the person's terms exclude it, whether or
     not you sent `terms`, personal use included. A refusal.

   The terms grant nothing by themselves: only `allow` permits. An allow about a person who has
   terms lives at most 300 seconds.
4. **Keep the record in the proof.** Put the `pg.terms.v1` you accepted in that person's entry of
   the bundle (step 8): `{"request", "answer", "report", "ack", "terms"}`. `check_proof` then gives
   each person `terms`: `ok` (the use keeps to them), `outside` (the use reaches a fixed protection,
   or leaves the terms where the answer rests on the registry's policy rather than a licence),
   `unverified` (accepted, but the record is missing or does not check out) or `absent` (none
   accepted), and `terms_assent` / `termsAssent`, `"registry"` for a record that checked out: the
   registry's word on the person's instruction, never the person's own key. It does not change
   whether the proof passes. It shows what was signed, not that those terms still stand: the
   person's current terms are at the lookup's `status_url`.

## Selling and connected users

Everything above is the mandatory layer: every AI provider and every registry implements it,
and it costs nothing and needs no account. **Commerce is a registry's own, optional layer:** a
registry may sell licences to people or to providers, with its own prices, checkout and
contract. Each registry sets whether and how a provider known by its domain may buy; a registry
that sells nothing is still a complete registry. Two layers, one picture:
`https://www.pregen.org/docs/two-layers`.

- **A person's licence, used in your app.** When a customer holds a licence at a registry, they connect it to your app once, with one consent screen at their registry
  (extension `bind`, where the registry's document lists it; `https://www.pregen.org/spec/extensions/bind.md`: OAuth 2.0 code + PKCE).
  Send the person to `bind.authorize` (from the registry's document) with `response_type=code`,
  `client_id` = your provider id, a `redirect_uri` from your party document's `redirect_uris`
  (step 2), `state`, `code_challenge` and `code_challenge_method=S256`. Your callback gets a
  `code`. Post `pregen.sign_envelope("pg.bind_exchange.v1", {signers, provider_id, code,
  code_verifier, redirect_uri, issued_at}, KEY)` to `bind.token`, with `X-Provider-ID`. It returns
  `{"binding": <pg.binding.v1>}`, signed by the registry, with a random `licensee_id`. Send that
  id only for codes among the binding's grants (`GET {api}/v2/grants?licensee_id=…`); for any
  other code leave it out and rest on your own grant (step 4). HTTP 403 `PG_NOT_BOUND`
  means "connect your licence", never a refusal. A registry's own connect procedure (extension
  `licensee`) does the same with an id the registry gives you.
- **Buying for your product or your users.** Each registry publishes its commerce page and
  terms itself; PRE-GEN names none. The first registry: `https://prampta.com`.
- **Being vetted.** A registry that has not vetted you answers only about published
  subjects (their refusals included) and your own connected customers (`PG_PROVIDER_NOT_ACCEPTED`, step 4). Vetting is
  each registry's own published procedure, and is not needed to honour a licence your customer
  connected.

## Complete example (Python)

One job, one or more people (private or public), each at their own registry. Fill in the constants at the top,
and list each person once (a public person by one code: the example asks the others).

```python
import hashlib
import http.client
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

import pregen

PROVIDER = "https://frame.example"                                        # your domain (step 2); at a sandbox, any https://… you chose
NAME = "Frame"                                                             # what a consent screen shows beside your domain
KEY = open("provider.key").read().strip()                                 # step 2: from your secret store, never in code
DIRECTORY_URL, TEST_STEWARD = pregen.DIRECTORY_URL, None                    # testing: the test directory and its key
CODES = ["TOG-ABCD-418207365E"]                                            # the people in this job
FOLDER = "pregen-test" if TEST_STEWARD else "pregen"                       # test and production never share a file (step 8)
TESTING = False                                                            # True only for a job whose every code is at a sandbox, under a test directory
UA = {"User-Agent": "frame-ai (https://frame-ai.example/contact)"}        # who you are: Wikidata refuses anonymous clients
LICENSEES = {}                                                             # prefix -> the licensee_id that registry gave this customer
COVERED = set()                                                            # the codes their licences cover: GET /v2/grants under bind, or what a registry's connect told you

os.makedirs(os.path.join(FOLDER, "jobs"), exist_ok=True)
SAVED, ANCHORS = os.path.join(FOLDER, "directory.json"), os.path.join(FOLDER, "anchors.json")
SEEN = os.path.join(FOLDER, "seen.json")                                   # code -> when you last saw its claim confirmed
pub = pregen.public_key_hex(KEY)
key_id = pregen.fingerprint(pub)
saved = json.load(open(SAVED)) if os.path.exists(SAVED) else None
directory = pregen.load_directory(DIRECTORY_URL, previous=saved,
                                  **({"steward_public_key_hex": TEST_STEWARD} if TEST_STEWARD else {}))
json.dump(directory.to_json(), open(SAVED, "w"))


def get_json(url):
    return json.loads(urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=10).read())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None                                                       # a redirect is not the page: HTTPError 3xx


def account_post(url):                                                    # step 3: write this with each platform's API
    raise NotImplementedError(url)                                        # until then a claim on an account stays unconfirmed


def get_text(url):                                                        # a proof page, never followed through a redirect
    if urllib.parse.urlsplit(url).path != "/.well-known/pregen":
        return account_post(url)                                          # {"author", "text"}: the platform's record
    try:
        res = urllib.request.build_opener(NoRedirect).open(urllib.request.Request(url, headers=UA), timeout=10)
        return res.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code in (404, 410) or 300 <= e.code < 400:
            return ""                                                     # gone, or elsewhere: unconfirmed
        raise                                                             # unreadable: no decision (step 4)


saved_anchors = json.load(open(ANCHORS)) if os.path.exists(ANCHORS) else {}   # prefix -> {issued_at, entries}, last verified
seen = json.load(open(SEEN)) if os.path.exists(SEEN) else {}                    # kept 7 days (step 4.4)


def anchor_list(r):                                                       # step 4.1: entries; None: no list; raises: failed
    try:
        env = get_json(r["api"] + "/v2/anchors")
    except urllib.error.HTTPError as e:
        if e.code == 404:                                                 # "no list" only without identity
            try:
                if "identity" not in get_json(r["api"] + "/.well-known/pregen-registry.json").get("extensions", []):
                    return None
            except Exception:
                pass
        raise
    entries = pregen.verify_anchors(env, r["prefix"], directory)          # raises on one over a day old
    saved_anchors[r["prefix"]] = {"issued_at": env["body"]["issued_at"], "entries": entries}
    return entries


REFUSAL = {"opted_out": "PG_SUBJECT_OPTED_OUT", "paused": "PG_SUBJECT_UNAVAILABLE"}   # a status that refuses the person
ANCHOR_OF, CLAIMS, FAILED = {}, {}, set()
for r in directory.registries:
    if not r["prefix"]:
        continue                                                          # the legacy bare namespace
    last = saved_anchors.get(r["prefix"], {"issued_at": 0, "entries": []})
    if r.get("revoked"):                                                  # never asked; a refusal there outlives it (step 4.5)
        entries = [e for e in last["entries"] if e.get("status") in REFUSAL]
    else:
        try:
            entries = anchor_list(r) or []
        except Exception:
            entries = last["entries"]                                     # a blip: the last verified entries
            if time.time() - last["issued_at"] > 86400:
                FAILED.add(r["prefix"])                                   # over a day old: only its own people wait (step 4.5)
    for e in entries:
        ANCHOR_OF[e["code"]] = e["anchor"]
        CLAIMS.setdefault(e["anchor"], []).append(e)
json.dump(saved_anchors, open(ANCHORS, "w"))


def post(entry, path, envelope, member):                                  # rule 2: the same bytes, at most 4 sends
    data = json.dumps(envelope).encode()
    for _ in range(4):
        req = urllib.request.Request(entry["api"] + path, data=data, method="POST", headers={
            "Content-Type": "application/json", "X-Provider-ID": PROVIDER})
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
                wait = e.headers.get("Retry-After") or ""                 # seconds, or an HTTP date
                time.sleep(min(int(wait), 60) if wait.isdigit() else 3)
                continue
        except (urllib.error.URLError, OSError, http.client.HTTPException):
            pass                                                          # no answer: send the same bytes again
        time.sleep(3)
    raise RuntimeError(f"{path}: no answer after 4 sends")


INTRODUCED = set()                             # sandboxes that hold your party document (step 9)


def introduce(entry):                          # a sandbox takes the document by post; a registry reads your domain
    if TESTING and entry["prefix"] not in INTRODUCED:
        post(entry, "/v2/sandbox/party", pregen.party_document(PROVIDER, NAME, KEY), "party_id")
        INTRODUCED.add(entry["prefix"])


def report(entry, request, answer, outcome, output_hash, began):   # step 7
    env = pregen.sign_envelope("pg.report.v1", {
        "signers": [{"role": "provider", "key_id": key_id}],
        "request_id": pregen.message_id("pg.request.v1", request["body"]),
        "answer": pregen.message_id("pg.answer.v1", answer["body"]), "job_id": request["body"]["job_id"],
        "outcome": outcome, "output_hash": output_hash, "occurred_at": began}, KEY)
    return env, post(entry, "/v2/reports", env, "ack")


def give_back(items, when):                                              # step 7: not_generated, one by one
    for entry, request, answer in items:
        try:
            report(entry, request, answer, "not_generated", "", when)
        except Exception as e:                                           # e.g. a registry that never issued it
            print("give-back refused:", e)


job_id = "job-" + secrets.token_hex(8)                                   # new for every job
job_input = {"prompt": "<the prompt>", "settings": {"model": "<model>", "seed": 1, "temperature": "0.7"},  # keep it
             "customer": LICENSEES or None}                               # numbers other than whole ones as strings
job_hash = hashlib.sha256(pregen.canonical_json(job_input)).hexdigest()
json.dump({"job_id": job_id, "job_input": job_input}, open(os.path.join(FOLDER, "jobs", job_id + ".json"), "w"))
allowed = []                                                              # every answer whose body says allow


def ask(code):                                                            # step 4: one code, in this job
    entry = directory.registry_for(code)
    introduce(entry)
    request = pregen.sign_envelope("pg.request.v1", {
        "signers": [{"role": "provider", "key_id": key_id}],
        "subject_ref": code, "provider_id": PROVIDER, "profile": "likeness/1",
        "use": {"purpose": "commercial"}, "job_id": job_id, "job_hash": job_hash,
        **({"licensee_id": LICENSEES[entry["prefix"]]} if entry["prefix"] in LICENSEES and code in COVERED else {})}, KEY)
    answer = post(entry, "/v2/requests", request, "answer")
    if answer.get("body", {}).get("status") == "allow":
        allowed.append((entry, request, answer))                          # given back below if anything fails
    return answer, request


for code in CODES:                                                        # rule out locally first (step 4)
    entry = directory.registry_for(code)
    if entry is None or entry.get("revoked") or entry["prefix"] in FAILED:
        raise SystemExit(f"{code}: no listed registry, or its anchor list failed")
    if directory.is_false_claim(code):
        raise SystemExit(f"{code}: the steward recorded it as a false claim")

try:
    for code in CODES:                                                    # steps 4 and 5
        anchor = ANCHOR_OF.get(code)
        if anchor is None:                                                # a private person: one code
            pregen.check_answer(*ask(code), directory, testing=TESTING)  # raises unless a valid allow
            continue
        wikidata = anchor.startswith("wikidata:")                         # other anchors list no channels: nothing confirms
        now_urls = pregen.wikidata_official_urls(anchor, get_json=get_json) if wikidata else []
        then_urls = pregen.wikidata_official_urls(anchor, get_json=get_json,          # the item as it stood 7 days ago
                                                  at=int(time.time()) - pregen.SETTLED_AFTER) if wikidata else []
        gone = [u for u in then_urls if u not in now_urls]                # removed, replaced or ended this week
        claims, asked = [], {}                                            # a public person: every code under the anchor
        for e in CLAIMS[anchor]:
            week = time.time() - seen.get(e["code"], 0) < pregen.SETTLED_AFTER   # seen confirmed in the last 7 days
            confirmed = pregen.check_channel_proof(e["code"], e["proof_url"], now_urls, get_text, seen_confirmed=week)
            settled = confirmed and pregen.check_channel_proof(e["code"], e["proof_url"],
                                                               [u for u in now_urls if u in then_urls], get_text)
            refusal_only = not confirmed and (week or pregen.check_channel_proof(e["code"], e["proof_url"], gone, get_text))
            if confirmed:
                seen[e["code"]] = int(time.time())
            r = directory.registry_for(e["code"])
            if r.get("revoked"):
                body = {"status": "deny", "reason": REFUSAL[e["status"]]}  # its kept refusal (step 4.5)
            elif r["prefix"] in FAILED:
                body = None                                               # its list failed: kept, not asked (step 4.5)
            else:
                try:
                    asked[e["code"]] = ask(e["code"])
                    body = pregen.verify_answer(*asked[e["code"]], directory, testing=TESTING)
                except Exception:
                    body = None                                           # no valid answer: no decision if the claim counts
            claims.append({"code": e["code"], "answer": body, "confirmed": confirmed, "settled": settled,
                           "refusal_only": refusal_only})
        json.dump(seen, open(SEEN, "w"))
        verdict = pregen.decide_identity(claims, frozen=directory.frozen(anchor))   # a steward freeze denies first
        if verdict["status"] != "allow":
            raise RuntimeError(f"{code}: {verdict['status']} {verdict['reason']}")
        pregen.check_answer(*asked[verdict["code"]], directory, testing=TESTING)
        unconfirmed = {c["code"] for c in claims if not c["confirmed"]}   # their allows go back, not into the proof
        give_back([a for a in allowed if a[1]["body"]["subject_ref"] in unconfirmed], int(time.time()))
        allowed[:] = [a for a in allowed if a[1]["body"]["subject_ref"] not in unconfirmed]
    for entry, request, answer in allowed:                                # step 5: this product applies no obligations
        if answer["body"].get("obligations"):
            raise RuntimeError(f"{request['body']['subject_ref']}: an allow with obligations")
except Exception:
    give_back(allowed, int(time.time()))
    raise

began = int(time.time())                                                  # step 6: generation begins now
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
for entry, request, answer in allowed:                                    # step 7: every report, one by one
    try:
        rep, ack = report(entry, request, answer, "generated", output_hash, began)
        subjects.append({"request": request, "answer": answer, "report": rep, "ack": ack})
    except Exception as e:
        unreported.append(request["body"]["subject_ref"])
        print("report refused:", e)

if unreported:                                                            # no proof: keep the output unlabelled
    raise SystemExit(f"no proof for {unreported}: keep output.bin unlabelled")
bundle = {"format": "pg.proof.v1", "subjects": subjects}                  # step 8
print(pregen.check_proof(bundle, directory, output_sha256=output_hash, testing=TESTING))
json.dump(bundle, open("output.bin.proof.json", "w"))                    # kept with the file
```

It prints `{'output_hash': '…', 'job_id': 'job-…', 'subjects': [{'code': 'TOG-ABCD-418207365E',
'level': 'verified', 'basis': {'kind': 'grant', …}}]}`. Not shown, in either example: the
`answer: null` report of rule 2 after an answer that never arrived (step 7), the directory reload on `issuer_mismatch` (step 3),
`verify_answer` to log why a refusal refused (step 5), and saving the key sets for offline
checks (step 8: if you check proofs offline in the same folder, run its save right after
`load_directory`, since `directory.json`, `key_sets.json` and `saved_at.json` must be written
together).

## Complete example (JavaScript)

The same, in Node.js 20+ (save as `job.mjs`):

```js
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { loadDirectory, signEnvelope, checkAnswer, verifyAnswer, checkProof, messageId, publicKeyHex, fingerprint,
  canonicalJson, verifyAnchors, wikidataOfficialUrls, checkChannelProof, decideIdentity, partyDocument, DIRECTORY_URL,
  SETTLED_AFTER } from "@pregen/verify";

const PROVIDER = "https://frame.example";                                      // your domain (step 2); at a sandbox, any https://… you chose
const NAME = "Frame";                                                           // what a consent screen shows beside your domain
const KEY = readFileSync("provider.key", "utf8").trim();                       // step 2: from your secret store, never in code
const [url, TEST_STEWARD] = [DIRECTORY_URL, null];                              // testing: the test directory and its key
const CODES = ["TOG-ABCD-418207365E"];                                          // the people in this job
const FOLDER = TEST_STEWARD ? "pregen-test" : "pregen";                       // test and production never share a file (step 8)
const TESTING = false;                                                          // true only for a job whose every code is at a sandbox, under a test directory
const UA = "frame-ai (https://frame-ai.example/contact)";                       // who you are: Wikidata refuses anonymous clients
const LICENSEES = {};                                                           // prefix -> the licensee_id that registry gave this customer
const COVERED = new Set();                                                      // the codes their licences cover: GET /v2/grants under bind, or what a registry's connect told you

mkdirSync(`${FOLDER}/jobs`, { recursive: true });
const SAVED = `${FOLDER}/directory.json`, ANCHORS = `${FOLDER}/anchors.json`;
const SEEN = `${FOLDER}/seen.json`;                                             // code -> when you last saw its claim confirmed
const pub = await publicKeyHex(KEY);
const keyId = await fingerprint(pub);
const previous = existsSync(SAVED) ? JSON.parse(readFileSync(SAVED, "utf8")) : undefined;
const directory = await loadDirectory({ url, previous, ...(TEST_STEWARD ? { stewardPublicKeyHex: TEST_STEWARD } : {}) });
writeFileSync(SAVED, JSON.stringify(directory.toJSON()));

const fetchUA = (u, o = {}) => fetch(u, { ...o, signal: AbortSignal.timeout(10000), headers: { ...o.headers, "User-Agent": UA } });
const accountPost = async (u) => {                                              // step 3: write this with each platform's API
  throw new Error(`${u}: account posts not read yet`);                          // until then a claim on an account stays unconfirmed
};
const getText = async (u) => {                                                  // a proof page, never through a redirect
  if (new URL(u).pathname !== "/.well-known/pregen") return accountPost(u);     // {author, text}: the platform's record
  const res = await fetchUA(u, { redirect: "manual" });
  if (res.status === 404 || res.status === 410 || (res.status >= 300 && res.status < 400)) return "";   // gone, or elsewhere: unconfirmed
  if (!res.ok) throw new Error(`${u}: HTTP ${res.status}`);                     // unreadable: no decision (step 4)
  return res.text();
};

const savedAnchors = existsSync(ANCHORS) ? JSON.parse(readFileSync(ANCHORS, "utf8")) : {};   // prefix -> {issued_at, entries}, last verified
const seen = existsSync(SEEN) ? JSON.parse(readFileSync(SEEN, "utf8")) : {};    // kept 7 days (step 4.4)
async function anchorList(r) {                                                  // step 4.1: entries; null: no list; throws: failed
  const res = await fetchUA(r.api + "/v2/anchors");
  if (res.status === 404) {                                                     // "no list" only without identity
    const doc = await fetchUA(r.api + "/.well-known/pregen-registry.json").then((d) => d.json()).catch(() => null);
    if (doc && !(doc.extensions ?? []).includes("identity")) return null;
  }
  if (!res.ok) throw new Error(`${r.api}/v2/anchors: HTTP ${res.status}`);
  const env = await res.json();
  const entries = await verifyAnchors(env, r.prefix, { directory });           // throws on one over a day old
  savedAnchors[r.prefix] = { issued_at: env.body.issued_at, entries };
  return entries;
}

const REFUSAL = new Map([["opted_out", "PG_SUBJECT_OPTED_OUT"], ["paused", "PG_SUBJECT_UNAVAILABLE"]]);   // a status that refuses the person
const ANCHOR_OF = new Map(), CLAIMS = new Map(), FAILED = new Set();
for (const r of directory.registries) {
  if (!r.prefix) continue;                                                      // the legacy bare namespace
  const last = savedAnchors[r.prefix] ?? { issued_at: 0, entries: [] };
  let entries;
  if (r.revoked) entries = last.entries.filter((e) => REFUSAL.has(e.status));   // never asked; a refusal there outlives it (step 4.5)
  else {
    try { entries = (await anchorList(r)) ?? []; }
    catch {
      entries = last.entries;                                                   // a blip: the last verified entries
      if (Date.now() / 1000 - last.issued_at > 86400) FAILED.add(r.prefix);     // over a day old: only its own people wait (step 4.5)
    }
  }
  for (const e of entries) {
    ANCHOR_OF.set(e.code, e.anchor);
    if (!CLAIMS.has(e.anchor)) CLAIMS.set(e.anchor, []);
    CLAIMS.get(e.anchor).push(e);
  }
}
writeFileSync(ANCHORS, JSON.stringify(savedAnchors));

async function post(entry, path, envelope, member) {                          // rule 2: the same bytes, at most 4 sends
  const data = JSON.stringify(envelope);
  for (let i = 0; i < 4; i++) {
    let res, body;
    try {
      res = await fetch(entry.api + path, { method: "POST", body: data, signal: AbortSignal.timeout(10000), headers: {
        "Content-Type": "application/json", "X-Provider-ID": PROVIDER } });
      body = res.ok ? await res.json().catch(() => ({})) : await res.text();
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

async function report(entry, request, answer, outcome, outputHash, began) {      // step 7
  const env = await signEnvelope("pg.report.v1", { signers: [{ role: "provider", key_id: keyId }],
    request_id: await messageId("pg.request.v1", request.body), answer: await messageId("pg.answer.v1", answer.body),
    job_id: request.body.job_id, outcome, output_hash: outputHash, occurred_at: began }, KEY);
  return { report: env, ack: await post(entry, "/v2/reports", env, "ack") };
}

async function giveBack(items, when) {                                          // step 7: not_generated, one by one
  for (const { entry, request, answer } of items) {
    try { await report(entry, request, answer, "not_generated", "", when); }
    catch (e) { console.log("give-back refused:", e.message); }                 // e.g. a registry that never issued it
  }
}

const introduced = new Set();                                                   // sandboxes that hold your party document (step 9)
const jobId = `job-${crypto.randomUUID()}`;                                     // new for every job
const jobInput = { prompt: "<the prompt>", settings: { model: "<model>", seed: 1, temperature: "0.7" },     // keep it; non-whole
  customer: Object.keys(LICENSEES).length ? LICENSEES : null };                                            // numbers as strings
const jobHash = createHash("sha256").update(canonicalJson(jobInput)).digest("hex");
writeFileSync(`${FOLDER}/jobs/${jobId}.json`, JSON.stringify({ job_id: jobId, job_input: jobInput }));
const allowed = [];                                                             // every answer whose body says allow

async function ask(code) {                                                      // step 4: one code, in this job
  const entry = directory.registryFor(code);
  if (TESTING && !introduced.has(entry.prefix)) {                                // a sandbox takes the document by post
    await post(entry, "/v2/sandbox/party", await partyDocument(PROVIDER, NAME, KEY), "party_id");
    introduced.add(entry.prefix);                                               // a registry reads it from your domain
  }
  const request = await signEnvelope("pg.request.v1", { signers: [{ role: "provider", key_id: keyId }],
    subject_ref: code, provider_id: PROVIDER, profile: "likeness/1", use: { purpose: "commercial" }, job_id: jobId,
    job_hash: jobHash, ...(entry.prefix in LICENSEES && COVERED.has(code) ? { licensee_id: LICENSEES[entry.prefix] } : {}) }, KEY);
  const answer = await post(entry, "/v2/requests", request, "answer");
  if (answer?.body?.status === "allow") allowed.push({ entry, request, answer }); // given back below if anything fails
  return { answer, request };
}

for (const code of CODES) {                                                     // rule out locally first (step 4)
  const entry = directory.registryFor(code);
  if (!entry || entry.revoked || FAILED.has(entry.prefix)) {
    throw new Error(`${code}: no listed registry, or its anchor list failed`);
  }
  if (directory.isFalseClaim(code)) throw new Error(`${code}: the steward recorded it as a false claim`);
}

try {
  for (const code of CODES) {                                                   // steps 4 and 5
    const anchor = ANCHOR_OF.get(code);
    if (!anchor) {                                                              // a private person: one code
      const { answer, request } = await ask(code);
      await checkAnswer(answer, request, { directory, testing: TESTING });     // throws unless a valid allow
      continue;
    }
    const wikidata = anchor.startsWith("wikidata:");                            // other anchors list no channels: nothing confirms
    const nowUrls = wikidata ? await wikidataOfficialUrls(anchor, { fetch: fetchUA }) : [];
    const thenUrls = wikidata ? await wikidataOfficialUrls(anchor, { fetch: fetchUA,  // the item as it stood 7 days ago
      at: Math.floor(Date.now() / 1000) - SETTLED_AFTER }) : [];
    const gone = thenUrls.filter((u) => !nowUrls.includes(u));                  // removed, replaced or ended this week
    const claims = [], asked = new Map();                                       // a public person: every code under the anchor
    for (const e of CLAIMS.get(anchor)) {
      const week = Date.now() / 1000 - (seen[e.code] ?? 0) < SETTLED_AFTER;      // seen confirmed in the last 7 days
      const confirmed = await checkChannelProof(e.code, e.proof_url, nowUrls, getText, { seenConfirmed: week });
      const settled = confirmed && await checkChannelProof(e.code, e.proof_url, nowUrls.filter((u) => thenUrls.includes(u)), getText);
      const refusal_only = !confirmed && (week || await checkChannelProof(e.code, e.proof_url, gone, getText));
      if (confirmed) seen[e.code] = Math.floor(Date.now() / 1000);
      const r = directory.registryFor(e.code);
      let body;
      if (r.revoked) body = { status: "deny", reason: REFUSAL.get(e.status) };  // its kept refusal (step 4.5)
      else if (FAILED.has(r.prefix)) body = null;                               // its list failed: kept, not asked (step 4.5)
      else try {
        const { answer, request } = await ask(e.code);
        asked.set(e.code, { answer, request });
        body = await verifyAnswer(answer, request, { directory, testing: TESTING });
      } catch { body = null; }                                                  // no valid answer: no decision if the claim counts
      claims.push({ code: e.code, answer: body, confirmed, settled, refusal_only });
    }
    writeFileSync(SEEN, JSON.stringify(seen));
    const verdict = decideIdentity(claims, { frozen: directory.frozen(anchor) }); // a steward freeze denies first
    if (verdict.status !== "allow") throw new Error(`${code}: ${verdict.status} ${verdict.reason}`);
    const chosen = asked.get(verdict.code);
    await checkAnswer(chosen.answer, chosen.request, { directory, testing: TESTING });
    const unconfirmed = new Set(claims.filter((c) => !c.confirmed).map((c) => c.code));   // their allows go back
    const back = allowed.filter((a) => unconfirmed.has(a.request.body.subject_ref));
    await giveBack(back, Math.floor(Date.now() / 1000));
    allowed.splice(0, allowed.length, ...allowed.filter((a) => !back.includes(a)));
  }
  for (const { request, answer } of allowed) {                                  // step 5: this product applies no obligations
    if (answer.body.obligations?.length) throw new Error(`${request.body.subject_ref}: an allow with obligations`);
  }
} catch (e) {
  await giveBack(allowed, Math.floor(Date.now() / 1000));
  throw e;
}

const began = Math.floor(Date.now() / 1000);                                    // step 6: generation begins now
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
for (const { entry, request, answer } of allowed) {                             // step 7: every report, one by one
  try {
    const { report: rep, ack } = await report(entry, request, answer, "generated", outputHash, began);
    subjects.push({ request, answer, report: rep, ack });
  } catch (e) { unreported.push(request.body.subject_ref); console.log("report refused:", e.message); }
}
if (unreported.length) throw new Error(`no proof for ${unreported}: keep output.bin unlabelled`);
const bundle = { format: "pg.proof.v1", subjects };                             // step 8
console.log(await checkProof(bundle, { directory, outputSha256: outputHash, testing: TESTING }));
writeFileSync("output.bin.proof.json", JSON.stringify(bundle));                 // kept with the file
```

## Errors

A refusal about a person is a signed answer (step 5). HTTP errors carry
`{"error", "error_description"}` (a 429 may carry only `Retry-After`):

| Code | HTTP | Meaning |
|---|---|---|
| `PG_MALFORMED` | 422 | the request does not follow the core (a member, a type, a code's spelling) |
| `PG_NOT_AUTHENTICATED` | 401 | the signature or the provider id is not accepted: no party document on your domain (or none posted to this sandbox), a key that is not your chain's current one, a credential sent beside a provider URL, or a registry that wants its own credential (`"providers": "registered"`: the credential path) |
| `PG_PROFILE_UNSUPPORTED` | 422 | the registry does not answer under this profile |
| `PG_NOT_BOUND` | 403 | this `licensee_id` has no active binding to your app (`bind`): ask the person to connect their licence; not a refusal |
| `PG_KEYSET_CONFLICT` / `PG_KEY_EXISTS` / `PG_KEYSET` | 409 | credential path only: a different first keyset was already registered, or a rotation does not chain to the current keyset: rotate from the current one |
| `PG_REPORT_CONFLICT` | 409 | another report for the same answer was already filed: resend the report you kept |
| `PG_ASK_CLOSED` | 409 | this person in this job was already reported: use a new `job_id` for a new job |
| `PG_ASK_CONFLICT` | 409 | this person in this job was asked with a different request: resend the identical one |
| `PG_JOB_CONFLICT` | 409 | this `job_id` was already used with another `job_hash`: use a new `job_id` |
| `PG_RATE_LIMITED` | 429 | not answered yet: wait (`Retry-After` if sent), then send the same bytes again |
| any other code | any | no answer: do not generate; if it refused a give-back, log it and go on |
| HTTP 200 without `answer` / `ack` / `keyset` | 200 | no answer, as a 4xx |

To keep the acknowledgement a 409 `PG_ASK_CLOSED` carries, parse that response's body
(`json.loads(body)["ack"]`) before raising; the examples' `post()` puts that body in its error
message instead.

Answer reasons you will meet: `PG_UNKNOWN_SUBJECT` (this registry holds no such person:
not a prohibition, and not a permission), `PG_PROVIDER_NOT_ACCEPTED` (this registry has not vetted
you and answers only about published subjects (their refusals included) and your connected customers: a refusal),
`PG_OTHER_REGISTRY`, `PG_NO_LICENSE`, `PG_NOT_CONNECTED`
(only a connected end user's grant would do: show "connect your account" if your customer could
hold this registry's grant),
`PG_USAGE_LIMIT`, `PG_SCOPE_VIOLATION` (the grant does not cover this purpose or use),
`PG_REVIEW_REQUIRED` (held for a person), `PG_TERMS_NOT_ACCEPTED` and `PG_TERMS_EXCLUDED` (the section
"Accepting a person's terms"), and
the fixed protections no grant overrides: `PG_SUBJECT_OPTED_OUT`, `PG_SUBJECT_UNAVAILABLE`,
`PG_PROHIBITED_USE`, `PG_IMMUTABLE_DENIAL`, `PG_PERSONAL_SIGNATURE_REQUIRED`. A registry may add
its own reasons (PRAMPTA also sends `PG_SUBJECT_DISPUTED`, a dispute open at that registry only,
`PG_PROVIDER_VETOED` and `PG_REFUSED`): all are refusals. Treat any reason you do not know as a refusal.

## The credential path (a registry that says `"providers": "registered"`)

Some registries still issue their own credentials. Everything in this guide holds there too,
with these differences:

1. The registry gives you, privately, a **provider id** (`frame-ai`) and a **token**. Keep one
   pair per registry, keyed by its prefix, in your secret store. Always send to the `api` in
   the registry's directory entry.
2. Every `POST` carries `X-Provider-ID: <that id>` and `Authorization: Bearer <token>`, and
   `provider_id` in the body is that id. The request is **not** signed: `signatures` is `[]`
   and the body has no `signers` (`pregen.sign_envelope("pg.request.v1", body)` with no key).
3. **Register your key once at that registry**, with its credential, before your first
   request there, because reports are signed with it: `POST {api}/v2/keys` with a `first`
   keyset (`kind: "first"`, `provider_id` = that id, `previous: null`, `recovery_registry: ""`,
   your current key), signed with your key: `pregen.sign_envelope("pg.keyset.v1", {...}, KEY)`.
   HTTP 200 `{"keyset": …}`; the same keyset again returns the same. A different first keyset
   is refused with 409 (`PG_KEYSET_CONFLICT` at the reference registry, `PG_KEY_EXISTS` at
   PRAMPTA): to change your key, send a `rotation`
   (`https://www.pregen.org/spec/extensions/provider-keys.md`).
4. Reads a registry offers (`GET /v2/grants…`, `/v2/statement`) take the same two headers. A
   provider known by its domain instead sends `PG-Access: ` +
   `pregen.pg_access(PROVIDER, KEY, entry["api"], "GET", path)` /
   `await pgAccess(PROVIDER, KEY, entry.api, "GET", path)`, valid 60 s, for that registry only.
5. A sandbox of such a registry mints a credential without an account:
   `POST {sandbox api}/v2/sandbox/access` → `{"provider_id", "token", "registry", "note"}` (shown
   once; at most 10 an hour per address).

Both paths may be used at once, each at the registries that take it. A registry announces
which it takes in `providers` of its document; `open` registries answer providers known by
their domain and their registered providers alike.

## You are done when

- [ ] Your party document is served at `https://<your domain>/.well-known/pregen-party.json`, over HTTPS, with no redirect
- [ ] Your private key is in your secret store and nowhere else; every request and report is signed with it
- [ ] The directory is saved after every load, and loaded again (with `previous`) at least every 24 hours
- [ ] If you check proofs offline, the directory and every key set are saved with `saved_at`, at least every 24 hours
- [ ] Every generation of a listed person is preceded by a request for each of their codes, to the registry each code names
- [ ] A public person is asked at every code their anchor names, and generated only on `decide_identity`'s `allow`
- [ ] `check_answer` / `checkAnswer` passes for every private person, and for the code `decide_identity` names for each public person, before generating
- [ ] Every allow is reported: `generated` with `occurred_at` = when generation began, or `not_generated`
- [ ] The proof bundle is checked with `check_proof` / `checkProof` and kept with the output
- [ ] The complete example ran on the test network: the proof for code `1`, `not an allow` for codes 2 to 8, and the table's answers for codes 9 to 11
- [ ] Nothing in production accepts a sandbox answer; no prompt, output or key leaves your servers
