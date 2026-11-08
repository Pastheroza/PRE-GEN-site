# PRE-GEN reference provider

A small, runnable AI app that does the whole PRE-GEN provider side, written to be copied into production rather than
read as a hello world. Creators sign in, connect the licence they hold at their registry (extension `bind`), and
generate. Before each generation the server asks the registry, stores the signed answer, renders only on a valid allow,
reports what happened, and keeps the proof next to the exact file it delivered.

Node 22.13 or later. No dependencies except `@pregen/verify`, imported from `../../packages/verify-js`. In your own
project, run `npm install @pregen/verify` and change the one import line in `pregen.mjs`.

| File | What it holds |
|---|---|
| `app.mjs` | the web app: accounts, sessions, CSRF, connect, products, the job journal, workers, reports, crash recovery |
| `pregen.mjs` | everything that talks to registries: configuration, the directory, signing, asking, reports, proofs, bind |
| `selfcheck.mjs` | the self-check kit: runs an integration through the sandbox codes and compares the answers |
| `adapter.mjs` | the self-check adapter for this app |
| `test/e2e.test.mjs` | the end-to-end test against a local reference registry |

## Start it in the sandbox

```
npm start                 # node app.mjs --sandbox
```

This uses the public test network: the test directory `https://www.pregen.org/test/registries.json`, signed by the
test steward key, and the PRE-GEN Test Registry (prefix `TEST`). It makes a throwaway provider key in
`data-sandbox/sandbox-provider.key`, posts its party document to the sandbox (a laptop has no domain to serve it on),
and listens on port 8443. Your provider id is bound to that key, `https://<32 hex of the key id>.localhost:8443`, so it
never collides with anyone else's test (`sandboxProviderUrl` in the library).

Open `http://localhost:8443`, create an account, and generate on any test code, for example `PG-TEST-000001N` (allow) or
`PG-TEST-000002Z` (refused). Connecting a licence needs a registry whose document lists `bind`.

For now, connecting a licence works only against a local reference registry: the public sandbox.pregen.org does not
serve `bind` yet, and will once it runs the new version of `packages/registry`. Until then, on the public sandbox the
Connect button reports that the registry does not offer bind, and the self-check skips its code 12 rows. To try bind
today, run the reference registry yourself with `--sandbox` over HTTPS and point the app at a test directory that
lists it (`--directory`, `--steward`), as `test/e2e.test.mjs` does.

No certificate is needed. In a sandbox the app registers `http://localhost:8443/callback` as its bind redirect: plain
HTTP is allowed for a redirect only on a loopback host and only in a sandbox (RFC 8252 §7.3). With `--tls-cert` and
`--tls-key` it serves HTTPS on the provider id instead.

## What happens, and which rule it follows

- Sign-in: local accounts, scrypt password hashes (N = 2^17, r = 8, p = 1, stored with the hash so they can be raised
  later), a random session id in an HttpOnly, SameSite=Lax cookie (Secure and `__Host-` behind TLS). Lax and not
  Strict, because the bind callback is a navigation from the registry. The app reads only that exact cookie name, and
  two values of it count as no session, so a cookie planted on a narrower path cannot swap in another account. Every
  signed-in form carries the session's CSRF token, and any cross-site post is refused.
- Connect your licence (`spec/extensions/bind.md`). The app picks the authority itself: its configured prefix, looked
  up in the verified directory. It reads that registry's document, sends the creator to `bind.authorize` with PKCE S256
  and a random `state`, and on return checks that `state` was made for this account and that `iss` is the authority it
  started with. It then posts a signed `pg.bind_exchange.v1` to `bind.token` with `X-Provider-ID` once: never retry
  it, because a code sent twice ends the binding issued with it. If the exchange's response is lost, the creator starts
  the connection again. The app checks the
  registry's signature on the returned `pg.binding.v1` through the directory, and stores it on the account. A
  registry's "Use at" button opens `/bind/initiate?iss=…`: the app asks the person first, and only for an `iss` that is
  a prefix in the directory.
- Which licence a request rests on: the creator's `licensee_id` goes only into a request about a code among their
  binding's grants (read with `GET /v2/grants` when they connect, and each time the licence is shown). Any other code is
  asked for the provider itself, exactly as for an account with no licence, and rests on the provider's own grant,
  which covers generating for users only with the resale right (`catalog.md`). So a connected creator can still use a
  test purchase on code 9, and a connection that expired or was revoked blocks only its own codes.
- The connected licence: `GET {api}/v2/grants?licensee_id=…` with `PG-Access`, shown on the account page. `status`
  and `remaining` are unsigned and only inform the page. A connection that expired, or that the registry no longer
  knows (replaced by a newer one, or revoked), is shown as "connect your licence", never as a refusal.
- Products: the user picks a product and writes a prompt. The server sets `purpose` and `categories` from the product
  (a research still is `research`; an ad banner is `commercial` with `advertising`). A request's `use` is the
  provider's own signed statement, and the proof keeps it, so the provider decides it from what it will render. A use
  a user declares for themselves would be a statement the provider signs without knowing it is true.
- The job journal (`spec/extensions/jobs.md`). The job input (job id, provider id, the ask, product, prompt, renderer,
  customer) is fixed once and stored with its `job_hash` and the signed request before anything is sent. Workers
  claim a job with one atomic `UPDATE … RETURNING`. Every answer is stored before the app acts on it: an allow reserves
  a use the moment it is issued (`limits.md`). Just before rendering, the app checks the allow again and checks that
  the stored input still hashes to the `job_hash` the registry saw, then renders from that input only.
- Reports (`reports.md`): `generated` with the output's SHA-256 after rendering, `not_generated` when the app decides
  not to render. The signed report is stored before it is sent, and counts as filed only when the registry's
  acknowledgement for exactly that report verifies.
- A lost answer: when the registry cannot be reached, or its answer does not verify, an allow may still be reserved
  there. The request is never sent again, since a resend after that allow expired would reserve a second use. Once any
  answer to it has certainly expired, the app reports `not_generated` with `answer: null` and the full signed request
  (`reports.md`); the registry releases the ask's expired reserved allows within the give-back window and closes the
  ask (a later identical request gets 409 `PG_ASK_CLOSED`, which the app shows as closed, never as a crash).
  "Certainly expired" is `--lost-answer-wait` seconds after the first send: by default 993, the longest answer the core
  allows (900 seconds) plus every send and its timeout plus 60 seconds for clocks, whatever the registry. Lower it
  only in tests. The creator sees "could not be reached".
- After a crash, at start: every stored allow with no report and no render begun gets `not_generated`, so its use
  goes back instead of staying reserved and counted. A job never sent goes back to the queue; a job sent whose answer
  was never stored gets the `answer: null` report above. A job whose render may have begun is never restarted or given
  back automatically: it is marked unresolved (jobs.md X-7), and an operator who knows the output was never delivered
  runs `node app.mjs <same flags> --give-back <job id>`. Every ten seconds the app files the `answer: null` reports
  that have come due and sends again any report the registry could not be reached for.
- Proof (`proof.md`): `GET {api}/v2/proofs/{first 16 hex of the report id}`, checked with `checkProof` against the
  file's SHA-256, saved as `<file>.proof.json` beside the file.
- Three messages the creator can tell apart: the registry could not be reached (network error, timeout, 5xx);
  "connect your licence" (HTTP 403 `PG_NOT_BOUND`, never shown as a refusal); refused, with the reason code.
- The renderer is a stub that writes a small text file from the stored input. Put your model there; it must read
  nothing but the stored input.

A provider id on a real domain is first come, first served at the public sandbox: whoever posts a party document for
it first holds it there. Use the key-bound `https://<32 hex>.localhost` id the app makes, or a domain you control.

## Point it at production

```
PREGEN_PROVIDER_KEY_HEX=… node app.mjs --provider-url https://your.domain --authority PRAM --port 3000
# or --key-file /run/secrets/pregen-provider.key
```

- Production is the default; `--sandbox` is the only way to test. Without it the app uses the real directory
  (`https://www.pregen.org/registries.json`) and the PRE-GEN steward key, refuses `--directory` and `--steward`,
  never posts its party document anywhere, and accepts no sandbox answer.
- `--provider-url` is `https://` and your registrable domain, nothing else. Serve the app on that domain behind your
  TLS proxy: it answers `/.well-known/pregen-party.json` itself, with `redirect_uris`
  (`https://your.domain/callback`) and `bind_initiate_uri` (`https://your.domain/bind/initiate`).
- `--authority` is the prefix of the registry that holds your creators' licences, for example `PRAM`.
- The key is read from `PREGEN_PROVIDER_KEY_HEX` or `--key-file`, from your secret store. A sandbox refuses
  `PREGEN_PROVIDER_KEY_HEX`, so a production key is never used in a test. Make it once with
  `newPrivateKeyHex()` from `@pregen/verify` and keep it off the code and the repository.
- Data goes to `./data` (`--data` to change it); the sandbox uses `./data-sandbox`, so the two never share a file.

The first production run is one licence and two jobs. A test creator connects their real licence, then generates
once inside the licence (an allow, a file, its proof beside it) and once outside it, for example with the ad banner
on a research-only licence (refused, with the reason). The app needs no change for this.

## Production checklist

1. Every path that can start a render (API, queues, retries, batch jobs, admin tools) goes through `createJob` and the
   workers. Nothing renders around them.
2. Your product menu maps every product to an honest `use`. Add a category whenever an output may fall in one.
3. You have your own policy for recognising who an output depicts and which codes a job needs, uploaded reference
   images and voices included. PRE-GEN answers only for the codes you ask about.
4. The provider key is in your secret store, your domain serves the party document, and the app runs behind TLS.
5. One app process, or move recovery to a heartbeat: at start, `recover()` treats every claimed job as its own.
6. Put a rate limit in front of `/signin` and `/signup`.
7. Back up `data/app.db` and `data/outputs`: they hold the signed answers, reports, acknowledgements and proofs.
8. Run the self-check against the sandbox after every change to the integration.

## Self-check

```
npm run selfcheck         # node selfcheck.mjs ./adapter.mjs --sandbox
```

It runs only against a sandbox: the adapter refuses production flags, and the kit refuses an adapter that does not
say `sandbox: true`, because it buys, asks about every serial of the prefix and signs with a creator's licensee id. It
runs an integration through the sandbox codes 1 to 12 and the rows of `spec/extensions/sandbox.md`: 1 to 8, the
code 9 purchase rows (before buying, one use per purchase, again while reserved, after a give-back, two jobs racing
for the last use), the code 10 terms rows, the code 11 floor rows, and code 12 through a connected licence (allowed for
research, `PG_SCOPE_VIOLATION` for commercial, `PG_NO_LICENSE` without the licensee, `PG_NOT_BOUND` for an id not bound
to you). It prints PASS or FAIL per row and exits non-zero on a failure. Every allow it gets is given back.

To check your own integration, write an adapter with the shape of `adapter.mjs`: `open(argv)` returns `{sandbox: true, prefix,
api, licenseeId?, ask, buy?, giveBack?}`, and `ask({code, purpose, categories, licenseeId, terms})` returns
`{status, reason}` from the answer your code verified, or `{error, httpStatus}`. Code 12 rows run when the adapter
has a connected licence (this app's adapter takes the newest binding in its database). The "before buying" row needs a
provider id that has never bought at that sandbox.

What it does not check: recognising people in prompts or outputs, classifying a use correctly, your own mapping from
products to purposes, the code 9 and 10 rows that need another provider, and your production key and domain. A
passing self-check says your integration reads answers the way the sandbox gives them, not that it asks the right
questions.

## Test

```
PYTHON=/path/to/python npm test
```

One command. The Python needs fastapi, uvicorn, cryptography and jsonschema (the reference registry's dependencies).
The test makes a temporary folder, a self-signed certificate, a local reference registry with `--sandbox` over
HTTPS, and a test directory signed by a throwaway steward key. It runs the app as `npm start` does (plain HTTP on
loopback, a key-bound provider id) and drives it like a browser:

1. Sign in, and connect: the consent page is read for its one-time nonce and approved by its form post.
2. A planted or wrongly named session cookie is no session.
3. An allowed job on code 12 has a proof that passes `checkProof` against the file, and its allow names the binding.
4. A commercial job is refused with `PG_SCOPE_VIOLATION`.
5. The self-check passes with this app's adapter.
6. A second connection replaces the first creator's binding, and that creator's job ends "connect your licence".
7. The app crashes right after storing an allow; the restart gives the use back, seen as `given_back` in
   `/v2/statement`.
8. Two jobs from the connected creator race for the last bought use of code 9, with no licensee id: exactly one allow.
9. An allow is dropped on the way. Nothing is reported while it could still be valid; after it expires, the
   `answer: null` report gives it back. The registry runs with answers that live 6 seconds
   (`PREGEN_REGISTRY_ANSWER_TTL`, sandbox only) and the app with `--lost-answer-wait 9`, so this takes seconds.
10. The connection is revoked at the registry (`pregen-registry bindings --revoke`), then expires in the app's own
    record: the licence's code is "connect your licence", while code 1 still generates without a licensee id.
11. With the registry stopped, the creator sees "could not be reached".

It never touches sandbox.pregen.org and writes nothing into the repository.

## Known limits

- Recovery assumes one app process (production checklist, item 5).
- An `answer: null` report the registry refuses is kept with its error and not retried; check `report_error` in
  `jobs` from time to time.
