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
and listens on port 8443. Your provider id is `https://localhost:8443`. A sandbox pins the first key it sees for an id,
so if another test already took that id there, start with `--port 8444` (the id follows the port).

Open the app, create an account, and generate on any test code, for example `PG-TEST-000001N` (allow) or
`PG-TEST-000002Z` (refused). Connecting a licence needs a registry whose document lists `bind`.

The bind callback is `https://localhost:8443/callback`. Without a certificate the app serves plain HTTP, so the
browser cannot open that address after you approve at the registry: change `https` to `http` in the address bar and
load it (the code lives 60 seconds). For a clean run, give it a local certificate, for example one made with mkcert:
`node app.mjs --sandbox --tls-cert localhost.pem --tls-key localhost-key.pem`.

## What happens, and which rule it follows

- Sign-in: local accounts, scrypt password hashes, a random session id in an HttpOnly, SameSite=Lax cookie (Secure and
  `__Host-` behind TLS). Lax and not Strict, because the bind callback is a navigation from the registry. Every
  signed-in form carries the session's CSRF token, and any cross-site post is refused.
- Connect your licence (`spec/extensions/bind.md`). The app picks the authority itself: its configured prefix, looked
  up in the verified directory. It reads that registry's document, sends the creator to `bind.authorize` with PKCE S256
  and a random `state`, and on return checks that `state` was made for this account and that `iss` is the authority it
  started with. It then posts a signed `pg.bind_exchange.v1` to `bind.token` with `X-Provider-ID`, checks the
  registry's signature on the returned `pg.binding.v1` through the directory, and stores it on the account. A
  registry's "Use at" button opens `/bind/initiate?iss=…`: the app asks the person first, and only for an `iss` that is
  a prefix in the directory.
- The connected licence: `GET {api}/v2/grants?licensee_id=…` with `PG-Access`, shown on the account page. `status`
  and `remaining` are unsigned and only inform the page.
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
- After a crash, at start: every stored allow with no report and no render begun gets `not_generated`, so its use
  goes back instead of staying reserved and counted. A job whose render may have begun is never restarted or given
  back automatically: it is marked unresolved, and an operator who knows the output was never delivered runs
  `node app.mjs <same flags> --give-back <job id>`.
- Proof (`proof.md`): `GET {api}/v2/proofs/{first 16 hex of the report id}`, checked with `checkProof` against the
  file's SHA-256, saved as `<file>.proof.json` beside the file.
- Three messages the creator can tell apart: the registry could not be reached (network error, timeout, 5xx);
  "connect your licence" (HTTP 403 `PG_NOT_BOUND`, never shown as a refusal); refused, with the reason code.
- The renderer is a stub that writes a small text file from the stored input. Put your model there; it must read
  nothing but the stored input.

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
- The key is read from `PREGEN_PROVIDER_KEY_HEX` or `--key-file`, from your secret store. Make it once with
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

It runs an integration through the sandbox codes 1 to 12 and the rows of `spec/extensions/sandbox.md`: 1 to 8, the
code 9 purchase rows (before buying, one use per purchase, again while reserved, after a give-back, two jobs racing
for the last use), the code 10 terms rows, the code 11 floor rows, and code 12 through a connected licence (allowed for
research, `PG_SCOPE_VIOLATION` for commercial, `PG_NO_LICENSE` without the licensee, `PG_NOT_BOUND` for an id not bound
to you). It prints PASS or FAIL per row and exits non-zero on a failure. Every allow it gets is given back.

To check your own integration, write an adapter with the shape of `adapter.mjs`: `open(argv)` returns `{prefix, api,
licenseeId?, ask, buy?, giveBack?}`, and `ask({code, purpose, categories, licenseeId, terms})` returns
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
The test makes a temporary folder, a self-signed certificate for localhost, a local reference registry with
`--sandbox` over HTTPS, and a test directory signed by a throwaway steward key, then drives the app like a browser:
sign in, connect (approving the consent page by its form post), an allowed job on code 12 whose proof passes
`checkProof` against the file, a commercial job refused with `PG_SCOPE_VIOLATION`, the self-check with this app's
adapter, a binding replaced by a second connection so the old licensee id gets "connect your licence", a crash right
after an allow is stored and a restart that gives the use back (seen as `given_back` in `/v2/statement`), two jobs
racing for the last bought use of code 9 (exactly one allow), and a stopped registry ("could not be reached"). It
never touches sandbox.pregen.org and writes nothing into the repository.

## Known limits

- The app sends a creator's `licensee_id` with every code at their licence's registry. A grant the provider bought for
  itself then covers that request only if it carries the resale right (`catalog.md`).
- When the registry cannot be reached after three sends, the app tells the creator and stops. If the request did reach
  the registry and got an allow the app never saw, that use stays reserved and counted (`limits.md`). Sending the
  identical request again would return that same answer, which could then be given back; the app does not do this yet.
