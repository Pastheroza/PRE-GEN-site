# pregen-registry

The reference PRE-GEN registry. **Ask before you generate; get a signed answer anyone can
check.** It implements [`PRE-GEN-CORE.md`](https://www.pregen.org/spec/PRE-GEN-CORE.md), the profile `likeness/1` and these extensions:
`reports`, `provider-keys`, `limits`, `jobs`, `grants`, `licensee`, `observe`, `lookup`, `identity`,
`proof`, `catalog`, `provider-identity` (with `--open-providers`, and always in a sandbox), `terms` (with
`provider-identity`) and, in sandbox mode, `sandbox`.

It is a registry, not a marketplace: it has no prices, payments or dashboards. Those belong to
each registry's own business.

## Run a sandbox in a minute

```bash
pip install pregen-registry
pregen-registry init --dir ./data --prefix TEST --name "My sandbox" --api http://127.0.0.1:8000 --sandbox
pregen-registry serve --dir ./data
curl -X POST http://127.0.0.1:8000/v2/sandbox/access      # a provider id and token, no account
```

The sandbox answers the standard test codes `PG-TEST-000001N` `PG-TEST-000002Z`
`PG-TEST-0000034` `PG-TEST-000004E` `PG-TEST-000005R` `PG-TEST-000006$` `PG-TEST-0000077`
`PG-TEST-000008H` `PG-TEST-000009V` `PG-TEST-000010M` `PG-TEST-000011Y` `PG-TEST-0000123` (code 8 is deliberately
not registered). Codes 1 to 8 test refusals; 9 a test purchase (`POST /v2/sandbox/purchases`: one use,
a race, a give-back), 10 a person's terms, 11 a minor, 12 a creator's licence reached only through `bind`.
The last character is a check
character; with another prefix the codes differ, and `init` prints them. Each one answers as
[`extensions/sandbox.md`](https://www.pregen.org/spec/extensions/sandbox.md) says.

A sandbox made by 0.3 holds codes 1 to 7 only; it gains 9 to 12 when it next starts on 0.4. If an earlier
version gave one of your own test people serial 9, 10, 11 or 12, it refuses to start and names that code: make a
fresh sandbox with `init --sandbox` and add them again (they now get serials from 13).

A sandbox also offers `bind` ([`extensions/bind.md`](https://www.pregen.org/spec/extensions/bind.md)): an app sends
the person to `/v2/bind/authorize`, where the sandbox's test creator, signed in with no password, approves; the
app exchanges the code at `/v2/bind/token` for a binding and reads the licence at `GET /v2/grants?licensee_id=…`.
Each consent gives the test creator a new licence on code 12 (research, three uses), so apps never share one.
`pregen-registry bindings --dir DATA` lists the bindings, with their allows, and `--revoke LICENSEE_ID` ends one.
For a test that watches an answer expire, a sandbox started with `PREGEN_REGISTRY_ANSWER_TTL=5` (seconds, at most
300) issues shorter-lived answers; a production registry ignores it.

## Run a real registry

1. **Pick a prefix.** Four letters from `ABCDEFGHJKMNPQRSTVWXYZ`, then apply for it
   (https://www.pregen.org/registries).
2. **Create the registry:**
   `pregen-registry init --dir ./data --prefix ABCD --name "…" --api https://registry.example --policy https://… --complaints mailto:… --open-providers`

   Keep `--open-providers`: open access is a listing condition (`PG-CODE.md` §9.1, item 5). A listed
   registry answers any AI service known by its domain, with no account.
3. **Give the steward the operator key.** Hand over the key id and public key printed by
   `init`, out of band. Back up `data/operator.key` offline; it is created with mode 600.
4. **Add subjects, grants, providers and end users:**
   - `pregen-registry subject add --dir ./data --name "…" --level verified`
   - `pregen-registry grant add --dir ./data --subject 'PG-ABCD-…' --any-provider --purposes commercial --days 365 --max-uses 100`
   - `pregen-registry provider add --dir ./data --id frame-ai` — prints the credential once (providers known by
     their domain need no credential: [`extensions/provider-identity.md`](https://www.pregen.org/spec/extensions/provider-identity.md);
     `pregen-registry provider accept --dir ./data --id https://frame.example` once you have vetted one)
   - `pregen-registry connect --dir ./data --provider frame-ai --licensee frame-ai:user-1`
5. **Serve it behind TLS:** `pregen-registry serve --dir ./data --host 0.0.0.0 --port 8000`, or HTTPS directly with
   `--ssl-certfile cert.pem --ssl-keyfile key.pem`.
6. **Anchor public people:** `pregen-registry subject anchor --dir ./data --code 'PG-ABCD-…' --anchor wikidata:Q… --proof-url https://…`
7. **Check yourself:** `pregen-registry check --api https://registry.example [--directory URL]` ends `OK: all checks
   passed` when your document, key set and listing are right.

The whole path, step by step with what each command prints: [the registry guide](https://www.pregen.org/docs/registry.md).

`PREGEN_OPERATOR_KEY_HEX` may hold the operator key instead of the file.

**Rotating the operator key.**
1. `pregen-registry key next --dir ./data` makes the next key; `/keys` lists it as `next` at once. Open a
   key-update registry application with its key id.
2. 24 hours after the directory lists it, stop the server, run `pregen-registry key rotate --dir ./data`, and start
   it again ([the registry guide](https://www.pregen.org/docs/registry.md), step 4).

The old key stays in `GET /keys` as `retired`, so every answer and proof it signed still verifies. A retired key
never signs again. Move its private key file offline.

## HTTP interface

| Method and path | What |
|---|---|
| `GET /.well-known/pregen-registry.json` | who this registry is |
| `GET /keys` | its signed operator key set: every key it ever signed with, current and retired |
| `GET /policy` | the registry's policy (`policy.md` from the data folder) |
| `POST /v2/requests` | ask → `{"answer": <signed pg.answer.v1>}` |
| `POST /v2/reports` | report → `{"ack": <signed pg.report_ack.v1>}` |
| `POST /v2/keys`, `GET /v2/keys/{provider_id}` | provider keysets (a provider known by its domain publishes them in its party document instead) |
| `GET /v2/grants/{id}` | a signed grant (credential, or `PG-Access`) |
| `GET /v2/codes/{code}` | public lookup; with the subject's current terms, if they have any |
| `GET /v2/codes/{code}/terms` | the `status_url` of a published subject with terms: the current version and every earlier one |
| `GET /v2/terms/{id}` | every version of a subject's terms ever published (extension `terms`) |
| `GET /v2/anchors` | signed `pg.anchors.v1` list of anchored subjects (extension `identity`) |
| `GET /v2/catalog` | subjects who chose to be listed (extension `catalog`) |
| `GET /v2/statement` | a provider's statement of the allows it received (extension `catalog`; credential or `PG-Access`) |
| `GET /v2/proofs/{16 hex}` | this registry's part of a `pg.proof.v1` bundle (extension `proof`) |
| `POST /v2/sandbox/access` | sandbox credentials (sandbox mode only) |
| `POST /v2/sandbox/purchases` | a test purchase, no money: one use of a catalog subject for this provider (sandbox mode only) |
| `POST /v2/sandbox/party` | a provider's party document by post (sandbox mode only) |

## AFTER-GEN (working draft)

AFTER-GEN ([`drafts/after-gen.md`](https://www.pregen.org/spec/drafts/after-gen.md)) lets a rights holder approve one
video that already exists, under a licence the registry holds. The registry signs a `pg.after_gen.v1` record that
names the file by its `media/1` hash. A record is never a PRE-GEN permission: no answer rests on one, and a report
that cites one is refused. A sandbox declares `after-gen` by default. A production registry declares it only with
`"after_gen": true` in `registry.json`, or `init --open-providers --after-gen`: the record names its holder by its
party id, so requesters are providers known by their domain. Turned off again, the registry takes no new request or
approval, and keeps answering status, lookup and withdrawal for every record it signed.

| Method and path | What |
|---|---|
| `POST /v2/after-gen/requests` | `{"request": <pg.after_gen_request.v1>, "preview_url"?: "https://…"}`, signed by the requester's key from its own domain (role `requester`, no credential). Returns `{request, state: "pending", review_until}`; a sandbox adds `review_url`, its test approval page |
| `GET /v2/after-gen/requests/{id}` | the requester only (`PG-Access`): `{request, state, review_until, record?}` |
| `POST /v2/after-gen/decisions` | a `pg.after_gen_decision.v1` signed by the subject's own key (custody self, role `subject`), or by an agent's key (role `agent`, `X-Provider-ID` naming the agent) under a mandate that lists `after_gen`; to anyone else (another key, a key the registry holds, an agent without a live mandate of the subject) every request is an unknown one (404). The registry keeps the decision with the record |
| `GET`, `POST /v2/after-gen/review/{token}` | sandbox only: the approval page of the sandbox's test creator, with a simulated second factor |
| `POST /v2/after-gen/{record}/withdraw` | a `pg.after_gen_withdrawal.v1` `{signers, record, issued_at}` signed by the subject's own key; any other signature gets the answer an unknown record gets (404) |
| `GET /v2/after-gen?media={64 hex}` | `{"records": [ids]}`, approved records only; readable from any origin |
| `GET /v2/after-gen/{id}` | `{"record", "status"}`, the status signed now and valid for 300 seconds; readable from any origin |

The operator acts on the subject's authenticated instruction, from the command line. An approval or a mandate opens,
so it names the second factor you confirmed. A refusal, a withdrawal and the end of a mandate close, and need none.

```bash
pregen-registry after-gen show --dir ./data REQUEST_ID
pregen-registry after-gen approve --dir ./data REQUEST_ID --instruction-sha256 HEX --factor authenticator [--purposes commercial]
pregen-registry after-gen refuse --dir ./data REQUEST_ID
pregen-registry after-gen withdraw --dir ./data RECORD_ID --instruction-sha256 HEX
pregen-registry mandate add --dir ./data PG-… https://agency.example --purposes commercial --not-after 1830000000 --instruction-sha256 HEX --factor email
pregen-registry mandate add --dir ./data --envelope mandate.json
pregen-registry mandate end --dir ./data MANDATE_ID
```

A request undecided after 14 days expires, and nothing approves it after that. The preview link is deleted when the
request is decided or expires, and only the approver sees it. One use of the licence is counted when a record is
signed, on the same counter as allows under the `limits` extension. A record carries no status address, because its
id is the hash of its body; its status is at `GET /v2/after-gen/{record id}`.

## Limits of this version

- **One process, SQLite, one write lock.** Correct and simple; move to Postgres with per-row
  locks when throughput matters.
- **Managed subject keys are stored in the database.** Encrypt them, or use a KMS, before
  holding real people.
- **Provider key recovery** (a keyset co-signed by the registry) is not implemented yet.
- **`bind`** (a person connecting licences to an app) works in a sandbox only, with its one test creator. A
  production registry needs people's own accounts and sign-in, which this reference does not have, so it does not
  list `bind`.
- **Terms** ([`extensions/terms.md`](https://www.pregen.org/spec/extensions/terms.md)) are published from Python only,
  `Registry.publish_terms(code, purposes=…, excluded_categories=…, template=…, legal=…, factor=…)`, on the subject's
  own instruction; you check the second factor yourself. There is no CLI command.
- **Party documents** are fetched after a one-shot address check; a resolver that pins the checked address closes
  the rebinding gap before holding real people. The registrable-domain rule is not enforced: a subdomain is
  taken as a provider of its own, with its own budget and document reads. A production registry must check it with
  the Public Suffix List, or a wildcard of subdomains gets around P-7.

## Tests

```bash
pip install -e ".[test]" && pytest
```

The tests cover:
- every rule of the core and of the extensions above;
- that the vendored schemas are byte-for-byte the spec's (`tests/test_schema_parity.py`);
- twenty concurrent jobs racing for a grant's last use;
- the byte vectors in [`messages.json`](https://www.pregen.org/spec/test-vectors/messages.json), and the request
  shapes in [`terms.json`](https://www.pregen.org/spec/test-vectors/terms.json).
