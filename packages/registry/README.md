# pregen-registry

The reference PRE-GEN registry. **Ask before you generate; get a signed answer anyone can
check.** It implements [`PRE-GEN-CORE.md`](https://www.pregen.org/spec/PRE-GEN-CORE.md), the profile `likeness/1` and these extensions:
`reports`, `provider-keys`, `limits`, `jobs`, `grants`, `licensee`, `observe`, `lookup`, `identity`,
`proof`, `catalog`, `provider-identity` (with `--open-providers`, and always in a sandbox) and, in sandbox
mode, `sandbox`.

It is a registry, not a marketplace: it has no prices, payments or dashboards. Those belong to
each registry's own business.

## Run a sandbox in a minute

```bash
pip install pregen-registry
pregen-registry init --dir ./data --prefix TEST --name "My sandbox" --api http://127.0.0.1:8000 --sandbox
pregen-registry serve --dir ./data
curl -X POST http://127.0.0.1:8000/v2/sandbox/access      # a provider id and token, no account
```

The sandbox answers the eight standard test codes `PG-TEST-000001N` `PG-TEST-000002Z`
`PG-TEST-0000034` `PG-TEST-000004E` `PG-TEST-000005R` `PG-TEST-000006$` `PG-TEST-0000077`
`PG-TEST-000008H` (code 8 is deliberately not registered). The last character is a check
character; with another prefix the codes differ, and `init` prints them. Each one answers as
[`extensions/sandbox.md`](https://www.pregen.org/spec/extensions/sandbox.md) says.

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
   - `pregen-registry grant add --dir ./data --subject 'PG-ABCD-…' --purposes commercial --days 365 --max-uses 100`
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
| `GET /v2/codes/{code}` | public lookup |
| `GET /v2/anchors` | signed `pg.anchors.v1` list of anchored subjects (extension `identity`) |
| `GET /v2/catalog` | subjects who chose to be listed (extension `catalog`) |
| `GET /v2/statement` | a provider's statement of the allows it received (extension `catalog`; credential or `PG-Access`) |
| `GET /v2/proofs/{16 hex}` | this registry's part of a `pg.proof.v1` bundle (extension `proof`) |
| `POST /v2/sandbox/access` | sandbox credentials (sandbox mode only) |
| `POST /v2/sandbox/party` | a provider's party document by post (sandbox mode only) |

## Limits of this version

- **One process, SQLite, one write lock.** Correct and simple; move to Postgres with per-row
  locks when throughput matters.
- **Managed subject keys are stored in the database.** Encrypt them, or use a KMS, before
  holding real people.
- **Provider key recovery** (a keyset co-signed by the registry) is not implemented yet.
- **`bind`** (a person connecting licences to an app) is specified ([`extensions/bind.md`](https://www.pregen.org/spec/extensions/bind.md)), not implemented.
- **Party documents** are fetched after a one-shot address check; a resolver that pins the checked address closes
  the rebinding gap before holding real people. The registrable-domain rule (Public Suffix List) is not enforced.

## Tests

```bash
pip install -e ".[test]" && pytest
```

The tests cover:
- every rule of the core and of the extensions above;
- twenty concurrent jobs racing for a grant's last use;
- the byte vectors in [`messages.json`](https://www.pregen.org/spec/test-vectors/messages.json).
