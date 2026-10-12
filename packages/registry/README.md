# pregen-registry

The reference PRE-GEN registry. **Ask before you generate; get a signed answer anyone can
check.** It implements `spec/PRE-GEN-CORE.md`, the profile `likeness/1` and these extensions:
`reports`, `provider-keys`, `limits`, `jobs`, `grants`, `licensee`, `observe`, `lookup` and,
in sandbox mode, `sandbox`.

It is a registry, not a marketplace: it has no prices, payments or dashboards. Those belong to
each registry's own business.

## Run a sandbox in a minute

```bash
pip install pregen-registry
pregen-registry init --dir ./data --prefix TEST --name "My sandbox" --api http://127.0.0.1:8000 --sandbox
pregen-registry serve --dir ./data
curl -X POST http://127.0.0.1:8000/v2/sandbox/access      # a provider id and token, no account
```

The sandbox holds the standard test subjects `PG-TEST-000001…` to `…000008`. Each one
answers as `spec/extensions/sandbox.md` says.

## Run a real registry

1. **Pick a prefix.** Four letters from `ABCDEFGHJKMNPQRSTVWXYZ`, then apply for it
   (`pregen.org/registries`).
2. **Create the registry:**
   `pregen-registry init --dir ./data --prefix ABCD --name "…" --api https://registry.example --policy https://… --complaints mailto:…`
3. **Give the steward the operator key.** Hand over the key id and public key printed by
   `init`, out of band. Back up `data/operator.key` offline; it is created with mode 600.
4. **Add subjects, grants, providers and end users:**
   - `pregen-registry subject add --name "…" --level verified`
   - `pregen-registry grant add --subject PG-ABCD-… --purposes commercial --days 365 --max-uses 100`
   - `pregen-registry provider add --id frame-ai` — prints the credential once
   - `pregen-registry connect --provider frame-ai --licensee user-1`
5. **Serve it behind TLS:** `pregen-registry serve --dir ./data --host 0.0.0.0 --port 8000`

`PREGEN_OPERATOR_KEY_HEX` may hold the operator key instead of the file.

## HTTP interface

| Method and path | What |
|---|---|
| `GET /.well-known/pregen-registry.json` | who this registry is |
| `GET /keys` | its signed operator key set |
| `POST /v2/requests` | ask → `{"answer": <signed pg.answer.v1>}` |
| `POST /v2/reports` | report → `{"ack": <signed pg.report_ack.v1>}` |
| `POST /v2/keys`, `GET /v2/keys/{provider_id}` | provider keysets |
| `GET /v2/grants/{id}` | a signed grant |
| `GET /v2/codes/{code}` | public lookup |
| `POST /v2/sandbox/access` | sandbox credentials (sandbox mode only) |

## Limits of this version

- **One process, SQLite, one write lock.** Correct and simple; move to Postgres with per-row
  locks when throughput matters.
- **Managed subject keys are stored in the database.** Encrypt them, or use a KMS, before
  holding real people.
- **Provider key recovery** (a keyset co-signed by the registry) is not implemented yet.

## Tests

```bash
pip install -e ".[test]" && pytest
```

The tests cover:
- every rule of the core and of the extensions above;
- twenty concurrent jobs racing for a grant's last use;
- the byte vectors in `spec/test-vectors/messages.json`.
