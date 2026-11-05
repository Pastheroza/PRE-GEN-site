# PRE-GEN for registries: run one and join the directory

You run a **registry**: you hold people's (or works') records and answer AI providers'
requests with signed answers. This guide takes you from nothing to being listed in the
signed PRE-GEN directory, where every provider finds you. Every step has the exact command
and what it prints. Where this guide and the specification differ, the specification
wins: `https://www.pregen.org/spec/PRE-GEN-CORE.md`.

**You need:** Python 3.10 or later, a server reachable over HTTPS on your own domain, and a
four-letter prefix (step 8). Any company or person can run a registry on the same terms.

## Ground rules

1. **Your operator key is the registry.** Whoever holds it can answer for every person you
   hold. Keep it on the server only, back it up offline, never paste it anywhere.
2. **Never delete a key from your key set.** A retired key stays listed, so every answer
   and proof it signed keeps verifying (step 3).
3. **A provider credential is shown once.** Give it over a private channel.
4. **HTTPS only.** The directory lists only `https://` addresses, with no credentials,
   query or fragment.

## 1. Install

```bash
pip install "pregen-registry>=0.2.0"
pregen-registry --help
```

`--help` lists the commands `init, serve, subject, grant, provider, connect, info, key,
check`. If you write your own registry instead, implement `PRE-GEN-CORE.md`, pass
conformance Level 1 with your signing library (step 7), and serve the same HTTP interface
(the table at the end); the rest of this guide still applies.

## 2. Create the registry

Pick your prefix (step 8 says how) and your public HTTPS address, then:

```bash
pregen-registry init --dir ./data --prefix ABCD --name "Example Registry" \
  --api https://registry.example --policy https://registry.example/policy \
  --complaints mailto:complaints@registry.example
```

It prints:

```
Registry created in ./data.
  prefix: ABCD
  operator key id: pg-ed25519:<32 hex>
  public key: <64 hex>
Give the key id and public key to the steward for the directory.
The private key is in ./data/operator.key (mode 600): back it up offline.
```

Write down the key id and the public key: the steward needs both (step 8). `--api` is the
address providers will use, exactly as you will serve it, with no trailing slash.

## 3. Keys: one current key, with its whole history

`GET {api}/keys` is your signed key set: the current key and every key you ever signed
with. Never edit it by hand. To change keys:

```bash
pregen-registry key next --dir ./data
```

```
next operator key id: pg-ed25519:<32 hex>
  public key: <64 hex>
Give both to the steward to announce in the directory. When the directory lists it, run `pregen-registry key rotate`.
```

Send both to the steward (step 8). **Only after the directory lists the new key:**

```bash
pregen-registry key rotate --dir ./data
```

```
operator key is now pg-ed25519:<new>; pg-ed25519:<old> is retired and stays in /keys, so everything it signed still verifies. Move the retired private key file offline.
```

Restart the server (step 4). If you rotate before the directory lists the new key, every
answer you sign is refused by providers until it does.

## 4. Serve it over HTTPS

In production, run the server behind your TLS proxy (nginx, Caddy, a load balancer) that
forwards `https://registry.example` to it:

```bash
pregen-registry serve --dir ./data --host 127.0.0.1 --port 8000
```

To serve HTTPS directly, for example on a test machine with your own certificate:

```bash
pregen-registry serve --dir ./data --host 127.0.0.1 --port 8443 \
  --ssl-certfile cert.pem --ssl-keyfile key.pem
```

Leave it running, and check from another shell:

```bash
curl -s https://registry.example/.well-known/pregen-registry.json
curl -s https://registry.example/keys
```

The first returns your document: `prefix`, `name`, `api`, `keys`, `profiles`
(`["likeness/1"]`), `extensions`, `policy`, `complaints`, `sandbox`, `spec`. The second
returns `{"current_key_id": "pg-ed25519:…", "keys": [{"key_id", "public_key_hex",
"activated_at", "deactivated_at", "status", …}], "signature": "…"}`.

## 5. People, anchors, grants and providers

Add a person you have verified:

```bash
pregen-registry subject add --dir ./data --name "Maya Cole" --level verified
```

It prints the person's code, for example `PG-ABCD-000001G`. The last character is a
check character: always copy codes, never type them.

**Anchor a public person** (extension `identity`): record their public identifier (a
Wikidata item, an ISNI, or a domain) and the page on their official channel where they
posted the line `PRE-GEN: PG-ABCD-000001G`:

```bash
pregen-registry subject anchor --dir ./data --code PG-ABCD-000001G \
  --anchor wikidata:Q42 --proof-url https://www.instagram.com/mayacole/p/1
```

```
PG-ABCD-000001G anchored to wikidata:Q42; GET /v2/anchors lists it
```

A confirmation on the person's own channel is what lets clients count your record when
several registries claim the same person. A matching name is never evidence.

**Grant a use** the person agreed to. It prints the grant id (64 hex):

```bash
pregen-registry grant add --dir ./data --subject PG-ABCD-000001G \
  --purposes commercial,editorial --days 30 --max-uses 10
```

**Give a provider its credential.** It is printed once:

```bash
pregen-registry provider add --dir ./data --id frame-ai
```

```
provider_id: frame-ai
token: <secret>
Shown once. Give it to the provider over a private channel.
```

`pregen-registry connect --dir ./data --provider frame-ai --licensee user-1` lets that
provider ask for a named end customer (extension `licensee`).

## 6. A sandbox, for providers to test against

A sandbox is a **separate** registry, with its own data folder, key and test prefix, that
holds the eight standard test subjects and gives credentials without an account:

```bash
pregen-registry init --dir ./sandbox --prefix ABCE --name "Example Registry sandbox" \
  --api https://sandbox.registry.example --sandbox
pregen-registry serve --dir ./sandbox --host 127.0.0.1 --port 8001
curl -s -X POST https://sandbox.registry.example/v2/sandbox/access
```

The last command returns `{"provider_id": "sbx-…", "token": "…", "registry": "…", "note": "…"}`. The subjects are
`PG-ABCE-000001…` to `…000008`: `1` allows, `2` to `7` refuse, hold or say `not_blocked`,
`8` is unknown (`spec/extensions/sandbox.md`). Every sandbox answer carries
`ext: {"sandbox": true}`, and clients refuse it unless they are testing. A sandbox is listed
only in a **test directory**, never in the real one.

## 7. Check yourself before you apply

From any machine, as a provider would see you:

```bash
pregen-registry check --api https://registry.example
```

```
PASS registry document: prefix ABCD, profiles ['likeness/1']
PASS document api is 'https://registry.example'
PASS answers under likeness/1
PASS declares reports, provider-keys
PASS key set: current key pg-ed25519:<32 hex>, 1 key(s) in its history
PASS every key id is its key's fingerprint, and no key is small-order
PASS key set signed by its current key
PASS an unauthenticated request is refused with an error code: HTTP 422 PG_MALFORMED
OK: all checks passed
```

Any `FAIL` line names what to fix; the command exits 1 until everything passes. Add
`--provider-id frame-ai --token <secret> --subject PG-ABCD-000001G` to also ask about one
person and see the answer's status.

**If you wrote your own registry,** also run conformance Level 1 against your signing
library (`spec/conformance/README.md`). It requires the v5 operations by default:

```bash
python3 spec/conformance/level1/run_conformance.py --adapter "<command that runs your adapter>"
```

The last line must read `… passed, 0 failed, … ; v5: 112 passed` or more.

## 8. Apply for your prefix

A prefix is four letters from `ABCDEFGHJKMNPQRSTVWXYZ` (no digits, no I, L, O, U). Look at
`https://www.pregen.org/registries.json` to see which are taken; bring a second choice.
Open a "Registry application" issue:
`https://github.com/Pastheroza/PRE-GEN-site/issues/new?template=registry-application.md`.

It asks for:
1. **Operator:** legal name, public address, a complaints contact answered within 7 days,
   website;
2. **Policy:** its URL; how you verify that a rights holder is who they claim; the anchor
   you record for public people; your own refusals and answer lifetime;
3. **Acceptance of the core**, its fixed protections, and the revocation grounds;
4. **Endpoints:** `api`, `keys`, and that `/.well-known/pregen-registry.json` answers;
5. **Keys:** the fingerprint of every operator key: current, retired, and the next one if
   you made it. **Send the same list to the steward by a second channel** (an email from
   your domain), so a stolen account cannot list someone else's key;
6. **Your `pregen-registry check` output**, ending `OK: all checks passed`;
7. **Status:** sandbox or production.

## 9. Listed: the steward signs

**Listed** means the steward signed a new directory with your prefix and keys. Until
then, providers refuse your answers: that is the directory doing its job. Confirm it:

```bash
pregen-registry check --api https://registry.example \
  --directory https://www.pregen.org/registries.json
```

The output now also has:

```
PASS the directory (sequence <n>) lists prefix ABCD
PASS listed with this api and keys URL
PASS listed with the current key
```

For a test directory, add `--steward <its steward public key hex>`. Then send your
providers your `api`, their credentials, and your sandbox. A listing can be revoked, with
notice and reasons; a prefix is never given to anyone else.

## You are done when

- [ ] The operator key is backed up offline; the server is the only place it is in use
- [ ] `GET {api}/keys` lists every key you ever used; the next key is announced before rotation
- [ ] `{api}/.well-known/pregen-registry.json` answers over HTTPS with your prefix and policy
- [ ] Every public person has an anchor and a proof URL; every grant matches what the person agreed
- [ ] Providers got their credentials over a private channel; your sandbox is separate
- [ ] `pregen-registry check --api … --directory …` ends `OK: all checks passed`, listing included

## The HTTP interface

| Method and path | What |
|---|---|
| `GET /.well-known/pregen-registry.json` | who this registry is |
| `GET /keys` | its signed operator key set: every key it ever signed with, current and retired |
| `POST /v2/requests` | ask → `{"answer": <signed pg.answer.v1>}` |
| `POST /v2/reports` | report → `{"ack": <signed pg.report_ack.v1>}` |
| `POST /v2/keys`, `GET /v2/keys/{provider_id}` | provider key sets |
| `GET /v2/grants/{id}` | a signed grant |
| `GET /v2/codes/{code}` | public lookup |
| `GET /v2/anchors` | anchored subjects, signed (extension `identity`) |
| `GET /v2/proofs/{16 hex}` | this registry's part of a proof |
| `POST /v2/sandbox/access` | sandbox credentials (sandbox mode only) |

Providers authenticate with `X-Provider-ID: <id>` and `Authorization: Bearer <token>`.
Errors are `{"error": "PG_…", "error_description": "…"}` with HTTP 401 or 422.
