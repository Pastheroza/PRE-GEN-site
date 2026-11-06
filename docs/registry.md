# PRE-GEN for registries: run one and join the directory

You run a **registry**: you hold people's (or works') records and answer AI providers'
requests with signed answers. This guide takes you from nothing to being listed in the
signed PRE-GEN directory, where every provider finds you. Every step has the exact command
and what it prints. Where this guide and the specification differ, the specification
wins: `https://www.pregen.org/spec/PRE-GEN-CORE.md`.

**You need:** Python 3.10 or later, and a server reachable over HTTPS on your own domain.
Any company or person can run a registry on the same terms.

## Ground rules

1. **Your operator key is the registry.** Whoever holds it can answer for every person you
   hold. Keep it on the server only, never paste it anywhere.
2. **Never delete a key from your key set.** A retired key stays listed, so every answer
   and proof it signed keeps verifying (step 4).
3. **A provider credential is shown once.** Give it over a private channel.
4. **HTTPS only.** The directory lists only `https://` addresses, with no credentials,
   query or fragment.
5. **Quote PG codes.** A code ends with a check character that may be `*`, `~`, `$`, `=` or
   `!`. In a shell, put codes in single quotes (`'PG-ABCD-000001$'`); in a URL path, encode
   them (`$` is `%24`, `*` is `%2A`). Always copy codes, never retype them.

**Order on a first run:** steps 1–3, 5, 7–8, 9 for the sandbox, then 6, 9 for production,
then 10. Step 4 only when you rotate. Run every command from the folder that holds `./data`
(`registry.pid`, `registry.log` and `./backup` are relative to it).

## 1. Install

```bash
pip install "pregen-registry>=0.2.0"
pregen-registry --help
```

`--help` lists the commands `init, serve, subject, grant, provider, connect, info, key,
check`. If you write your own registry instead, implement `PRE-GEN-CORE.md`, pass
conformance Level 1 with your signing library (step 8), and serve the same HTTP interface
(the table at the end); the rest of this guide still applies.

## 2. Choose your prefix and your address

**Your prefix** is four letters from `ABCDEFGHJKMNPQRSTVWXYZ` (no digits, no I, L, O, U).
It starts every code you issue (`PG-ABCD-…`) and is never given to anyone else, so choose it
first. List the prefixes already taken, from the directory checked against the steward's
signature:

```bash
python3 -c "import pregen; print(sorted(r['prefix'] for r in pregen.load_directory().registries))"
```

**The public test directory is not online yet** (it will be `https://test.pregen.org/registries.json`,
with its own test steward key): until it is, a sandbox cannot be listed and providers cannot
check its answers outside a test network you are given. On such a network, list its prefixes
with this one line instead:

```bash
python3 -c "import pregen; print(sorted(r['prefix'] for r in pregen.load_directory('<test directory url>', steward_public_key_hex='<test steward key hex>').registries))"
```

Pick a prefix that is not listed in either directory (the test one once you have its key), and a
second choice in case someone asks for yours first. For your sandbox's prefix, also check
the test directory's list: sandboxes are listed only there, and no prefix is ever reused. Until
you have its steward key, give a second choice: the steward checks the sandbox prefix for you.

**A sandbox is a separate registry with its own prefix** (step 7), applied for the same way.
Any free prefix will do; one close to yours (`ABCE` beside `ABCD`) helps people recognise it.

**Your complaints contact** is a mailbox or web form you answer within 7 days (for example
`mailto:complaints@registry.example`).

**Your address** (`api`) is the HTTPS URL providers will use, exactly as you will serve
it, with no trailing slash: for example `https://registry.example`.

**Your policy** is a public page that says how you verify that a rights holder is who they
claim and may license the person, which anchor you record for public people (step 6), your
own refusals, how long your answers live, and how long an opt-out waits. The reference
registry serves it for you: step 3 writes a template to `./data/policy.md` that already
states the reference registry's behaviour (answers live 300 seconds; an opt-out applies
from the next answer); replace each `<…>` with your own text, and it answers at
`{api}/policy`. Or publish it on your website. It must answer before you apply.

## 3. Create the registry

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
Give the key id to the steward (step 9 of docs/registry.md); it reads the public key from https://registry.example/keys.
The private key is in data/operator.key (mode 600): back it up offline.
A policy to edit is in data/policy.md; `serve` publishes it at https://registry.example/policy.
```

Keep the folder private: `chmod 700 ./data` (the database holds your people, grants and
provider credentials). Replace each `<…>` in `./data/policy.md`, the operator line included
(`grep -nE '<(legal name|any refusals|who may|the anchor)' ./data/policy.md` must then print
nothing; with no refusals of your own, write `We add no refusals of our own.`);
under "Anchors for public people", name Wikidata: clients confirm no other anchor today (step 6).

The **key id** (`pg-ed25519:` and 32 hex) is the key's **fingerprint**: it is what the
directory lists and what the steward asks for (step 9). The directory lists key ids only;
the steward checks your current key id against your live `/keys`. A next key is announced
by its id alone (step 4).

**Back up the whole `./data` folder offline** (an encrypted drive kept apart): `operator.key`
is your signing key, and `registry.db` holds your people, grants and provider credentials.
While the server runs, copy the database safely with Python's `sqlite3`, and the rest with
`cp`:

```bash
umask 077 && rm -rf ./backup/data && mkdir -p ./backup/data
python3 -c "import sqlite3; sqlite3.connect('./data/registry.db').backup(sqlite3.connect('./backup/data/registry.db'))"
cp -p ./data/*.key ./data/registry.json ./data/policy.md ./backup/data/
```

For the sandbox, the same with `./sandbox` and `./backup/sandbox`. Then move `./backup` to
the offline drive. Back up again after you add people or grants, and after every `key next`
or `key rotate`.

## 4. Keys: one current key, with its whole history

`GET {api}/keys` is your signed key set: the current key, every key you ever signed with,
and your next key once you make one. Never edit it by hand. The steward reads your key ids
there, on your own domain: that is how it knows an application really comes from you. You
need a next key only when you want to rotate. To rotate:

```bash
pregen-registry key next --dir ./data
```

```
next operator key id: pg-ed25519:<32 hex>
  public key: <64 hex>
https://registry.example/keys now lists it as `next`. Apply again with this key id added; 24 hours after the directory lists it, stop the server, run `pregen-registry key rotate`, and start it again.
```

`{api}/keys` lists it at once, with `"status": "next"` (no restart needed). Send the steward,
as a new Registry application issue titled `Registry application: ABCD — key update`, the
same application as in step 9 with the new key id added to your key ids, and a fresh
plain `check` output; the steward finds the new key id in your live `/keys`. Back up
`./data/operator.next.key` (step 3). Then confirm the
steward listed it: `pregen-registry check --api … --directory …` (on a test directory, add
`--steward <its key hex>`) prints `PASS the directory (sequence <n>) lists prefix ABCD with
keys …`, the new key id must be among them, and the sequence must be higher than in your
previous `check`.

**Wait 24 hours after the listing (note the time `check` first shows the new key id among
the listed keys), then stop the server, wait until it has exited, rotate, and start it
again at once.** Providers may check answers against a directory they loaded up to 24 hours earlier;
until they reload, they refuse what a key it does not list signs. Every answer the old
process signs after `rotate` is refused by every client, hence the restart. Stop the server
the way you started it (your service manager, or, for `nohup … &`, the first two lines below),
rotate, and start it again. Run each line on its own, not chained with `&&`:

```bash
kill "$(cat registry.pid)"
while kill -0 "$(cat registry.pid)" 2>/dev/null; do sleep 1; done
pregen-registry key rotate --dir ./data
nohup <the exact serve command you used in step 5> >> registry.log 2>&1 & echo $! > registry.pid
```

The last line is your own step 5 command: the same port, and the same
`--ssl-certfile`/`--ssl-keyfile` if you serve HTTPS directly.

```
operator key is now pg-ed25519:<new>; pg-ed25519:<old> is retired and stays in /keys, so everything it signed still verifies. Move the retired private key file offline.
```

Then run `pregen-registry check --api … --directory …` (test
directory: add `--steward <its key hex>`): it must show `PASS listed with the current key`.
The directory does not change, so nothing goes to the steward.
The retired key's file is `./data/operator.retired.<the 32 hex of the old key id>.key`. Nothing
needs it any more, but whoever holds it could forge answers and acknowledgements, whole proofs, dated before it
was retired: keep it only in the offline backup, encrypted, in its own folder beside `./backup`
(for example `./offline/retired/`, never inside `./backup/data`), and remove it from `./data` before the next step 3 backup (the recipe
copies every `*.key` still in `./data` and empties `./backup/data` each time). To encrypt it:
`openssl enc -aes-256-cbc -pbkdf2 -salt -in <file> -out <file>.enc`, then delete the plain
file; openssl asks for a passphrase: keep it in a password manager, never beside the `.enc` file. If you rotate before the directory lists the new key, providers refuse
every answer you sign until it does. A retired key cannot sign anything new (clients refuse
what it signs after it was retired), but keep its file as secret as the current one.

**If a key is stolen,** report it at once, privately, through PRE-GEN's security advisory
form: `https://github.com/Pastheroza/PRE-GEN-site/security/advisories/new` (never a public
issue). A thief may control your domain; that channel stays yours. The steward revokes the
key in the directory: from then on everything it ever signed fails, old proofs included.
Make a new key with `key next`, have it listed, and run `key rotate` as soon as `check` shows
it listed (do not wait 24 hours after a theft); then tell your providers.

## 5. Serve it over HTTPS

In production, run the server behind your TLS proxy (nginx, Caddy, a load balancer) that
forwards `https://registry.example` to it:

```bash
pregen-registry serve --dir ./data --host 127.0.0.1 --port 8000
```

The proxy must pass the client's address: in nginx, `proxy_set_header X-Forwarded-For
$proxy_add_x_forwarded_for;` (Caddy does it by default). If the proxy runs on another host,
start `serve` with `FORWARDED_ALLOW_IPS=<proxy address>`. Without this, your sandbox counts every
provider as one address: 10 credentials an hour for everyone.

To serve HTTPS directly, for example on a test machine with your own certificate:

```bash
pregen-registry serve --dir ./data --host 127.0.0.1 --port 8443 \
  --ssl-certfile cert.pem --ssl-keyfile key.pem
```

Keep it running (a service manager, or `nohup … >> registry.log 2>&1 & echo $! > registry.pid`;
the sandbox likewise, for example `nohup pregen-registry serve --dir ./sandbox --host 127.0.0.1
--port 8001 >> sandbox.log 2>&1 & echo $! > sandbox.pid`, with the same `--ssl-certfile`/`--ssl-keyfile`
to serve it over HTTPS directly,
so you can stop it later with `kill "$(cat registry.pid)"`). A registry and its sandbox are
two servers on two ports, each with its own pid file and log (`sandbox.pid`,
`sandbox.log`); each is stopped and started on its own. Only a key rotation needs a restart:
people, anchors, grants, providers and `policy.md` take effect at once. Check from another
shell:

```bash
curl -s https://registry.example/.well-known/pregen-registry.json
curl -s https://registry.example/keys
curl -s https://registry.example/v2/anchors
```

The first returns your document: `prefix`, `name`, `api`, `keys`, `profiles`
(`["likeness/1"]`: fixed names of vocabularies of uses, never versions of your policy; when
your policy changes, the profile names stay), `extensions`, `policy`, `complaints`, `sandbox`, `spec`. The second
returns `{"current_key_id": "pg-ed25519:…", "keys": [{"key_id", "public_key_hex",
"activated_at", "deactivated_at", "status", …}], "signature": "…"}`. The third returns your signed
anchor list (`{"type": "pg.anchors.v1", …}`), never a 404, through your proxy too: a provider
that cannot read it stops generating your people, and every public person at any registry,
until it reads it again.

## 6. People, anchors, grants and providers

Set up and try your sandbox first (steps 7–8); add only real people here.

Add a person you have verified:

```bash
pregen-registry subject add --dir ./data --name "Maya Cole" --level verified
```

It prints the person's code, for example `PG-ABCD-000001G`. Codes can be computed by anyone (serials
count from 1; the last character is a checksum), so `GET {api}/v2/codes/<code>` shows the person's
name and level only if you add `--publish`, which you do only when the person chose to be
public (`subject publish --code … [--off]` changes it later). Anchoring publishes the code,
its level and its anchor (so who the person is) at `/v2/anchors`, whatever `--publish` says:
anchor only a person who chose to be public. `--level` is how far you checked
them: `self`, `asserted`, `consented` or `verified`. Without `--level` the person is `self`, and
proof checkers label only `verified` by default (provider.md step 9): give `--level verified` once
you have checked identity and authority, or raise it later with `pregen-registry subject level
--dir ./data --code '<code>' --level verified`. `pregen-registry subject list --dir ./data`
prints every code you hold, with its level and name.

**Anchor a public person** (extension `identity`; every public person needs one): record their
public identifier, written exactly as `wikidata:Q42`, `isni:0000000123456789` (16 characters,
no spaces) or `domain:example.com` (lower case); the command does not check the spelling, and
a different spelling is a different person to every client. **Use `wikidata:Q…` whenever the
person has one:** clients today confirm only `wikidata:` anchors, so a person anchored as
`isni:` or `domain:`, or without `--proof-url`, is refused by every provider (`not_blocked`,
`PG_IDENTITY_UNCONFIRMED`), grant or not, until confirmed. An anchor that cannot be confirmed
means nobody can generate that person.

Add the page where the person posted the line `PRE-GEN: PG-ABCD-000001G`. It must be an
`https://` page, readable without a login, at or under a channel their Wikidata item lists:
the official website (use it: social posts are mostly scripts a plain fetch cannot read),
`https://x.com/<handle>/…`, `https://www.instagram.com/<handle>/…`,
`https://www.youtube.com/channel/<id>/…` or `https://www.tiktok.com/@<handle>/…`, on exactly the
host Wikidata lists (`www.` counts). The command records what you give it and fetches nothing,
so check first; this must print `True`. The page's HTML source (view-source) must contain
`PRE-GEN: <code>` exactly (one plain space, no tags or entities inside it, the whole code), and a
handle in the URL must match Wikidata's spelling, case included; a path with a `.` or `..`
segment (or `%2e`, or an encoded slash) confirms nothing:

```bash
CODE='PG-ABCD-000001G' URL='https://mayacole.example/pregen' ANCHOR='wikidata:Q42' python3 -c "
import os, pregen, urllib.request as u
ua = {'User-Agent': 'Example Registry (https://registry.example/contact)'}
print(pregen.check_channel_proof(os.environ['CODE'], os.environ['URL'], pregen.wikidata_official_urls(os.environ['ANCHOR']),
      lambda x: u.urlopen(u.Request(x, headers=ua)).read().decode('utf-8', 'replace')))"
```

If it prints `False`, the page answers 404, or it raises (page unreadable, Wikidata 403), anchor without `--proof-url` (the claim stays unconfirmed) and run
`subject anchor` again with both once it does. Re-check every proof page at least daily; once
the line is gone, anchor again without `--proof-url`.

```bash
pregen-registry subject anchor --dir ./data --code 'PG-ABCD-000001G' \
  --anchor wikidata:Q42 --proof-url https://mayacole.example/pregen
```

```
PG-ABCD-000001G anchored to wikidata:Q42; GET /v2/anchors lists it
```

When several registries claim the same person, a client counts only a record whose anchor
the person confirmed on their own channel (the libraries' `decide_identity`). A matching
name is never evidence.

**Grant a use** the person agreed to. It prints the grant id (64 hex):

```bash
pregen-registry grant add --dir ./data --subject 'PG-ABCD-000001G' \
  --purposes commercial,editorial --days 30 --max-uses 10
```

- `--purposes` lists the `use.purpose` values it covers (`personal`, `educational`,
  `research`, `editorial`, `commercial`). A request for any other purpose is answered
  `deny`, `PG_SCOPE_VIOLATION`.
- Without `--licensee`, the grant covers any provider that asks for this person. With
  `--licensee frame-ai:user-1` (exactly the string you pass to `connect` below), it covers
  only requests that name that licensee (extension `licensee`).
- `--max-uses` counts allows (without it, no limit); `--days` is how long the grant lasts
  (default 365). Without `--purposes`, only `research` is covered.
- `grant add` does not check spellings: use the five lower-case purposes and the full
  `<provider id>:<customer id>`, then try such a grant in your sandbox (steps 7–8). To confirm a
  provider's token works without using a grant, `GET {api}/v2/grants/<grant id>` with its
  headers returns 200. Any provider with a credential can read any grant by its id, licensee
  included: give a grant id only to the provider it concerns.
- `--licensee <provider id>` (no customer part) covers only that provider's requests sent
  without `licensee_id`: a grant to one company rather than one of its customers.
- **Without `--licensee` the grant is open:** any provider may use it for these purposes. If
  the person agreed to one client, pass `--licensee`.

To see what you hold: `subject list` prints your codes; grants and connections are in the
database (`python3 -c "import sqlite3; [print(r) for r in sqlite3.connect('./data/registry.db')
.execute('SELECT id, subject_code, licensee_id, purposes, expires_at, max_uses FROM grants')]"`, and the same with
`SELECT provider_id, licensee_id FROM connections`).

**Give a provider its credential.** It is printed once:

```bash
pregen-registry provider add --dir ./data --id frame-ai
```

A provider id is letters, digits and `-`, never `:` (it separates provider and customer in a
licensee id).

```
provider_id: frame-ai
token: <secret>
Shown once. Give it to the provider over a private channel.
```

Until you hand it over, keep it only in a file readable by you
(`umask 077; pregen-registry provider add … > frame-ai.credential`), and delete that file
once it is sent.

`pregen-registry connect --dir ./data --provider frame-ai --licensee frame-ai:user-1` lets that
provider ask on behalf of its end customer `user-1`; it prints `connected`. Run `provider add`
first: `connect` does not check that the provider exists, so a typo connects nobody. **A licensee id names one customer of
one provider, so always write it as `<provider id>:<the customer's id at that provider>`.**
`connect` refuses any other shape: a grant to a licensee covers every provider connected to
that id, so two providers' `user-1` written bare would share each other's grants. The grant
may come before or after `connect`. Tell the
provider the exact licensee id (step 10); it sends it as `licensee_id`.

**When things change**, each takes effect from the next answer; answers already given stay
what they were:

```bash
pregen-registry subject opt-out --dir ./data --code 'PG-ABCD-000001G'   # the person opted out or withdrew
pregen-registry grant revoke --dir ./data --id <grant id>                # the grant ends now
pregen-registry provider remove --dir ./data --id frame-ai               # a leaked token: see below
```

After `provider remove` for a leaked token: `provider add` again, run `connect` again for each
of its licensees (removal drops them), and send the new token privately. If a provider lost its
signing key, this registry cannot replace it: `provider add` a new id, re-`connect` its
customers under that id, and re-issue licensee-only grants to the new licensee ids.

Nothing you publish can be deleted afterwards, so add no test records to this registry:
test in your sandbox (step 7).

## 7. A sandbox, for providers to test against

A sandbox is a **separate** registry, with its own data folder, key, address, prefix and
policy, that holds the standard test subjects and gives credentials without an account. Use
the same flags as in step 3, plus `--sandbox` (its `./sandbox/policy.md` template already says
it holds no real people):

```bash
pregen-registry init --dir ./sandbox --prefix ABCE --name "Example Registry sandbox" \
  --api https://sandbox.registry.example --policy https://sandbox.registry.example/policy \
  --complaints mailto:complaints@registry.example --sandbox
```

After the key and policy lines it prints the eight test codes:

```
Sandbox test subjects (copy them; the last character is a check character):
  PG-ABCE-000001…  Test subject 1 (allow)
  …
  PG-ABCE-000007…  Test subject 7 (not blocked)
  PG-ABCE-000008…  Test subject 8 (not registered: PG_UNKNOWN_SUBJECT)
```

Serve it (step 5) and get test credentials:

```bash
curl -s -X POST https://sandbox.registry.example/v2/sandbox/access
```

It returns `{"provider_id": "sbx-…", "token": "…", "registry": "…", "note": "…"}`. Every
sandbox answer carries `ext: {"sandbox": true}`, and clients refuse it unless they are
testing. Replace each `<…>` in `./sandbox/policy.md`, as in step 3. The sandbox accepts any
licensee without `connect`; in production, run `connect` first or the provider gets 401. A
licensee-only grant still needs `licensee_id` in the request (without it: `deny
PG_NOT_CONNECTED`).
Apply for the sandbox's prefix too (step 9, status `sandbox`): a sandbox is listed only in a
**test directory**, never in the real one (step 2: not online yet). The directory entry looks like any
other; the document's `sandbox` member is only `true` or `false`, and nothing links your
registry to your sandbox: give providers the sandbox `api` yourself (step 10).

## 8. Check yourself before you apply

From any machine, as a provider would see you:

```bash
pregen-registry check --api https://registry.example
```

```
PASS registry document: prefix ABCD, profiles ['likeness/1']
PASS document api is 'https://registry.example'
PASS answers under likeness/1
PASS declares reports, provider-keys
PASS the policy page answers: https://registry.example/policy
PASS key set: current key pg-ed25519:<32 hex>, 1 key(s) in its history
PASS every key id is its key's fingerprint, and no key is small-order
PASS key set signed by its current key
PASS a request with an unknown credential is refused: HTTP 401 PG_NOT_AUTHENTICATED
PASS anchors list signed by the current key: 0 public person(s)
OK: all checks passed
```

Any `FAIL` line names what to fix; the command exits 1 until everything passes. To see an
answer as a provider would, ask your **sandbox** (never production: an `allow` uses a real
use, and test records cannot be removed), with its credentials from step 7 and a code:

```bash
pregen-registry check --api https://sandbox.registry.example \
  --provider-id sbx-… --token '<sandbox token>' --subject '<sandbox code 1>' --purpose commercial
```

The extra line reads `PASS POST /v2/requests for PG-ABCE-000001…, purpose commercial: HTTP
200, allow`; with test code 2 it reads `… deny PG_NO_LICENSE`. To try a grant of your own
(purposes, a licensee), add a test person and that grant to the sandbox (`subject add
--dir ./sandbox --level verified --publish --name "Test subject 9 (allow, licensee test:t1, commercial)"`, named by what it
answers, which numbers added people from 9 on, and `grant add --dir ./sandbox …`)
and ask for it the same way (give sandbox test grants no `--max-uses`: every provider shares
them, and each allow, a `check` included, uses one for good); for a licensee-only grant, give
it `--licensee test:t1` and add `--licensee test:t1` to `check`. If you added your own test
people, also change the line in `./sandbox/policy.md` that says it holds only the standard test
subjects.

**If you wrote your own registry,** also run conformance Level 1 against your signing
library (`spec/conformance/README.md`; `spec/` is in `git clone https://github.com/Pastheroza/PRE-GEN-site`).
Write the adapter yourself, on the pattern of `packages/verify-py/tests/conformance_adapter.py`. It requires the v5 operations by default:

```bash
python3 spec/conformance/level1/run_conformance.py --adapter "<command that runs your adapter>"
```

The last line must read `… 0 failed … ; v5: 114 passed` or more.

## 9. Apply for your prefix

Open a "Registry application" issue:
`https://github.com/Pastheroza/PRE-GEN-site/issues/new?template=registry-application.md`.
It asks for:
0. **Prefix** asked for, and a second choice (step 2);
1. **Operator:** legal name, public address, a complaints contact answered within 7 days,
   and the operator's website (any public `https://` page about you or your registry; your
   policy URL will do);
2. **Policy:** its URL (step 2). The details live on that page;
3. **Acceptance of the core**, its fixed protections, the rule for a person held by several
   registries (a refusal of the person, such as an opt-out, by any registry whose claim the
   person confirmed holds everywhere; "no licence here" does not), and the revocation
   grounds;
4. **Endpoints:** `api`, `keys` (`{api}/keys`), that `/.well-known/pregen-registry.json`
   answers, and the profiles you answer under (`likeness/1`);
5. **Keys** (the application's `keys` field is the key set URL; this item is the list of
   key ids): the key id (fingerprint) of every operator key: current, retired, and the next
   one if you made one. The steward lists only key ids it finds in your live `{api}/keys`,
   with your current key among them, so a stolen GitHub account cannot list someone else's
   key;
6. **Your `pregen-registry check --api …` output** (the plain run of step 8, without any
   token), ending `OK: all checks passed`; if you wrote your own registry, also the last line
   of conformance Level 1 (step 8);
7. **Status:** `production`, or `sandbox` for a sandbox (one application per prefix). The
   steward lists a sandbox in its **test directory**, not the real one, and gives you that
   directory's URL and test steward key.

## 10. Listed: the steward signs

**Listed** means the steward signed a new directory with your prefix and keys. Until
then, providers refuse your answers: that is the directory doing its job. Confirm it:

```bash
pregen-registry check --api https://registry.example \
  --directory https://www.pregen.org/registries.json
```

The output now also has:

```
PASS the directory (sequence <n>) lists prefix ABCD with keys pg-ed25519:<32 hex>
PASS listed with this api and keys URL
PASS listed with the current key
```

For a test directory, add `--steward <its steward public key hex>`. Then send each provider,
privately: your `api`; its credential in the shape it stores, for your production prefix
(sandbox credentials are self-service),
`{"ABCD": {"provider_id": "frame-ai", "token": "<secret>"}}`; the codes it may ask about,
and the exact licensee id of each customer you connected for it; your sandbox `api`, the
sandbox's eight test codes (and any test people you added, with what each is for), and the
test directory's URL and steward key. Providers take
sandbox credentials themselves (`POST {sandbox api}/v2/sandbox/access`).
A listing can be revoked, with notice and reasons; a prefix is never given to anyone else.

## You are done when

- [ ] The `./data` folder (key and database) is backed up offline; the server is the only place the key is in use
- [ ] `GET {api}/keys` lists every key you ever used; a rotation waits 24 hours after the directory lists the next key
- [ ] `{api}/.well-known/pregen-registry.json` and your policy page answer over HTTPS
- [ ] Every public person has an anchor, with a proof URL once `check_channel_proof` prints `True` (until then anchored without one: nobody can generate them); every grant matches what the person agreed
- [ ] Providers got their credentials over a private channel; your sandbox is a separate registry
- [ ] `pregen-registry check --api … --directory …` ends `OK: all checks passed`, listing included

## The HTTP interface

| Method and path | What |
|---|---|
| `GET /.well-known/pregen-registry.json` | who this registry is |
| `GET /keys` | its signed operator key set: every key it ever signed with, current and retired |
| `GET /policy` | `policy.md` from the data folder, if you wrote one |
| `POST /v2/requests` | ask → `{"answer": <signed pg.answer.v1>}` |
| `POST /v2/reports` | report → `{"ack": <signed pg.report_ack.v1>}` |
| `POST /v2/keys`, `GET /v2/keys/{provider_id}` | provider key sets |
| `GET /v2/grants/{id}` | a signed grant (provider credential required in production; a sandbox answers without one) |
| `GET /v2/codes/{code}` | public lookup |
| `GET /v2/anchors` | anchored subjects, signed (extension `identity`) |
| `GET /v2/proofs/{16 hex}` | this registry's part of a proof |
| `POST /v2/sandbox/access` | sandbox credentials (sandbox mode only) |

Providers authenticate with `X-Provider-ID: <id>` and `Authorization: Bearer <token>` on
`POST /v2/requests`, `/v2/reports`, `/v2/keys` and `GET /v2/grants/…`; the rest of this table
is public. The server also answers endpoints of extensions this guide does not cover.
Errors are `{"error": "PG_…", "error_description": "…"}` with HTTP 401, 404, 409, 422 or 429.
