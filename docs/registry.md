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
3. **A provider needs no credential from you.** A provider is its domain and its key (extension
   `provider-identity`); your registry reads its key from its domain and vets it under your
   published procedure. If you also issue credentials, each is shown once: give it over a
   private channel.
4. **HTTPS only.** The directory lists only `https://` addresses, with no credentials,
   query or fragment.
5. **Quote codes.** An older code may end with a check character `*`, `~`, `$`, `=` or
   `!`. In a shell, put codes in single quotes (`'TOG-TEST-000006$'`); in a URL path, encode
   them (`$` is `%24`, `*` is `%2A`). Always copy codes, never retype them.

**Order on a first run:** steps 1–3, 5, 7–8, 9 for the sandbox, then 6, the step 3 backup, `key next` (step 4), 8, 9 for production,
then 10. The rest of step 4 only when you rotate. Run every command from the folder that holds `./data`
(`registry.pid`, `registry.log` and `./backup` are relative to it).

## 1. Install

```bash
pip install "pregen-registry>=0.4.0"
pregen-registry --help
```

`--help` lists the commands `init, serve, subject, grant, provider, connect, info, key,
check`. If you write your own registry instead, implement `PRE-GEN-CORE.md`, pass
conformance Level 1 with your signing library (step 8), and serve the same HTTP interface
(the table at the end); the rest of this guide still applies.

## 2. Choose your prefix and your address

**Your prefix** is four letters from `ABCDEFGHJKMNPQRSTVWXYZ` (no digits, no I, L, O, U).
It starts every code you issue (`TOG-ABCD-…`) and is never given to anyone else, so choose it
first. List the prefixes already taken, from the directory checked against the steward's
signature:

```bash
python3 -c "import pregen; print(sorted(r['prefix'] for r in pregen.load_directory().registries))"
```

**The public test directory** is `https://www.pregen.org/test/registries.json`, signed by the test
steward key `78c95e45a79c5e271fdec762b92c2ec1b27d6d08e512b7a94779de2429868ef0`; it lists sandboxes only. List its prefixes with this one line:

```bash
python3 -c "import pregen; print(sorted(r['prefix'] for r in pregen.load_directory('https://www.pregen.org/test/registries.json', steward_public_key_hex='78c95e45a79c5e271fdec762b92c2ec1b27d6d08e512b7a94779de2429868ef0').registries))"
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
  --complaints mailto:complaints@registry.example --open-providers
```

`--open-providers` lets any AI service known by its domain ask you with no account. It is a
listing condition (`PG-CODE.md` §9.1, item 5), so keep it.

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

**Lose `operator.key` and every copy of it,** and nothing can sign for your prefix until the
steward lists a new key. Keep `registry.db` (it holds your key history), run
`pregen-registry key next --dir ./data` and then `pregen-registry key rotate --dir ./data`:
the new key is current and the lost one stays in `/keys` as retired. Start the server, and
apply as a key update (step 4) with the new key id; write through the security advisory form
too, and the steward confirms it is you through the operator contact in your application.
Proofs your lost key signed keep verifying from the key sets providers saved (provider guide,
step 9).

## 4. Keys: one current key, with its whole history

`GET {api}/keys` is your signed key set: the current key, every key you ever signed with,
and your next key once you make one. Never edit it by hand. The steward reads your key ids
there, on your own domain: that is how it knows an application really comes from you.
Admission asks for a next key announced before you apply (`PG-CODE.md` §9.1, item 4): run
`key next` once after step 3 and back up `operator.next.key`. To rotate later:

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
file; openssl asks for a passphrase (or reads it with `-pass file:<a path outside the backup>`
when no one is at the keyboard): keep it in a password manager, never beside the `.enc` file. If you rotate before the directory lists the new key, providers refuse
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

Rate-limit requests per address at the proxy as well. The registry itself limits three things per
client address and hour, all in a sandbox: 10 sandbox credentials, 60 consent pages and 20 approved
consents (`bind`). Behind a proxy that does not pass the client's address, every client is one
address and shares those limits. Keep the machine's clock synced (NTP, the default on most servers): answers and
the 24-hour give-back window are timed by it, and `check` (step 8) shows how far off it is.

To serve HTTPS directly, for example on a test machine with your own certificate:

```bash
pregen-registry serve --dir ./data --host 127.0.0.1 --port 8443 \
  --ssl-certfile cert.pem --ssl-keyfile key.pem
```

Keep it running (a service manager, or `nohup … >> registry.log 2>&1 & echo $! > registry.pid`;
the sandbox likewise, as a second site (point `sandbox.registry.example`, DNS and certificate, at
your proxy and forward it to its port, not a path under the first), for example
`nohup pregen-registry serve --dir ./sandbox --host 127.0.0.1
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
your policy changes, the profile names stay), `extensions`, `policy`, `complaints`, `sandbox`, `providers` (`"open"`), `spec`. The second
returns `{"current_key_id": "pg-ed25519:…", "keys": [{"key_id", "public_key_hex",
"activated_at", "deactivated_at", "status", …}], "signature": "…"}`. The third returns your signed
anchor list (`{"type": "pg.anchors.v1", …}`), never a 404, through your proxy too: a provider
that cannot read it for a day stops generating your people (everyone who confirmed a claim at
your registry) until it reads it again.

## 6. People, anchors, grants and providers

Set up and try your sandbox first (steps 7–8); add only real people here.

Add a person you have verified:

```bash
pregen-registry subject add --dir ./data --name "Maya Cole" --level verified
```

It prints the person's code, for example `TOG-ABCD-418207365E`. Codes can be guessed (a 9-digit number
and a checksum), so `GET {api}/v2/codes/<code>` shows the person's
name and level only if you add `--publish`, which you do only when the person chose to be
public (`subject publish --code … [--off]` changes it later). Anchoring publishes the code,
its level and its anchor (so who the person is) at `/v2/anchors`, whatever `--publish` says:
anchor only a person who chose to be public. `--level` is how far you checked
them: `self`, `asserted`, `consented` or `verified`. Without `--level` the person is `self`, and
proof checkers label only `verified` by default (provider.md step 9): give `--level verified` once
you have checked identity and authority, or raise it later with `pregen-registry subject level
--dir ./data --code '<code>' --level verified`. `pregen-registry subject list --dir ./data`
prints every code you hold, with its level and name.

**Anchor a public person** (extension `identity`): a public person is anyone with a Wikidata item,
and every one needs an anchor; before adding one, look for their anchor in every listed
registry's `/v2/anchors` (provider.md step 5.1's loop; a 404 is fine only from a registry whose
document does not list `identity`) and use the same id. Record their
public identifier, written exactly as `wikidata:Q42`, `isni:0000000123456789` (16 characters,
no spaces) or `domain:example.com` (lower case); the command does not check the spelling, and
a different spelling is a different person to every client. **Use `wikidata:Q…` whenever the
person has one:** clients today confirm only `wikidata:` anchors, so a person anchored as
`isni:` or `domain:`, or without `--proof-url`, is refused by every provider (`not_blocked`,
`PG_IDENTITY_UNCONFIRMED`), grant or not, until confirmed. An anchor that cannot be confirmed
means nobody can generate that person.

Add the place where the person posted the line `PRE-GEN: TOG-ABCD-418207365E`. Only two places
count (`spec/extensions/identity.md`), on a channel that a **current** statement of their
Wikidata item lists (not deprecated, not ended):
- **their official website** (use it: social posts are mostly scripts a plain fetch cannot read):
  exactly `https://<host>/.well-known/pregen`, on the host Wikidata lists, in lower case (`www.`
  counts), as plain text with a line `PRE-GEN: <code>`;
- **their own X, Instagram, YouTube or TikTok account**: a post or the profile at or under the
  account's URL, which the platform itself records as written by that account.

Any other page on the site (a search page, a comment, another account's post) confirms
nothing. A handle must match Wikidata's spelling, case included; a URL over 512 characters,
with any `%` escape, an empty, `.` or `..` segment, a port, a `?` query or a `#` fragment, or
one that answers with a redirect, confirms nothing.
A channel newly added to Wikidata can refuse at once but permits only after it has stood for
7 days. The command records what you give it and fetches nothing, so check first. The check
below reads only the website place (`/.well-known/pregen`), where it must print `True`; for an
account it always prints `False`, because a page's text cannot say who wrote it. For an account,
`page` must return `{"author": …, "text": …}` from the platform's own API (as provider.md's
`account_post`), or check the post by other means. A place that cannot be read is unconfirmed for a provider that never saw it
confirmed, and blocks the person for one that did. The check (it follows no redirect):

```bash
CODE='TOG-ABCD-418207365E' URL='https://mayacole.example/.well-known/pregen' ANCHOR='wikidata:Q42' python3 -c "
import os, pregen, urllib.request as u
ua = {'User-Agent': 'Example Registry (https://registry.example/contact)'}
class Stay(u.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None
page = lambda x: u.build_opener(Stay).open(u.Request(x, headers=ua), timeout=10).read().decode('utf-8', 'replace')
print(pregen.check_channel_proof(os.environ['CODE'], os.environ['URL'], pregen.wikidata_official_urls(os.environ['ANCHOR']), page))"
```

If it prints `False`, the page answers 404, or it raises (page unreadable, Wikidata 403), anchor without `--proof-url` (the claim stays unconfirmed) and run
`subject anchor` again with both once it does. Re-check every proof page at least daily; once
the line is gone, anchor again without `--proof-url`.

```bash
pregen-registry subject anchor --dir ./data --code 'TOG-ABCD-418207365E' \
  --anchor wikidata:Q42 --proof-url https://mayacole.example/.well-known/pregen
```

```
TOG-ABCD-418207365E anchored to wikidata:Q42; GET /v2/anchors lists it
```

When several registries claim the same person, a client counts only a record whose anchor
the person confirmed on their own channel (the libraries' `decide_identity`). A matching
name is never evidence. A complaint about one of your codes follows the procedure in
`spec/extensions/identity.md` ("Complaints"): decide within 7 days. While you examine it, the
code is `disputed` and refused with `PG_SUBJECT_DISPUTED` at your registry only; it does not
refuse the person anywhere else.

**Grant a use** the person agreed to. It prints the grant id (64 hex):

```bash
pregen-registry grant add --dir ./data --subject 'TOG-ABCD-418207365E' --any-provider \
  --purposes commercial,editorial --days 30 --max-uses 10
```

- `--purposes` lists the `use.purpose` values it covers (`personal`, `educational`,
  `research`, `editorial`, `commercial`). A request for any other purpose is answered
  `deny`, `PG_SCOPE_VIOLATION`.
- `--any-provider` makes the grant cover any provider that asks for this person; `grant add`
  refuses to run with neither it nor `--licensee`, so the broadest grant is always asked for. With
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

**Providers known by their domain** (extension `provider-identity`,
`https://www.pregen.org/spec/extensions/provider-identity.md`) need nothing from you. A registry
created with `--open-providers` (a sandbox always is) says `"providers": "open"` in its document
and answers any provider whose `provider_id` is `https://<its domain>`: it reads
`https://<that domain>/.well-known/pregen-party.json` the first time the provider asks, pins the
key chain in it, checks the signature on every request and report against that chain, and reads
the document again at least daily. A later document that does not extend the pinned chain is
refused, so whoever takes over a domain does not get its keys. Until you vet a provider, it
learns only about your published subjects (their refusals included) and what its own connected
customers hold; everything else, a refusal of a private subject included, is `deny
PG_PROVIDER_NOT_ACCEPTED`. This registry does not check
that a `provider_id` is a registrable domain (Public Suffix List): it takes
`https://app.frame.example` as a provider of its own, so every subdomain gets its own budget and
its own document reads (P-7). A production registry should check it, with the Public Suffix List,
or a wildcard of subdomains gets around P-7. Vetting is your own
published procedure; once done:

```bash
pregen-registry provider accept --dir ./data --id https://frame.example
```

`connect` works for such a provider too: `--provider https://frame.example --licensee
'https://frame.example:user-1'`. Registries listed in the directory are always open (step 3);
you may also issue your own credentials to providers that prefer them:

**Give a provider its credential.** It is printed once:

```bash
umask 077; pregen-registry provider add --dir ./data --id frame-ai > frame-ai.credential
```

A provider id is letters, digits and `-`, never `:` (it separates provider and customer in a
licensee id). The file `frame-ai.credential` then holds (shown once):

```
provider_id: frame-ai
token: <secret>
Shown once. Give it to the provider over a private channel.
```

Keep that file readable only by you until you hand it over, and delete it once it is sent.

`pregen-registry connect --dir ./data --provider frame-ai --licensee frame-ai:user-1` lets that
provider ask on behalf of its end customer `user-1`; it prints `connected`. Run `provider add`
first: `connect` does not check that the provider exists, so a typo connects nobody. **A licensee id names one customer of
one provider, so always write it as `<provider id>:<the customer's id at that provider>`.**
`connect` refuses any other shape: a grant to a licensee covers every provider connected to
that id, so two providers' `user-1` written bare would share each other's grants. The grant
may come before or after `connect`. Tell the
provider the exact licensee id (step 10) and the codes that customer's licence covers; it sends
the id as `licensee_id` only for those codes, and rests on its own grant for the others.

**When things change**, each takes effect from the next answer; answers already given stay
what they were:

```bash
pregen-registry subject opt-out --dir ./data --code 'TOG-ABCD-418207365E'   # the person opted out or withdrew
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
policy, that holds the standard test subjects and answers any provider known by its domain,
or hands out a credential, without an account. Use the same flags as in step 3, plus
`--sandbox` (its `./sandbox/policy.md` template already says it holds no real people):

```bash
pregen-registry init --dir ./sandbox --prefix ABCE --name "Example Registry sandbox" \
  --api https://sandbox.registry.example --policy https://sandbox.registry.example/policy \
  --complaints mailto:complaints@registry.example --sandbox
```

After the key and policy lines it prints the standard test codes:

```
Sandbox test subjects (copy them; the last character is a check character):
  TOG-ABCE-000001…  Test subject 1 (allow)
  …
  TOG-ABCE-000007…  Test subject 7 (not blocked)
  TOG-ABCE-000009…  Test subject 9 (buy first)
  TOG-ABCE-000010…  Test subject 10 (the person's terms)
  TOG-ABCE-000011…  Test subject 11 (a minor)
  TOG-ABCE-000012…  Test subject 12 (a creator's licence, through bind)
  TOG-ABCE-000008…  Test subject 8 (not registered: PG_UNKNOWN_SUBJECT)
```

Save this output: code 8 is never stored, so `subject list` shows only 1–7, 9–12 and your own.
What each code tests, buying a use of code 9 included: `docs/provider.md`, step 9.

Serve it (step 5). A provider introduces itself by posting its party document (a laptop has
no domain to serve it on), then asks with signed requests, exactly as it will in production:

```bash
curl -s -X POST https://sandbox.registry.example/v2/sandbox/party -H 'Content-Type: application/json' \
  --data @pregen-party.json          # → {"party_id": "https://…", "note": "…"}
```

A sandbox accepts any `https://…` id, with a port too, and masks nothing; on `localhost` only an id bound to
the key, `https://<32 hex of the key id>.localhost[:port]` (`pregen.sandbox_provider_url`). The
credential path works too: `curl -s -X POST https://sandbox.registry.example/v2/sandbox/access`
returns `{"provider_id": "sbx-…", "token": "…", "registry": "…", "note": "…"}`. Every
sandbox answer carries `ext: {"sandbox": true}`, and clients refuse it unless they are
testing. Replace each `<…>` in `./sandbox/policy.md`, as in step 3. Like production, the
sandbox accepts a licensee only after `connect` (or, for a provider known by its domain, a `bind`
binding); otherwise the provider gets 401 (403 `PG_NOT_BOUND` for a provider known by its domain). So a
registered sandbox credential tests a licensee grant only in a sandbox you run, after `connect`; on
anyone else's sandbox only a provider known by its domain can, through `bind`. A
licensee-only grant still needs `licensee_id` in the request (without it: `deny PG_NO_LICENSE`
in the sandbox, where `test:t1` names no sandbox provider; in production, `deny PG_NOT_CONNECTED`).
Apply for the sandbox's prefix too (step 9, status `sandbox`): a sandbox is listed only in a
**test directory**, never in the real one (step 2). The directory entry looks like any
other; the document's `sandbox` member is only `true` or `false`, and nothing links your
registry to your sandbox: give providers the sandbox `api` yourself (step 10).

## 8. Check yourself before you apply

From any machine, as a provider would see you:

```bash
pregen-registry check --api https://registry.example
```

```
PASS the registry's clock is 0 s behind this one
PASS registry document: prefix ABCD, profiles ['likeness/1']
PASS document api is 'https://registry.example'
PASS answers under likeness/1
PASS declares reports, provider-keys
PASS answers AI services known by their domain, no account (providers: open; a listing condition, PG-CODE.md §9.1 item 5)
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

The extra line reads `PASS POST /v2/requests for TOG-ABCE-000001…, purpose commercial: HTTP
200, allow`; with test code 2 it reads `… deny PG_NO_LICENSE`. To try a grant of your own
(purposes, a licensee), add a test person and that grant to the sandbox (`subject add
--dir ./sandbox --level verified --publish --name "Test subject 12 (allow, licensee test:t1, commercial)"`, named by what it
answers, which numbers added people from 13 on, and `grant add --dir ./sandbox …`)
and ask for it the same way (give sandbox test grants no `--max-uses`: every provider shares
them, and each allow, a `check` included, uses one for good); for a licensee-only grant, give
it `--licensee test:t1` and add `--licensee test:t1` to `check`. If you added your own test
people, also change the template's sentence in `./sandbox/policy.md`, "it holds no real people,
only the standard test subjects (codes 1-7 and 9-12; code 8 is deliberately unregistered)", for
example to "It holds no real people: the standard test subjects (codes 1-7 and 9-12) and test
people of our own (codes 13 and up)."

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
   answers, the profiles you answer under (`likeness/1`), and that the document says
   `"providers": "open"` and lists `provider-identity` (open access, `PG-CODE.md` §9.1 item 5);
5. **Keys** (the application's `keys` field is the key set URL; this item is the list of
   key ids): the key id (fingerprint) of every operator key: current, retired, and your
   announced next key (`pregen-registry key next`). The steward lists only key ids it finds in your live `{api}/keys`,
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

For a test directory, add `--steward <its steward public key hex>`. A provider known by its
domain needs nothing more from you than the listing: it finds your `api` in the directory and
asks. Publish for providers: how you vet them (step 6), your sandbox `api`, the sandbox's standard
test codes (1 to 11) (and any test people you added, with what each is for), and the test directory's URL
and steward key. If you issue credentials, send each provider its credential privately, in the
shape it stores (`{"ABCD": {"provider_id": "frame-ai", "token": "<secret>"}}`), with the codes
it may ask about and the exact licensee id of each customer you connected for it.
A listing can be revoked on the grounds in `PG-CODE.md` §9.1; the steward asks you to answer
first unless there is ongoing harm, and announces every revocation with its reason. A prefix is
never given to anyone else.

## Selling: your optional commerce

Everything above is the mandatory layer, the same for every registry, free, with no account for
providers. Selling licences (to people or to providers) is your own,
optional business: your prices, checkout and contract, on your own site. PRE-GEN names no
checkout, and a registry that sells nothing is complete. If you sell, publish a
commerce page and link it from your policy, and say there whether a provider known only by its
domain may buy. A person who bought a licence connects it to an app through extension `bind`
(`https://www.pregen.org/spec/extensions/bind.md`), which the reference registry does not
implement yet. Two layers, one picture: `https://www.pregen.org/docs/two-layers`.

## You are done when

- [ ] The `./data` folder (key and database) is backed up offline; the server is the only place the key is in use
- [ ] `GET {api}/keys` lists every key you ever used; a rotation waits 24 hours after the directory lists the next key
- [ ] `{api}/.well-known/pregen-registry.json` and your policy page answer over HTTPS
- [ ] Every public person has an anchor, with a proof URL once `check_channel_proof` prints `True` (until then anchored without one: nobody can generate them); every grant matches what the person agreed
- [ ] Providers known by their domain are answered (`"providers": "open"`, a listing condition); any credential you also issue went over a private channel; your sandbox is a separate registry
- [ ] `pregen-registry check --api … --directory …` ends `OK: all checks passed`, listing included

## The HTTP interface

| Method and path | What |
|---|---|
| `GET /.well-known/pregen-registry.json` | who this registry is |
| `GET /keys` | its signed operator key set: every key it ever signed with, current and retired |
| `GET /policy` | `policy.md` from the data folder, if you wrote one |
| `POST /v2/requests` | ask → `{"answer": <signed pg.answer.v1>}` |
| `POST /v2/reports` | report → `{"ack": <signed pg.report_ack.v1>}` |
| `POST /v2/keys`, `GET /v2/keys/{provider_id}` | provider key sets (a provider known by its domain publishes them in its party document instead) |
| `GET /v2/grants/{id}` | a signed grant (`PG-Access` or a credential in production; a sandbox answers without either) |
| `GET /v2/codes/{code}` | public lookup |
| `GET /v2/anchors` | anchored subjects, signed (extension `identity`) |
| `GET /v2/proofs/{16 hex}` | this registry's part of a proof |
| `POST /v2/sandbox/access` | sandbox credentials (sandbox mode only) |
| `POST /v2/sandbox/party` | a provider's party document by post (sandbox mode only) |

A provider known by its domain authenticates by its signature: `X-Provider-ID: https://<domain>`,
no `Authorization`, `signers` and one signature on `POST /v2/requests` and `/v2/reports`, and the
`PG-Access` header on `GET /v2/grants/…` (extension `provider-identity`). A registered provider
authenticates with `X-Provider-ID: <id>` and `Authorization: Bearer <token>` on `POST /v2/requests`,
`/v2/reports`, `/v2/keys` and `GET /v2/grants/…`. The rest of this table is public. The server also answers endpoints of extensions this guide does not cover.
Protocol errors are `{"error": "PG_…", "error_description": "…"}` with HTTP 401, 404, 409, 422 or 429;
a body that is not JSON, or an unknown path, gets the framework's `{"detail": …}` (422 or 404).
