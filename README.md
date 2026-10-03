# PRE-GEN

The PRE-GEN standard and its website, [pregen.org](https://www.pregen.org):
static HTML/CSS/JS, no build step. The standard is in [`spec/`](spec/)
(Apache-2.0, `spec/LICENSE`); the website itself is not (`NOTICE`).

## Steward key

The registry directory [`registries.json`](registries.json) is signed by the
PRE-GEN steward key (`spec/PG-CODE.md` §9.1). Verify it with these values,
never with a key taken from the directory or from the connection that served it:

- public key: `5cb949aab04186e3e216ec541b847c912fc3f78138c0ec3cb2560b2dad0d1f1b`
- fingerprint: `pg-ed25519:dcdd244659e6d0e2426f2b504cb11590`

Successor steward key (kept apart, unused until the steward key is lost or
stolen; a directory it signs replaces the current line):

- public key: `658544163d6abd5fef046407980d249817875d87d8cf4b67879a2e265fa5612f`
- fingerprint: `pg-ed25519:3e5e20729ce8485eea274c4cb33721d6`

The same values are in `spec/PG-CODE.md` §9.1, in the PRE-GEN v5 paper (§11)
and in the DNS TXT record `_pregen-steward.pregen.org`.

```sh
python3 spec/tools/steward.py verify registries.json
```

Deploy: Vercel (production branch `main`).
