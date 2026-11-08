# PRE-GEN

The PRE-GEN standard and its website, [pregen.org](https://www.pregen.org):
static HTML/CSS/JS, no build step. The standard is in [`spec/`](spec/)
(Apache-2.0, `spec/LICENSE`); the website itself is not (`NOTICE`).
Start with the one-page core: [`spec/PRE-GEN-CORE.md`](spec/PRE-GEN-CORE.md).

PRE-GEN is an open standard by Valerii Egorov for asking permission before AI
generates a real person, a character or a brand. An AI service asks the registry
that represents them, checks the signed answer, and generates only on a yes.
It needs no account at any registry: its identity is its domain and a key.

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

Both keys are in `spec/PG-CODE.md` §9.1 and the PRE-GEN v5 paper (§5); the current
steward key is also in the DNS TXT record `_pregen-steward.pregen.org`.

```sh
python3 spec/tools/steward.py verify registries.json
```

## Libraries and reference registry (Apache-2.0)

- Python: `pip install pregen` ([`packages/verify-py`](packages/verify-py)), https://pypi.org/project/pregen/
- JavaScript: `npm install @pregen/verify` ([`packages/verify-js`](packages/verify-js)), https://www.npmjs.com/package/@pregen/verify
- Reference registry: `pip install pregen-registry` ([`packages/registry`](packages/registry)), https://pypi.org/project/pregen-registry/
- Guides: [`docs/provider.md`](docs/provider.md) (AI services, no account needed), [`docs/registry.md`](docs/registry.md) (running a registry)
- Test network: test directory https://www.pregen.org/test/registries.json, sandbox registry https://sandbox.pregen.org

Deploy: Vercel (production branch `main`).
