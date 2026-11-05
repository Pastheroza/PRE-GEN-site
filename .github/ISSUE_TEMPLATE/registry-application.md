---
name: Registry application
about: Ask for a four-letter prefix and a listing in the signed registry directory (PG-CODE.md §9.1)
title: "Registry application: <PREFIX> — <operator name>"
labels: registry-application
---

**Prefix asked for** (four letters from `ABCDEFGHJKMNPQRSTVWXYZ`; a second choice in case it is taken):

**1. Operator**
- Legal name (company or person):
- Public address:
- Contact for complaints and disputes (a URL or an address, answered within 7 days):
- Website:

**2. Published policy** — URL (the details live on that page: how you verify rights holders, the anchor you record for public people, your own refusals, answer lifetime, opt-out timing):

**3. The core.** I accept the core, its floor of protections, the rule for a subject held by several registries (`PRE-GEN-SPEC.md` R-15, P-10) and the revocation grounds of `PG-CODE.md` §9.1. yes / no

**4. Endpoints** (HTTPS, no credentials, query or fragment)
- `api`:
- `keys` (key set URL):
- `{api}/.well-known/pregen-registry.json` returns your `prefix`, `profiles`, `extensions`, `policy`, `complaints`: yes / no
- Profiles you answer under (e.g. `likeness/1`):

**5. Keys.** Fingerprints (`pg-ed25519:…`) of every operator key — current, retired and the next one (`pregen-registry key next` lists it in `/keys` as `next`). The steward lists only fingerprints it finds in your live `{api}/keys`, on your own domain, so a stolen GitHub account cannot list someone else's key. A stolen operator key is reported privately, never here: https://github.com/Pastheroza/PRE-GEN-site/security/advisories/new

**6. Conformance.** Paste the output of `pregen-registry check --api <your api>` (it must end `OK: all checks passed`). If you wrote your own registry, also paste the summary line of conformance Level 1 against your signing library (`spec/conformance/`):

```
```

**Status:** sandbox / production
