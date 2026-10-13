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

**2. Published policy** (`PRE-GEN-SPEC.md` E-5) — URL:
- How you verify that a rights holder is who they claim and may license the subject:
- Anchor you record for every public person (Wikidata, ISNI or a domain):
- Your own floors and refusal codes, answer lifetime, opt-out waiting period:

**3. The core.** I accept the core, its floor of protections, the rule for a subject held by several registries (`PRE-GEN-SPEC.md` R-15, P-10) and the revocation grounds of `PG-CODE.md` §9.1. yes / no

**4. Endpoints** (HTTPS, no credentials, query or fragment)
- `api`:
- `keys` (key set URL):
- `{api}/.well-known/pregen-registry.json` returns your `prefix`, `profiles`, `extensions`, `policy`, `complaints`: yes / no
- Profiles you answer under (e.g. `likeness/1`):

**5. Keys.** Fingerprints (`pg-ed25519:…`) of every operator key — current, retired and the next one announced. **Do not paste them only here:** send the same list to the steward by a second channel (email from the operator's domain, or a signed message), so a stolen GitHub account cannot list someone else's key.

**6. Conformance.** Paste the summary line of the conformance runner against your registry (`spec/conformance/`):

```
```

**Status:** sandbox / production
