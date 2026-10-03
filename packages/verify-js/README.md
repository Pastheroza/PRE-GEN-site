# @pregen/verify

Checks that a PRE-GEN decision or license was really signed by the registry
that owns its PG code, using the signed registry directory at
[pregen.org](https://www.pregen.org/registries.json). The PRE-GEN steward key
is built in; no dependencies (Web Crypto, Node 20+ or a modern browser).

```js
import { loadDirectory, verifyDecision } from "@pregen/verify";

const directory = await loadDirectory({ minSequence: savedSequence });
saveSequence(directory.sequence);              // refuse older copies next time

// decision: the JSON a registry returned from /v1/verify
// code: the PG code you asked about (the license id, or the subject code)
if (!(await verifyDecision(decision, code, { directory }))) throw new Error("not genuine");
```

The chain it checks:

1. the directory is signed by the PRE-GEN steward key
   (`pg-ed25519:dcdd244659e6d0e2426f2b504cb11590`) and is not older than one
   you have seen;
2. the code's namespace (bare `PG-…` or a four-letter prefix) belongs to one
   listed registry;
3. the decision's `operator_key_id` is one of that registry's listed keys, and
   the key its key set serves hashes to that fingerprint;
4. the Ed25519 signature over the canonical JSON verifies.

What it does **not** check, and you still must (`PRE-GEN-SPEC.md` §5.4):
that the decision answers your own request (V-4), has not expired (V-3),
carries a verified user binding when you named a user (V-13), and that
`disposition` is `allow` before you generate (P-5). A listing in the directory
proves which registry may issue a code, not that it holds any right over a
person or a work.

Also exported: `verifyDirectory`, `Directory.checkSigner` / `registryFor` /
`publicKey`, `verifyLicense` (subject signature plus operator countersignature),
`verifySigned`, `canonicalJson`, `fingerprint`, `issuerOf`.

Tests: `npm test` runs the unit tests and the PRE-GEN Level 1 conformance
vectors with every verifier operation required.

Apache-2.0. Part of the PRE-GEN standard,
[github.com/Pastheroza/PRE-GEN-site](https://github.com/Pastheroza/PRE-GEN-site).
