# @pregen/verify

Checks that a PRE-GEN decision or license was really signed by the registry
that owns its PG code, using the signed registry directory at
[pregen.org](https://www.pregen.org/registries.json). The PRE-GEN steward key
is built in; no dependencies (Web Crypto, Node 20+ or a modern browser).

```js
import { loadDirectory, checkDecision } from "@pregen/verify";

// Keep the last accepted directory (any storage) and pass it back each time.
const directory = await loadDirectory({ previous: saved });
saved = directory.toJSON();

// request: what you sent to /v1/verify, plus provider_id and licensee_id
await checkDecision(decision, request, { directory });   // throws with the reason, or you may generate
```

`checkDecision` checks everything a provider must check before generating
(`PRE-GEN-SPEC.md` §5.4):

1. the decision is a license-backed `allow` (P-5);
2. every echoed member equals what you sent, empty ones included, and
   intended-use members you did not send are empty (V-4);
3. `expires_at` is a positive integer, later than `issued_at`, not yet passed (V-3);
4. if you named a user, the binding is `verified` with a link id (V-13);
5. the signature chain: the directory is signed by the PRE-GEN steward key
   (`pg-ed25519:dcdd244659e6d0e2426f2b504cb11590`), the license's namespace
   belongs to one listed registry, the decision's key is one of that
   registry's keys and hashes to its fingerprint, and the signature verifies;
6. neither that registry nor that key is revoked in the directory (V-14);
7. the decision lists no `critical` member the library does not understand (E-3).

Pass `requireVerifiedAuthority: true` to also refuse a subject whose rights holder the
registry has not verified (`subject_authority` other than `verified`).

The directory check also refuses an older directory, a newer one that removes
a registry or key or undoes a revocation, and a different one with the same sequence. The origin
registry's keys are pinned in the library as well, so a stolen steward key
cannot add its own key to bare `PG-…` codes; a new origin key comes with a
new release. A successor steward key
(`pg-ed25519:3e5e20729ce8485eea274c4cb33721d6`) is pinned too: a directory it
signs replaces those of the current steward key whatever their sequence, so a
thief holding the old key cannot outbid it.

A listing in the directory proves which registry may issue a code, not that
it holds any right over a person or a work. A signed decision proves what the
registry answered, not that the output was lawful.

## Test without a secret: the simulator

```js
import { createSimulator, checkDecision } from "@pregen/verify";
const sim = await createSimulator();           // offline registry, throwaway keys
globalThis.fetch = sim.fetch;                   // or pass sim.fetch to your HTTP client
// …your normal code: POST sim.baseUrl + "/v1/verify/", then:
await checkDecision(decision, request, { directory: sim.directory, fetch: sim.fetch });
```

`sbx-allowed` → `allow`; `sbx-revoked`, `sbx-expired` → `PG_NO_LICENSE`;
`sbx-exhausted` → `PG_USAGE_LIMIT`; `sbx-optedout` → `PG_SUBJECT_OPTED_OUT`;
anything else → `PG_NO_SUBJECT`. Receipts: one per decision, a second is refused.
With `@prampta/sdk` 0.7.0 pass `baseUrl: sim.baseUrl`, `operatorPublicKeyHex:
sim.operatorPublicKeyHex` and `pregenDirectory: sim.directory`. The simulator's
keys are new on every run and its directory is signed by a throwaway steward,
so nothing it signs is ever accepted by the real directory.

Also exported: `verifyDecision` (signatures only), `verifyDirectory`,
`Directory.checkSigner` / `registryFor` / `publicKey`, `verifyLicense` (subject
signature plus operator countersignature), `verifySigned`, `canonicalJson`,
`fingerprint`, `issuerOf`.

Tests: `npm test` runs the unit tests and the PRE-GEN Level 1 conformance
vectors with every verifier operation required.

Apache-2.0. Part of the PRE-GEN standard,
[github.com/Pastheroza/PRE-GEN-site](https://github.com/Pastheroza/PRE-GEN-site).
