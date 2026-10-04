# pregen

Checks that a PRE-GEN decision or license was really signed by the registry
that owns its PG code, using the signed registry directory at
[pregen.org](https://www.pregen.org/registries.json). The PRE-GEN steward key
is built in. Same API as the npm package `@pregen/verify`.

```python
import pregen

# Keep the last accepted directory (any storage) and pass it back each time.
directory = pregen.load_directory(previous=saved)
saved = directory.to_json()

# request: what you sent to /v1/verify, plus provider_id and licensee_id
pregen.check_decision(decision, request, directory)   # raises with the reason, or you may generate
```

`check_decision` checks everything a provider must check before generating
(`PRE-GEN-SPEC.md` §5.4):

1. the decision is a license-backed `allow` (P-5);
2. every echoed member equals what you sent, empty ones included, and
   intended-use members you did not send are empty (V-4);
3. `expires_at` is a positive integer, later than `issued_at`, not yet passed (V-3);
4. if you named a user, the binding is `verified` with a link id (V-13);
5. the signature chain: the directory is signed by the PRE-GEN steward key
   (`pg-ed25519:dcdd244659e6d0e2426f2b504cb11590`), the license's namespace
   belongs to one listed registry, the decision's key is one of that
   registry's keys and hashes to its fingerprint, and the signature verifies.

The directory check also refuses an older directory, a newer one that removes
a registry or key, and a different one with the same sequence. The origin
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

```python
sim = pregen.Simulator()                        # offline registry, throwaway keys
decision = sim.verify(request, provider_id="acme", licensee_id="lic-1")
pregen.check_decision(decision, {**request, "provider_id": "acme", "licensee_id": "lic-1"},
                      sim.directory, sim.get_json)
sim.receipt(decision["decision_id"])            # one per decision; a second raises
```

Same sandbox answers as the npm package. Nothing it signs is ever accepted by the
real directory.

Also: `verify_decision` (signatures only), `verify_directory`,
`Directory.check_signer` / `registry_for` / `public_key`, `verify_license`
(subject signature plus operator countersignature), `verify_signed`,
`canonical_json`, `fingerprint`, `issuer_of`.

Tests: `pytest packages/verify-py/tests`, and the PRE-GEN Level 1 vectors with
`python3 spec/conformance/level1/run_conformance.py --adapter "python3 packages/verify-py/tests/conformance_adapter.py"`.

Apache-2.0. Part of the PRE-GEN standard,
[github.com/Pastheroza/PRE-GEN-site](https://github.com/Pastheroza/PRE-GEN-site).
