# pregen

Checks that a PRE-GEN decision or license was really signed by the registry
that owns its PG code, using the signed registry directory at
[pregen.org](https://www.pregen.org/registries.json). The PRE-GEN steward key
is built in. Same API as the npm package `@pregen/verify`.

```python
import pregen

directory = pregen.load_directory(min_sequence=saved_sequence)
save_sequence(directory.sequence)              # refuse older copies next time

# decision: the JSON a registry returned from /v1/verify
# code: the PG code you asked about (the license id, or the subject code)
if not pregen.verify_decision(decision, code, directory):
    raise RuntimeError("not genuine")
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

Also: `verify_directory`, `Directory.check_signer` / `registry_for` /
`public_key`, `verify_license` (subject signature plus operator
countersignature), `verify_signed`, `canonical_json`, `fingerprint`, `issuer_of`.

Tests: `pytest packages/verify-py/tests`, and the PRE-GEN Level 1 vectors with
`python3 spec/conformance/level1/run_conformance.py --adapter "python3 packages/verify-py/tests/conformance_adapter.py"`.

Apache-2.0. Part of the PRE-GEN standard,
[github.com/Pastheroza/PRE-GEN-site](https://github.com/Pastheroza/PRE-GEN-site).
