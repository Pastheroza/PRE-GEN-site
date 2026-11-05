#!/usr/bin/env python3
"""Generate spec/test-vectors/answers.json: the answer-check differential for conformance Level 1 (core rule 5).

Every case is one pg.request.v1 and one pg.answer.v1, checked against one test directory and its key sets at one
moment. An implementation passes a case when its check_answer accepts exactly the cases marked "ok": true and refuses
the others. Keys are derived as Ed25519 seed = SHA-256('pregen-answer-vector-<name>'), signatures are deterministic
(RFC 8032), so the file is reproducible byte for byte:

    python3 spec/tools/answer_vectors.py > spec/test-vectors/answers.json

Needs the `pregen` library (packages/verify-py) and `cryptography`.
"""
import copy
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "packages" / "verify-py"))
import pregen  # noqa: E402

NOW = 1_790_000_000
SMALL_ORDER = "0100000000000000000000000000000000000000000000000000000000000000"


def seed(name):
    return hashlib.sha256(f"pregen-answer-vector-{name}".encode()).hexdigest()


KEYS = {n: seed(n) for n in ("steward", "registry", "registry_revoked", "registry_retired", "other_registry")}
PUB = {n: pregen.public_key_hex(k) for n, k in KEYS.items()}
KID = {n: pregen.fingerprint(p) for n, p in PUB.items()}
KID["small_order"] = pregen.fingerprint(SMALL_ORDER)
API, OTHER = "https://registry.test.example", "https://other.test.example"


def directory():
    body = {"schema": pregen.SCHEMA, "sequence": 1, "steward_key_id": KID["steward"],
            "registries": [
                {"name": "Test registry", "prefix": "TEST", "api": API, "keys": API + "/keys",
                 "key_fingerprints": [KID["registry"], KID["registry_revoked"], KID["small_order"],
                                      KID["registry_retired"]]},
                {"name": "Other registry", "prefix": "NWRD", "api": OTHER, "keys": OTHER + "/keys",
                 "key_fingerprints": [KID["other_registry"]]}],
            "revoked_keys": [{"key_id": KID["registry_revoked"], "at": "2026-10-01T00:00:00Z"}]}
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sig = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(KEYS["steward"])).sign(pregen.canonical_json(body))
    return {**body, "signature": sig.hex()}


KEY_SETS = {
    API + "/keys": {"keys": [{"key_id": KID[n], "public_key_hex": p} for n, p in
                             (("registry", PUB["registry"]), ("registry_revoked", PUB["registry_revoked"]),
                              ("small_order", SMALL_ORDER))]
                    + [{"key_id": KID["registry_retired"], "public_key_hex": PUB["registry_retired"],
                        "activated_at": NOW - 86_400 * 30, "deactivated_at": NOW - 86_400, "status": "retired"}]},
    OTHER + "/keys": {"keys": [{"key_id": KID["other_registry"], "public_key_hex": PUB["other_registry"]}]},
}
REQUEST = {"type": "pg.request.v1", "signatures": [], "body": {
    "subject_ref": "PG-TEST-000001N", "provider_id": "frame-ai", "profile": "likeness/1",
    "use": {"purpose": "commercial"}, "job_id": "job-8841", "job_hash": "a" * 64}}


def answer(request=REQUEST, key="registry", sign=True, **change):
    body = {"signers": [{"role": "registry", "key_id": KID[key]}],
            "request_id": pregen.message_id("pg.request.v1", request["body"]), "profile": "likeness/1",
            "status": "allow", "basis": {"kind": "policy", "rule": "test"}, "issued_at": NOW - 10, "expires_at": NOW + 290}
    for k, v in change.items():
        if v is None:
            body.pop(k, None)
        else:
            body[k] = v
    if key == "small_order":                        # C1: the universal forgery under a small-order key
        return {"type": "pg.answer.v1", "body": body, "signatures": ["01" + "00" * 63]}
    return pregen.sign_envelope("pg.answer.v1", body, KEYS[key]) if sign else {"type": "pg.answer.v1", "body": body,
                                                                               "signatures": []}


def other_request(**change):
    r = copy.deepcopy(REQUEST)
    r["body"].update(change)
    return r


def cases():
    yield "allow", REQUEST, answer(), True, False
    yield "allow, sandbox answer, testing", REQUEST, answer(ext={"sandbox": True}), True, True
    yield "sandbox answer outside testing", REQUEST, answer(ext={"sandbox": True}), False, False
    yield "deny is not an allow", REQUEST, answer(status="deny", basis=None, reason="PG_NO_LICENSE"), False, False
    yield "not_blocked is not an allow", REQUEST, answer(status="not_blocked", basis=None, reason="PG_UNKNOWN_SUBJECT"), False, False
    yield "an allow for another request", other_request(job_id="job-0001"), answer(), False, False
    yield "an allow under another profile", REQUEST, answer(profile="work/1"), False, False
    yield "expired", REQUEST, answer(issued_at=NOW - 400, expires_at=NOW - 100), False, False
    yield "issued more than 60 s in the future", REQUEST, answer(issued_at=NOW + 61, expires_at=NOW + 300), False, False
    yield "lives longer than 900 s", REQUEST, answer(issued_at=NOW - 10, expires_at=NOW + 900), False, False
    yield "an allow with no basis", REQUEST, answer(basis=None), False, False
    yield "an allow with a reason", REQUEST, answer(reason="PG_NO_LICENSE"), False, False
    yield "a critical extension not understood", REQUEST, answer(critical=["x-unknown"]), False, False
    yield "a member the core does not define (a registry's own go in ext)", REQUEST, answer(note="x"), False, False
    yield "signed by another registry's key", REQUEST, answer(key="other_registry"), False, False
    yield "signed by a revoked key", REQUEST, answer(key="registry_revoked"), False, False
    yield "signed by a key retired before it was issued", REQUEST, answer(key="registry_retired"), False, False
    yield "a small-order key and a forged signature (C1)", REQUEST, answer(key="small_order"), False, False
    yield "no signature", REQUEST, answer(sign=False), False, False
    bad = answer()
    yield "a tampered body", REQUEST, {**bad, "body": {**bad["body"], "expires_at": NOW + 291}}, False, False
    yield "a lower-case code (H5)", other_request(subject_ref="pg-test-000001n"), answer(
        request=other_request(subject_ref="pg-test-000001n")), False, False
    yield "a code with a trailing space (H5)", other_request(subject_ref="PG-TEST-000001N "), answer(
        request=other_request(subject_ref="PG-TEST-000001N ")), False, False


def main():
    out = {"description": __doc__.split("\n\n")[0], "now": NOW, "steward_public_key_hex": PUB["steward"],
           "directory": directory(), "key_sets": KEY_SETS,
           "cases": [{"name": n, "request": r, "answer": a, "testing": t, "ok": ok} for n, r, a, ok, t in cases()]}
    json.dump(out, sys.stdout, indent=1, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
