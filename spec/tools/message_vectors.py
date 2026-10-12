"""Generate spec/test-vectors/messages.json: canonical bytes, signing input, message id and
signatures for every message type of PRE-GEN-CORE.md and its extensions, made with fixed keys.

Run from the repository root:  python3 spec/tools/message_vectors.py
Needs: pip install cryptography pregen
"""
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pregen import canonical_json, fingerprint


def key(seed: str):
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())
    pub = sk.public_key().public_bytes_raw().hex()
    return sk, pub, fingerprint(pub)


def signing_input(t, body):
    return b"PREGEN-V5\x00" + t.encode() + b"\x00" + canonical_json(body)


def message_id(t, body):
    return hashlib.sha256(b"PREGEN-V5-ID\x00" + t.encode() + b"\x00" + canonical_json(body)).hexdigest()


KEYS = {name: key(f"pregen-vector-{name}") for name in ("registry", "provider", "provider_next", "rights_holder")}


def sealed(t, body, roles):
    body = {**body, "signers": [{"role": r, "key_id": KEYS[k][2]} for r, k in roles]} if roles else body
    data = signing_input(t, body)
    env = {"type": t, "body": body, "signatures": [KEYS[k][0].sign(data).hex() for _, k in roles]}
    return {"name": t, "envelope": env, "canonical_body_utf8": canonical_json(body).decode(),
            "signing_input_hex": data.hex(), "message_id": message_id(t, body)}


def build():
    req = {"subject_ref": "PG-TEST-000001N", "provider_id": "frame-ai", "profile": "likeness/1",
           "use": {"purpose": "commercial"}, "job_id": "job-8841", "job_hash": "a" * 64}
    v_req = sealed("pg.request.v1", req, [])
    grant = sealed("pg.grant.v1", {"subject_ref": req["subject_ref"], "licensee_id": "", "profile": "likeness/1",
                                   "use": {"purposes": ["commercial"]}, "not_before": 1791800000,
                                   "expires_at": 1823336000, "max_uses": 10},
                   [("rights_holder", "rights_holder"), ("registry", "registry")])
    answer = sealed("pg.answer.v1", {"request_id": v_req["message_id"], "profile": "likeness/1", "status": "allow",
                                     "basis": {"kind": "grant", "grant": {"format": "pg.grant.v1", "id": grant["message_id"]}},
                                     "level": "verified", "obligations": [], "issued_at": 1791800000,
                                     "expires_at": 1791800300}, [("registry", "registry")])
    deny = sealed("pg.answer.v1", {"request_id": v_req["message_id"], "profile": "likeness/1", "status": "deny",
                                   "reason": "PG_NO_LICENSE", "level": "verified", "obligations": [],
                                   "issued_at": 1791800000, "expires_at": 1791800300}, [("registry", "registry")])
    keyset = sealed("pg.keyset.v1", {"kind": "first", "provider_id": "frame-ai", "previous": None, "recovery_registry": "",
                                     "keys": [{"key_id": KEYS["provider"][2], "public_key_hex": KEYS["provider"][1],
                                               "status": "current"}]}, [("provider", "provider")])
    rotation = sealed("pg.keyset.v1", {"kind": "rotation", "provider_id": "frame-ai", "previous": keyset["message_id"],
                                       "recovery_registry": "",
                                       "keys": [{"key_id": KEYS["provider_next"][2], "public_key_hex": KEYS["provider_next"][1],
                                                 "status": "current"},
                                                {"key_id": KEYS["provider"][2], "public_key_hex": KEYS["provider"][1],
                                                 "status": "previous"}]},
                      [("provider", "provider_next"), ("provider_previous", "provider")])
    report = sealed("pg.report.v1", {"request_id": v_req["message_id"], "answer": answer["message_id"],
                                     "job_id": "job-8841", "outcome": "generated", "output_hash": "e" * 64,
                                     "occurred_at": 1791800100}, [("provider", "provider")])
    ack = sealed("pg.report_ack.v1", {"report": report["message_id"], "answer": answer["message_id"],
                                      "answer_status": "allow", "counted": answer["message_id"], "released": [],
                                      "provider_key_id": KEYS["provider"][2], "received_at": 1791800101},
                 [("registry", "registry")])
    for v, n in ((answer, "pg.answer.v1 (allow)"), (deny, "pg.answer.v1 (deny)"), (keyset, "pg.keyset.v1 (first)"),
                 (rotation, "pg.keyset.v1 (rotation)")):
        v["name"] = n
    return {
        "description": "PRE-GEN v5 message vectors (PRE-GEN-CORE.md, extensions/*.md). Keys are derived as "
                       "Ed25519 seed = SHA-256('pregen-vector-<name>'). Signatures are deterministic (RFC 8032).",
        "keys": {n: {"public_key_hex": k[1], "key_id": k[2]} for n, k in KEYS.items()},
        "vectors": [v_req, grant, answer, deny, keyset, rotation, report, ack],
    }


if __name__ == "__main__":
    out = Path(__file__).resolve().parents[1] / "test-vectors" / "messages.json"
    out.write_text(json.dumps(build(), indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out}")
