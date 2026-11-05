"""sign_envelope reproduces every signed v5 message vector byte for byte; new keys sign what verifies."""
import hashlib
import json
from pathlib import Path

import pregen

VECTORS = json.loads((Path(__file__).resolve().parents[3] / "spec/test-vectors/messages.json").read_text())


def seed(name):
    return hashlib.sha256(f"pregen-vector-{name}".encode()).hexdigest()


def test_sign_envelope_reproduces_the_message_vectors():
    by_id = {pregen.public_key_hex(seed(n)): seed(n) for n in VECTORS["keys"]}
    keys = {k["key_id"]: k["public_key_hex"] for k in VECTORS["keys"].values()}
    for v in VECTORS["vectors"]:
        env = v["envelope"]
        signers = env["body"].get("signers") or []
        got = pregen.sign_envelope(env["type"], env["body"], *(by_id[keys[s["key_id"]]] for s in signers))
        assert got == env, v["name"]
        assert pregen.signing_input(env["type"], env["body"]).hex() == v["signing_input_hex"]
        assert pregen.message_id(env["type"], env["body"]) == v["message_id"]


def test_a_new_key_signs_what_verifies():
    k = pregen.new_private_key_hex()
    pub = pregen.public_key_hex(k)
    body = {"signers": [{"role": "provider", "key_id": pregen.fingerprint(pub)}], "x": 1}
    env = pregen.sign_envelope("pg.test.v1", body, k)
    assert pregen.verify_bytes(pub, env["signatures"][0], pregen.signing_input("pg.test.v1", body))
    assert pregen.sign_envelope("pg.request.v1", {"a": 1})["signatures"] == []
