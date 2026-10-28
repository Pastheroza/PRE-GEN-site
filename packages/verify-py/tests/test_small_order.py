"""Stress test C1: a key no one can be held to is refused, and nothing verifies under it
(spec/test-vectors/small-order-keys.json)."""
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import pregen

V = json.loads((Path(__file__).resolve().parents[3] / "spec" / "test-vectors" / "small-order-keys.json").read_text())
MESSAGE = bytes.fromhex(V["message_hex"])


@pytest.mark.parametrize("key", [r["public_key_hex"] for r in V["refuse"]])
def test_a_key_no_one_can_be_held_to_is_refused_and_verifies_nothing(key):
    with pytest.raises(pregen.PregenError):
        pregen.check_public_key(key)
    for forged in ("01" + "00" * 63, key + "00" * 32):
        assert not pregen.verify_bytes(key, forged, MESSAGE)


def test_an_ordinary_key_still_verifies():
    k = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    pub = k.public_key().public_bytes_raw().hex()
    assert pregen.check_public_key(pub) == bytes.fromhex(pub)
    assert pregen.verify_bytes(pub, k.sign(MESSAGE).hex(), MESSAGE)
