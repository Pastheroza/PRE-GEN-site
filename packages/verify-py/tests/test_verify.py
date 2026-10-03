import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pregen import PregenError, canonical_json, fingerprint, verify_decision, verify_directory  # noqa: E402


class Key:
    def __init__(self):
        self.k = Ed25519PrivateKey.generate()
        self.pub = self.k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        self.id = fingerprint(self.pub)

    def sign(self, obj, field):
        body = {k: v for k, v in obj.items() if k != field}
        return {**obj, field: self.k.sign(canonical_json(body)).hex()}


steward, origin, other = Key(), Key(), Key()
KEY_SETS = {"https://origin.test/keys": {"keys": [{"key_id": origin.id, "public_key_hex": origin.pub}]},
            "https://other.test/keys": {"keys": [{"key_id": other.id, "public_key_hex": other.pub}]}}


def directory(sequence=2, registries=None):
    return steward.sign({"schema": "pregen.registries.v2", "sequence": sequence, "steward_key_id": steward.id,
                         "registries": registries or [
                             {"name": "Origin", "prefix": "", "api": "https://origin.test",
                              "keys": "https://origin.test/keys", "key_fingerprints": [origin.id]},
                             {"name": "Other", "prefix": "NWRD", "api": "https://other.test",
                              "keys": "https://other.test/keys", "key_fingerprints": [other.id]}]}, "signature")


def load(d, min_sequence=0):
    return verify_directory(d, steward.pub, min_sequence)


def test_directory_signed_by_pinned_steward_is_accepted():
    assert load(directory()).sequence == 2


def test_tampered_foreign_older_or_malformed_directory_is_refused():
    d = directory()
    with pytest.raises(PregenError):
        load({**d, "registries": d["registries"][:1]})
    with pytest.raises(PregenError, match="different steward"):
        verify_directory(d)  # the default pin is the real steward key
    with pytest.raises(PregenError, match="older"):
        load(d, 3)
    with pytest.raises(PregenError, match="HTTPS"):
        load(directory(registries=[{"name": "X", "prefix": "", "api": "http://x.test", "keys": "https://x.test/k",
                                    "key_fingerprints": [origin.id]}]))


def test_namespaces_are_symmetric():
    dir_ = load(directory())
    assert dir_.check_signer("PG-000042*", origin.id) == "valid"
    assert dir_.check_signer("PG-000042*", other.id) == "issuer_mismatch"
    assert dir_.check_signer("PG-NWRD-000042-K", other.id) == "valid"
    assert dir_.check_signer("PG-NWRD-000042-K", origin.id) == "issuer_mismatch"
    assert dir_.check_signer("PG-ABCD-000042-K", origin.id) == "unknown_issuer"


def test_decision_is_genuine_only_from_the_namespace_owner():
    dir_ = load(directory())
    get = KEY_SETS.__getitem__
    decision = origin.sign({"decision_id": "d1", "allowed": True, "license_id": "PG-RND-000042-ZZZZZZ1",
                            "operator_key_id": origin.id}, "operator_signature")
    assert verify_decision(decision, decision["license_id"], dir_, get) is True
    assert verify_decision({**decision, "allowed": False}, decision["license_id"], dir_, get) is False
    forged = other.sign({"decision_id": "d2", "allowed": True, "operator_key_id": other.id}, "operator_signature")
    with pytest.raises(PregenError, match="issuer_mismatch"):
        verify_decision(forged, "PG-000042*", dir_, get)
    swapped = {"https://origin.test/keys": {"keys": [{"key_id": origin.id, "public_key_hex": other.pub}]}}
    with pytest.raises(PregenError, match="no key"):
        verify_decision(decision, decision["license_id"], dir_, swapped.__getitem__)


def test_canonical_json_refuses_unportable_values():
    for bad in ({"x": 1.5}, {"x": 2**53}, {"x": "\ud800"}, {"x": object()}):
        with pytest.raises(PregenError):
            canonical_json(bad)

