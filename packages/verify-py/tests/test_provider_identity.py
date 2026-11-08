"""extensions/provider-identity.md: a provider known by its domain."""
import base64
import json

import pytest

import pregen


def test_a_provider_url_is_the_apps_domain_and_nothing_else():
    assert pregen.check_provider_url("https://frame.example") == "https://frame.example"
    assert pregen.check_provider_url("https://alice.github.io") == "https://alice.github.io"
    for bad in ["http://frame.example", "https://frame.example/", "https://Frame.example", "https://frame.example:8443",
                "https://www.frame.example?x=1", "https://frame.example#a", "https://a@frame.example",
                "https://frame.example.", "https://localhost", "https://frame", "frame.example", 42, "https://xn--"]:
        with pytest.raises(pregen.PregenError):
            pregen.check_provider_url(bad)
    assert pregen.check_provider_url("https://0123456789abcdef0123456789abcdef.localhost:8443", allow_port=True) == "https://0123456789abcdef0123456789abcdef.localhost:8443"
    for bad in ("https://localhost:8443", "https://localhost", "https://0123456789abcdef0123456789abcdef.localhost:08443",
                "https://0123456789abcdef0123456789abcdef.localhost:443", "https://0123456789abcdef0123456789abcdef.localhost:65536", "https://0123456789abcdef0123456789abcdef.localhost:0"):
        with pytest.raises(pregen.PregenError):
            pregen.check_provider_url(bad, allow_port=True)
    assert pregen.check_provider_url("https://frame.example:8443", allow_port=True) == "https://frame.example:8443"


def test_the_party_document_carries_a_first_keyset_signed_by_the_key():
    k = pregen.new_private_key_hex()
    pub = pregen.public_key_hex(k)
    doc = pregen.party_document("https://frame.example", "Frame", k, redirect_uris=["https://frame.example/pregen/callback"])
    assert doc == pregen.party_document("https://frame.example", "Frame", k, redirect_uris=["https://frame.example/pregen/callback"])
    assert (doc["party_id"], doc["name"], doc["roles"]) == ("https://frame.example", "Frame", ["provider"])
    ks = doc["keysets"][0]
    assert ks["body"]["signers"] == [{"role": "provider", "key_id": pregen.fingerprint(pub)}]
    assert ks["body"]["kind"] == "first" and ks["body"]["provider_id"] == "https://frame.example"
    assert pregen.verify_bytes(pub, ks["signatures"][0], pregen.signing_input(ks["type"], ks["body"]))
    with pytest.raises(pregen.PregenError):
        pregen.party_document("https://frame.example/", "Frame", k)


def test_pg_access_is_a_base64url_access_envelope_over_method_path_and_time():
    k = pregen.new_private_key_hex()
    pub = pregen.public_key_hex(k)
    h = pregen.pg_access("https://frame.example", k, "https://r.example/", "get", "/v2/grants/abc?x=1", now=1_800_000_000)
    assert "=" not in h and "+" not in h and "/" not in h
    env = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    assert env["body"] == {"signers": [{"role": "provider", "key_id": pregen.fingerprint(pub)}],
                           "provider_id": "https://frame.example", "aud": "https://r.example", "method": "GET", "path": "/v2/grants/abc?x=1",
                           "issued_at": 1_800_000_000}
    assert pregen.verify_bytes(pub, env["signatures"][0], pregen.signing_input("pg.access.v1", env["body"]))


def test_a_sandbox_test_id_is_bound_to_the_key():
    key = pregen.new_private_key_hex()
    hexid = pregen.fingerprint(pregen.public_key_hex(key)).split(":")[1]
    assert pregen.sandbox_provider_url(key) == f"https://{hexid}.localhost"
    assert pregen.sandbox_provider_url(key, 8443) == f"https://{hexid}.localhost:8443"
    assert pregen.sandbox_provider_url(key, 443) == f"https://{hexid}.localhost"
    for bad in (0, 65536, "8443", True, 8443.0):
        with pytest.raises(pregen.PregenError):
            pregen.sandbox_provider_url(key, bad)
