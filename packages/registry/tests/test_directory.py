"""Core rule 2 end to end: a provider trusts an answer only through the signed directory.

A real registry, a test directory signed by a test steward key, and the provider-side check
(`pregen.check_answer`). The fake-registry cases are the attacks the directory exists to stop.
"""
import pytest
from fastapi.testclient import TestClient
from pregen import PregenError, canonical_json, check_answer, verify_directory

from pregen_registry.app import create_app
from pregen_registry.protocol import Key, mint_code
from pregen_registry.registry import Config, Registry

NOW = 1_800_000_000
steward = Key()


def registry(prefix, api):
    reg = Registry(Config(prefix=prefix, name=prefix, api=api, sandbox=True), Key(), clock=lambda: NOW)
    reg.seed_sandbox()
    return reg, TestClient(create_app(reg))


real, real_http = registry("TEST", "https://test.example")


def directory(revoked=False):
    entry = {"name": "PRE-GEN Test Registry", "prefix": "TEST", "api": "https://test.example",
             "keys": "https://test.example/keys", "key_fingerprints": [real.key.id]}
    if revoked:
        entry["revoked"] = {"at": "2027-01-01T00:00:00Z", "reason": "licensed subjects it had no authority over"}
    d = {"schema": "pregen.registries.v2", "sequence": 1, "steward_key_id": steward.id, "registries": [entry]}
    return verify_directory({**d, "signature": steward.sign(canonical_json(d))}, steward.public_hex)


def get_json(url):
    assert url == "https://test.example/keys", url  # the only key set the directory points to
    return real_http.get("/keys").json()


def ask(reg, http, code):
    provider_id, token = reg.add_provider(None)
    request = {"type": "pg.request.v1", "signatures": [],
               "body": {"subject_ref": code, "provider_id": provider_id, "profile": "likeness/1",
                        "use": {"purpose": "research"}, "job_id": "job-1", "job_hash": "a" * 64}}
    r = http.post("/v2/requests", json=request, headers={"X-Provider-ID": provider_id, "Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    return request, r.json()["answer"]


def check(request, answer, d=None, **kw):
    return check_answer(answer, request, d or directory(), get_json=get_json, now=NOW + 10, **kw)


def test_a_genuine_allow_is_accepted_only_in_testing():
    request, answer = ask(real, real_http, mint_code("TEST", 1))
    assert check(request, answer, testing=True)["status"] == "allow"
    with pytest.raises(PregenError, match="sandbox"):
        check(request, answer)


def test_a_registry_the_steward_never_listed_is_refused():
    # Someone sets up their own registry and registers a fake "Cristiano Ronaldo" under its own prefix.
    fake, fake_http = registry("AFRK", "https://fake.example")
    request, answer = ask(fake, fake_http, mint_code("AFRK", 1))
    with pytest.raises(PregenError, match="unknown_issuer"):
        check(request, answer, testing=True)


def test_a_copy_of_a_registry_cannot_sign_for_its_prefix():
    # The same software and the same prefix, but not the listed key.
    clone, clone_http = registry("TEST", "https://test.example")
    request, answer = ask(clone, clone_http, mint_code("TEST", 1))
    with pytest.raises(PregenError, match="issuer_mismatch"):
        check(request, answer, testing=True)


def test_a_revoked_registry_authorizes_nothing_again():
    request, answer = ask(real, real_http, mint_code("TEST", 1))
    with pytest.raises(PregenError, match="revoked"):
        check(request, answer, directory(revoked=True), testing=True)


def test_an_answer_cannot_be_reused_changed_or_kept_past_its_life():
    request, answer = ask(real, real_http, mint_code("TEST", 1))
    other = {**request, "body": {**request["body"], "job_id": "job-2"}}
    with pytest.raises(PregenError, match="another request"):
        check(other, answer, testing=True)
    edited = {**answer, "body": {**answer["body"], "expires_at": answer["body"]["expires_at"] + 1}}
    with pytest.raises(PregenError, match="bad signature"):
        check(request, edited, testing=True)
    with pytest.raises(PregenError, match="expired"):
        check_answer(answer, request, directory(), get_json=get_json, now=NOW + 901, testing=True)


def test_a_refusal_is_genuine_but_never_permits():
    request, answer = ask(real, real_http, mint_code("TEST", 3))
    with pytest.raises(PregenError, match="not an allow: deny PG_SUBJECT_OPTED_OUT"):
        check(request, answer, testing=True)


def test_no_new_registry_issues_bare_codes():
    with pytest.raises(ValueError, match="four letters"):
        Config(prefix="", name="x", api="https://x.example")
