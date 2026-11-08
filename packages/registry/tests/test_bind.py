"""Extension bind in a sandbox (extensions/bind.md) and sandbox serial 12 (extensions/sandbox.md)."""
import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlsplit

import pregen as lib
import pytest
from fastapi.testclient import TestClient

from pregen_registry.app import create_app
from pregen_registry.protocol import Key, check_body, message_id, mint_code, signing_input
from pregen_registry.registry import Config, Registry
from test_registry import Clock, OpenProvider, Provider, make

CB = "https://frame.example/bind/callback"
TWELVE = mint_code("TEST", 12)


def app(reg, c, url="https://frame.example"):
    p = OpenProvider(reg, c, url=url)
    p.doc = lib.party_document(url, "Frame", p.key, redirect_uris=[url + "/bind/callback"])
    assert c.post("/v2/sandbox/party", json=p.doc).status_code == 200
    return p


def pkce():
    verifier = secrets.token_urlsafe(48)
    return verifier, base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def consent(c, p, challenge, decision="approve", redirect=None, state="s1"):
    q = {"response_type": "code", "client_id": p.id, "redirect_uri": redirect or p.id + "/bind/callback",
         "state": state, "code_challenge": challenge, "code_challenge_method": "S256"}
    return c.get("/v2/bind/authorize", params=q), c.post("/v2/bind/authorize", data={**q, "decision": decision},
                                                         follow_redirects=False)


def exchange(c, p, code, verifier, redirect=None, issued_at=None):
    body = {"provider_id": p.id, "code": code, "code_verifier": verifier,
            "redirect_uri": redirect or p.id + "/bind/callback", "issued_at": issued_at or p.reg.clock()}
    return c.post("/v2/bind/token", headers=p.h, json=p.signed("pg.bind_exchange.v1", body))


def bind(c, p):
    verifier, challenge = pkce()
    page, back = consent(c, p, challenge)
    assert page.status_code == 200 and back.status_code == 303
    q = parse_qs(urlsplit(back.headers["location"]).query)
    assert q["state"] == ["s1"] and q["iss"] == ["TEST"]
    r = exchange(c, p, q["code"][0], verifier)
    assert r.status_code == 200, r.text
    return r.json()["binding"]


def test_a_sandbox_lists_bind_and_shows_the_app_by_its_domain():
    reg, c, _ = make()
    doc = c.get("/.well-known/pregen-registry.json").json()
    check_body("registry-document", doc)
    assert "bind" in doc["extensions"] and doc["bind"]["token"] == "https://test.example/v2/bind/token"
    p = app(reg, c)
    page, _ = consent(c, p, pkce()[1])
    assert "frame.example" in page.text and TWELVE in page.text and "will not learn your account" in page.text
    assert page.headers["x-frame-options"] == "DENY"


def test_a_production_registry_does_not_offer_bind():
    reg, c, _ = make(sandbox=False)
    assert "bind" not in c.get("/.well-known/pregen-registry.json").json()
    assert c.get("/v2/bind/authorize", params={"client_id": "https://frame.example"}).status_code == 404


def test_code_twelve_through_a_binding():
    reg, c, _ = make()
    p = app(reg, c)
    assert p.answer(p.body(TWELVE, job="j0"))["body"]["reason"] == "PG_NO_LICENSE"          # no binding: nothing
    env = bind(c, p)
    b = env["body"]
    check_body("binding", b)
    assert lib.verify_bytes(reg.key.public_hex, env["signatures"][0], signing_input(env["type"], b))
    assert (b["authority"], b["provider_id"], len(b["grants"])) == ("TEST", p.id, 1) and len(b["licensee_id"]) >= 16
    assert b["expires_at"] - b["issued_at"] <= 365 * 86400
    lic = b["licensee_id"]
    a = p.answer(p.body(TWELVE, job="j1", licensee_id=lic))["body"]
    assert a["status"] == "allow" and a["basis"]["grant"]["id"] == b["grants"][0]
    assert a["ext"] == {"sandbox": True, "bind": {"binding": message_id("pg.binding.v1", b)}}
    a = p.answer(p.body(TWELVE, job="j2", purpose="commercial", licensee_id=lic))["body"]
    assert a["reason"] == "PG_SCOPE_VIOLATION"                                              # outside the licence
    r = p.ask(p.body(TWELVE, job="j3", licensee_id="made-up-licensee-id"))
    assert r.status_code == 403 and r.json()["error"] == "PG_NOT_BOUND"
    r = p.ask(p.body(TWELVE, job="j4", licensee_id="account:holder"))                      # the account is not an id
    assert r.status_code == 403 and r.json()["error"] == "PG_NOT_BOUND"
    assert p.answer(p.body(mint_code("TEST", 1), job="j5", licensee_id=lic))["body"]["status"] == "allow"


def test_three_uses_then_the_limit_and_the_app_reads_what_is_left():
    reg, c, _ = make()
    p = app(reg, c)
    lic = bind(c, p)["body"]["licensee_id"]
    path = f"/v2/grants?licensee_id={lic}"
    access = lambda: {**p.h, "PG-Access": base64.urlsafe_b64encode(lib.canonical_json(p.signed("pg.access.v1", {  # noqa
        "provider_id": p.id, "aud": "https://test.example", "method": "GET", "path": path,
        "issued_at": reg.clock()}))).rstrip(b"=").decode()}
    for n in range(3):
        assert p.answer(p.body(TWELVE, job=f"j{n}", licensee_id=lic))["body"]["status"] == "allow"
    assert p.answer(p.body(TWELVE, job="j9", licensee_id=lic))["body"]["reason"] == "PG_USAGE_LIMIT"
    g = c.get(path, headers=access()).json()["grants"]
    assert [(x["status"], x["remaining"]) for x in g] == [("active", 0)] and g[0]["grant"]["body"]["max_uses"] == 3
    assert c.get(path, headers=p.h).status_code == 401                                     # no PG-Access
    other = app(reg, c, url="https://other.example")
    path = f"/v2/grants?licensee_id={lic}"
    h = {**other.h, "PG-Access": base64.urlsafe_b64encode(lib.canonical_json(other.signed("pg.access.v1", {
        "provider_id": other.id, "aud": "https://test.example", "method": "GET", "path": path,
        "issued_at": reg.clock()}))).rstrip(b"=").decode()}
    assert c.get(path, headers=h).status_code == 403                                       # bound to frame only


def test_a_leaked_licensee_id_is_useless_to_another_app_and_each_app_has_its_own_licence():
    reg, c, _ = make()
    p, q = app(reg, c), app(reg, c, url="https://other.example")
    lp, lq = bind(c, p)["body"]["licensee_id"], bind(c, q)["body"]["licensee_id"]
    r = q.ask(q.body(TWELVE, job="x", licensee_id=lp))
    assert r.status_code == 403 and r.json()["error"] == "PG_NOT_BOUND"
    for n in range(3):
        assert p.answer(p.body(TWELVE, job=f"p{n}", licensee_id=lp))["body"]["status"] == "allow"
    assert q.answer(q.body(TWELVE, job="q0", licensee_id=lq))["body"]["status"] == "allow"   # not used up by p


def test_a_registered_credential_naming_a_binding_gets_nothing_from_it():
    reg, c, _ = make()
    lic = bind(c, app(reg, c))["body"]["licensee_id"]
    old = Provider(reg, c)
    assert old.answer(old.body(TWELVE, licensee_id=lic))["body"]["reason"] == "PG_NO_LICENSE"


def test_a_new_binding_replaces_the_old_and_revocation_takes_effect_at_once():
    reg, c, _ = make()
    p = app(reg, c)
    first = bind(c, p)["body"]["licensee_id"]
    second = bind(c, p)["body"]["licensee_id"]
    assert first != second
    assert p.ask(p.body(TWELVE, job="a", licensee_id=first)).status_code == 403              # B-1
    assert p.answer(p.body(TWELVE, job="b", licensee_id=second))["body"]["status"] == "allow"
    assert [(x["active"], x["allows"]) for x in reg.bindings()] == [(False, 0), (True, 1)]
    reg.revoke_binding(second)                                                               # B-2
    assert p.ask(p.body(TWELVE, job="c", licensee_id=second)).status_code == 403


def test_the_code_is_single_use_short_lived_and_bound_to_client_redirect_and_verifier():
    reg, c, clock = make()
    p, q = app(reg, c), app(reg, c, url="https://other.example")

    def code(state="s1"):
        verifier, challenge = pkce()
        back = consent(c, p, challenge, state=state)[1]
        return parse_qs(urlsplit(back.headers["location"]).query)["code"][0], verifier

    k, v = code()
    assert exchange(c, p, k, pkce()[0]).json()["error"] == "PG_BIND_CODE"                   # wrong verifier
    assert exchange(c, p, k, v).json()["error"] == "PG_BIND_CODE"                           # and now spent
    k, v = code()
    assert exchange(c, q, k, v).json()["error"] == "PG_BIND_CODE"                           # another app
    k, v = code()
    clock.t += 61
    assert exchange(c, p, k, v).json()["error"] == "PG_BIND_CODE"                           # expired
    k, v = code()
    assert exchange(c, p, k, v, issued_at=reg.clock() - 120).status_code == 401             # an old exchange
    k, v = code()
    r = c.post("/v2/bind/token", headers=p.h, json=p.signed("pg.bind_exchange.v1", {
        "provider_id": p.id, "code": k, "code_verifier": v, "redirect_uri": CB, "issued_at": reg.clock()},
        key=lib.new_private_key_hex()))
    assert r.status_code == 401                                                             # not the app's key
    assert exchange(c, p, k, v).status_code == 200


def test_a_bad_app_or_redirect_is_never_redirected_to_and_a_refusal_carries_no_code():
    reg, c, _ = make()
    p = app(reg, c)
    _, challenge = pkce()
    page, back = consent(c, p, challenge, redirect="https://evil.example/cb")
    assert page.status_code == 400 and back.status_code == 400
    stranger = OpenProvider(reg, c, url="https://stranger.example")                        # no party document
    assert consent(c, stranger, challenge)[0].status_code == 400
    back = consent(c, p, challenge, decision="deny")[1]
    q = parse_qs(urlsplit(back.headers["location"]).query)
    assert q == {"error": ["access_denied"], "state": ["s1"], "iss": ["TEST"]}
    q = {"response_type": "token", "client_id": p.id, "redirect_uri": CB, "state": "s",
         "code_challenge": challenge, "code_challenge_method": "plain"}
    assert c.get("/v2/bind/authorize", params=q).status_code == 400


def test_a_sandbox_made_before_code_twelve_gains_it_and_refuses_a_person_on_serial_twelve(tmp_path):
    cfg, key = Config(prefix="TEST", name="T", api="https://test.example", sandbox=True), Key()
    reg = Registry(cfg, key, db_path=str(tmp_path / "a.db"), clock=Clock())
    reg.db.execute("DELETE FROM subjects WHERE serial = 12")                       # as made by an earlier 0.4
    reg = Registry(cfg, key, db_path=str(tmp_path / "a.db"), clock=Clock())
    assert reg._row("SELECT name FROM subjects WHERE serial = 12")["name"].startswith("Test subject 12")
    assert TestClient(create_app(reg)).get(f"/v2/codes/{TWELVE}").json()["status"] == "active"
    reg.db.execute("UPDATE subjects SET name = 'My own test person' WHERE serial = 12")
    with pytest.raises(ValueError, match="1-7 and 9-12"):
        Registry(cfg, key, db_path=str(tmp_path / "a.db"), clock=Clock())
