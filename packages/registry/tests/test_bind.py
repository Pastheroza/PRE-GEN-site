"""Extension bind in a sandbox (extensions/bind.md) and sandbox serial 12 (extensions/sandbox.md)."""
import base64
import hashlib
import re
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


def consent(c, p, challenge, decision="approve", redirect=None, state="s1", nonce=None, headers=None):
    """GET the consent page, then answer it the way a browser posts its form (with the page's one-time nonce)."""
    q = {"response_type": "code", "client_id": p.id, "redirect_uri": redirect or p.id + "/bind/callback",
         "state": state, "code_challenge": challenge, "code_challenge_method": "S256"}
    page = c.get("/v2/bind/authorize", params=q)
    found = re.search(r'name="consent" value="([^"]+)"', page.text)
    nonce = nonce if nonce is not None else (found.group(1) if found else "")
    return page, c.post("/v2/bind/authorize", data={**q, "consent": nonce, "decision": decision},
                        follow_redirects=False, headers=headers or {})


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
    a = p.answer(p.body(mint_code("TEST", 1), job="j5", licensee_id=lic))["body"]
    assert a["status"] == "allow" and a["ext"] == {"sandbox": True}           # an open grant: no ext.bind (B-3c)


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


def test_a_licensee_id_not_bound_to_the_asker_never_reaches_a_grant():
    reg, c, _ = make()
    p = app(reg, c)
    lic = bind(c, p)["body"]["licensee_id"]
    for n in (1, 12):                                    # a made-up https id is no loophole (sandbox.md)
        r = p.ask(p.body(mint_code("TEST", n), job=f"m{n}", licensee_id="https://made-up.example"))
        assert (r.status_code, r.json()["error"]) == (403, "PG_NOT_BOUND")
    old = Provider(reg, c)                               # a registered credential: licensee.md, 401
    for who in (lic, "made-up", p.id):
        r = old.ask(old.body(TWELVE, job="o-" + who[:5], licensee_id=who))
        assert (r.status_code, r.json()["error"]) == (401, "PG_NOT_AUTHENTICATED")


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


def test_redirect_uris_are_the_apps_own_https_host_or_its_private_scheme():
    reg, c, _ = make()
    key = lib.new_private_key_hex()
    for bad in ("https://evil.example/cb", "http://frame.example/cb", "https://frame.example:444/cb",
                "https://user@frame.example/cb", "https://frame.example/cb#x", "https://frame.example.evil.example/cb",
                "javascript:alert(1)", "evil.example:/cb"):
        doc = lib.party_document("https://frame.example", "Frame", key, redirect_uris=[bad])
        assert c.post("/v2/sandbox/party", json=doc).status_code == 422, bad
    doc = lib.party_document("https://frame.example", "Frame", key,
                             redirect_uris=["https://frame.example/cb", "example.frame:/cb", "example.frame.app:/cb"])
    assert c.post("/v2/sandbox/party", json=doc).status_code == 200


def test_an_approval_needs_the_page_it_answers_and_comes_from_this_registry():
    reg, c, _ = make()
    p = app(reg, c)
    _, challenge = pkce()
    assert consent(c, p, challenge, nonce="")[1].status_code == 400                      # no page shown
    page, back = consent(c, p, challenge)
    nonce = re.search(r'name="consent" value="([^"]+)"', page.text).group(1)
    assert back.status_code == 303
    assert consent(c, p, challenge, nonce=nonce)[1].status_code == 400                   # spent
    assert consent(c, p, challenge, headers={"Origin": "https://evil.example"})[1].status_code == 403
    assert consent(c, p, challenge, headers={"Origin": "https://test.example"})[1].status_code == 303
    assert "posted to this sandbox" in page.text                                         # BIND-6: said so
    assert reg._row("SELECT COUNT(*) FROM grants WHERE licensee_id = 'account:holder'")[0] == 0   # no licence yet


def test_another_app_cannot_burn_a_code_and_a_replay_ends_the_binding():
    reg, c, _ = make()
    p, q = app(reg, c), app(reg, c, url="https://other.example")
    verifier, challenge = pkce()
    k = parse_qs(urlsplit(consent(c, p, challenge)[1].headers["location"]).query)["code"][0]
    assert exchange(c, q, k, verifier).json()["error"] == "PG_BIND_CODE"                 # not q's code
    r = exchange(c, p, k, verifier)
    assert r.status_code == 200                                                          # still p's
    lic = r.json()["binding"]["body"]["licensee_id"]
    assert exchange(c, p, k, verifier).json()["error"] == "PG_BIND_CODE"                 # replayed
    assert p.ask(p.body(TWELVE, licensee_id=lic)).status_code == 403                     # RFC 6749 §4.1.2


def test_a_sandbox_database_never_starts_as_a_production_registry(tmp_path):
    db = str(tmp_path / "s.db")
    key = Key()
    Registry(Config(prefix="TEST", name="T", api="https://test.example", sandbox=True), key, db_path=db, clock=Clock())
    with pytest.raises(ValueError, match="sandbox"):
        Registry(Config(prefix="TEST", name="T", api="https://test.example"), key, db_path=db, clock=Clock())


def test_an_allow_never_received_is_given_back_by_a_report_with_no_answer():
    """limits.md: answer null releases every reserved allow of the ask; the request is never sent again."""
    reg, c, clock = make()
    p = app(reg, c)
    lic = bind(c, p)["body"]["licensee_id"]
    env = p.signed("pg.request.v1", p.body(TWELVE, job="lost", licensee_id=lic))
    body = env["body"]
    r = c.post("/v2/requests", headers=p.h, json=env)
    assert r.json()["answer"]["body"]["status"] == "allow"                  # issued, but say the app never got it
    report = {"request_id": message_id("pg.request.v1", body), "answer": None, "request": body, "job_id": "lost",
              "outcome": "not_generated", "output_hash": "", "occurred_at": reg.clock()}
    early = p.signed("pg.report.v1", {**report, "job_id": "lost"})
    clock.t += 301                                                           # expired before it arrived
    r = c.post("/v2/reports", headers=p.h, json=p.signed("pg.report.v1", report))
    assert r.status_code == 200, r.text
    assert len(r.json()["ack"]["body"]["released"]) == 1
    late = c.post("/v2/requests", headers=p.h, json=env)                    # the same request, arriving late
    assert (late.status_code, late.json()["error"]) == (409, "PG_ASK_CLOSED") and "ack" in late.json()
    for n in range(3):                                                       # all three uses are there again
        assert p.answer(p.body(TWELVE, job=f"after{n}", licensee_id=lic))["body"]["status"] == "allow"


def test_localhost_ids_in_a_sandbox_are_bound_to_their_key_and_loopback_http_is_a_sandbox_callback():
    reg, c, _ = make()
    key = lib.new_private_key_hex()
    own = lib.sandbox_provider_url(key, 8443)
    other = lib.sandbox_provider_url(lib.new_private_key_hex(), 8443)               # another key's id
    assert c.post("/v2/sandbox/party", json=lib.party_document(other, "X", key)).status_code == 422
    with pytest.raises(lib.PregenError):
        lib.party_document("https://localhost:8443", "X", key)                       # a bare localhost is no id
    doc = lib.party_document(own, "Mine", key, redirect_uris=["http://localhost:8443/callback",
                                                              "http://127.0.0.1:9000/cb", "http://[::1]/cb"])
    assert c.post("/v2/sandbox/party", json=doc).status_code == 200
    prod, cp, _ = make(sandbox=False)
    doc = lib.party_document("https://frame.example", "F", key, redirect_uris=["http://localhost:8443/callback"])
    with pytest.raises(Exception):
        prod.pin_party(doc)                                                  # http only in a sandbox


def test_a_report_with_no_answer_never_gives_back_an_allow_that_is_still_valid():
    reg, c, clock = make()
    p = app(reg, c)
    lic = bind(c, p)["body"]["licensee_id"]
    env = p.signed("pg.request.v1", p.body(TWELVE, job="early", licensee_id=lic))
    allow = c.post("/v2/requests", headers=p.h, json=env).json()["answer"]
    report = {"request_id": message_id("pg.request.v1", env["body"]), "answer": None, "request": env["body"],
              "job_id": "early", "outcome": "not_generated", "output_hash": "", "occurred_at": reg.clock()}
    r = c.post("/v2/reports", headers=p.h, json=p.signed("pg.report.v1", report))
    assert r.json()["ack"]["body"]["released"] == []                         # still valid: stays reserved
    assert c.post("/v2/requests", headers=p.h, json=env).status_code == 409  # and the ask is closed
    assert p.report(allow, "generated").status_code == 200                    # it can still be reported, and counts


def test_a_given_back_answer_is_never_served_again_as_open():
    reg, c, clock = make()
    p = app(reg, c)
    lic = bind(c, p)["body"]["licensee_id"]
    body = p.body(TWELVE, job="job-1", licensee_id=lic)
    first = p.answer(body)
    assert p.report(first, "not_generated").json()["ack"]["body"]["released"]
    assert p.ask(body).status_code == 429                                     # the same bytes, the same second
    clock.t += 1
    again = p.answer(body)
    assert again["body"]["status"] == "allow" and again != first                # a new answer, a new reservation


def test_redirect_uris_edges_agree_with_the_schema():
    reg, c, _ = make()
    key = lib.new_private_key_hex()
    for bad in ("https://FRAME.example/cb", "https://frame.example./cb", "https://frame.example:443/cb",
                "https://frame.example?x=1", "example.frame://cb", "example.frame:///cb", "https://frame.example/c b",
                "https://frame.example/c\x01", "http://localhost:80/cb", "EXAMPLE.frame:/cb"):
        doc = lib.party_document("https://frame.example", "Frame", key, redirect_uris=[bad])
        assert c.post("/v2/sandbox/party", json=doc).status_code == 422, bad
    doc = lib.party_document("https://frame.example", "Frame", key,
                             redirect_uris=["https://frame.example", "https://frame.example/cb?x=1", "example.frame:/",
                                            "http://localhost:8080/cb"])
    assert c.post("/v2/sandbox/party", json=doc).status_code == 200


def test_an_old_plain_localhost_pin_is_dropped_when_the_sandbox_starts(tmp_path):
    cfg, key, db = Config(prefix="TEST", name="T", api="https://test.example", sandbox=True), Key(), str(tmp_path / "s.db")
    reg = Registry(cfg, key, db_path=db, clock=Clock())
    pk = lib.new_private_key_hex()
    reg.pin_party(lib.party_document(lib.sandbox_provider_url(pk, 8443), "A", pk), posted=True)
    reg.db.execute("UPDATE keysets SET provider_id = 'https://localhost:8443'")      # as an earlier version pinned it
    reg = Registry(cfg, key, db_path=db, clock=Clock())
    assert reg._q("SELECT * FROM keysets WHERE provider_id = 'https://localhost:8443'") == []
    assert len(reg._q("SELECT * FROM keysets")) == 0


def test_an_early_bind_codes_table_is_rebuilt(tmp_path):
    db = str(tmp_path / "s.db")
    cfg, key = Config(prefix="TEST", name="T", api="https://test.example", sandbox=True), Key()
    reg = Registry(cfg, key, db_path=db, clock=Clock())
    reg.db.execute("DROP TABLE bind_codes")
    reg.db.execute("CREATE TABLE bind_codes (code_hash TEXT PRIMARY KEY, grants TEXT NOT NULL)")   # 6cab298's shape
    reg = Registry(cfg, key, db_path=db, clock=Clock())
    assert "binding" in {r["name"] for r in reg.db.execute("PRAGMA table_info(bind_codes)")}


def test_only_a_valid_approval_counts_toward_the_limit():
    reg, c, _ = make()
    p = app(reg, c)
    _, challenge = pkce()
    for _ in range(25):                                                       # no page: refused, not counted
        assert consent(c, p, challenge, nonce="x")[1].status_code == 400
    assert consent(c, p, challenge)[1].status_code == 303


def test_concurrent_requests_keep_a_posted_document_posted():
    import threading
    reg, c, clock = make()
    p = app(reg, c)
    out = []

    def ask(n):
        out.append(p.ask(p.body(mint_code("TEST", 1), job=f"t{n}")).status_code)
    threads = [threading.Thread(target=ask, args=(n,)) for n in range(20)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert out == [200] * 20 and reg._meta("party:" + p.id) == "posted"
    clock.t += 86400 * 2                                                       # past PARTY_REFRESH: still no fetch
    assert p.ask(p.body(mint_code("TEST", 1), job="later")).status_code == 200


def _terms_allow(reg, c, clock):
    from pregen_registry.registry import SANDBOX_LEGAL, SANDBOX_TEMPLATE
    p = app(reg, c)
    s = reg.add_subject("Terms person", level="verified", published=1)
    reg.add_grant(s, purposes=("research",))
    terms = lambda *purposes: reg.publish_terms(s, purposes=purposes, template=SANDBOX_TEMPLATE,  # noqa: E731
                                                legal=SANDBOX_LEGAL, factor="authenticator")
    env = p.signed("pg.request.v1", p.body(s, job="j", terms=terms("research")))
    assert c.post("/v2/requests", headers=p.h, json=env).json()["answer"]["body"]["status"] == "allow"
    return p, s, env, terms


def _null_report(c, p, env, reg):
    report = {"request_id": message_id("pg.request.v1", env["body"]), "answer": None, "request": env["body"],
              "job_id": "j", "outcome": "not_generated", "output_hash": "", "occurred_at": reg.clock()}
    return c.post("/v2/reports", headers=p.h, json=p.signed("pg.report.v1", report))


@pytest.mark.parametrize("newer_stale_too", [False, True])
def test_a_null_report_gives_back_an_allow_whose_ask_stepped_aside(newer_stale_too):
    reg, c, clock = make()
    p, s, env, terms = _terms_allow(reg, c, clock)
    clock.t += 301                                            # the first allow, never received, expires
    env2 = p.signed("pg.request.v1", p.body(s, job="j", terms=terms("research", "editorial")))   # T-7: steps aside
    assert c.post("/v2/requests", headers=p.h, json=env2).json()["answer"]["body"]["status"] == "allow"
    if newer_stale_too:
        clock.t += 301
        terms("research", "editorial", "educational")
    r = _null_report(c, p, env, reg)
    assert r.status_code == 200, r.text
    assert len(r.json()["ack"]["body"]["released"]) == 1


def test_concurrent_consent_pages_cannot_share_a_count(monkeypatch):
    import threading
    from pregen_registry import app as app_module
    monkeypatch.setattr(app_module, "BIND_PAGES_PER_HOUR", 5)
    reg, c, _ = make()
    p = app(reg, c)
    _, challenge = pkce()
    q = {"response_type": "code", "client_id": p.id, "redirect_uri": CB, "state": "s", "code_challenge": challenge,
         "code_challenge_method": "S256"}
    out = []
    threads = [threading.Thread(target=lambda: out.append(c.get("/v2/bind/authorize", params=q).status_code))
               for _ in range(20)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(out) == [200] * 5 + [429] * 15


def test_the_redirect_pattern_refuses_a_trailing_newline_and_ports_past_65535():
    from pregen_registry.registry import REDIRECT_URI
    from pregen_registry.protocol import check_body
    key = lib.new_private_key_hex()
    for bad in ("https://frame.example/cb\n", "https://frame.example:99999/cb", "http://localhost:65536/cb"):
        doc = lib.party_document("https://frame.example", "F", key)
        doc["redirect_uris"] = [bad]
        with pytest.raises(Exception):
            check_body("party-document", doc)                 # the schema says no, as the registry does
        assert not REDIRECT_URI.fullmatch(bad)


def test_masked_answers_for_a_private_and_an_unknown_code_are_alike():
    """provider-identity P-5a: the level of an unknown code, so nothing tells them apart."""
    docs = {}
    clock = Clock()
    reg = Registry(Config(prefix="ABCD", name="R", api="https://r.example", providers="open"), Key(), clock=clock,
                   fetch_party=lambda url: docs[url])
    c = TestClient(create_app(reg))
    private = reg.add_subject("Private Person", level="verified")
    p = OpenProvider(reg, c)
    docs[p.id] = p.doc
    same = lambda x: {k: v for k, v in x.items() if k not in ("request_id", "issued_at", "expires_at")}  # noqa: E731
    for n, extra in enumerate(({}, {"terms": "0" * 64})):     # with terms too: a masked answer is kept like any other
        bodies = [p.body(private, job=f"a{n}", **extra), p.body(mint_code("ABCD", 99), job=f"b{n}", **extra)]
        first = [p.answer(x) for x in bodies]
        clock.t += 1
        again = [p.answer(x) for x in bodies]
        assert first[0]["body"]["reason"] == "PG_PROVIDER_NOT_ACCEPTED"
        assert same(first[0]["body"]) == same(first[1]["body"])
        assert again == first                        # both repeats give the stored answer


def test_grant_add_needs_a_licensee_or_any_provider(tmp_path, capsys):
    from pregen_registry.cli import main as cli
    cli(["init", "--dir", str(tmp_path), "--prefix", "ABCD", "--name", "R", "--api", "https://r.example"])
    code = mint_code("ABCD", 1)
    cli(["subject", "add", "--dir", str(tmp_path), "--name", "Maya"])
    with pytest.raises(SystemExit, match="any-provider"):
        cli(["grant", "add", "--dir", str(tmp_path), "--subject", code])
    capsys.readouterr()
    with pytest.raises(SystemExit, match="exactly one"):
        cli(["grant", "add", "--dir", str(tmp_path), "--subject", code, "--any-provider", "--licensee", "x:y"])
    capsys.readouterr()
    cli(["grant", "add", "--dir", str(tmp_path), "--subject", code, "--any-provider"])
    assert re.fullmatch(r"[0-9a-f]{64}\n", capsys.readouterr().out)


def test_a_consent_body_that_is_not_utf8_is_a_bad_request_and_takes_no_slot():
    reg, c, _ = make()
    p = app(reg, c)
    r = c.post("/v2/bind/authorize", content=b"client_id=\xff\xfe", headers={"Content-Type":
                                                                             "application/x-www-form-urlencoded"})
    assert r.status_code == 400
    _, challenge = pkce()
    assert consent(c, p, challenge)[1].status_code == 303
