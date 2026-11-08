"""Sandbox serials 9-11 (spec/extensions/sandbox.md): buy first, the person's terms, a minor."""
import json
import threading

import pytest
from fastapi.testclient import TestClient
from test_registry import OpenProvider, Provider, code, make

from pregen_registry.app import create_app
from pregen_registry.cli import main as cli
from pregen_registry.protocol import Key, check_body, message_id
from pregen_registry.registry import Config, Registry


def status(p, body):
    a = p.answer(body)["body"]
    assert a["ext"] == {"sandbox": True}
    return a.get("reason") or a["status"]


def buy(p, subject=code(9), signed=False):
    env = p.signed("pg.request.v1", p.body(subject, job="buy")) if signed else \
        {"type": "pg.request.v1", "body": p.body(subject, job="buy"), "signatures": []}
    return p.c.post("/v2/sandbox/purchases", headers=p.h, json=env)


# ── serial 9: buy first ─────────────────────────────────────────────────

def test_buy_first_one_use_per_purchase_billed_and_given_back():
    reg, c, _ = make()
    offer = next(o for o in c.get("/v2/catalog").json()["offers"] if o["subject_ref"] == code(9))
    assert offer["price"] == {"amount": 100, "currency": "USD", "unit": "generation"}
    p, other = Provider(reg, c), Provider(reg, c)
    p.register()
    assert status(p, p.body(code(9), job="j0")) == "PG_NO_LICENSE"
    r = buy(p)
    assert r.status_code == 200, r.text
    g = r.json()["grant"]
    check_body("grant", g["body"])
    assert (g["body"]["licensee_id"], g["body"]["max_uses"], g["body"]["ext"]) == (p.id, 1, {"sandbox": True, "purchase": 1})
    a1 = p.answer(p.body(code(9), job="j1"))
    assert a1["body"]["basis"]["grant"]["id"] == message_id(g["type"], g["body"])
    assert status(p, p.body(code(9), job="j2")) == "PG_USAGE_LIMIT"
    assert status(other, other.body(code(9), job="j1")) == "PG_NO_LICENSE"         # one provider's purchase is its own
    assert p.send(p.report(a1, outcome="not_generated")).status_code == 200      # given back within the window
    assert status(p, p.body(code(9), job="j3")) == "allow"                        # the use is restored
    assert status(p, p.body(code(9), job="j4")) == "PG_USAGE_LIMIT"
    assert buy(p).json()["grant"]["body"]["ext"] == {"sandbox": True, "purchase": 2}   # buy again: one more
    assert status(p, p.body(code(9), job="j5")) == "allow"
    assert status(p, p.body(code(9), job="j6")) == "PG_USAGE_LIMIT"
    st = c.get("/v2/statement", headers=p.h).json()["grants"]
    assert sorted((x["billed"], x["given_back"]) for x in st) == [(1, 0), (1, 1)]


def test_buy_first_for_a_provider_known_by_its_domain_and_only_in_a_sandbox():
    reg, c, _ = make()
    p = OpenProvider(reg, c)
    c.post("/v2/sandbox/party", json=p.doc)
    assert buy(p).status_code == 422                                              # an open provider signs
    assert buy(p, signed=True).status_code == 200
    assert status(p, p.body(code(9), job="j1")) == "allow"
    r = buy(p, code(2), signed=True)
    assert r.status_code == 404 and r.json()["error"] == "PG_NOT_FOUND"           # not in the catalog
    reg2, c2, _ = make(sandbox=False)
    assert buy(Provider(reg2, c2)).status_code == 404


@pytest.mark.parametrize("buyer_kind", [Provider, OpenProvider])
def test_another_provider_naming_the_buyer_as_its_licensee_gets_no_licence(buyer_kind):
    reg, c, _ = make()
    buyer, other = buyer_kind(reg, c), Provider(reg, c)
    if buyer_kind is OpenProvider:
        c.post("/v2/sandbox/party", json=buyer.doc)
    assert buy(buyer, signed=buyer_kind is OpenProvider).status_code == 200
    assert status(other, other.body(code(9), job="x", licensee_id=buyer.id)) == "PG_NO_LICENSE"   # its alone
    assert status(buyer, buyer.body(code(9), job="b")) == "allow"                # the use is still the buyer's
    assert c.get("/v2/statement", headers=other.h).json()["grants"] == []


def test_two_jobs_racing_for_the_last_bought_use_one_allow_one_usage_limit():
    reg, c, _ = make()
    p = Provider(reg, c)
    for rnd in range(20):
        assert buy(p).status_code == 200
        gate, out = threading.Barrier(2), []

        def go(job):
            gate.wait()
            out.append(status(p, p.body(code(9), job=job)))
        threads = [threading.Thread(target=go, args=(f"r{rnd}-{i}",)) for i in range(2)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert sorted(out) == ["PG_USAGE_LIMIT", "allow"], out


# ── serial 10: the person's terms (extensions/terms.md, The gate) ───────

@pytest.mark.parametrize("purpose,categories,cite,expected", [
    ("research", None, None, "PG_NO_LICENSE"),                # no terms cited: answered as before
    ("research", None, "current", "PG_NO_LICENSE"),           # accepted, but the terms grant nothing
    ("research", None, "0" * 64, "PG_TERMS_NOT_ACCEPTED"),    # T-7: not the current id
    ("commercial", None, None, "PG_TERMS_EXCLUDED"),          # step 5: a purpose not opened
    ("commercial", None, "current", "PG_TERMS_EXCLUDED"),
    ("research", ["advertising"], None, "PG_TERMS_EXCLUDED"),  # step 5: an excluded category
    ("research", ["advertising"], "current", "PG_TERMS_EXCLUDED"),
])
def test_the_persons_terms(purpose, categories, cite, expected):
    reg, c, _ = make()
    assert "terms" in c.get("/.well-known/pregen-registry.json").json()["extensions"]
    look = c.get(f"/v2/codes/{code(10)}").json()
    terms = c.get(f"/v2/terms/{look['terms']['id']}").json()["terms"]["body"]
    assert terms["rules"] == {"purposes": ["editorial", "research"], "excluded_categories": ["advertising"]}
    assert terms["minor"] is False
    p = OpenProvider(reg, c)
    c.post("/v2/sandbox/party", json=p.doc)
    body = p.body(code(10), purpose=purpose)
    if categories:
        body["use"]["categories"] = categories
    if cite:
        body["terms"] = look["terms"]["id"] if cite == "current" else cite
    assert status(p, body) == expected


def test_a_credential_provider_cannot_accept_the_terms():
    reg, c, _ = make()
    p = Provider(reg, c)
    tid = c.get(f"/v2/codes/{code(10)}").json()["terms"]["id"]
    assert status(p, p.body(code(10), terms=tid, signers=[])) == "PG_TERMS_NOT_ACCEPTED"    # T-8


# ── serial 11: a minor, licensed for everything (likeness/1, the floor) ─

@pytest.mark.parametrize("categories,expected", [
    (None, "allow"), (["fashion"], "allow"),
    (["violence"], "PG_PROHIBITED_USE"), (["nsfw-art"], "PG_PROHIBITED_USE"),   # unknown word: fails closed
    (["sexual"], "PG_PROHIBITED_USE"), (["adult"], "PG_PROHIBITED_USE"),        # before the personal-signature rule
])
def test_a_minor(categories, expected):
    reg, c, _ = make()
    assert c.get(f"/v2/codes/{code(11)}").json()["subject_key"]["custody"] == "self"
    p = Provider(reg, c)
    body = p.body(code(11), purpose="commercial")
    if categories:
        body["use"]["categories"] = categories
    assert status(p, body) == expected


def test_an_unknown_word_fails_closed_only_for_a_minor():
    reg, c, _ = make()
    p = Provider(reg, c)
    assert status(p, {**p.body(code(1)), "use": {"purpose": "research", "categories": ["nsfw-art"]}}) == "allow"


# ── a sandbox made by 0.3 (serials 1-7 only) ────────────────────────────

OLD = ["Test subject 1 (allow)", "Test subject 2 (no licence)", "Test subject 3 (opted out)",
       "Test subject 4 (usage limit)", "Test subject 5 (prohibited)", "Test subject 6 (review)",
       "Test subject 7 (not blocked)"]


def old_sandbox(path, *own):
    """The subjects a 0.3 sandbox held: 1-7, then the operator's own numbered from 9."""
    reg = Registry(Config(prefix="TEST", name="Test", api="https://test.example"), Key(), str(path))
    for n, name in enumerate(OLD, 1):
        reg.add_subject(name, serial=n, level="verified")
    for n, name in enumerate(own, 9):
        reg.add_subject(name, serial=n)
    return reg.key


def test_an_older_sandbox_gains_serials_9_to_12_when_opened(tmp_path):
    key = old_sandbox(tmp_path / "registry.db")
    cfg = Config(prefix="TEST", name="Test", api="https://test.example", sandbox=True)
    for _ in range(2):                                                     # opening it again changes nothing
        reg = Registry(cfg, key, str(tmp_path / "registry.db"))
        assert [r["serial"] for r in reg._q("SELECT serial FROM subjects ORDER BY serial")] == [*range(1, 8), 9, 10, 11, 12]
    c = TestClient(create_app(reg))
    assert [o["subject_ref"] for o in c.get("/v2/catalog").json()["offers"]] == [code(9)]
    assert "terms" in c.get(f"/v2/codes/{code(10)}").json()
    p = Provider(reg, c)
    assert status(p, p.body(code(11))) == "allow"


def test_an_older_sandbox_whose_serial_9_is_the_operators_own_is_refused_clearly(tmp_path, capsys):
    key = old_sandbox(tmp_path / "registry.db", "My own test person")
    with pytest.raises(ValueError, match="PG-TEST-000009V"):                # even on a new key, nothing is written
        Registry(Config(prefix="TEST", name="Test", api="https://test.example", sandbox=True), Key(), str(tmp_path / "registry.db"))
    (tmp_path / "registry.json").write_text(json.dumps({"prefix": "TEST", "name": "Test", "api": "https://test.example",
                                                      "sandbox": True}))
    (tmp_path / "operator.key").write_text(key.private_hex)
    with pytest.raises(SystemExit, match="My own test person"):            # the CLI says so instead of a traceback
        cli(["subject", "list", "--dir", str(tmp_path)])
