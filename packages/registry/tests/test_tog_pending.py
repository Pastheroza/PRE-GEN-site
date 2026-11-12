"""lookup.md, ToG codes: a holder's code is issued pending, signs nothing, becomes active on proof and is deleted after
7 days without it; its serial is never issued again. A licence or record names the ToG code it is tied to."""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from pregen_registry import registry as registry_module
from pregen_registry.app import create_app
from pregen_registry.cli import main as cli
from pregen_registry.protocol import Key, parse_code
from pregen_registry.registry import TOG_PENDING, Config, Registry
from test_registry import Clock, Provider

DAY = 86400
TEMPLATE = {"id": "t", "version": 1}
LEGAL = {"sha256": "0" * 64, "url": "https://r.example/legal"}


def make(path=":memory:", **cfg):
    clock = Clock()
    reg = Registry(Config(prefix="TEST", name="Test", api="https://test.example", **cfg), Key(), path, clock=clock)
    c = TestClient(create_app(reg))
    return reg, c, clock, Provider(reg, c)


def test_a_pending_code_answers_pending_only_and_signs_nothing():
    reg, c, _, p = make()
    code = reg.add_subject("Lena", pending=True, published=1)       # even a published name stays hidden
    assert c.get(f"/v2/codes/{code}").json() == {"code": code, "kind": "subject", "registry": "TEST",
                                                 "status": "pending"}
    b = p.answer(p.body(code))["body"]
    assert (b["status"], b["reason"]) == ("not_blocked", "PG_SUBJECT_PENDING")   # permits and forbids nothing
    with pytest.raises(ValueError, match="pending"):
        reg.add_grant(code)
    with pytest.raises(ValueError, match="pending"):
        reg.publish_terms(code, purposes=["research"], template=TEMPLATE, legal=LEGAL)


def test_proof_makes_it_active_with_its_holder_and_level_and_no_unpublished_name():
    reg, c, _, p = make()
    code = reg.add_subject("Lena", pending=True)
    reg.prove(code)
    assert c.get(f"/v2/codes/{code}").json() == {"code": code, "kind": "subject", "registry": "TEST",
                                                 "status": "active", "holder": "person", "level": "channel"}
    assert p.answer(p.body(code))["body"]["reason"] == "PG_NO_LICENSE"            # its answers count now
    reg.set_published(code, True)
    assert c.get(f"/v2/codes/{code}").json()["name"] == "Lena"


def test_the_level_only_rises_and_only_a_pending_code_is_proved():
    reg, *_ = make()
    code = reg.add_subject("Lena", pending=True)
    reg.prove(code, "verified")
    reg.prove(code, "channel")
    assert reg.lookup(code)["level"] == "verified"
    with pytest.raises(ValueError, match="channel or verified"):
        reg.prove(code, "self")
    with pytest.raises(ValueError, match="not issued as a pending"):
        reg.prove(reg.add_subject("Operator's"))


def test_seven_days_unproved_deletes_the_code_for_good():
    reg, c, clock, p = make()
    code = reg.add_subject("Boris", pending=True)
    clock.t += TOG_PENDING - 1
    assert reg.lookup(code)["status"] == "pending"
    clock.t += 1
    assert c.get(f"/v2/codes/{code}").json() == {"code": code, "kind": "subject", "registry": "TEST",
                                                 "status": "expired"}
    assert p.answer(p.body(code))["body"]["reason"] == "PG_UNKNOWN_SUBJECT"
    with pytest.raises(ValueError):
        reg.prove(code)


def test_a_retired_serial_is_never_issued_again(monkeypatch):
    reg, _, clock, _ = make()
    code = reg.add_subject("Boris", pending=True)
    clock.t += TOG_PENDING
    reg.lookup(code)                                                  # the lazy expiry runs
    serial = int(parse_code(code)["serial"])
    draws = iter([serial, serial, 123456780])
    monkeypatch.setattr(registry_module, "mint_serial", lambda prefix: next(draws))
    assert int(parse_code(reg.add_subject("Someone new"))["serial"]) == 123456780


def test_only_pending_tog_codes_expire_never_an_operators_or_a_proved_one():
    reg, _, clock, _ = make()
    older, proved = reg.add_subject("Marketplace subject", published=1), reg.add_subject("Lena", pending=True)
    reg.prove(proved)
    clock.t += 30 * DAY
    assert reg.lookup(older)["status"] == "active" and reg.lookup(proved)["status"] == "active"


def test_a_company_code_has_a_persons_form_and_one_domain_one_code():
    reg, *_ = make()
    code = reg.add_subject("Northwind Coffee", pending=True, domain="northwind.example")
    assert parse_code(code)["shape"] == "person"
    reg.prove(code)
    got = reg.lookup(code)
    assert (got["holder"], got["domain"], got["level"]) == ("company", "northwind.example", "channel")
    with pytest.raises(sqlite3.IntegrityError):
        reg.add_subject("Impostor", pending=True, domain="northwind.example")


def test_a_licence_and_an_allow_name_the_tog_code_they_are_tied_to():
    reg, c, _, p = make(tog_yes=True)
    code = reg.add_subject("Lena", pending=True)
    reg.prove(code, "verified")
    gid = reg.add_grant(code, licensee_id=p.id)
    lic = reg.db.execute("SELECT code FROM grants WHERE id = ?", (gid,)).fetchone()["code"]
    got = c.get(f"/v2/codes/{lic}").json()
    assert (got["subject"], got["subject_level"]) == (code, "verified")
    r = p.ask(p.body(code)).json()
    got = c.get(f"/v2/codes/{r['code']}").json()
    assert (got["kind"], got["subject"], got["subject_level"]) == ("generated", code, "verified")


def test_a_yes_stays_shut_until_the_setting_opens_it_and_then_needs_identity():
    """lookup.md: only `verified` may open a use; and a ToG yes stays shut by default (Config.tog_yes)."""
    for opened in (False, True):
        reg, c, _, p = make(tog_yes=opened)
        channel, verified = reg.add_subject("Lena", pending=True), reg.add_subject("Maya", pending=True)
        reg.prove(channel)
        reg.prove(verified, "verified")
        with pytest.raises(ValueError, match="verified"):
            reg.add_grant(channel, licensee_id=p.id)
        with pytest.raises(ValueError, match="verified"):
            reg.publish_terms(channel, purposes=["research"], template=TEMPLATE, legal=LEGAL)
        assert p.answer(p.body(channel))["body"]["reason"] == "PG_NO_LICENSE"
        if opened:
            reg.add_grant(verified, licensee_id=p.id)
        else:
            with pytest.raises(ValueError, match="shut"):
                reg.add_grant(verified, licensee_id=p.id)


def test_a_licence_of_an_unpublished_person_never_names_them():
    reg, c, _, p = make()
    hidden = reg.add_subject("Hidden", level="verified")
    gid = reg.add_grant(hidden, licensee_id=p.id)
    lic = reg.db.execute("SELECT code FROM grants WHERE id = ?", (gid,)).fetchone()["code"]
    assert c.get(f"/v2/codes/{hidden}").json()["status"] == "unknown"
    got = c.get(f"/v2/codes/{lic}").json()
    assert got["status"] == "active" and "subject" not in got and "subject_level" not in got
    reg.set_published(hidden, True)
    assert c.get(f"/v2/codes/{lic}").json()["subject"] == hidden


def test_a_pending_code_is_never_listed_as_opted_out_in_anchors():
    reg, c, _, _ = make()
    code = reg.add_subject("Lena", pending=True)
    reg.set_identity(code, anchor="wikidata:Q1")
    reg.opt_out(code)
    assert [a["code"] for a in c.get("/v2/anchors").json()["body"]["anchors"]] == []
    reg.prove(code)
    assert [a["status"] for a in c.get("/v2/anchors").json()["body"]["anchors"]] == ["opted_out"]


def test_an_expired_code_cannot_be_proved_even_if_nothing_looked_it_up():
    reg, _, clock, _ = make()
    code = reg.add_subject("Boris", pending=True)
    clock.t += 8 * DAY                                                # no lookup or request ran the lazy expiry
    with pytest.raises(ValueError):
        reg.prove(code)
    assert reg.lookup(code)["status"] == "expired"


def test_one_domain_one_code_whatever_its_spelling():
    reg, *_ = make()
    code = reg.add_subject("Northwind", pending=True, domain="Northwind.Example.")
    reg.prove(code)
    assert reg.lookup(code)["domain"] == "northwind.example"
    with pytest.raises(sqlite3.IntegrityError):
        reg.add_subject("Impostor", pending=True, domain="northwind.example")
    assert reg.lookup(reg.add_subject("Bücher", pending=True, domain="bücher.example"))["status"] == "pending"
    assert reg.db.execute("SELECT 1 FROM subjects WHERE domain = 'xn--bcher-kva.example'").fetchone()


def test_a_database_from_before_pending_codes_gains_the_columns(tmp_path):
    db = tmp_path / "r.db"
    reg, *_ = make(str(db))
    older = reg.add_subject("Before", published=1)
    reg.db.execute("DROP INDEX subjects_domain")
    for col in ("holder", "domain", "tog_issued_at", "proved_at"):
        reg.db.execute(f"ALTER TABLE subjects DROP COLUMN {col}")
    reg.db.close()
    again, *_ = make(str(db))
    assert again.lookup(older)["holder"] == "person"
    assert again.lookup(again.add_subject("After", pending=True))["status"] == "pending"


def test_cli_adds_a_pending_code_and_proves_it(tmp_path, capsys):
    cli(["init", "--dir", str(tmp_path), "--prefix", "ABCD", "--name", "R", "--api", "https://r.example"])
    capsys.readouterr()
    cli(["subject", "add", "--dir", str(tmp_path), "--name", "Lena", "--pending"])
    code = capsys.readouterr().out.strip()
    cli(["subject", "prove", "--dir", str(tmp_path), "--code", code, "--by", "verified"])
    assert "active (verified)" in capsys.readouterr().out
    with pytest.raises(SystemExit, match="needs --code"):
        cli(["subject", "prove", "--dir", str(tmp_path)])
