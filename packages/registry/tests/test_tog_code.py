"""The ToG code at the registry (spec/TOG-CODE.md): every code written TOG-; PG code is incompatible, so a PG- string
is not a code (refused like any other non-code) and the registry migrates its own rows once; new persons at random;
act and licence codes computed from the signed records."""
import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pregen import PregenError, check_char, check_proof, code_for, message_id, parse_code
from test_identity_market import World
from test_registry import Provider, code, make

from pregen_registry.app import create_app
from pregen_registry.protocol import Key
from pregen_registry.registry import PURPOSES, Config, Registry

VECTORS = json.loads((Path(__file__).parents[3] / "spec" / "test-vectors" / "tog-code.json").read_text())


def pg(tog):
    return "PG" + tog[3:]


def mistyped(c):
    return c[:-1] + ("1" if c[-1] != "1" else "2")


def test_lookup_vectors():
    """test-vectors/tog-code.json `lookup`: a person found by number; an over-padded number PG_MALFORMED with the code
    as a hint; a string that is not a code, a PG- string included, 400 with no hint."""
    regs = {}
    for c in VECTORS["lookup"]["issued"]:
        p = parse_code(c)
        if not p["issuer"]:
            continue                      # the bare namespace is the first registry's: this registry never holds it
        reg = Registry(Config(prefix=p["issuer"], name="R", api="https://r.example"), Key())
        assert reg.add_subject("Person", serial=int(p["serial"]), published=1) == c
        regs[p["issuer"]] = TestClient(create_app(reg))
    tried = 0
    for case in VECTORS["lookup"]["cases"]:
        if case.get("error"):                          # not a code: every registry refuses it alike
            for http in regs.values():
                r = http.get(f"/v2/codes/{case['asked']}")
                assert (r.status_code, r.json()["error"], "hint" in r.json()) == (400, "invalid_format", False), case
            tried += 1
            continue
        issuer = parse_code(case["asked"], check=False)["issuer"]
        if issuer not in regs:
            continue
        tried += 1
        r = regs[issuer].get(f"/v2/codes/{case['asked']}")
        if case["status"] == "found":
            assert (r.status_code, r.json()["code"], r.json()["status"]) == (200, case["code"], "active"), case
        elif case["status"] == "PG_MALFORMED":
            assert (r.status_code, r.json()["error"], r.json()["hint"]) == (422, "PG_MALFORMED", case["hint"]), case
        else:
            assert (r.status_code, r.json()["status"]) == (200, "unknown"), case
    assert tried == 8


def test_a_0_4_database_is_migrated_once_and_a_pg_string_is_refused_everywhere(tmp_path):
    """A database made by 0.4 holds PG- rows. At open the registry respells its own rows by the marker (same serial
    and check); signed envelopes keep their bytes. From outside, a PG- string is not a code anywhere."""
    db = str(tmp_path / "r.db")
    reg = Registry(Config(prefix="TEST", name="T", api="https://t.example"), Key(), db)
    tog = reg.add_subject("Maya", level="verified", published=1, serial=42)
    reg.set_identity(tog, anchor="wikidata:Q1", proof_url="https://maya.example/p")
    gid = reg.add_grant(tog, purposes=["research"])
    lic = reg._row("SELECT code FROM grants WHERE id = ?", (gid,))["code"]
    for table, col in (("subjects", "code"), ("grants", "subject_code")):              # as 0.4 stored them
        reg.db.execute(f"UPDATE {table} SET {col} = ? WHERE {col} = ?", (pg(tog), tog))
    reg.db.execute("UPDATE grants SET code = NULL")
    again = Registry(Config(prefix="TEST", name="T", api="https://t.example"), reg.key, db)
    assert [r[0] for r in again.db.execute("SELECT code FROM subjects")] == [tog]
    assert [tuple(r) for r in again.db.execute("SELECT subject_code, code FROM grants")] == [(tog, lic)]
    c = TestClient(create_app(again))
    assert c.get(f"/v2/codes/{tog}").json()["code"] == tog
    assert c.get(f"/v2/codes/{lic}").json()["status"] == "active"
    r = c.get(f"/v2/codes/{pg(tog)}")
    assert (r.status_code, r.json()["error"], "hint" in r.json()) == (400, "invalid_format", False)
    assert c.get("/v2/anchors").json()["body"]["anchors"][0]["code"] == tog
    p = Provider(again, c)
    assert p.answer(p.body(tog, job="j1"))["body"]["status"] == "allow"
    r = p.ask(p.body(pg(tog), job="j2"))                # a PG string: not a code, no answer
    assert (r.status_code, r.json()["error"]) == (422, "PG_MALFORMED")
    again.opt_out(tog)
    assert p.answer(p.body(tog, job="o1"))["body"]["reason"] == "PG_SUBJECT_OPTED_OUT"
    r = p.ask(p.body(pg(tog), job="o2"))                # fails closed: a refusal is never bypassed by spelling
    assert (r.status_code, r.json()["error"]) == (422, "PG_MALFORMED")
    with pytest.raises(ValueError):
        again.opt_out(pg(tog))                           # an operator action takes the code only


def test_never_a_signed_answer_to_an_over_padded_number_or_a_string_that_is_not_a_persons_code():
    reg, c, _ = make()
    p = Provider(reg, c)
    for asked, error in ((mistyped(code(1)), "mistyped"), (pg(code(1)), "a PG string"),
                         ("PG-TEST-00000001N", "PG person, 8 digits"),
                         ("TOG-LIC-TEST-ABCD-ABCD-ABC" + "0", "an event code")):
        r = p.ask(p.body(asked, job=asked))
        assert (r.status_code, r.json()["error"]) == (422, "PG_MALFORMED"), error
    padded = "TOG-TEST-0000001" + check_char("TEST0000001")   # serial 1 written with 7 digits, its own check
    assert parse_code(padded)["serial"] == "0000001"
    r = p.ask(p.body(padded))
    assert (r.status_code, r.json()["error"], r.json()["hint"]) == (422, "PG_MALFORMED", code(1))


def test_an_unpublished_person_answers_as_never_issued_unless_they_refused():
    reg, c, _ = make(sandbox=False)
    quiet, refused = reg.add_subject("Quiet"), reg.add_subject("Refused")
    reg.opt_out(refused)
    assert c.get(f"/v2/codes/{quiet}").json() == {"code": quiet, "kind": "subject", "registry": "TEST",
                                                  "status": "unknown"}
    assert c.get(f"/v2/codes/{refused}").json() == {"code": refused, "kind": "subject", "registry": "TEST",
                                                    "status": "opted_out"}
    assert c.get(f"/v2/codes/{code(1, 'NWRD')}").json() == {"code": code(1, "NWRD"), "kind": "subject",
                                                            "registry": "NWRD", "status": "other_registry",
                                                            "directory": "https://www.pregen.org/registries.v3.json"}


def test_an_allow_has_one_pg_lic_code_and_its_licence_one_lic_code_both_computed_and_looked_up():
    w = World()
    reg, http = w.regs["AAAA"]
    p = Provider(reg, http)
    p.register()
    s = reg.add_subject("Creator", level="verified")
    gid = reg.add_grant(s, purposes=PURPOSES)
    body = p.body(s, purpose="commercial")
    r = p.ask(body).json()
    answer = r["answer"]
    act = {"type": "pg.answer.v1", "id": message_id("pg.answer.v1", answer["body"]), "signer": "AAAA",
           "subject_ref": s, "grant": {"id": gid, "signer": "AAAA"}}
    assert r["code"] == code_for(act) and r["code"].startswith("TOG-PG-LIC-AAAA-")
    assert p.ask(body).json()["code"] == r["code"]                          # one allow, one code
    lic = code_for({"type": "pg.grant.v1", "id": gid, "signer": "AAAA", "subject_ref": s})
    assert http.get(f"/v2/codes/{lic}").json() == {"code": lic, "kind": "license", "registry": "AAAA",
                                                    "status": "active", "issuer": "AAAA"}
    looked = http.get(f"/v2/codes/{r['code']}").json()
    assert looked == {"code": r["code"], "kind": "generated", "registry": "AAAA", "status": "valid",
                      "issued_at": answer["body"]["issued_at"], "purpose": "commercial", "provider": p.id,
                      "reported": False}                                     # allowed; no output reported
    video = hashlib.sha256(b"the video").hexdigest()
    report = p.report(answer, output_hash=video)
    assert p.send(report).status_code == 200
    assert http.get(f"/v2/codes/{r['code']}").json()["reported"] is True
    assert "proof" not in http.get(f"/v2/codes/{r['code']}?media={'f' * 64}").json()   # another file: no record
    entry = http.get(f"/v2/codes/{r['code']}?media={video}").json()["proof"]
    bundle = http.get(f"/v2/proofs/{message_id('pg.report.v1', report['body'])[:16]}").json()
    assert bundle["subjects"] == [entry]
    assert (entry["code"], entry["licence"], message_id("pg.grant.v1", entry["grant"]["body"])) == (r["code"], lic, gid)
    check_proof(bundle, w.directory, w.get_json, output_sha256=video, now=NOW_LATER(answer))
    for member, wrong in (("code", mistyped(r["code"])), ("licence", mistyped(lic))):
        doctored = {"format": "pg.proof.v1", "subjects": [{**entry, member: wrong}]}
        with pytest.raises(PregenError, match="readable copy"):
            check_proof(doctored, w.directory, w.get_json, output_sha256=video, now=NOW_LATER(answer))
    assert http.get(f"/v2/codes/{mistyped(r['code'])}").json()["error"] == "mistyped"   # apart from unknown


def NOW_LATER(answer):
    return answer["body"]["issued_at"] + 60


def test_an_act_with_no_code_or_a_code_issued_already_is_signed_again_with_a_changed_body():
    reg, c, clock = make(sandbox=False)
    s = reg.add_subject("Maya")
    real, calls = reg._code, []

    def first_gives_none(*a, **k):
        calls.append(1)
        return None if len(calls) == 1 else real(*a, **k)
    reg._code = first_gives_none
    gid = reg.add_grant(s, purposes=["research"], days=1)
    grant = reg.grant(gid)["grant"]["body"]
    assert grant["expires_at"] < clock.t + 86400       # signed again, shorter (a second try may give no code too)
    calls.clear()
    p = Provider(reg, c)
    a = p.answer(p.body(s))["body"]
    assert a["expires_at"] < a["issued_at"] + reg.ttl     # signed again; a second try may give no code too (1 in 7)
    assert reg._row("SELECT expires_at FROM answers WHERE code IS NOT NULL")["expires_at"] == a["expires_at"]


def test_records_signed_before_0_5_get_their_codes_by_computation(tmp_path):
    db = str(tmp_path / "r.db")
    reg = Registry(Config(prefix="TEST", name="T", api="https://t.example"), Key(), db)
    s = reg.add_subject("Maya")
    gid = reg.add_grant(s, purposes=["research"])
    p = Provider(reg, TestClient(create_app(reg)))
    p.answer(p.body(s))
    codes = [tuple(r) for r in reg.db.execute("SELECT code FROM grants UNION ALL SELECT code FROM answers")]
    reg.db.execute("UPDATE grants SET code = NULL")                         # as a 0.4 database holds them
    reg.db.execute("UPDATE answers SET code = NULL")
    again = Registry(Config(prefix="TEST", name="T", api="https://t.example"), reg.key, db)
    assert [tuple(r) for r in again.db.execute("SELECT code FROM grants UNION ALL SELECT code FROM answers")] == codes
    assert again.lookup(codes[0][0])["status"] == "active" and again.lookup(codes[0][0])["code"].startswith("TOG-LIC-")
    assert json.loads(again._row("SELECT envelope FROM grants")["envelope"]) == json.loads(
        reg._row("SELECT envelope FROM grants WHERE id = ?", (gid,))["envelope"])   # the record itself never changes
