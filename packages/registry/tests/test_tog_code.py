"""The ToG code at the registry (spec/TOG-CODE.md, hard switch): every code written TOG-, a PG- string only legacy
input for the same person, new persons at random, and act and licence codes computed from the signed records."""
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
    """test-vectors/tog-code.json `lookup`: a person found by number, in either spelling, answered in TOG; an
    over-padded number PG_MALFORMED with the TOG spelling as a hint; a string that is not a code 400."""
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
        issuer = parse_code(case["asked"], check=False)["issuer"]
        if issuer not in regs:
            continue
        tried += 1
        r = regs[issuer].get(f"/v2/codes/{case['asked']}")
        if case.get("error"):
            assert (r.status_code, r.json()["error"]) == (400, "invalid_format"), case
        elif case["status"] == "found":
            assert (r.status_code, r.json()["code"], r.json()["status"]) == (200, case["code"], "active"), case
        elif case["status"] == "PG_MALFORMED":
            assert (r.status_code, r.json()["error"], r.json()["hint"]) == (422, "PG_MALFORMED", case["hint"]), case
        else:
            assert (r.status_code, r.json()["status"]) == (200, "unknown"), case
    assert tried == 6


def test_a_pg_born_person_is_written_tog_and_both_spellings_are_one_person():
    """A database made by 0.4 keeps its PG- rows (records are never rewritten); everything written now says TOG-."""
    reg, c, _ = make(sandbox=False)
    tog = reg.add_subject("Maya", level="verified", published=1, serial=42)
    reg.db.execute("UPDATE subjects SET code = ? WHERE code = ?", (pg(tog), tog))          # as 0.4 stored it
    reg.set_identity(pg(tog), anchor="wikidata:Q1", proof_url="https://maya.example/p")
    gid = reg.add_grant(tog, purposes=["research"])
    assert reg.grant(gid)["grant"]["body"]["subject_ref"] == tog
    for asked in (tog, pg(tog)):
        assert c.get(f"/v2/codes/{asked}").json()["code"] == tog
    assert c.get("/v2/anchors").json()["body"]["anchors"][0]["code"] == tog
    p = Provider(reg, c)
    assert p.answer(p.body(pg(tog), job="j1"))["body"]["status"] == "allow"            # legacy input, answered
    r = p.ask(p.body(tog, job="j1"))                     # the other spelling in the same job: the same ask
    assert (r.status_code, r.json()["error"]) == (409, "PG_ASK_CONFLICT")
    reg.opt_out(tog)                                     # a refusal cannot be bypassed by spelling
    for n, asked in enumerate((tog, pg(tog))):
        assert p.answer(p.body(asked, job=f"o{n}"))["body"]["reason"] == "PG_SUBJECT_OPTED_OUT"


def test_never_a_signed_answer_to_an_over_padded_number_or_a_string_that_is_not_a_persons_code():
    reg, c, _ = make()
    p = Provider(reg, c)
    for asked, error in ((mistyped(pg(code(1))), "mistyped"), ("PG-TEST-00000001N", "PG person, 8 digits"),
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
    assert grant["expires_at"] == clock.t + 86400 - 1                         # signed again, a second shorter
    calls.clear()
    p = Provider(reg, c)
    a = p.answer(p.body(s))["body"]
    assert a["expires_at"] == a["issued_at"] + reg.ttl - 1
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
