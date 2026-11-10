"""extensions/terms.md: a person's terms as a signed record, the floor and the person's rules, and what a proof shows
about the terms its request accepted. spec/test-vectors/terms.json runs here and in verify-js (test/terms.test.js); the
tables below hold only what the vectors do not."""
import hashlib
import json
from pathlib import Path

import pytest

import pregen

ROOT = Path(__file__).resolve().parents[3]
V = json.loads((ROOT / "spec/test-vectors/answers.json").read_text())
T = json.loads((ROOT / "spec/test-vectors/terms.json").read_text())
NOW, CODE, OTHER_CODE = V["now"], "TOG-TEST-000001N", "TOG-TEST-0000034"
D = pregen.verify_directory(V["directory"], V["steward_public_key_hex"], now=NOW)
get_json = V["key_sets"].__getitem__
DROP = object()


def seed(name):
    return hashlib.sha256(f"pregen-answer-vector-{name}".encode()).hexdigest()


def signer(key):
    return [{"role": "registry", "key_id": pregen.fingerprint(pregen.public_key_hex(key))}]


RULES = {"purposes": ["editorial", "personal"], "excluded_categories": ["gambling", "political"]}


def terms(key=seed("registry"), **change):
    body = {"signers": signer(key), "subject_ref": CODE, "profile": "likeness/1", "version": 1,
            "template": {"id": "prampta-likeness", "version": 1, "jurisdiction": "US"},
            "legal": {"sha256": "b" * 64, "url": "https://registry.test.example/terms-template-1.txt"},
            "rules": RULES, "minor": False, "assent": "registry", "instruction": "c" * 64, "factor": "authenticator",
            "issued_at": NOW - 100}
    body.update(change)
    return pregen.sign_envelope("pg.terms.v1", {k: v for k, v in body.items() if v is not DROP}, key)


def check(env, code=CODE):
    return pregen.check_terms(env, code, D, get_json)


# ── vocabulary and floor (TC1, TH1, TH6; D3: advertising is the 16th code) ──

def test_the_closed_vocabulary_holds_the_floor():
    assert len(pregen.CATEGORIES) == 16 and "advertising" in pregen.CATEGORIES
    assert pregen.INTIMATE <= pregen.PROHIBITED_FOR_MINORS <= pregen.CATEGORIES
    assert pregen.PROHIBITED_FOR_MINORS == {"sexual", "adult", "violence"} and pregen.INTIMATE == {"sexual", "adult"}


# the floor never reads a spelling of its own words as the word: the caller refuses it as outside CATEGORIES
SPELLED = [{"purpose": "personal", "categories": c} for c in (["Sexual"], ["ADULT"], ["sex‍ual"], ["adult "], ["аdult"])]
FLOOR = [(v["use"], v["minor"], v["result"]) for v in T["floor"]] + [(use, True, None) for use in SPELLED]


@pytest.mark.parametrize("use,minor,expected", FLOOR)
def test_floor(use, minor, expected):
    assert pregen.floor(use, minor) == expected


@pytest.mark.parametrize("categories", ["sexual", [["adult"]], [1]])
def test_floor_refuses_categories_that_are_not_a_list_of_words(categories):
    with pytest.raises(pregen.PregenError):
        pregen.floor({"purpose": "personal", "categories": categories}, True)


FORBIDS = [(v["rules"], v["use"], v["result"]) for v in T["forbids"]]


@pytest.mark.parametrize("rules,use,expected", FORBIDS)
def test_forbids(rules, use, expected):
    assert pregen.forbids(rules, use) == expected


OPENS = [(v["old"], v["new"], v["result"]) for v in T["opens"]]


@pytest.mark.parametrize("old,new,expected", OPENS)
def test_terms_opens(old, new, expected):
    assert pregen.terms_opens(old, new) is expected


# ── the record ──

@pytest.mark.parametrize("v", T["records"], ids=lambda v: v["name"])
def test_record_vectors(v):
    if v["ok"]:
        assert check(v["envelope"], v["code"]) == v["envelope"]["body"]
    else:
        with pytest.raises(pregen.PregenError):
            check(v["envelope"], v["code"])


def test_a_published_version_checks_out_and_says_whose_word_it_is():
    env = terms()
    body = check(env)
    assert body == env["body"] and body["assent"] == "registry"
    later = terms(version=2, amends=pregen.message_id("pg.terms.v1", body), factor=DROP)  # it only narrows: no factor
    assert check(later)["version"] == 2


@pytest.mark.parametrize("change", [   # beyond the vectors
    {"profile": "likeness/2"}, {"instruction": DROP}, {"minor": 0}, {"issued_at": -1}, {"subject_ref": OTHER_CODE},
    {"rules": {"excluded_categories": []}},
    {"template": {"id": "prampta-likeness", "version": 1}}, {"template": {"id": "Prampta", "version": 1, "jurisdiction": "US"}},
    {"template": {"id": "prampta-likeness", "version": 1, "jurisdiction": "U‍S"}},
    {"legal": {"sha256": "B" * 64, "url": "https://x"}},
    {"legal": {"sha256": "b" * 64, "url": "https://x/a b"}}, {"legal": {"sha256": "b" * 64, "url": "https://" + "x" * 2041}},
    {"template": {"id": "prampta-likeness", "version": 1, "jurisdiction": "USA"}},
])
def test_anything_else_is_refused(change):
    with pytest.raises(pregen.PregenError):
        check(terms(**change))


def test_pl1_a_number_canonical_json_refuses_is_refused_not_crashed():
    env = terms()
    for change in ({"version": 1.5}, {"version": 2**53}, {"issued_at": NOW + 0.5}):
        with pytest.raises(pregen.PregenError, match="signed JSON"):
            check({**env, "body": {**env["body"], **change}})


def test_pl1_an_integral_number_is_that_integer_however_it_is_written():
    # JSON.parse reads 1.0 and 1e0 as 1, so verify-js accepts them; json.loads reads a float. Same text, same
    # finding (test/terms.test.js runs these texts too).
    env = terms()
    text = json.dumps(env).replace('"version": 1,', '"version": 1.0,').replace(f'"issued_at": {NOW - 100}', f'"issued_at": {NOW - 100}e0')
    assert type(json.loads(text)["body"]["version"]) is float
    assert check(json.loads(text)) == env["body"]
    assert pregen.message_id("pg.terms.v1", json.loads(text)["body"]) == pregen.message_id("pg.terms.v1", env["body"])


def test_pm1_pm10_only_this_persons_terms_signed_by_their_registrys_key():
    with pytest.raises(pregen.PregenError, match="another person"):
        check(terms(), OTHER_CODE)
    with pytest.raises(pregen.PregenError, match="may not sign"):              # another registry's key (PM10)
        check(terms(key=seed("other_registry")))
    env = terms()
    with pytest.raises(pregen.PregenError, match="bad signature"):
        check({**env, "body": {**env["body"], "minor": True}})
    two = {**env, "body": {**env["body"], "signers": env["body"]["signers"] * 2}, "signatures": env["signatures"] * 2}
    with pytest.raises(pregen.PregenError, match="exactly one registry key"):
        check(two)


# ── what a proof shows about the terms (D1: cited only through the provider's signed request) ──

POLICY, GRANT = {"kind": "policy", "rule": "test"}, {"kind": "grant", "grant": {"format": "pg.grant.v1", "id": "e" * 64}}
USE = {"purpose": "personal", "categories": ["fashion"]}


def finding(use=USE, record=None, cite=None, carry=True, basis=POLICY, code=CODE):
    record = record or terms()
    key, s = seed("registry"), signer(seed("registry"))
    asked = {"subject_ref": code, "provider_id": "https://frame.example", "profile": "likeness/1", "use": use,
             "job_id": "job-1", "job_hash": "a" * 64}
    if cite is not DROP:
        asked["terms"] = cite or pregen.message_id("pg.terms.v1", record["body"])
    answer = pregen.sign_envelope("pg.answer.v1", {
        "signers": s, "request_id": pregen.message_id("pg.request.v1", asked), "profile": "likeness/1",
        "status": "allow", "basis": basis, "issued_at": NOW - 10, "expires_at": NOW + 290}, key)
    report = {"type": "pg.report.v1", "signatures": [], "body": {
        "answer": pregen.message_id("pg.answer.v1", answer["body"]), "outcome": "generated", "output_hash": "d" * 64,
        "job_id": "job-1", "occurred_at": NOW}}
    ack = pregen.sign_envelope("pg.report_ack.v1", {"signers": s, "report": pregen.message_id("pg.report.v1", report["body"]),
                                                    "answer": report["body"]["answer"], "received_at": NOW}, key)
    item = {"request": {"type": "pg.request.v1", "body": asked, "signatures": []}, "answer": answer, "report": report, "ack": ack}
    if carry:
        item["terms"] = record
    s0 = pregen.check_proof({"format": "pg.proof.v1", "subjects": [item]}, D, get_json, now=NOW)["subjects"][0]
    return s0["terms"], s0["terms_assent"]


def test_a_proof_for_a_false_claim_is_refused():   # identity round B4e: check_proof skipped the steward's ruling
    with pytest.raises(pregen.PregenError, match="false claim"):
        finding(code="TOG-TEST-000002Z", cite=DROP, carry=False)


@pytest.mark.parametrize("v", T["proofs"], ids=lambda v: v["name"])
def test_proof_vectors(v):
    s0 = pregen.check_proof(v["bundle"], D, get_json, now=NOW)["subjects"][0]
    assert (s0["terms"], s0["terms_assent"]) == (v["terms"], v["terms_assent"])


def test_pl1_a_proof_reads_integral_numbers_as_verify_js_does():
    text = json.dumps(T["proofs"][0]["bundle"])
    for spelled in (text.replace('"version": 1,', '"version": 1.0,'),                     # the carried terms
                    text.replace(f'"issued_at": {NOW - 10},', f'"issued_at": {NOW - 10}.0,')):  # the answer (core)
        assert spelled != text
        s0 = pregen.check_proof(json.loads(spelled), D, get_json, now=NOW)["subjects"][0]
        assert (s0["terms"], s0["terms_assent"]) == ("ok", "registry")


def test_terms_in_a_proof():   # beyond the vectors
    assert finding() == ("ok", "registry")
    assert finding(cite=DROP, carry=False) == ("absent", None)
    assert finding(cite="f" * 64) == ("unverified", None)                                    # not the version accepted
    assert finding(record=terms(subject_ref=OTHER_CODE)) == ("unverified", None)              # PM1
    assert finding(use={"purpose": "commercial"}) == ("outside", "registry")
    assert finding(use={"purpose": "personal", "categories": ["adult"]}, basis=GRANT) == ("outside", "registry")  # never the floor
    assert finding(use={"purpose": "personal", "categories": ["violence"]}) == ("ok", "registry")
    for spelled in (["Sexual"], "fashion"):                                         # TC1: never PG_MALFORMED-free
        assert finding(use={"purpose": "personal", "categories": spelled}) == ("outside", "registry")
