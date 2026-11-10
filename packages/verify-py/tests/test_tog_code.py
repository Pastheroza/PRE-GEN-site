"""TOG-CODE.md: spec/test-vectors/tog-code.json, every section a verifier implements. verify-js runs the same file.
The `lookup` section is a registry's answer and runs in the registry package, not here."""
import json
import re
from pathlib import Path

import pytest

import pregen

ROOT = Path(__file__).resolve().parents[3]
V = json.loads((ROOT / "spec/test-vectors/tog-code.json").read_text())


def run(fn, *a):
    """{"result": …} or {"error": …, "hints"?}, as the vectors write it."""
    try:
        return {"result": fn(*a)}
    except pregen.NotACode as e:
        return {"error": "malformed", **({"hints": e.hints} if e.hints else {}),
                **({"message": str(e)} if str(e) == pregen.RETIRED else {})}
    except pregen.CodeError as e:
        return {"error": e.reason}


def without_name(case):
    return {k: v for k, v in case.items() if k not in ("name", "act", "record", "code", "input", "old",
                                                       "registry_speaks_tog")}


def test_alphabet():
    a = V["alphabet"]
    assert (pregen.CROCKFORD, pregen.TOG_VALUES, pregen._CHECKS) == (a["crockford"], a["tog_values"], a["check"])
    assert (pregen._MAX_BODY, pregen._TAIL, pregen.BARE_ISSUER) == (a["max_body"], a["tail_symbols"], a["bare_issuer"])
    assert {k: i + 1 for i, k in enumerate(pregen._FIVE)} == a["kind_digit"]
    assert (pregen._RESERVED_SERIAL, pregen._RESERVED_TAIL) == (a["reserved_serial"], a["reserved_tail"])
    assert list(pregen.FIXTURE_PREFIXES) == a["fixture_prefixes"]


@pytest.mark.parametrize("code", [c for cs in V["examples"].values() for c in cs])
def test_every_example_is_a_tog_code_and_its_own_key(code):
    assert pregen.parse_code(code)["marker"] == "TOG" and pregen.code_key(code) == code


@pytest.mark.parametrize("case", V["check_char"], ids=lambda c: c["body"])
def test_check_char(case):
    assert run(pregen.check_char, case["body"]).get("result") == case["tog"]
    assert run(pregen.check_char, case["body"], pregen.CROCKFORD).get("result") == case["pg"]


@pytest.mark.parametrize("case", V["parse"], ids=lambda c: c["code"])
def test_parse(case):
    r = run(pregen.parse_code, case["code"])
    assert ({"parsed": r["result"]} if "result" in r else r) == without_name(case)
    if "result" in r:
        assert pregen.kind_of(case["code"]) == r["result"]["kind"]


@pytest.mark.parametrize("case", V["describe"], ids=lambda c: c["code"])
def test_describe(case):
    assert run(pregen.describe, case["code"]) == without_name(case)


@pytest.mark.parametrize("case", V["must_reject"], ids=lambda c: c["why"])
def test_must_reject(case):
    assert run(pregen.parse_code, case["string"]) == {"error": case["error"]}


# The grammar pregen 0.13 published (PG-CODE.md §7), verbatim.
_0_13 = re.compile(r"PG-(?:([ABCDEFGHJKMNPQRSTVWXYZ]{4})-)?(?:[0-9]{6,}[0-9A-HJKMNP-TV-Z*~$=!]"
                   r"|[A-Z]{3}-[0-9]{6,}-[0-9A-HJKMNP-TV-Z]{6}[0-9A-HJKMNP-TV-Z*~$=!])|PG-[A-Z]{3}-[0-9]{6,}")


@pytest.mark.parametrize("code", V["refused_by_0_13"])
def test_the_0_13_grammar_refuses_every_tog_code(code):
    assert not _0_13.fullmatch(code)


@pytest.mark.parametrize("case", V["code_key"], ids=lambda c: c["code"])
def test_code_key(case):
    assert run(pregen.code_key, case["code"]) == without_name(case)


@pytest.mark.parametrize("case", V["typed"], ids=lambda c: repr(c["input"]))
def test_typed(case):
    assert run(pregen.normalize_typed, case["input"]) == without_name(case)


@pytest.mark.parametrize("case", V["code_for"], ids=lambda c: c["name"])
def test_code_for(case):
    assert run(pregen.code_for, case["act"]) == without_name(case)


@pytest.mark.parametrize("case", V["metadata"], ids=lambda c: c["name"])
def test_metadata(case):
    assert pregen.metadata_ok(case["meta"], case["act"], case["licence"]) is case["ok"]


@pytest.mark.parametrize("case", V["verdict"])
def test_verdict(case):
    assert pregen.code_verdict(case["file"], case["act"], case["caption"], case["ingredient"]) == case["words"]


@pytest.mark.parametrize("case", V["parties"]["cases"])
def test_parties(case):
    entries = V["parties"]["directories"][case["directory"]]
    assert pregen.check_parties(case["code"], entries, case["at"], case["provider"]) == \
        {"ok": case["ok"], "facts": case["facts"]}


def test_admission_in_order():
    built = {}
    for case in V["admission"]["in_order"]:
        assert sorted(built) == case["directory"]
        assert pregen.admission_refusal(case["prefix"], case["entity"], case["government"], built, ()) == case["refusal"]
        built[case["prefix"]] = {"entity": case["entity"]}


@pytest.mark.parametrize("case", V["admission"]["cases"], ids=lambda c: c["prefix"])
def test_admission(case):
    if case["directory"] is None:
        directory = {p: {"entity": e["entity"]} for p, e in V["admission"]["fixtures"].items()}
    else:
        directory = {p: {"entity": e} for p, e in case["directory"].items()}
    reserved = pregen.FIXTURE_PREFIXES if case["fixtures_reserved"] else ()
    refusal = pregen.admission_refusal(case["prefix"], case["entity"], case["government"], directory, reserved)
    assert bool(refusal) == bool(case["refusal"])          # refused or not is normative, the wording is not


@pytest.mark.parametrize("case", V["find_codes"], ids=lambda c: c["text"])
def test_find_codes(case):
    assert pregen.find_codes(case["text"]) == case["codes"]


@pytest.mark.parametrize("typed", ["PG–STD–000001–K7M2QX9", "PG-STD-000001-K7M2QX9.", "РG-STD-000001-K7M2QX9",
                                   "https://www.pregen.org/lookup/PG-STD-000001-K7M2QX9", "pg 000 042 *",
                                   "https://api2.prampta.com/v1/pg/PG-PRAM-000037J"])
def test_a_typed_pg_string_gets_the_retired_message_and_no_tog_suggestion(typed):
    with pytest.raises(pregen.NotACode) as e:
        pregen.normalize_typed(typed)
    assert str(e.value) == pregen.RETIRED and not e.value.hints and "TOG" not in str(e.value).upper().replace("TOG CODE", "")


@pytest.mark.parametrize("case", V["migrate"], ids=lambda c: c["old"])
def test_no_pg_string_is_a_code_anywhere(case):
    """Every old id a registry migrates is, from outside, not a code: parse, key, kind, issuer, describe, free text."""
    c = case["old"]
    if not c.startswith("PG-"):
        return
    for fn in (pregen.parse_code, pregen.code_key, pregen.kind_of, pregen.issuer_of, pregen.describe):
        with pytest.raises(pregen.NotACode):
            fn(c)
    assert pregen.find_codes(f"see {c}.") == [] and pregen.code_verdict("aa" * 32, caption=c) == "Not a code."
