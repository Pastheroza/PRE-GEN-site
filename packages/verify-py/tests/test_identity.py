"""extensions/identity.md in the library (stress identity round, fix B): which channels count, where a confirmation
may stand, what an unreadable page means, and an anchor list that fails blocks only the people it held.
tests/identity_cases.json runs here and in verify-js (test/identity.test.js), so both libraries read every case alike."""
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import pregen

HERE = Path(__file__).resolve().parent
CASES = json.loads((HERE / "identity_cases.json").read_text())
V = json.loads((HERE.parents[2] / "spec/test-vectors/answers.json").read_text())
ANCHOR_LISTS = json.loads((HERE.parents[2] / "spec/test-vectors/anchors.json").read_text())
NOW, KEY = V["now"], hashlib.sha256(b"pregen-answer-vector-registry").hexdigest()
D = pregen.verify_directory(V["directory"], V["steward_public_key_hex"], now=NOW)


def page(value):
    def get_text(url):
        if value == "RAISE":
            raise OSError("HTTP 429")
        return value
    return get_text


@pytest.mark.parametrize("case", CASES["channel"], ids=lambda c: c["name"])
def test_check_channel_proof(case):
    run = lambda: pregen.check_channel_proof(case["code"], case["proof_url"], case["official"], page(case["page"]),  # noqa: E731
                                             seen_confirmed=case["seen_confirmed"])
    if case["expect"] == "raises":
        with pytest.raises(OSError):
            run()
    else:
        assert run() is case["expect"]


@pytest.mark.parametrize("case", CASES["wikidata"], ids=lambda c: c["name"])
def test_wikidata_official_urls(case):
    get_json = lambda url: {"entities": {"Q11571": {"claims": case["claims"]}}}  # noqa: E731
    assert pregen.wikidata_official_urls("wikidata:Q11571", get_json=get_json, now=CASES["now"]) == case["expect"]


@pytest.mark.parametrize("body", [{"entities": {"Q1": {"claims": {}}}}, {"entities": {}}, {}])
def test_a_merged_or_missing_entity_is_refused(body):
    with pytest.raises(pregen.PregenError, match="no entity"):
        pregen.wikidata_official_urls("wikidata:Q11571", get_json=lambda url: body)


@pytest.mark.parametrize("case", CASES["wikidata_at"], ids=lambda c: c["name"])
def test_wikidata_official_urls_as_the_item_stood(case):
    answers = {CASES["wikidata_at_api"]: case["revisions"],
               CASES["wikidata_at_entity"]: {"entities": {"Q11571": {"claims": case["claims"]}}}}
    run = lambda: pregen.wikidata_official_urls("wikidata:Q11571", get_json=answers.__getitem__,  # noqa: E731
                                                now=CASES["now"], at=CASES["now"] - pregen.SETTLED_AFTER)
    if isinstance(case["expect"], dict):
        with pytest.raises(pregen.PregenError, match=case["expect"]["raises"]):
            run()
    else:
        assert run() == case["expect"]


@pytest.mark.parametrize("case", CASES["decide"], ids=lambda c: c["name"])
def test_decide_identity(case):
    run = lambda: pregen.decide_identity(case["claims"], frozen=case.get("frozen"))  # noqa: E731
    if case["expect"] == "raises":
        with pytest.raises(pregen.PregenError, match="no decision"):
            run()
    else:
        assert run() == case["expect"]


STEWARD = Ed25519PrivateKey.generate()
STEWARD_HEX = STEWARD.public_key().public_bytes_raw().hex()


def signed(sequence, add):
    d = {k: v for k, v in V["directory"].items() if k not in ("signature", "false_claims")}
    d = {**d, "sequence": sequence, "steward_key_id": pregen.fingerprint(STEWARD_HEX), **add}
    return {**d, "signature": STEWARD.sign(pregen.canonical_json(d)).hex()}


@pytest.mark.parametrize("case", CASES["directory"], ids=lambda c: c["name"])
def test_directory_freezes_false_claims_and_reversals(case):
    prev = signed(1, case["previous"]) if "previous" in case else None
    run = lambda: pregen.verify_directory(signed(2, case["add"]), STEWARD_HEX, previous=prev, now=NOW)  # noqa: E731
    if "raises" in case:
        with pytest.raises(pregen.PregenError, match=case["raises"]):
            run()
        return
    d = run()
    for anchor, at, expect in case.get("frozen", []):
        assert bool(d.frozen(anchor, at)) is expect, (anchor, at)
    for code, anchor, expect in case.get("false_claim", []):
        assert d.is_false_claim(code, anchor) is expect, (code, anchor)


def anchors(entries, issued_at=NOW - 10):
    body = {"signers": [{"role": "registry", "key_id": pregen.fingerprint(pregen.public_key_hex(KEY))}],
            "registry": "TEST", "issued_at": issued_at, "anchors": entries}
    return pregen.verify_anchors(pregen.sign_envelope("pg.anchors.v1", body, KEY), "TEST", D, V["key_sets"].__getitem__,
                                 now=NOW)


def entry(code, anchor="wikidata:Q11571"):
    return {"anchor": anchor, "code": code, "level": "verified", "proof_url": "", "status": "active"}


@pytest.mark.parametrize("case", ANCHOR_LISTS["cases"], ids=lambda c: c["name"])
def test_anchor_list_vectors(case):
    """spec/test-vectors/anchors.json: TOG lines kept, foreign codes dropped; an entry that is not a person code (a PG
    line included) fails the whole list."""
    a = case.get("anchor", "wikidata:Q11571")
    if "error" in case:
        with pytest.raises(pregen.PregenError, match=case["error"]):
            anchors([entry(c, a) for c in case["codes"]])
    else:
        assert anchors([entry(c, a) for c in case["codes"]]) == [entry(c, a) for c in case["keep"]]


def test_an_anchor_list_naming_a_code_twice_is_refused():
    with pytest.raises(pregen.PregenError, match="each code once"):
        anchors([entry("TOG-TEST-000001N"), entry("TOG-TEST-000001N", "wikidata:Q1")])


@pytest.mark.parametrize("bad", ["TOG-TEST-000001N", {"code": 1}])
def test_an_anchor_list_with_a_malformed_entry_is_refused(bad):
    with pytest.raises(pregen.PregenError, match="entry is"):
        anchors([entry("TOG-TEST-0000034"), bad])


def test_an_old_anchor_list_is_refused():
    with pytest.raises(pregen.PregenError, match="24 hours"):
        anchors([entry("TOG-TEST-000001N")], issued_at=NOW - pregen.DIRECTORY_MAX_AGE - 1)


def test_an_anchor_list_drops_a_false_claim_only_under_its_own_anchor():
    false = "TOG-TEST-000002Z"               # the vector directory: a false claim under wikidata:Q42
    assert anchors([entry(false, "wikidata:Q42"), entry("TOG-TEST-000001N")]) == [entry("TOG-TEST-000001N")]
    assert anchors([entry(false)]) == [entry("TOG-TEST-000002Z")]


def test_a_false_claim_is_weighed_under_another_anchor_but_never_generated_alone():
    case = next(c for c in V["cases"] if c["name"] == "a code the steward recorded as a false claim")
    assert pregen.verify_answer(case["answer"], case["request"], D, V["key_sets"].__getitem__, now=NOW)["status"] == "allow"
    with pytest.raises(pregen.PregenError, match="false claim"):
        pregen.check_answer(case["answer"], case["request"], D, V["key_sets"].__getitem__, now=NOW)


# The provider's identity step (docs/provider.md step 4) for one claim, as identity.md defines it.
SITE, NEW = "https://cristianoronaldo.com", "https://cr7-media.example"


def claim(code, proof_url, now_urls, then_urls, pages, answer, seen=False):
    get_text = lambda url: pages.get(url, "")  # noqa: E731
    confirmed = pregen.check_channel_proof(code, proof_url, now_urls, get_text, seen_confirmed=seen)
    settled = confirmed and pregen.check_channel_proof(code, proof_url, [u for u in now_urls if u in then_urls], get_text)
    gone = [u for u in then_urls if u not in now_urls]
    refusal_only = not confirmed and (seen or pregen.check_channel_proof(code, proof_url, gone, get_text))
    return {"code": code, "confirmed": confirmed, "settled": settled, "refusal_only": refusal_only, "answer": answer}


def channels(now_sites, then_sites):
    entity = lambda sites: {"entities": {"Q11571": {"claims": {"P856": [  # noqa: E731
        {"mainsnak": {"datavalue": {"value": u}}, "rank": "normal"} for u in sites]}}}}
    answers = {CASES["wikidata_at_api"]: {
        "query": {"pages": [{"title": "Q11571", "revisions": [{"revid": 123}]}]}},
        CASES["wikidata_at_entity"]: entity(then_sites),
        "https://www.wikidata.org/wiki/Special:EntityData/Q11571.json": entity(now_sites)}
    return (pregen.wikidata_official_urls("wikidata:Q11571", get_json=answers.__getitem__, now=CASES["now"]),
            pregen.wikidata_official_urls("wikidata:Q11571", get_json=answers.__getitem__, now=CASES["now"],
                                          at=CASES["now"] - pregen.SETTLED_AFTER))


def test_a_channel_added_today_refuses_but_does_not_permit():
    now_urls, then_urls = channels([SITE, NEW], [SITE])
    pages = {NEW + "/.well-known/pregen": "ToG: TOG-XXXX-0000014"}
    c = claim("TOG-XXXX-0000014", NEW + "/.well-known/pregen", now_urls, then_urls, pages, {"status": "allow"})
    assert (c["confirmed"], c["settled"]) == (True, False)
    assert pregen.decide_identity([c]) == {"status": "not_blocked", "reason": "PG_IDENTITY_UNCONFIRMED", "code": None}
    out = {"status": "deny", "reason": "PG_SUBJECT_OPTED_OUT"}
    c = claim("TOG-XXXX-0000014", NEW + "/.well-known/pregen", now_urls, then_urls, pages, out)
    assert pregen.decide_identity([c])["status"] == "deny"


def test_a_recent_refusal_survives_replacing_the_channel():
    now_urls, then_urls = channels([NEW], [SITE])
    pages = {SITE + "/.well-known/pregen": "ToG: TOG-AAAA-0000029", NEW + "/.well-known/pregen": "ToG: TOG-XXXX-0000014"}
    ron = claim("TOG-AAAA-0000029", SITE + "/.well-known/pregen", now_urls, then_urls, pages,
                {"status": "deny", "reason": "PG_SUBJECT_OPTED_OUT"})
    thief = claim("TOG-XXXX-0000014", NEW + "/.well-known/pregen", now_urls, then_urls, pages, {"status": "allow"})
    assert (ron["confirmed"], ron["refusal_only"]) == (False, True)
    assert pregen.decide_identity([ron, thief]) == {"status": "deny", "reason": "PG_SUBJECT_OPTED_OUT",
                                                    "code": "TOG-AAAA-0000029"}


def test_a_refusal_seen_this_week_survives_its_line_being_deleted():
    now_urls, then_urls = channels([SITE], [SITE])
    ron = claim("TOG-AAAA-0000029", SITE + "/.well-known/pregen", now_urls, then_urls, {},
                {"status": "deny", "reason": "PG_SUBJECT_OPTED_OUT"}, seen=True)
    assert (ron["confirmed"], ron["refusal_only"]) == (False, True)
    assert pregen.decide_identity([ron])["reason"] == "PG_SUBJECT_OPTED_OUT"
    never = claim("TOG-AAAA-0000029", SITE + "/.well-known/pregen", now_urls, then_urls, {}, {"status": "allow"})
    assert (never["confirmed"], never["refusal_only"]) == (False, False)


def test_the_proof_line_is_only_tog_and_the_earlier_spelling_confirms_nothing():
    assert pregen.proof_line("TOG-XXXX-0000014") == "ToG: TOG-XXXX-0000014"
    assert pregen.PROOF_PREFIX == "ToG:" and not hasattr(pregen, "LEGACY_PROOF_PREFIXES")
    old = [c for c in CASES["channel"] if "PRE-GEN:" in (c["page"] if isinstance(c["page"], str) else c["page"]["text"])]
    assert len(old) == 2 and not any(c["expect"] for c in old)
