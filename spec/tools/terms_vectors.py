#!/usr/bin/env python3
"""Generate spec/test-vectors/terms.json: extension terms (spec/extensions/terms.md) under likeness/1, for every
implementation to agree on.

- `vocabulary`: likeness/1's closed vocabulary and its two floor sets.
- `records`: pg.terms.v1 envelopes; check_terms(envelope, code) accepts exactly those marked "ok": true.
- `floor`, `forbids`, `opens`: floor(use, minor), forbids(rules, use) and terms_opens(old, new), with their results.
- `requests`: request bodies; a registry that declares terms answers those marked "ok": false PG_MALFORMED, with no
  signed answer (T-5).
- `proofs`: pg.proof.v1 bundles; check_proof passes each and reports `terms` and `terms_assent` for its one subject.

Records and proofs check against the directory, key sets and `now` of answers.json. Deterministic, like it:

    python3 spec/tools/terms_vectors.py > spec/test-vectors/terms.json

Needs the `pregen` library (packages/verify-py) and `cryptography`.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from answer_vectors import KEYS, KID, NOW, accepting, answer, pregen, terms  # noqa: E402

CODE, OTHER_CODE = "TOG-TEST-000001N", "TOG-TEST-0000034"
RULES = {"purposes": ["editorial", "personal"], "excluded_categories": ["gambling", "political"]}
# TC1: what a reader takes for a code but a machine does not; never normalised, never passed
SPELLINGS = [("a capital", ["Gambling"]), ("all capitals", ["GAMBLING"]), ("a zero-width joiner", ["gam‍bling"]),
             ("a trailing space", ["gambling "]), ("a Cyrillic letter", ["gаmbling"]), ("a nested list", [["gambling"]]),
             ("a string, not a list", "gambling"), ("a word outside the vocabulary", ["beer"])]


def mid(env):
    return pregen.message_id(env["type"], env["body"])


def records():
    first = terms()
    narrower = {"purposes": ["personal"], "excluded_categories": ["adult", "gambling", "political"]}
    yield "version 1", first, CODE, True
    yield "version 2 only closes: no factor", terms(version=2, amends=mid(first), rules=narrower, factor=None), CODE, True
    yield "version 2 opens: names its factor", terms(version=2, amends=mid(first), factor="email",
                                                     rules={**RULES, "purposes": ["commercial", "editorial", "personal"]}), CODE, True
    yield "assent self is reserved", terms(assent="self"), CODE, False
    yield "assent agent is reserved", terms(assent="agent"), CODE, False
    yield "another profile", terms(profile="work/1"), CODE, False
    yield "version 0", terms(version=0), CODE, False
    yield "version 2 without amends", terms(version=2), CODE, False
    yield "version 1 with amends", terms(amends="a" * 64), CODE, False
    yield "version 1 without factor", terms(factor=None), CODE, False
    yield "an unknown factor", terms(factor="sms"), CODE, False
    yield "another person's terms (PM1)", first, OTHER_CODE, False
    yield "signed by another registry's key (PM10)", terms(key="other_registry"), CODE, False
    yield "a tampered body", {**first, "body": {**first["body"], "minor": True}}, CODE, False
    two = {**first, "body": {**first["body"], "signers": first["body"]["signers"] * 2}, "signatures": first["signatures"] * 2}
    yield "two registry signers", two, CODE, False
    yield "an unknown member", terms(note="x"), CODE, False
    yield "TL2: amends with a trailing newline", terms(version=2, amends=mid(first) + "\n", factor=None), CODE, False
    yield "TL2: instruction with a trailing newline", terms(instruction="c" * 64 + "\n"), CODE, False
    for name, spelled in SPELLINGS:
        yield f"TC1: an exclusion with {name}", terms(rules={**RULES, "excluded_categories": spelled}), CODE, False
    yield "purposes unsorted", terms(rules={**RULES, "purposes": ["personal", "editorial"]}), CODE, False
    yield "a purpose twice", terms(rules={**RULES, "purposes": ["personal", "personal"]}), CODE, False
    yield "no purpose", terms(rules={**RULES, "purposes": []}), CODE, False
    yield "no excluded_categories", terms(rules={"purposes": ["personal"]}), CODE, False
    yield "territories (phase 1 sends none)", terms(rules={**RULES, "territories": ["US"]}), CODE, False
    yield "a lower-case jurisdiction", terms(template={"id": "example-likeness", "version": 1, "jurisdiction": "us"}), CODE, False
    yield "legal text over http", terms(legal={"sha256": "b" * 64, "url": "http://registry.test.example/t.txt"}), CODE, False
    for name, value in (("a fraction", 1.5), ("2^53", 2 ** 53)):     # PL1: canonical JSON has neither; no one can sign it
        yield f"PL1: version {name}", {**first, "body": {**first["body"], "version": value}}, CODE, False


FLOOR = [(["violence"], True, "PG_PROHIBITED_USE"), (["violence"], False, None),
         (["sexual"], True, "PG_PROHIBITED_USE"), (["adult"], False, "PG_PERSONAL_SIGNATURE_REQUIRED"),
         (["advertising", "fashion"], True, None), ([], True, None), (None, True, None)] \
    + [(s, True, None) for _, s in SPELLINGS[:5]]   # spellings match nothing: the caller refuses them as outside CATEGORIES

FORBIDS = [(RULES, {"purpose": "personal", "categories": ["fashion"]}, None),
           (RULES, {"purpose": "commercial"}, 'purpose "commercial"'),
           (RULES, {"purpose": "personal", "categories": ["political", "gambling", "fashion"]}, 'categories ["gambling","political"]'),
           (RULES, {"categories": ["fashion"]}, "purpose null"),
           ({"purposes": ["personal"]}, {"purpose": "personal", "categories": ["gambling"]}, None),
           (RULES, {"purpose": "personal", "categories": ["beer"]}, None)]   # open vocabulary, without terms: the residual


def _v(rules=RULES, minor=False, **extra):
    return {"rules": rules, "minor": minor, **extra}


OPENS = [(None, _v(), True), (_v(), _v(), False),
         (_v(), _v({**RULES, "purposes": ["commercial", "editorial", "personal"]}), True),
         (_v(), _v({**RULES, "purposes": ["personal"]}), False),
         (_v(), _v({**RULES, "excluded_categories": ["gambling"]}), True),
         (_v(), _v({**RULES, "excluded_categories": ["adult", "gambling", "political"]}), False),
         (_v(minor=True), _v(), True), (_v(), _v(minor=True), False),
         (_v(template={"id": "a", "version": 1, "jurisdiction": "US"}), _v(template={"id": "a", "version": 2, "jurisdiction": "US"}), True)]


def requests():
    body = accepting(terms())["body"]
    use = body["use"]
    yield "accepts the current terms", body, True
    for name, spelled in SPELLINGS:
        yield f"TC1: a category with {name}", {**body, "use": {**use, "categories": spelled}}, False
    yield "TL2: a terms id with a trailing newline", {**body, "terms": body["terms"] + "\n"}, False
    yield "a terms id in capitals", {**body, "terms": body["terms"].upper()}, False
    yield "terms without signers", {k: v for k, v in body.items() if k != "signers"}, False
    without = {k: v for k, v in body.items() if k != "terms"}
    yield "no terms: another word is still allowed", {**without, "use": {**use, "categories": ["beer"]}}, True
    yield "no terms: another spelling is still allowed", {**without, "use": {**use, "categories": ["Gambling"]}}, True


def bundle(record, use, basis, cite=True):
    """One subject's four signed messages, plus the record its request accepted."""
    request = accepting(record, use=use) if cite else pregen.sign_envelope("pg.request.v1", {
        k: v for k, v in accepting(record, use=use)["body"].items() if k != "terms"}, KEYS["provider"])
    allow = answer(request=request, basis=basis)
    report = pregen.sign_envelope("pg.report.v1", {
        "signers": [{"role": "provider", "key_id": KID["provider"]}], "request_id": mid(request), "answer": mid(allow),
        "job_id": request["body"]["job_id"], "outcome": "generated", "output_hash": "d" * 64, "occurred_at": NOW},
        KEYS["provider"])
    ack = pregen.sign_envelope("pg.report_ack.v1", {
        "signers": [{"role": "registry", "key_id": KID["registry"]}], "report": mid(report), "answer": mid(allow),
        "answer_status": "allow", "counted": mid(allow), "released": [], "provider_key_id": KID["provider"],
        "received_at": NOW}, KEYS["registry"])
    return {"format": "pg.proof.v1", "subjects": [{"request": request, "answer": allow, "report": report, "ack": ack,
                                                   "terms": record}]}


def proofs():
    policy, grant = {"kind": "policy", "rule": "test"}, {"kind": "grant", "grant": {"format": "pg.grant.v1", "id": "e" * 64}}
    fashion, gambling = {"purpose": "personal", "categories": ["fashion"]}, {"purpose": "personal", "categories": ["gambling"]}
    yield "the use keeps to the terms", bundle(terms(), fashion, policy), "ok", "registry"
    yield "the request accepted no terms", bundle(terms(), fashion, policy, cite=False), "absent", None
    lost = bundle(terms(), fashion, policy)
    del lost["subjects"][0]["terms"]
    yield "the record is not carried", lost, "unverified", None
    yield "the record is signed by another registry's key (PM10)", bundle(terms(key="other_registry"), fashion, policy), "unverified", None
    yield "a category the terms exclude, on a policy basis", bundle(terms(), gambling, policy), "outside", "registry"
    yield "a grant decides its own scope", bundle(terms(), gambling, grant), "ok", "registry"
    yield "the floor under any basis: a minor, violence", bundle(
        terms(minor=True), {"purpose": "personal", "categories": ["violence"]}, grant), "outside", "registry"
    yield "an intimate category, whatever the basis", bundle(
        terms(), {"purpose": "personal", "categories": ["sexual"]}, grant), "outside", "registry"
    yield "a category outside the vocabulary, on a policy basis", bundle(
        terms(), {"purpose": "personal", "categories": ["beer"]}, policy), "outside", "registry"


def main():
    out = {"description": __doc__.split("\n\n")[0].replace("\n", " "), "code": CODE,
           "vocabulary": {"categories": sorted(pregen.CATEGORIES), "prohibited_for_minors": sorted(pregen.PROHIBITED_FOR_MINORS),
                          "intimate": sorted(pregen.INTIMATE)},
           "records": [{"name": n, "code": c, "envelope": e, "ok": ok} for n, e, c, ok in records()],
           "floor": [{"use": {"purpose": "personal", **({} if c is None else {"categories": c})}, "minor": m, "result": r}
                     for c, m, r in FLOOR],
           "forbids": [{"rules": r, "use": u, "result": x} for r, u, x in FORBIDS],
           "opens": [{"old": o, "new": n, "result": x} for o, n, x in OPENS],
           "requests": [{"name": n, "body": b, "ok": ok} for n, b, ok in requests()],
           "proofs": [{"name": n, "bundle": b, "terms": t, "terms_assent": a} for n, b, t, a in proofs()]}
    json.dump(out, sys.stdout, indent=1)   # escaped: a hidden character stays visible
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
