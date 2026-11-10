"""TOG-CODE.md in the protocol paths: one code in either spelling (code_key), readable copies in a proof (§14,
proof.md step 3) and the directory v3 (§9.2) beside v2. The code layer itself runs on the shared vectors in
test_tog_code.py."""
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import pregen

ROOT = Path(__file__).resolve().parents[3]
V = json.loads((ROOT / "spec/test-vectors/answers.json").read_text())
NOW = V["now"]
D = pregen.verify_directory(V["directory"], V["steward_public_key_hex"], now=NOW)
get_json = V["key_sets"].__getitem__
KEY = hashlib.sha256(b"pregen-answer-vector-registry").hexdigest()
SIGNERS = [{"role": "registry", "key_id": pregen.fingerprint(pregen.public_key_hex(KEY))}]


def test_a_tog_code_routes_to_its_first_prefix():
    assert pregen.issuer_of("TOG-TEST-000001N") == pregen.issuer_of("PG-TEST-000001N") == "TEST"
    assert pregen.issuer_of("TOG-PG-LIC-NWRD-PRAM-ZZZZ-VGDY-WCWV") == "NWRD"
    assert D.registry_for("TOG-TEST-000001N")["prefix"] == "TEST"


def test_a_false_claim_holds_under_either_spelling():
    assert D.is_false_claim("PG-TEST-000002Z") and D.is_false_claim("TOG-TEST-000002Z")
    assert not D.is_false_claim("TOG-TEST-000001N")


def test_a_channel_confirms_a_code_in_either_spelling():
    page = lambda url: "PRE-GEN: PG-TEST-000001N\n"   # noqa: E731
    assert pregen.check_channel_proof("TOG-TEST-000001N", "https://example.com/.well-known/pregen",
                                      ["https://example.com"], page)


# ── readable copies in a proof ──

def entry(code="PG-TEST-000001N", grant_body=None, n=0, **copies):
    """A signed allow, its acknowledged report, and the act code_for reads from them. The basis is the grant when
    one is given, else a policy rule."""
    basis = {"kind": "grant", "grant": {"format": "pg.grant.v1", "id": pregen.message_id("pg.grant.v1", grant_body)}} \
        if grant_body else {"kind": "policy", "rule": "test"}
    asked = {"subject_ref": code, "provider_id": "https://frame.example", "profile": "likeness/1",
             "use": {"purpose": "personal"}, "job_id": "job-1", "job_hash": "a" * 64}
    answer = pregen.sign_envelope("pg.answer.v1", {
        "signers": SIGNERS, "request_id": pregen.message_id("pg.request.v1", asked), "profile": "likeness/1",
        "status": "allow", "basis": basis, "issued_at": NOW - 10 - n, "expires_at": NOW + 290}, KEY)
    report = {"type": "pg.report.v1", "signatures": [], "body": {
        "answer": pregen.message_id("pg.answer.v1", answer["body"]), "outcome": "generated", "output_hash": "d" * 64,
        "job_id": "job-1", "occurred_at": NOW}}
    ack = pregen.sign_envelope("pg.report_ack.v1", {"signers": SIGNERS, "answer": report["body"]["answer"],
                                                    "report": pregen.message_id("pg.report.v1", report["body"]),
                                                    "received_at": NOW}, KEY)
    item = {"request": {"type": "pg.request.v1", "body": asked, "signatures": []}, "answer": answer, "report": report,
            "ack": ack, **copies}
    act = {"type": "pg.answer.v1", "id": pregen.message_id("pg.answer.v1", answer["body"]), "signer": "TEST",
           "subject_ref": code, "grant": {"id": basis["grant"]["id"], "signer": "TEST"} if grant_body else None}
    return item, act


def coded(grant_body=None):
    """An entry whose answer (and grant) give a code: about 1 in 7 end in a symbol and give none."""
    for n in range(50):
        body = grant_body and dict(grant_body, n=n)
        item, act = entry(grant_body=body, n=n)
        try:
            lic = body and pregen.code_for({"type": "pg.grant.v1", "id": act["grant"]["id"], "signer": "TEST",
                                            "subject_ref": "TOG-TEST-000001N"})
            return item, pregen.code_for(act), lic, body and {"type": "pg.grant.v1", "body": body, "signatures": []}
        except pregen.PregenError:
            continue


def proof(item):
    return pregen.check_proof({"format": "pg.proof.v1", "subjects": [item]}, D, get_json, now=NOW)["subjects"][0]


GRANT = {"subject_ref": "TOG-TEST-000001N", "licensee_id": "", "profile": "likeness/1"}


def test_a_proof_needs_no_copy():
    item = coded()[0]
    assert proof(item)["code"] == "PG-TEST-000001N"     # the code as the request asked it


def test_a_code_copy_must_equal_the_recomputed_code():
    item, code, _, _ = coded()
    assert code.startswith("TOG-PG-TEST-")
    assert proof(dict(item, code=code))["level"] is None
    for wrong in (code[:-1] + ("0" if code[-1] != "0" else "1"), code.replace("TOG-PG-", "TOG-PG-LIC-"),
                  "TOG-TEST-000001N"):
        with pytest.raises(pregen.PregenError, match="readable copy"):
            proof(dict(item, code=wrong))


def test_a_licence_copy_needs_its_grant_and_a_licence_basis():
    item, code, lic, grant = coded(GRANT)
    assert code.startswith("TOG-PG-LIC-TEST-") and lic.startswith("TOG-LIC-TEST-")
    assert proof(dict(item, code=code, licence=lic, grant=grant))
    with pytest.raises(pregen.PregenError, match="readable copy"):
        proof(dict(item, licence=lic))                                  # the licence is not at hand
    with pytest.raises(pregen.PregenError, match="readable copy"):
        proof(dict(item, licence=lic[:-1] + ("0" if lic[-1] != "0" else "1"), grant=grant))
    plain = coded()[0]
    with pytest.raises(pregen.PregenError, match="readable copy"):
        proof(dict(plain, licence=lic, grant=grant))                    # a licence copy on a terms basis


# ── directory v3 ──

class Steward:
    def __init__(self):
        self.k = Ed25519PrivateKey.generate()
        self.pub = self.k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def sign(self, d):
        d = dict(d, steward_key_id=pregen.fingerprint(self.pub))
        return dict(d, signature=self.k.sign(pregen.canonical_json(d)).hex())


S, FP = Steward(), "pg-ed25519:" + "0" * 32
ALWAYS = {"from": "2026-01-01T00:00:00Z", "until": None}


def reg(prefix, entity, roles, **more):
    return {"name": entity, "prefix": prefix, "api": f"https://{prefix.lower()}.example",
            "keys": f"https://{prefix.lower()}.example/keys", "key_fingerprints": [FP], "entity": entity,
            "group": "g-" + prefix, "roles": {r: ALWAYS for r in roles}, **more}


V3 = {"schema": "pregen.registries.v3", "sequence": 1, "registries": [
    reg("PRAM", "PRAMPTA Inc.", ("home", "market")),
    reg("KOBEMK", "Kobe market KK", ("market",), provider_domains=[{"domain": "https://kobe.example", **ALWAYS}]),
    reg("NWRD", "Newroad", ("market",), void_from="2027-01-01T00:00:00Z", closed="2027-01-01T00:00:00Z")]}


def load(d):
    return pregen.verify_directory(S.sign(d), S.pub, successor_public_key_hex=None)


def test_v3_lists_long_prefixes_and_dated_roles_and_v2_still_verifies():
    d = load(V3)
    assert d.registry_for("TOG-LIC-KOBEMK-PRAM-ZZZZ-BYAV-K2AQ")["prefix"] == "KOBEMK"
    assert d.parties("TOG-LIC-KOBEMK-PRAM-ZZZZ-BYAV-K2AQ", provider="https://kobe.example") == {"ok": True, "facts": [
        "issuer KOBEMK (Kobe market KK)", "home PRAM (PRAMPTA Inc.)", "KOBEMK also generated it (https://kobe.example)"]}
    when = pregen._when("2028-01-01T00:00:00Z")
    assert d.parties("TOG-LIC-NWRD-PRAM-ZZZZ-84RN-RT04")["ok"]                    # no act time: a fact, still ok
    assert not d.parties("TOG-LIC-NWRD-PRAM-ZZZZ-84RN-RT04", at=when)["ok"]       # void at the act
    v2 = dict(V3, schema="pregen.registries.v2", registries=[reg("PRAM", "PRAMPTA Inc.", ())])
    with pytest.raises(pregen.PregenError, match="v3"):
        load(v2).parties("TOG-PRAM-900000037K")
    with pytest.raises(pregen.PregenError, match="bad prefix"):                  # v2 keeps 4 Crockford letters
        load(dict(v2, registries=[reg("KOBEMK", "Kobe market KK", ())]))
    assert pregen.DIRECTORY_URL.endswith("/registries.v3.json") and pregen.DIRECTORY_V2_URL.endswith("/registries.json")


def test_v2_and_v3_are_two_lines_and_v2_never_follows_v3():
    v2 = S.sign(dict(V3, schema="pregen.registries.v2", sequence=9, registries=[reg("PRAM", "PRAMPTA Inc.", ())]))
    v3 = load(V3)
    assert pregen.verify_directory(S.sign(V3), S.pub, previous=v2, successor_public_key_hex=None).sequence == 1
    with pytest.raises(pregen.PregenError, match="v3 directory was already accepted"):
        pregen.verify_directory(v2, S.pub, previous=v3, successor_public_key_hex=None)


@pytest.mark.parametrize("change", [{"prefix": "LICX"}, {"prefix": "PRAMPTAIN"}, {"government": "yes"},
                                    {"roles": {"home": {"from": 2026, "until": None}}}, {"void_from": "soon"},
                                    {"provider_domains": ["https://kobe.example"]}, {"entity": ""},
                                    {"roles": {"branch": {"from": "2026-01-01T00:00:00Z", "until": None}}},
                                    {"closed": "2027"}])
def test_v3_refuses_a_malformed_entry(change):
    with pytest.raises(pregen.PregenError):
        load(dict(V3, registries=[dict(V3["registries"][0], **change)]))
