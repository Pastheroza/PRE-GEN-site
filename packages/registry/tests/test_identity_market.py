"""Extensions identity, proof and catalog, and the likeness/1 personal-signature rule, end to end:
real registries, a test directory, and the provider- and platform-side checks in `pregen`.
Scenario ids (I*, M*, V*) are those of nmp/pregen-identity-proof-market.md in the PRAMPTA repository."""
import hashlib

import pytest
from fastapi.testclient import TestClient
from pregen import (PregenError, canonical_json, check_answer, check_channel_proof, check_proof, decide_identity,
                    verify_answer, verify_anchors, verify_directory, wikidata_official_urls)
from test_registry import Provider

from pregen_registry.app import create_app
from pregen_registry.protocol import Key, check_body, message_id, seal
from pregen_registry.registry import PURPOSES, Config, Registry

NOW = 1_800_000_000
RONALDO = "wikidata:Q11571"
steward = Key()


class World:
    """Registries AAAA and BBBB (honest), XXXX and YYYY (listed, but claim people they cannot prove)."""

    def __init__(self, false_claims=()):
        self.regs = {}
        for prefix in ("AAAA", "BBBB", "XXXX", "YYYY"):
            reg = Registry(Config(prefix=prefix, name=prefix, api=f"https://{prefix.lower()}.example"), Key(),
                           clock=lambda: NOW)
            self.regs[prefix] = (reg, TestClient(create_app(reg)))
        d = {"schema": "pregen.registries.v2", "sequence": 1, "steward_key_id": steward.id, "registries": [
            {"name": p, "prefix": p, "api": f"https://{p.lower()}.example", "keys": f"https://{p.lower()}.example/keys",
             "key_fingerprints": [r.key.id]} for p, (r, _) in self.regs.items()]}
        if false_claims:
            d["false_claims"] = [{"anchor": RONALDO, "code": c, "at": "2027-01-15T00:00:00Z",
                                  "reason": "not the person"} for c in false_claims]
        self.directory = verify_directory({**d, "signature": steward.sign(canonical_json(d))}, steward.public_hex,
                                          now=NOW)

    def get_json(self, url):
        prefix = url.split("//")[1].split(".")[0].upper()
        return self.regs[prefix][1].get("/keys").json()

    def person(self, prefix, *, confirmed, grant=True, **flags):
        reg, _ = self.regs[prefix]
        code = reg.add_subject("Cristiano Ronaldo", level="verified" if confirmed else "asserted", **flags)
        proof = f"https://www.instagram.com/cristiano/p/{prefix}" if confirmed else f"https://{prefix.lower()}.example/c"
        reg.set_identity(code, anchor=RONALDO, proof_url=proof)
        if grant:
            reg.add_grant(code, purposes=PURPOSES)
        return code

    jobs = 0

    def ask(self, prefix, code, provider=None, licensee="", **use):
        reg, http = self.regs[prefix]
        p = provider or Provider(reg, http)
        World.jobs += 1
        body = {**p.body(code, job=f"job-{World.jobs}", purpose=use.pop("purpose", "commercial")),
                **({"licensee_id": licensee} if licensee else {})}
        body["use"].update(use)
        env = p.answer(body)
        return {"type": "pg.request.v1", "body": body, "signatures": []}, env

    def claims(self, official_page_text):
        """What a provider's client does for one public person: every registry's anchor list, the
        official-channel check, a verified answer from each code the lists name."""
        wikidata = {"entities": {"Q11571": {"claims": {"P2003": [{"mainsnak": {"datavalue": {"value": "cristiano"}}}]}}}}
        official = wikidata_official_urls(RONALDO, get_json=lambda url: wikidata)
        out = []
        for prefix, (reg, http) in self.regs.items():
            for e in verify_anchors(http.get("/v2/anchors").json(), prefix, self.directory, self.get_json, now=NOW):
                if e["anchor"] != RONALDO:
                    continue
                request, answer = self.ask(prefix, e["code"])
                out.append({"code": e["code"], "answer": verify_answer(answer, request, self.directory, self.get_json,
                                                                       now=NOW + 10),
                            "confirmed": check_channel_proof(e["code"], e["proof_url"], official,
                                                             lambda url: official_page_text.get(url, ""))})
        return out


def page(*codes_by_prefix):
    return {f"https://www.instagram.com/cristiano/p/{p}": f"Licensing my face — PRE-GEN: {c}" for p, c in codes_by_prefix}


# ── identity: not who came first, but who proved it ─────────────────────

def test_i1_only_the_confirmed_registry():
    w = World()
    a = w.person("AAAA", confirmed=True)
    assert decide_identity(w.claims(page(("AAAA", a)))) == {"status": "allow", "reason": None, "code": a}


def test_i2_an_unconfirmed_claim_alone_does_not_permit_a_public_person():
    w = World()
    x = w.person("XXXX", confirmed=False)
    claims = w.claims({})
    assert decide_identity(claims)["reason"] == "PG_IDENTITY_UNCONFIRMED"
    assert decide_identity(claims, allow_unconfirmed=True)["status"] == "allow"   # the provider's own, explicit choice
    assert claims[0]["code"] == x


def test_i3_i11_a_proven_claim_silences_unproven_ones_both_ways():
    w = World()
    a = w.person("AAAA", confirmed=True, grant=False)
    w.person("XXXX", confirmed=False)                       # the impostor allows
    w.person("YYYY", confirmed=False, opted_out=1)          # a saboteur "opts out" to block the real one
    d = decide_identity(w.claims(page(("AAAA", a))))
    assert (d["status"], d["reason"], d["code"]) == ("deny", "PG_NO_LICENSE", a)   # only the real registry decides


def test_i4_one_person_in_two_registries_a_refusal_in_either_holds_everywhere():
    w = World()
    a = w.person("AAAA", confirmed=True)
    b = w.person("BBBB", confirmed=True, opted_out=1)
    d = decide_identity(w.claims(page(("AAAA", a), ("BBBB", b))))
    assert (d["status"], d["reason"], d["code"]) == ("deny", "PG_SUBJECT_OPTED_OUT", b)


def test_i5_two_unproven_claims_freeze():
    w = World()
    w.person("XXXX", confirmed=False)
    w.person("YYYY", confirmed=False)
    assert decide_identity(w.claims({}), allow_unconfirmed=True)["reason"] == "PG_IDENTITY_CONFLICT"


def test_a_proof_must_be_on_the_persons_own_channel():
    official = ["https://www.instagram.com/cristiano"]
    fake = lambda url: "PRE-GEN: PG-XXXX-000001V"                     # noqa: E731
    assert check_channel_proof("PG-XXXX-000001V", "https://www.instagram.com/cristiano/p/1", official, fake)
    assert not check_channel_proof("PG-XXXX-000001V", "https://www.instagram.com/cristiano_fan/p/1", official, fake)
    assert not check_channel_proof("PG-XXXX-000001V", "https://xxxx.example/cristiano", official, fake)
    assert not check_channel_proof("PG-AAAA-000001V", "https://www.instagram.com/cristiano/p/1", official, fake)


def test_the_steward_marks_a_false_claim_and_every_client_drops_it():
    x_code = World().person("XXXX", confirmed=False)       # same serial in a fresh world: PG-XXXX-000001…
    w = World(false_claims=[x_code])
    w.person("XXXX", confirmed=False)
    assert w.claims({}) == []


def test_anchor_lists_are_signed_and_fresh():
    w = World()
    w.person("AAAA", confirmed=True)
    reg, http = w.regs["AAAA"]
    signed = http.get("/v2/anchors").json()
    check_body("anchors", signed["body"])
    assert verify_anchors(signed, "AAAA", w.directory, w.get_json, now=NOW)[0]["anchor"] == RONALDO
    with pytest.raises(PregenError, match="24 hours"):        # an old copy could hide a new opt-out
        verify_anchors(signed, "AAAA", w.directory, w.get_json, now=NOW + 86_401)
    forged = seal("pg.anchors.v1", {**signed["body"], "anchors": []}, [("registry", w.regs["XXXX"][0].key)])
    with pytest.raises(PregenError):
        verify_anchors(forged, "AAAA", w.directory, w.get_json, now=NOW)


# ── likeness/1: intimate categories only with the person's own signature ──

def test_intimate_use_needs_the_persons_own_key():
    w = World()
    reg, http = w.regs["AAAA"]
    managed = reg.add_subject("Managed", level="verified")
    reg.add_grant(managed, purposes=PURPOSES, categories=["sexual"])     # signed with the key the registry holds
    _, ans = w.ask("AAAA", managed, categories=["sexual"])
    assert ans["body"]["reason"] == "PG_PERSONAL_SIGNATURE_REQUIRED"

    holder = Key()
    own = reg.add_subject("Holds her key", level="verified", holder_public=holder.public_hex)
    with pytest.raises(ValueError):                           # the registry cannot sign for her
        reg.add_grant(own, purposes=PURPOSES, categories=["sexual"])
    reg.add_grant(own, purposes=PURPOSES, holder_key=holder)  # a grant without the category
    _, ans = w.ask("AAAA", own, categories=["sexual"])
    assert ans["body"]["status"] == "deny"
    reg.add_grant(own, purposes=PURPOSES, categories=["sexual"], holder_key=holder)
    _, ans = w.ask("AAAA", own, categories=["sexual"])
    assert ans["body"]["status"] == "allow"


# ── catalog: providers sell what registries offer ───────────────────────

def test_m1_m2_resale_needs_the_explicit_right():
    w = World()
    reg, http = w.regs["AAAA"]
    shop, shop2 = Provider(reg, http, "shop-1"), Provider(reg, http, "shop-2")
    reg.connect("shop-1", "user-7")
    reg.connect("shop-2", "user-7")
    s = reg.add_subject("Creator", level="verified")
    reg.add_grant(s, licensee_id="shop-1", purposes=["personal"])                  # for the provider itself
    assert w.ask("AAAA", s, shop, purpose="personal")[1]["body"]["status"] == "allow"
    # M1: selling it to a user needs the resale right
    assert w.ask("AAAA", s, shop, licensee="user-7", purpose="personal")[1]["body"]["reason"] == "PG_NO_LICENSE"
    reg.add_grant(s, licensee_id="shop-2", purposes=["personal"], resale=True)     # may sell to its users
    assert w.ask("AAAA", s, shop2, licensee="user-7", purpose="personal")[1]["body"]["status"] == "allow"
    # M2: outside the granted purpose
    assert w.ask("AAAA", s, shop2, licensee="user-7", purpose="commercial")[1]["body"]["reason"] == "PG_SCOPE_VIOLATION"


def test_the_catalog_lists_only_who_chose_to_be_offered():
    w = World()
    reg, http = w.regs["AAAA"]
    offered = reg.add_subject("Offered", level="verified")
    quiet = reg.add_subject("Not offered", level="verified")
    gone = reg.add_subject("Opted out", level="verified", opted_out=1)
    for c in (offered, gone):
        reg.set_identity(c, offer={"purposes": ["commercial"], "resale": True, "price": {"amount": 500, "currency": "USD",
                                                                                         "unit": "video"}})
    offers = http.get("/v2/catalog").json()["offers"]
    assert [o["subject_ref"] for o in offers] == [offered] and quiet not in str(offers)


def test_m8_billing_counts_the_allows_the_registry_issued_minus_give_backs():
    w = World()
    reg, http = w.regs["AAAA"]
    p = Provider(reg, http, "shop-1")
    p.register()
    s = reg.add_subject("Creator", level="verified")
    reg.add_grant(s, licensee_id="shop-1", purposes=["commercial"])
    answers = [p.answer(p.body(s, job=f"j{i}", purpose="commercial")) for i in range(3)]
    assert p.send(p.report(answers[0])).status_code == 200                         # generated
    assert p.send(p.report(answers[1], outcome="not_generated")).status_code == 200  # given back
    # answers[2]: no report at all — still billed: the registry knows it said yes
    st = http.get("/v2/statement", headers=p.h).json()
    assert st["grants"][0]["billed"] == 2 and st["grants"][0]["given_back"] == 1


# ── proof: the record travels with the video ────────────────────────────

def test_v_a_platform_checks_the_proof_carried_with_the_video():
    w = World()
    reg, http = w.regs["AAAA"]
    p = Provider(reg, http)
    p.register()
    s = reg.add_subject("Creator", level="verified")
    reg.add_grant(s, purposes=PURPOSES)
    body = p.body(s, purpose="commercial")
    answer = p.answer(body)
    request = {"type": "pg.request.v1", "body": body, "signatures": []}
    check_answer(answer, request, w.directory, w.get_json, now=NOW + 10)
    video = b"the generated video"
    report = p.report(answer, output_hash=hashlib.sha256(video).hexdigest(),
                      bindings=[{"alg": "com.example.watermark", "value": "AAAA:0123"}])
    assert p.send(report).status_code == 200
    short = message_id("pg.report.v1", report["body"])[:16]                       # what the watermark carries
    bundle = http.get(f"/v2/proofs/{short}").json()
    check_body("proof", bundle)
    check_body("report", report["body"])
    later = NOW + 30 * 86400                                                        # checked a month later
    w.directory = verify_directory(w.directory.to_json(), steward.public_hex, now=later)
    ok = check_proof(bundle, w.directory, w.get_json, output_sha256=hashlib.sha256(video).hexdigest(), now=later)
    assert ok["subjects"][0]["code"] == s and ok["subjects"][0]["level"] == "verified"
    with pytest.raises(PregenError, match="another file"):                         # V3: copied onto another video
        check_proof(bundle, w.directory, w.get_json, output_sha256=hashlib.sha256(b"a deepfake").hexdigest(), now=later)
    edited = {**bundle["subjects"][0], "report": {**report, "body": {**report["body"], "output_hash": "f" * 64}}}
    with pytest.raises(PregenError, match="did not acknowledge"):                  # V2: a doctored report
        check_proof({"format": "pg.proof.v1", "subjects": [edited]}, w.directory, w.get_json, now=later)
    revoked = w.directory.to_json()
    revoked["registries"][0]["revoked"] = {"at": "2027-02-01T00:00:00Z", "reason": "fraud"}
    revoked["sequence"] = 2
    del revoked["signature"]
    revoked = verify_directory({**revoked, "signature": steward.sign(canonical_json(revoked))}, steward.public_hex,
                               now=later)
    with pytest.raises(PregenError, match="revoked"):                              # V12: every past proof falls too
        check_proof(bundle, revoked, w.get_json, now=later)
