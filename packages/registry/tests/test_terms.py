"""Extension terms (spec/extensions/terms.md): publishing a person's terms, the gate in its order, accepting by
signing, and what the proof carries. Request shapes come from spec/test-vectors/terms.json."""
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pregen import canonical_json, check_proof, check_terms, message_id, verify_bytes, verify_directory
from test_registry import Clock, OpenProvider, Provider, code, make

from pregen_registry.app import create_app
from pregen_registry.protocol import Key, check_body, signing_input
from pregen_registry.registry import Config, Registry

VECTORS = json.loads((Path(__file__).resolve().parents[3] / "spec" / "test-vectors" / "terms.json").read_text())
TEMPLATE = {"id": "example-likeness", "version": 1, "jurisdiction": "US"}
LEGAL = {"sha256": "b" * 64, "url": "https://test.example/terms-template-1.txt"}


def publish(reg, subject, purposes=("personal", "research"), excluded=("gambling",), **kw):
    return reg.publish_terms(subject, purposes=purposes, excluded_categories=excluded, template=kw.pop("template", TEMPLATE),
                             legal=kw.pop("legal", LEGAL), **kw)


def world():
    """A sandbox (open, masks nothing), a provider known by its domain, and a directory that lists the registry."""
    reg, c, clock = make()
    p = OpenProvider(reg, c)
    assert c.post("/v2/sandbox/party", json=p.doc).status_code == 200
    steward = Key()
    d = {"schema": "pregen.registries.v2", "sequence": 1, "steward_key_id": steward.id, "registries": [
        {"name": "Test", "prefix": "TEST", "api": "https://test.example", "keys": "https://test.example/keys",
         "key_fingerprints": [reg.key.id]}]}
    directory = verify_directory({**d, "signature": steward.sign(canonical_json(d))}, steward.public_hex, now=clock.t)
    return reg, c, clock, p, directory, lambda url: c.get("/keys").json()


def reason(p, body):
    a = p.answer(body)["body"]
    return a.get("reason") or a["status"]


# ── publishing (T-1 to T-3) ─────────────────────────────────────────────

def test_versions_grow_open_with_a_factor_close_without_and_stay_fetchable():
    reg, c, clock, p, directory, get_json = world()
    s = reg.add_subject("Maya", level="verified")
    with pytest.raises(ValueError, match="second factor"):                       # T-3: a first version opens
        publish(reg, s)
    v1 = publish(reg, s, factor="authenticator")
    assert publish(reg, s, factor="authenticator") == v1                          # nothing changed: no new version
    clock.t += 10
    v2 = publish(reg, s, excluded=("gambling", "political"), factor="email")      # only closes: no factor named
    with pytest.raises(ValueError, match="second factor"):                       # a purpose added opens
        publish(reg, s, purposes=("commercial", "personal", "research"), excluded=("gambling", "political"))
    with pytest.raises(ValueError, match="legal text is fixed"):
        publish(reg, s, excluded=("gambling", "political"), legal={**LEGAL, "sha256": "c" * 64})
    v3 = publish(reg, s, excluded=("political",), factor="email")                 # an exclusion removed opens
    bodies = [c.get(f"/v2/terms/{t}").json()["terms"] for t in (v1, v2, v3)]      # T-2: every version, forever
    assert [b["body"]["version"] for b in bodies] == [1, 2, 3]
    assert [b["body"].get("factor") for b in bodies] == ["authenticator", None, "email"]
    assert "amends" not in bodies[0]["body"] and [b["body"]["amends"] for b in bodies[1:]] == [v1, v2]
    for t, env in zip((v1, v2, v3), bodies):
        check_body("terms", env["body"])
        assert message_id(env["type"], env["body"]) == t
        assert check_terms(env, s, directory, get_json)["assent"] == "registry"
    r = c.get(f"/v2/terms/{'f' * 64}")
    assert r.status_code == 404 and r.json()["error"] == "PG_UNKNOWN_TERMS"
    look = c.get(f"/v2/codes/{s}").json()
    assert look["terms"] == {"id": v3, "url": f"https://test.example/v2/terms/{v3}"}
    assert look["status_url"] == f"https://test.example/v2/codes/{s}/terms"
    page = c.get(f"/v2/codes/{s}/terms").json()                                   # the status page: every version
    assert page == {"code": s, "terms": bodies[::-1]}
    for other in (reg.add_subject("No terms", level="verified"), code(8), "PG-nonsense"):
        r = c.get(f"/v2/codes/{other}/terms")
        assert r.status_code == 404 and r.json()["error"] == "PG_NOT_FOUND"
    reg.set_published(s, False)                                                   # no longer published: no page
    assert c.get(f"/v2/codes/{s}/terms").status_code == 404 and "status_url" not in c.get(f"/v2/codes/{s}").json()


def test_terms_only_for_a_published_confirmed_subject_and_a_registry_that_declares_them():
    reg, c, _, p, _, _ = world()
    for flags in ({"level": "self"}, {"level": "asserted"}, {"level": "verified", "published": 0}):
        with pytest.raises(ValueError, match="T-1"):
            publish(reg, reg.add_subject("Not yet", **flags), factor="email")
    for bad in ({"purposes": ()}, {"purposes": ("spam",)}, {"excluded": ("beer",)}, {"excluded": ("Gambling",)}):
        with pytest.raises(ValueError, match="purposes from"):
            publish(reg, code(1), factor="email", **bad)
    s = reg.add_subject("Maya", level="verified")
    v1 = publish(reg, s, factor="email")
    reg.set_published(s, False)                         # no longer published: answered as if it had no terms
    assert c.get(f"/v2/codes/{s}").json()["status"] == "unknown"
    assert c.get(f"/v2/terms/{v1}").status_code == 200  # but the version stays fetchable (T-2)
    assert reason(p, p.body(s, purpose="personal", terms=v1)) == "PG_TERMS_NOT_ACCEPTED"
    off = Registry(Config(prefix="TEST", name="T", api="https://t.example", sandbox=True, terms=False), Key())
    doc = TestClient(create_app(off)).get("/.well-known/pregen-registry.json").json()
    check_body("registry-document", doc)
    assert "terms" not in doc["extensions"] and "terms" not in doc
    with pytest.raises(ValueError, match="T-1"):
        publish(off, off.add_subject("Maya", level="verified"), factor="email")
    doc = c.get("/.well-known/pregen-registry.json").json()
    check_body("registry-document", doc)
    assert "terms" in doc["extensions"] and "lookup" in doc["extensions"] and doc["terms"] == "optional"


@pytest.mark.parametrize("providers,declared", [("registered", False), ("open", True)])
def test_terms_are_declared_only_with_provider_identity(providers, declared):
    """REG-2: terms requires provider-identity; a registry whose providers all hold credentials cannot offer them."""
    reg = Registry(Config(prefix="ABCD", name="R", api="https://r.example", providers=providers), Key())
    doc = reg.document()
    check_body("registry-document", doc)
    assert ("terms" in doc["extensions"], "terms" in doc, "provider-identity" in doc["extensions"]) == (declared,) * 3
    s = reg.add_subject("Maya", level="verified", published=1)
    if declared:
        assert publish(reg, s, factor="email")
    else:
        with pytest.raises(ValueError, match="T-1"):
            publish(reg, s, factor="email")
        old = Provider(reg, TestClient(create_app(reg)))
        r = old.ask(old.body(s, purpose="personal", terms="a" * 64, signers=[]))
        assert r.status_code == 422 and r.json()["error"] == "PG_MALFORMED"


# ── accepting (T-5 to T-8) ──────────────────────────────────────────────

def test_the_current_id_is_accepted_and_the_allow_covers_it():
    reg, c, _, p, _, _ = world()
    v1 = publish(reg, code(1), factor="authenticator")
    body = p.body(code(1), purpose="personal", terms=v1)
    a = p.answer(body)["body"]
    assert a["status"] == "allow" and a["expires_at"] - a["issued_at"] <= 300                   # T-9
    assert a["request_id"] == message_id("pg.request.v1", p.signed("pg.request.v1", body)["body"])  # T-6
    other = reg.add_subject("Theo", level="verified")
    publish(reg, other, factor="email")
    assert reason(p, p.body(code(1), job="j2", purpose="personal", terms=publish(reg, other))) == "PG_TERMS_NOT_ACCEPTED"
    assert reason(p, p.body(reg.add_subject("No terms", level="verified"), job="j3", terms=v1)) == "PG_TERMS_NOT_ACCEPTED"


def test_a_stale_id_binds_nothing_and_spends_nothing():
    reg, c, clock, p, _, _ = world()
    v1 = publish(reg, code(1), factor="authenticator")
    clock.t += 10
    v2 = publish(reg, code(1), excluded=("gambling", "political"))
    stale = p.body(code(1), purpose="personal", terms=v1)
    assert reason(p, stale) == "PG_TERMS_NOT_ACCEPTED"
    assert reason(p, stale) == "PG_TERMS_NOT_ACCEPTED"                           # a replay: the same refusal
    assert reg.db.execute("SELECT COUNT(*) FROM asks").fetchone()[0] == 0       # kept nowhere
    assert reg.db.execute("SELECT COUNT(*) FROM answers").fetchone()[0] == 0    # nothing spent
    assert p.answer(p.body(code(1), purpose="personal", terms=v2))["body"]["status"] == "allow"   # same job, no conflict
    assert reg.db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1       # the stale ask bound no job either


def jobs_asks(reg):
    return [reg.db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("jobs", "asks")]


def test_a_stale_id_binds_no_job():
    reg, c, clock, p, _, _ = world()
    v1 = publish(reg, code(1), factor="authenticator")
    clock.t += 10
    publish(reg, code(1), excluded=("gambling", "political"))
    assert reason(p, p.body(code(1), purpose="personal", terms=v1)) == "PG_TERMS_NOT_ACCEPTED"
    assert jobs_asks(reg) == [0, 0]
    assert reason(p, p.body(code(1), purpose="personal", job_hash="b" * 64)) == "allow"   # the job is free for any hash


def test_after_an_allow_expired_unused_a_new_version_does_not_lock_the_job():
    """KM2: the ask already held an answer when its terms went stale."""
    reg, c, clock, p, _, _ = world()
    v1 = publish(reg, code(1), factor="authenticator")
    first = p.answer(p.body(code(1), purpose="personal", terms=v1))
    assert first["body"]["status"] == "allow"
    clock.t += 400                                                              # expired, nothing generated
    v2 = publish(reg, code(1), excluded=("gambling", "political"))
    assert reason(p, p.body(code(1), purpose="personal", terms=v1)) == "PG_TERMS_NOT_ACCEPTED"   # T-7, signed
    again = p.answer(p.body(code(1), purpose="personal", terms=v2))                             # same job
    assert again["body"]["status"] == "allow"
    assert reason(p, p.body(code(1), purpose="personal", terms=v1)) == "PG_TERMS_NOT_ACCEPTED"   # a replay: still
    # the old ask stepped aside but kept its answer: still billed, still reportable
    assert reg.db.execute("SELECT COUNT(*) FROM answers a JOIN asks k ON k.id = a.ask_id WHERE a.status = 'allow' "
                          "AND a.use = 'reserved'").fetchone()[0] == 2
    assert p.report(first, outcome="not_generated").status_code == 200
    assert p.report(again).status_code == 200


def test_after_an_exclusion_a_widened_version_does_not_lock_the_job():
    """KM2: a stored PG_TERMS_EXCLUDED, then a version that adds the purpose."""
    reg, c, clock, p, _, _ = world()
    s = reg.add_subject("Maya", level="verified")
    v1 = publish(reg, s, purposes=("personal",), factor="authenticator")
    assert reason(p, p.body(s, purpose="research", terms=v1)) == "PG_TERMS_EXCLUDED"
    clock.t += 10
    v2 = publish(reg, s, purposes=("personal", "research"), factor="email")
    assert reason(p, p.body(s, purpose="research", terms=v2)) == "PG_NO_LICENSE"         # same job, no conflict


def test_terms_the_subject_no_longer_has_are_stale_too():
    reg, c, clock, p, _, _ = world()
    v1 = publish(reg, code(1), factor="authenticator")
    assert reason(p, p.body(code(1), purpose="personal", terms=v1)) == "allow"
    clock.t += 400
    reg.set_published(code(1), False)                                             # answered as if it had no terms
    assert reason(p, p.body(code(1), purpose="personal")) == "allow"              # same job, no conflict


@pytest.mark.parametrize("case", ["open allow", "generated", "no terms"])
def test_an_ask_that_still_stands_keeps_the_job(case):
    """Only an ask on stale terms steps aside: not one with an allow still open, not one reported generated, not one
    that cited no terms."""
    reg, c, clock, p, _, _ = world()
    v1 = publish(reg, code(1), factor="authenticator")
    first = p.answer(p.body(code(1), purpose="personal", **({} if case == "no terms" else {"terms": v1})))
    if case == "generated":
        assert p.report(first).status_code == 200
    clock.t += 10 if case == "open allow" else 400
    v2 = publish(reg, code(1), excluded=("gambling", "political"))
    r = p.ask(p.body(code(1), purpose="personal", terms=v2))
    assert r.status_code == 409 and r.json()["error"] == "PG_ASK_CONFLICT"
    if case == "generated":                                                       # the identical request: closed
        r = p.ask(p.body(code(1), purpose="personal", terms=v1))
        assert r.status_code == 409 and r.json()["error"] == "PG_ASK_CLOSED"


def test_a_masked_stale_refusal_is_kept_like_any_masked_answer_and_never_locks_the_job():
    """REG-1, LEAK-1b: P-5a hides the reason from an unvetted provider; a masked answer is kept like any other (so it
    cannot tell a private code from an unknown one), and a stale ask still steps aside for the next request (T-7)."""
    clock = Clock()
    docs = {}
    reg = Registry(Config(prefix="ABCD", name="R", api="https://r.example", providers="open"), Key(), clock=clock,
                   fetch_party=lambda url: docs[url])
    c = TestClient(create_app(reg))
    s = reg.add_subject("Maya", level="verified", published=1)
    tid = publish(reg, s, factor="email")
    reg.set_published(s, False)                                                   # answered as if it had no terms
    p = OpenProvider(reg, c)
    docs[p.id] = p.doc
    assert reason(p, p.body(s, purpose="personal", terms=tid)) == "PG_PROVIDER_NOT_ACCEPTED"
    assert jobs_asks(reg) == [1, 1]
    assert reason(p, p.body(s, purpose="personal")) == "PG_PROVIDER_NOT_ACCEPTED"   # same job: no 409
    assert jobs_asks(reg) == [1, 2]


def test_only_a_provider_known_by_its_domain_accepts():
    reg, c, _, _, _, _ = world()
    v1 = publish(reg, code(1), factor="authenticator")
    old = Provider(reg, c)
    assert old.answer(old.body(code(1), purpose="personal", terms=v1, signers=[]))["body"]["reason"] == "PG_TERMS_NOT_ACCEPTED"
    r = old.ask(old.body(code(1), job="j2", purpose="personal", terms=v1))                    # no signers at all
    assert r.status_code == 422 and r.json()["error"] == "PG_MALFORMED"


def test_terms_to_a_registry_that_does_not_declare_them_is_malformed():
    reg, c, _ = make()
    reg.config.terms = False
    p = OpenProvider(reg, c)
    c.post("/v2/sandbox/party", json=p.doc)
    r = p.ask(p.body(code(1), purpose="personal", terms="a" * 64))
    assert r.status_code == 422 and r.json()["error"] == "PG_MALFORMED"


@pytest.mark.parametrize("case", VECTORS["requests"], ids=lambda c: c["name"])
def test_request_shapes_from_the_vectors(case):
    """T-5, TC1, TL2: a request that accepts terms names categories only in the closed vocabulary, never normalised;
    one without terms is answered as before."""
    reg, c, _, p, _, _ = world()
    v1 = publish(reg, code(1), factor="authenticator")
    body = {k: v for k, v in case["body"].items() if k != "signers"}
    if "terms" in body and len(body["terms"]) == 64 and body["terms"] == body["terms"].lower():
        body["terms"] = v1                               # the vector's id is another registry's; ours is current here
    if "signers" in case["body"]:
        r = p.ask(body)
    else:
        r = c.post("/v2/requests", headers=p.h, json={"type": "pg.request.v1", "body": body, "signatures": []})
    if case["ok"]:
        assert r.status_code == 200, r.text
    else:
        assert r.status_code == 422 and r.json()["error"] == "PG_MALFORMED", r.text


def test_a_category_that_is_not_a_word_is_malformed_with_or_without_terms():
    reg, c, _, p, _, _ = world()
    r = p.ask({**p.body(code(1)), "use": {"purpose": "personal", "categories": [1]}})
    assert r.status_code == 422 and r.json()["error"] == "PG_MALFORMED"


# ── the gate, in its order ──────────────────────────────────────────────

def test_exclusions_bind_where_no_grant_covers_the_use_personal_use_included():
    reg, c, _, p, _, _ = world()
    s = reg.add_subject("Maya", level="verified")
    v1 = publish(reg, s, factor="authenticator")
    gamble = {"purpose": "personal", "categories": ["gambling"]}
    assert reason(p, {**p.body(s, job="j1"), "use": gamble}) == "PG_TERMS_EXCLUDED"                 # without terms
    assert reason(p, {**p.body(s, job="j2", terms=v1), "use": gamble}) == "PG_TERMS_EXCLUDED"       # with them
    assert reason(p, p.body(s, job="j3", purpose="commercial")) == "PG_TERMS_EXCLUDED"             # a purpose not listed
    assert reason(p, p.body(s, job="j4", purpose="personal")) == "PG_NO_LICENSE"                   # the terms grant nothing
    assert reason(p, {**p.body(s, job="j5"), "use": {"purpose": "personal", "categories": ["beer"]}}) == "PG_NO_LICENSE"
    reg.add_grant(s, purposes=["commercial", "personal"])                                          # a grant decides its scope
    assert reason(p, {**p.body(s, job="j6"), "use": gamble}) == "allow"
    assert reason(p, p.body(s, job="j7", purpose="commercial")) == "allow"


def test_the_floor_and_the_persons_refusals_come_before_who_asks():
    reg, c, clock, p, _, _ = world()
    kid = reg.add_subject("Young actor", level="verified", minor=1)
    out = reg.add_subject("Opted out", level="verified")
    stale = {}
    for s in (kid, out):
        reg.add_grant(s, purposes=["personal"])
        stale[s] = publish(reg, s, factor="authenticator")
        clock.t += 10
        publish(reg, s, excluded=("gambling", "political"))
    reg.opt_out(out)
    violence = {"purpose": "personal", "categories": ["violence"]}
    assert reason(p, {**p.body(kid, job="j1", terms=stale[kid]), "use": violence}) == "PG_PROHIBITED_USE"
    assert reason(p, p.body(out, job="j2", purpose="personal", terms=stale[out])) == "PG_SUBJECT_OPTED_OUT"
    s = reg.add_subject("Maya", level="verified")                    # no grant: the exclusion before the stale id
    old = publish(reg, s, factor="authenticator")
    clock.t += 10
    publish(reg, s, excluded=("gambling", "political"))
    assert reason(p, {**p.body(s, job="j3", terms=old), "use": {"purpose": "personal", "categories": ["political"]}}) \
        == "PG_TERMS_EXCLUDED"
    assert reason(p, p.body(code(9, "NWRD"), job="j4", terms=old)) == "PG_OTHER_REGISTRY"          # the subject step
    assert reason(p, p.body(code(8), job="j5", terms=old)) == "PG_UNKNOWN_SUBJECT"


# ── the proof carries what the provider signed ──────────────────────────

def test_the_proof_carries_the_request_signature_and_the_terms_it_accepted():
    reg, c, clock, p, directory, get_json = world()
    v1 = publish(reg, code(1), factor="authenticator")
    body = p.body(code(1), purpose="personal", terms=v1)
    answer = p.answer(body)
    assert p.report(answer).status_code == 200
    report_id = reg.db.execute("SELECT id FROM reports").fetchone()[0]
    bundle = c.get(f"/v2/proofs/{report_id[:16]}").json()
    check_body("proof", bundle)
    item = bundle["subjects"][0]
    assert item["terms"] == c.get(f"/v2/terms/{v1}").json()["terms"]
    signed = p.signed("pg.request.v1", body)
    assert item["request"] == signed and verify_bytes(p.doc["keysets"][0]["body"]["keys"][0]["public_key_hex"],
                                                      item["request"]["signatures"][0], signing_input("pg.request.v1", signed["body"]))
    s = check_proof(bundle, directory, get_json, now=clock.t, testing=True)["subjects"][0]
    assert (s["terms"], s["terms_assent"]) == ("ok", "registry")


def test_a_registry_made_by_0_3_gains_the_signatures_column(tmp_path):
    db = str(tmp_path / "r.db")
    old = sqlite3.connect(db)
    old.execute("CREATE TABLE asks (id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, job_id TEXT NOT NULL, subject_ref "
                "TEXT NOT NULL, request TEXT NOT NULL, closing_ack TEXT, null_report TEXT, "
                "UNIQUE (provider_id, job_id, subject_ref))")
    old.execute("INSERT INTO asks (id, provider_id, job_id, subject_ref, request) VALUES ('x', 'p', 'j', 's', '{}')")
    old.commit()
    old.close()
    reg = Registry(Config(prefix="TEST", name="T", api="https://t.example"), Key(), db)
    assert reg.db.execute("SELECT signatures FROM asks WHERE id = 'x'").fetchone()[0] == "[]"
