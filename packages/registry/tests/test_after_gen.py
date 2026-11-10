"""AFTER-GEN (spec/drafts/after-gen.md, working draft): requests, the three approval forms, the record, its status, the
lookup by hash, and every must-reject vector a registry enforces. Times come from the registry's clock, never sleeps."""
import json
import re
import secrets
import time

import pregen as lib
import pytest
from fastapi.testclient import TestClient
from test_registry import Clock, OpenProvider, Provider, code, make

from pregen_registry import app as app_module
from pregen_registry.app import create_app
from pregen_registry.cli import load
from pregen_registry.cli import main as cli
from pregen_registry.protocol import Key, ProtocolError, check_body, message_id
from pregen_registry.registry import AG_REVIEW, Config, Registry

MEDIA = "ab" * 32
AGENCY = "https://agency.example"
INSTRUCTION = "c" * 64


def sign(key_hex, role, type_, body):
    return lib.sign_envelope(type_, {"signers": [{"role": role, "key_id": lib.fingerprint(lib.public_key_hex(key_hex))}],
                                     **body}, key_hex)


class World:
    """A sandbox, a studio known by its domain (the requester), an agency (a representative), a subject the registry
    holds the key of, and one who holds their own; each with a licence to the studio."""

    def __init__(self, **grant):
        self.reg, self.c, self.clock = make()
        self.p = OpenProvider(self.reg, self.c)
        self.agency_key = lib.new_private_key_hex()
        for doc in (self.p.doc, lib.party_document(AGENCY, "Agency", self.agency_key)):
            assert self.c.post("/v2/sandbox/party", json=doc).status_code == 200
        self.s = self.reg.add_subject("Maya", level="verified")
        self.own = lib.new_private_key_hex()
        self.me = self.reg.add_subject("Theo", level="verified", holder_public=lib.public_key_hex(self.own))
        self.g = self.licence(self.s, **grant)
        self.mine = self.licence(self.me, holder_key=Key(self.own), **grant)

    def licence(self, subject, **kw):
        kw = {"licensee_id": self.p.id, "purposes": ("commercial", "editorial"), "categories": ("advertising", "fashion"),
              "ext": {"n": secrets.token_hex(4)}, **kw}                  # two licences in one second: two ids
        return self.reg.add_grant(subject, **kw)

    def scope(self, **kw):
        return {"purposes": ["commercial"], "categories": ["advertising"], "territories": ["ES", "IT"],
                "channels": ["online-video", "social"], "project": "Spring campaign 2027",
                "not_after": self.clock.t + 100 * 86400, **kw}

    def body(self, subject=None, licence=None, media=MEDIA, **kw):
        subject = subject or self.s
        return {"requester": self.p.id, "subject_ref": subject,
                "licence": {"format": "pg.grant.v1", "id": licence or (self.mine if subject == self.me else self.g)},
                "content": {"binding": "media/1", "hash": media, "leaves": 1843}, "scope": kw.pop("scope", self.scope()),
                "issued_at": self.clock.t, "nonce": secrets.token_urlsafe(16), **kw}

    def ask(self, body=None, preview="https://preview.example/v/1", key=None, headers=None, **kw):
        payload = {"request": sign(key or self.p.key, "requester", "pg.after_gen_request.v1", body or self.body(**kw))}
        if preview is not None:
            payload["preview_url"] = preview
        return self.c.post("/v2/after-gen/requests", headers=headers or self.p.h, json=payload)

    def pending(self, **kw) -> str:
        r = self.ask(**kw)
        assert r.status_code == 200, r.text
        return r.json()["request"]

    def decision(self, rid, key=None, role="subject", outcome="approve", scope=None, agent=None, **kw):
        body = {"request": rid, "outcome": outcome, "issued_at": self.clock.t, **kw}
        if outcome == "approve":
            body["scope"] = scope or json.loads(self.row(rid)["scope"])
        return sign(key or (self.own if role == "subject" else self.agency_key), role, "pg.after_gen_decision.v1", body)

    def decide(self, rid, agent=None, **kw):
        env = kw.pop("env", None) or self.decision(rid, **kw)
        return self.c.post("/v2/after-gen/decisions", json=env, headers={"X-Provider-ID": agent} if agent else {})

    def mandate(self, subject=None, agent=AGENCY, powers=("after_gen",), purposes=("commercial",), days=30):
        return self.reg.add_mandate(subject or self.s, agent, powers=powers, purposes=purposes,
                                    not_after=self.clock.t + days * 86400, instruction=INSTRUCTION, factor="email")

    def row(self, rid):
        return self.reg.db.execute("SELECT * FROM after_gen_requests WHERE id = ?", (rid,)).fetchone()

    def state(self, rid):
        path = f"/v2/after-gen/requests/{rid}"
        h = {**self.p.h, "PG-Access": lib.pg_access(self.p.id, self.p.key, "https://test.example", "GET", path,
                                                    now=self.clock.t)}
        return self.c.get(path, headers=h)

    def status(self, rid):
        r = self.c.get(f"/v2/after-gen/{rid}")
        assert r.status_code == 200, r.text
        record, status = r.json()["record"], r.json()["status"]
        for env in (record, status):
            assert env["body"]["signers"] == [{"role": "registry", "key_id": self.reg.key.id}]
            assert lib.verify_bytes(self.reg.key.public_hex, env["signatures"][0], lib.signing_input(env["type"], env["body"]))
        assert status["body"]["record"] == message_id(record["type"], record["body"])
        return record["body"], status["body"]


def refused(r, error, status=None):
    assert r.status_code == (status or r.status_code) and r.status_code >= 400 and r.json()["error"] == error, r.text


def record_body(w, rid, **kw):
    r = w.decide(rid, **kw)
    assert r.status_code == 200 and r.json()["state"] == "approved", r.text
    return w.status(r.json()["record"])[0]


# ── the three forms of approval, and the sandbox's page ─────────────────

def test_the_subject_approves_with_their_own_key_and_the_record_stands():
    w = World()
    r = w.ask(subject=w.me)
    assert r.status_code == 200 and r.json()["state"] == "pending" and r.json()["review_until"] == w.clock.t + AG_REVIEW
    rid = r.json()["request"]
    assert w.c.get(f"/v2/after-gen?media={MEDIA}").json() == {"records": []}           # a request permits nothing
    assert w.state(rid).json() == {"request": rid, "state": "pending", "review_until": w.clock.t + AG_REVIEW}
    w.clock.t += 3600
    d = w.decision(rid)
    r = w.decide(rid, env=d)
    assert r.status_code == 200, r.text
    rec_id = r.json()["record"]
    body, status = w.status(rec_id)
    assert {k: body[k] for k in ("kind", "label", "notice", "not")} == {
        "kind": "ratification", "label": "approved after generation", "not": ["pre_generation_permission",
                                                                             "statement_of_origin"],
        "notice": "Recorded after the content existed. Not a PRE-GEN permission given before generation. Says nothing "
                  "about whether the content is AI-generated."}
    assert body["approval"] == {"assent": "self", "decision": message_id(d["type"], d["body"])}
    assert (body["subject_ref"], body["holder"], body["request"], body["issued_at"]) == (w.me, w.p.id, rid, w.clock.t)
    assert body["content"] == {"binding": "media/1", "hash": MEDIA, "leaves": 1843}
    assert body["licence"] == {"format": "pg.grant.v1", "id": w.mine} and body["use"] == {"n": 1, "of": None}
    assert body["scope"] == w.scope(not_after=body["scope"]["not_after"])
    assert set(body) == {"signers", "kind", "label", "notice", "not", "subject_ref", "content", "request", "holder",
                         "licence", "use", "scope", "approval", "issued_at"}       # no status_url: it would name itself
    assert w.c.get(f"/v2/after-gen/{rid}").status_code == 404                     # the status is by the record's id
    assert w.c.get(f"/v2/after-gen?media={MEDIA}").json() == {"records": [rec_id]}
    assert w.state(rid).json() == {"request": rid, "state": "approved", "review_until": w.clock.t - 3600 + AG_REVIEW,
                                   "record": rec_id}
    assert status["state"] == "active"


def test_an_agent_approves_a_narrower_scope_under_a_mandate():
    w = World(max_uses=5)
    mandate = w.mandate()
    rid = w.pending()
    narrow = w.scope(channels=["social"], territories=["ES"])
    d = w.decision(rid, role="agent", scope=narrow)
    body = record_body(w, rid, agent=AGENCY, env=d)
    assert body["approval"] == {"assent": "agent", "agent": AGENCY, "mandate": mandate, "factor": "signature",
                                "decision": message_id(d["type"], d["body"])}
    assert body["scope"] == narrow and body["use"] == {"n": 1, "of": 5} and body["holder"] == w.p.id


def test_the_sandbox_review_page_is_the_test_creators_with_a_simulated_factor():
    w = World()
    r = w.ask()
    url = r.json()["review_url"]
    assert url.startswith("https://test.example/v2/after-gen/review/") and "production registry never" in r.json()["note"]
    path = url.removeprefix("https://test.example")
    page = w.c.get(path)
    assert page.status_code == 200 and "https://preview.example/v/1" in page.text and MEDIA in page.text
    assert "test creator" in page.text and "simulated second factor" in page.text and "Spring campaign 2027" in page.text
    assert page.headers["x-frame-options"] == "DENY" and "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert page.headers["cache-control"] == "no-store"
    refused(w.c.post(path, data={"decision": "approve"}, headers={"Origin": "https://evil.example"}), "PG_MALFORMED", 403)
    done = w.c.post(path, data={"decision": "approve"}, headers={"Origin": "https://test.example"})
    assert done.status_code == 200 and "Approved" in done.text
    rec_id = w.state(r.json()["request"]).json()["record"]
    body, _ = w.status(rec_id)
    assert body["approval"]["assent"] == "registry" and body["approval"]["factor"] == "email"
    assert re.fullmatch(r"[0-9a-f]{64}", body["approval"]["instruction"]) and set(body["approval"]) == {
        "assent", "instruction", "factor"}
    refused(w.c.get(path), "PG_NOT_FOUND", 404)                                          # single use
    refused(w.c.post(path, data={"decision": "approve"}), "PG_NOT_FOUND", 404)
    assert w.reg.db.execute("SELECT review_hash FROM after_gen_requests").fetchone()[0] is None   # hashed, then gone
    r2 = w.ask(media="cd" * 32)
    assert w.c.post(r2.json()["review_url"].removeprefix("https://test.example"), data={"decision": "refuse"}).status_code == 200
    assert w.state(r2.json()["request"]).json()["state"] == "refused"


def production(tmp_path, *flags):
    d = str(tmp_path)
    cli(["init", "--dir", d, "--prefix", "ABCD", "--name", "R", "--api", "https://r.example", "--open-providers", *flags])
    reg = load(d)
    p = OpenProvider(reg, None, url="https://studio.example")
    reg.fetch_party = lambda url: p.doc                                        # read from the studio's domain
    s = reg.add_subject("Maya", level="verified")
    g = reg.add_grant(s, licensee_id=p.id, purposes=("commercial",), max_uses=3)
    scope = {"purposes": ["commercial"], "categories": [], "territories": ["*"], "channels": ["*"],
             "project": "Launch film", "not_after": int(time.time()) + 86400}
    env = lib.after_gen_request(p.id, p.key, s, g, {"binding": "media/1", "hash": MEDIA, "leaves": 7}, scope)
    return d, reg, p, s, g, {"request": env, "preview_url": "https://studio.example/p/1"}


def test_the_operator_approves_on_the_subjects_instruction_with_a_second_factor(tmp_path, capsys):
    d, reg, p, s, g, payload = production(tmp_path, "--after-gen")
    assert "after-gen" in reg.document()["extensions"]
    r = reg.after_gen_request(p.id, None, payload)                             # signed by the studio's domain key
    assert r["state"] == "pending" and "review_url" not in r                   # production: never the approval page
    with pytest.raises(ProtocolError, match="PG_NOT_AUTHENTICATED"):            # a party known by its domain sends
        reg.after_gen_request(p.id, "Bearer x", payload)                        # no credential (P-1)
    rid = r["request"]
    capsys.readouterr()
    cli(["after-gen", "show", "--dir", d, rid])
    assert "https://studio.example/p/1" in capsys.readouterr().out
    with pytest.raises(SystemExit, match="second factor"):                      # vector 4: no factor, no approval
        cli(["after-gen", "approve", "--dir", d, rid, "--instruction-sha256", INSTRUCTION])
    with pytest.raises(SystemExit, match="instruction"):
        cli(["after-gen", "approve", "--dir", d, rid, "--factor", "email"])
    cli(["after-gen", "approve", "--dir", d, rid, "--instruction-sha256", INSTRUCTION, "--factor", "authenticator"])
    rec_id = capsys.readouterr().out.strip()
    out = reg.after_gen_status(rec_id)
    assert out["record"]["body"]["approval"] == {"assent": "registry", "instruction": INSTRUCTION, "factor": "authenticator"}
    assert out["record"]["body"]["use"] == {"n": 1, "of": 3} and out["status"]["body"]["state"] == "active"
    assert reg._row("SELECT preview_url FROM after_gen_requests WHERE id = ?", (rid,))[0] is None
    cfg = tmp_path / "registry.json"                                            # after-gen turned off: no new request,
    cfg.write_text(json.dumps({**json.loads(cfg.read_text()), "after_gen": False}))   # but its records still answer
    cli(["after-gen", "withdraw", "--dir", d, rec_id, "--instruction-sha256", INSTRUCTION])     # closing: no factor
    assert load(d).after_gen_status(rec_id)["status"]["body"]["state"] == "withdrawn"
    cli(["mandate", "add", "--dir", d, s, AGENCY, "--purposes", "commercial", "--not-after", str(int(time.time()) + 600),
         "--instruction-sha256", INSTRUCTION, "--factor", "email"])
    mid = capsys.readouterr().out.strip().splitlines()[-1]
    with pytest.raises(SystemExit, match="opens"):                             # a mandate opens: a factor
        cli(["mandate", "add", "--dir", d, s, AGENCY, "--purposes", "commercial", "--not-after",
             str(int(time.time()) + 600), "--instruction-sha256", INSTRUCTION])
    cli(["mandate", "end", "--dir", d, mid])
    assert reg._row("SELECT ended_at FROM mandates WHERE id = ?", (mid,))[0] is not None


def test_a_production_registry_declares_after_gen_only_when_configured(tmp_path):
    reg, c, _ = make(sandbox=False)
    doc = c.get("/.well-known/pregen-registry.json").json()
    check_body("registry-document", doc)
    assert "after-gen" not in doc["extensions"]
    for r in (c.get(f"/v2/after-gen/{MEDIA}"), c.post("/v2/after-gen/requests", json={}),
              c.post("/v2/after-gen/decisions", json={})):
        refused(r, "PG_NOT_FOUND", 404)
    assert c.get(f"/v2/after-gen?media={MEDIA}").json() == {"records": []}      # it signed none
    with pytest.raises(ValueError, match="open-providers"):                     # a record names a party id
        Config(prefix="ABCD", name="R", api="https://r.example", after_gen=True)
    on = Registry(Config(prefix="ABCD", name="R", api="https://r.example", providers="open", after_gen=True), Key())
    check_body("registry-document", on.document())
    assert "after-gen" in on.document()["extensions"]
    sandbox = TestClient(create_app(make()[0])).get("/.well-known/pregen-registry.json").json()
    check_body("registry-document", sandbox)
    assert "after-gen" in sandbox["extensions"]


def test_mandate_signed_by_the_subjects_own_key():
    w = World()
    body = {"subject_ref": w.me, "agent": AGENCY, "powers": ["after_gen"], "limits": {"purposes": ["commercial"]},
            "not_after": w.clock.t + 86400, "assent": "self", "issued_at": w.clock.t}
    mid = w.reg.add_mandate_envelope(sign(w.own, "subject", "pg.mandate.v1", body))
    record = record_body(w, w.pending(subject=w.me), role="agent", agent=AGENCY)
    assert record["approval"]["mandate"] == mid
    with pytest.raises(ProtocolError):                                          # another key
        w.reg.add_mandate_envelope(sign(lib.new_private_key_hex(), "subject", "pg.mandate.v1", body))
    with pytest.raises(ValueError, match="custody self"):                       # the registry holds Maya's key
        w.reg.add_mandate_envelope(sign(w.own, "subject", "pg.mandate.v1", {**body, "subject_ref": w.s}))


# ── laundering (vectors 1-5) ────────────────────────────────────────────

def test_1_silence_and_an_expired_review_period_approve_nothing():
    w = World()
    rid = w.pending(subject=w.me)
    assert w.c.get(f"/v2/after-gen/{rid}").status_code == 404                    # the request itself is no record
    w.clock.t += AG_REVIEW
    assert w.state(rid).json()["state"] == "expired"
    refused(w.decide(rid), "PG_REQUEST_CLOSED", 409)                            # a decision after expiry
    with pytest.raises(ValueError, match="no pending request"):
        w.reg.approve_after_gen(rid, instruction=INSTRUCTION, factor="email")
    rid2 = w.pending(subject=w.me, media="cd" * 32)
    w.clock.t += AG_REVIEW                                                      # expired, though nothing read it yet
    refused(w.decide(rid2), "PG_REQUEST_CLOSED", 409)
    assert w.c.get(f"/v2/after-gen?media={MEDIA}").json() == {"records": []}
    assert w.reg.db.execute("SELECT COUNT(*) FROM after_gen_records").fetchone()[0] == 0


def test_2_never_the_requester_another_party_or_a_key_the_registry_holds():
    w = World()
    rid = w.pending(subject=w.me)
    refused(w.decide(rid, key=w.p.key), "PG_NOT_FOUND", 404)                     # the requester's key as the subject
    w.mandate(subject=w.me, agent=w.p.id)                                       # even with a mandate of its own
    refused(w.decide(rid, role="agent", key=w.p.key, agent=w.p.id), "PG_NO_MANDATE", 403)
    port = OpenProvider(w.reg, w.c, url=w.p.id + ":8443")                        # the holder's host on another port
    w.c.post("/v2/sandbox/party", json=port.doc)
    w.mandate(subject=w.me, agent=port.id)
    refused(w.decide(rid, role="agent", key=port.key, agent=port.id), "PG_NO_MANDATE", 403)
    refused(w.decide(rid, role="agent", agent=AGENCY), "PG_NOT_FOUND", 404)      # another party, no mandate
    managed = w.pending()                                                       # Maya: the registry holds her key
    held = w.reg.db.execute("SELECT key_private FROM subjects WHERE code = ?", (w.s,)).fetchone()[0]
    r = w.decide(managed, key=Key(held).private_hex)       # refused on intake, as an unknown request would be;
    refused(r, "PG_NOT_FOUND", 404)                         # _sign_after_gen checks again (test 4)
    assert w.reg.db.execute("SELECT COUNT(*) FROM after_gen_records").fetchone()[0] == 0


def test_3_a_mandate_must_list_after_gen_be_live_be_for_this_subject_and_cover_the_scope():
    w = World()
    rid = w.pending()
    agent = {"role": "agent", "agent": AGENCY}
    w.mandate(powers=("sign_contracts",))                                       # without a live after_gen mandate
    refused(w.decide(rid, **agent), "PG_NOT_FOUND", 404)                         # of this subject, the request is
    w.reg.end_mandate(w.mandate())                                              # as unknown as one that is not there
    refused(w.decide(rid, **agent), "PG_NOT_FOUND", 404)                         # ended
    w.mandate(days=1)
    w.clock.t += 2 * 86400
    refused(w.decide(rid, **agent), "PG_NOT_FOUND", 404)                         # expired
    w.mandate(subject=w.me)
    refused(w.decide(rid, **agent), "PG_NOT_FOUND", 404)                         # another subject's
    w.mandate(purposes=("editorial",))
    refused(w.decide(rid, **agent), "PG_SCOPE_VIOLATION", 403)                   # beyond limits.purposes
    w.mandate(purposes=("commercial", "editorial"))
    assert w.decide(rid, **agent).json()["state"] == "approved"


def test_4_registry_names_a_factor_and_self_never_does():
    w = World()
    rid = w.pending(subject=w.me)
    with pytest.raises(ValueError, match="second factor"):
        w.reg.approve_after_gen(rid, instruction=INSTRUCTION, factor=None)
    row, scope = w.row(rid), json.loads(w.row(rid)["scope"])
    for approval in ({"assent": "self", "decision": "d" * 64, "factor": "email"},       # self naming a factor
                     {"assent": "registry", "instruction": INSTRUCTION},                 # registry naming none
                     {"assent": "registry", "instruction": INSTRUCTION, "factor": "sms"},
                     {"assent": "holder", "decision": "d" * 64},
                     {"assent": "agent", "agent": w.p.id + ":8443", "mandate": "e" * 64, "decision": "d" * 64,
                      "factor": "signature"}):                                    # the holder's host, another port
        with pytest.raises(ProtocolError, match="PG_MALFORMED"), w.reg.tx() as db:
            w.reg._sign_after_gen(db, row, scope, approval, w.clock.t)
    managed = w.row(w.pending())
    with pytest.raises(ProtocolError, match="PG_PERSONAL_SIGNATURE_REQUIRED"), w.reg.tx() as db:
        w.reg._sign_after_gen(db, managed, scope, {"assent": "self", "decision": "d" * 64}, w.clock.t)


def test_5_a_decision_names_exactly_its_request_and_is_signed_by_the_right_key():
    w = World()
    other = lib.new_private_key_hex()
    her = w.reg.add_subject("Ana", level="verified", holder_public=lib.public_key_hex(other))
    mine, hers = w.pending(subject=w.me), w.pending(subject=her, licence=w.licence(her, holder_key=Key(other)))
    d = w.decision(mine)
    unknown = w.decide("f" * 64, scope=w.scope())
    for r in (w.decide(hers),                                                    # Theo's key, Ana's request
              w.decide(mine, key=lib.new_private_key_hex()),                    # a key that is no one's
              w.decide(hers, env={**d, "body": {**d["body"], "request": hers}}),   # Theo's decision moved to Ana's
              w.decide(w.pending(), key=lib.new_private_key_hex())):            # Maya: the registry holds her key
        assert (r.status_code, r.json()) == (unknown.status_code, unknown.json()) == (404, {
            "error": "PG_NOT_FOUND", "error_description": "no such request"})  # a stranger learns nothing (step 4)
    refused(w.decide(mine, outcome="approve", env={**d, "body": {**d["body"], "extra": 1}}), "PG_MALFORMED", 422)
    refuse = w.decision(mine, outcome="refuse")
    refused(w.decide(mine, env=sign(w.own, "subject", "pg.after_gen_decision.v1",
                                    {**{k: v for k, v in refuse["body"].items() if k != "signers"},
                                     "scope": w.scope()})), "PG_MALFORMED", 422)   # a refusal carries no scope
    assert w.decide(mine, env=d).json()["state"] == "approved"


# ── the file (vectors 7, 8) ─────────────────────────────────────────────

def test_7_one_file_by_its_media_1_hash():
    w = World()
    good = w.body()
    for content in ({**good["content"], "binding": "sha256"}, {**good["content"], "binding": "media/2"},
                    [good["content"], {**good["content"], "hash": "cd" * 32}], {**good["content"], "hash": MEDIA.upper()},
                    {**good["content"], "hash": MEDIA[:-1]}, {**good["content"], "leaves": 0},
                    {**good["content"], "leaves": "1843"}, {**good["content"], "extra": 1}):
        refused(w.ask(body={**good, "content": content}), "PG_MALFORMED", 422)
    refused(w.ask(body={**good, "files": [MEDIA]}), "PG_MALFORMED", 422)
    assert w.ask(body=good).status_code == 200


def test_8_one_record_per_file_and_licence():
    w = World()
    first, second = w.pending(subject=w.me), w.pending(subject=w.me)            # two requests, one file
    assert w.decide(first).json()["state"] == "approved"
    refused(w.decide(second), "PG_ALREADY_APPROVED", 409)
    refused(w.ask(subject=w.me), "PG_ALREADY_APPROVED", 409)
    other = w.licence(w.me, holder_key=Key(w.own))
    assert w.decide(w.pending(subject=w.me, licence=other)).json()["state"] == "approved"   # another licence


# ── floors (vectors 12-14) ──────────────────────────────────────────────

def test_12_never_for_a_known_minor():
    w = World()
    kid = w.reg.add_subject("Kid", level="verified", minor=1)
    refused(w.ask(subject=kid, licence=w.licence(kid), scope=w.scope(categories=[])), "PG_PROHIBITED_USE", 403)
    eleven = w.reg.db.execute("SELECT id FROM grants WHERE subject_code = ?", (code(11),)).fetchone()[0]   # sandbox 11
    refused(w.ask(subject=code(11), licence=eleven, scope=w.scope(categories=[])), "PG_PROHIBITED_USE", 403)


def test_13_no_intimate_category_and_no_word_outside_the_vocabulary():
    w = World()
    lic = w.licence(w.me, holder_key=Key(w.own), categories=("adult", "advertising", "sexual"))
    for cat in ("sexual", "adult"):                                             # even on a licence that names it
        refused(w.ask(subject=w.me, licence=lic, scope=w.scope(categories=[cat])), "PG_PROHIBITED_USE", 403)
    for cats in (["beer"], ["Advertising"], ["advertising", "advertising"], "advertising"):
        refused(w.ask(subject=w.me, licence=lic, scope=w.scope(categories=cats)), "PG_MALFORMED", 422)


def test_14_opted_out_unavailable_withdrawn_from_the_holder_or_excluded_by_terms():
    w = World()
    late = w.pending()                                                          # taken, then the subject opts out
    w.reg.opt_out(w.s)
    refused(w.ask(), "PG_SUBJECT_OPTED_OUT", 403)
    with pytest.raises(ProtocolError, match="PG_SUBJECT_OPTED_OUT"):            # checked again at signing (step 4)
        w.reg.approve_after_gen(late, instruction=INSTRUCTION, factor="email")
    paused = w.reg.add_subject("Paused", level="verified")
    lic = w.licence(paused)
    w.reg.db.execute("UPDATE subjects SET status = 'paused' WHERE code = ?", (paused,))
    refused(w.ask(subject=paused, licence=lic), "PG_SUBJECT_UNAVAILABLE", 403)
    w.reg.revoke_grant(w.mine)                                                  # withdrawn from this holder
    refused(w.ask(subject=w.me), "PG_NO_LICENSE", 403)
    terms = w.reg.add_subject("Terms", level="verified")
    w.reg.publish_terms(terms, purposes=("commercial",), excluded_categories=("advertising",),
                        template={"id": "t", "version": 1, "jurisdiction": "US"},
                        legal={"sha256": "b" * 64, "url": "https://t.example/1.txt"}, factor="email")
    lic = w.licence(terms)                                                       # the licence names advertising
    refused(w.ask(subject=terms, licence=lic), "PG_TERMS_EXCLUDED", 403)
    assert w.ask(subject=terms, licence=lic, scope=w.scope(categories=["fashion"])).status_code == 200


# ── the licence (vector 15) ─────────────────────────────────────────────

def test_15_the_licence_is_for_this_subject_and_holder_valid_with_a_use_left_and_wide_enough():
    w = World()
    refused(w.ask(licence=w.mine), "PG_NO_LICENSE", 403)                         # another subject's
    refused(w.ask(licence=w.reg.add_grant(w.s, licensee_id="https://other.example")), "PG_NO_LICENSE", 403)
    later = w.licence(w.s)
    w.reg.db.execute("UPDATE grants SET not_before = ? WHERE id = ?", (w.clock.t + 60, later))
    refused(w.ask(licence=later), "PG_NO_LICENSE", 403)                          # not yet valid
    gone = w.licence(w.s)
    w.reg.db.execute("UPDATE grants SET expires_at = ? WHERE id = ?", (w.clock.t, gone))
    refused(w.ask(licence=gone), "PG_NO_LICENSE", 403)                           # expired
    for scope in (w.scope(purposes=["research"]), w.scope(categories=["alcohol"]),
                  w.scope(not_after=w.clock.t + 366 * 86400)):
        refused(w.ask(scope=scope), "PG_SCOPE_VIOLATION", 403)                   # wider than the licence
    rid = w.pending()
    refused(w.decide(rid, role="agent", agent=AGENCY, scope=w.scope(channels=["*"])), "PG_NOT_FOUND", 404)
    w.mandate()
    refused(w.decide(rid, role="agent", agent=AGENCY, scope=w.scope(channels=["*"])), "PG_SCOPE_VIOLATION")  # wider
    assert w.decide(rid, role="agent", agent=AGENCY).json()["state"] == "approved"   # than the request


def test_15_uses_are_one_counter_with_the_allows_of_the_limits_extension():
    w = World()
    w.reg.revoke_grant(w.g)
    one = w.licence(w.s, max_uses=1)
    allow = w.p.answer(w.p.body(w.s, purpose="commercial"))                     # the grant's one use, taken by an allow
    assert allow["body"]["status"] == "allow" and allow["body"]["basis"]["grant"]["id"] == one
    refused(w.ask(licence=one), "PG_USAGE_LIMIT", 403)
    w.reg.revoke_grant(one)
    two = w.licence(w.s, max_uses=1)
    w.reg.approve_after_gen(w.pending(licence=two), instruction=INSTRUCTION, factor="email")   # a record takes it
    a = w.p.answer(w.p.body(w.s, job="job-2", purpose="commercial"))["body"]
    assert (a["status"], a["reason"]) == ("deny", "PG_USAGE_LIMIT")
    refused(w.ask(licence=two, media="cd" * 32), "PG_USAGE_LIMIT", 403)
    g = w.c.get(f"/v2/grants/{two}").json()["grant"]
    assert g["body"]["max_uses"] == 1


# ── status and privacy (vectors 16-18) ──────────────────────────────────

def test_16_status_says_active_withdrawn_with_both_times_or_expired():
    w = World()
    rid = w.pending(subject=w.me, scope=w.scope(not_after=w.clock.t + 86400))
    rec = w.decide(rid).json()["record"]
    approved = w.clock.t
    _, s = w.status(rec)
    assert s == {"signers": s["signers"], "record": rec, "state": "active", "approved_at": approved,
                 "withdrawn_at": None, "not_after": approved + 86400, "issued_at": w.clock.t,
                 "expires_at": w.clock.t + 300}
    w.clock.t += 600
    refused(w.c.post(f"/v2/after-gen/{rec}/withdraw", json=sign(w.own, "subject", "pg.after_gen_withdrawal.v1", {
        "record": "f" * 64, "issued_at": w.clock.t})), "PG_MALFORMED", 422)      # a withdrawal of another record
    def withdraw(record, key):
        r = w.c.post(f"/v2/after-gen/{record}/withdraw", json=sign(key, "subject", "pg.after_gen_withdrawal.v1",
                                                                    {"record": record, "issued_at": w.clock.t}))
        return r.status_code, r.json()
    unknown = withdraw("f" * 64, w.own)
    managed = w.reg.approve_after_gen(w.pending(media="ef" * 32), instruction=INSTRUCTION, factor="email")
    held = Key(w.reg.db.execute("SELECT key_private FROM subjects WHERE code = ?", (w.s,)).fetchone()[0]).private_hex
    assert withdraw(rec, lib.new_private_key_hex()) == withdraw(managed, w.own) == withdraw(managed, held) == unknown \
        == (404, {"error": "PG_NOT_FOUND", "error_description": "no such record"})   # another key; a key the registry
    assert w.status(managed)[1]["state"] == "active"                                 # holds signs no withdrawal
    r = w.c.post(f"/v2/after-gen/{rec}/withdraw", json=sign(w.own, "subject", "pg.after_gen_withdrawal.v1",
                                                            {"record": rec, "issued_at": w.clock.t}))
    assert r.json() == {"record": rec, "state": "withdrawn", "withdrawn_at": w.clock.t}, r.text
    _, s = w.status(rec)
    assert (s["state"], s["approved_at"], s["withdrawn_at"]) == ("withdrawn", approved, approved + 600)
    w.clock.t += 86400                                                           # withdrawn stays withdrawn
    assert w.status(rec)[1]["state"] == "withdrawn"
    other = w.decide(w.pending(subject=w.me, media="cd" * 32, scope=w.scope(not_after=w.clock.t + 10))).json()["record"]
    w.clock.t += 10
    assert w.status(other)[1]["state"] == "expired" and w.status(other)[1]["withdrawn_at"] is None


def test_17_the_lookup_by_hash_shows_approved_records_only_and_tells_nothing_else():
    w = World()
    pending, refused_, expired = "11" * 32, "22" * 32, "33" * 32
    w.pending(media=pending)
    w.reg.refuse_after_gen(w.pending(media=refused_))
    rid = w.pending(media=expired)
    w.clock.t += AG_REVIEW
    unknown = w.c.get(f"/v2/after-gen?media={'44' * 32}")
    for media in (pending, refused_, expired):
        r = w.c.get(f"/v2/after-gen?media={media}")
        assert (r.status_code, r.content, r.headers) == (unknown.status_code, unknown.content, unknown.headers)
    for rid_ in (rid, "f" * 64):                                                 # nor by id
        r = w.c.get(f"/v2/after-gen/{rid_}")
        assert r.status_code == 404 and r.json() == w.c.get(f"/v2/after-gen/{'e' * 64}").json()
    refused(w.c.get("/v2/after-gen?media=xyz"), "PG_MALFORMED", 422)


def test_18_the_viewing_link_goes_to_the_approver_only_and_is_gone_after_a_decision_or_expiry():
    w = World()
    approved, refused_, expired = (w.pending(subject=w.me, media=m) for m in ("11" * 32, "22" * 32, "33" * 32))
    assert all(w.row(r)["preview_url"] == "https://preview.example/v/1" for r in (approved, refused_, expired))
    assert "preview" not in w.state(approved).text
    rec = w.decide(approved).json()["record"]
    w.decide(refused_, outcome="refuse")
    w.clock.t += AG_REVIEW
    w.state(expired)
    assert [w.row(r)["preview_url"] for r in (approved, refused_, expired)] == [None, None, None]
    assert "preview" not in w.c.get(f"/v2/after-gen/{rec}").text and "preview" not in w.state(approved).text
    for bad in ("http://preview.example/v", "https://a b", 5):
        refused(w.ask(preview=bad), "PG_MALFORMED", 422)


# ── the registry and the verify library agree ───────────────────────────

def test_the_library_accepts_every_record_and_status_the_registry_signs():
    """pregen.check_after_gen and check_after_gen_status, against a directory that lists this registry, on records of
    each approval form; requests and decisions built by the library's own helpers."""
    w = World()
    steward = Key()
    d = {"schema": "pregen.registries.v2", "sequence": 1, "steward_key_id": steward.id, "registries": [
        {"name": "Test", "prefix": "TEST", "api": "https://test.example", "keys": "https://test.example/keys",
         "key_fingerprints": [w.reg.key.id]}]}
    directory = lib.verify_directory({**d, "signature": steward.sign(lib.canonical_json(d))}, steward.public_hex,
                                     now=w.clock.t)
    get_json = lambda url: w.c.get("/keys").json()  # noqa: E731

    def ask(subject, licence, media):
        env = lib.after_gen_request(w.p.id, w.p.key, subject, licence, {"binding": "media/1", "hash": media, "leaves": 9},
                                    w.scope(not_after=w.clock.t + 86400), now=w.clock.t)
        r = w.c.post("/v2/after-gen/requests", headers=w.p.h, json={"request": env})
        assert r.status_code == 200, r.text
        return r.json()["request"]

    w.mandate()
    own = ask(w.me, w.mine, "11" * 32)
    agent = ask(w.s, w.g, "22" * 32)
    records = [w.c.post("/v2/after-gen/decisions", json=lib.after_gen_decision(
        own, "approve", w.scope(not_after=w.clock.t + 86400), w.own, "subject", now=w.clock.t)).json()["record"],
        w.c.post("/v2/after-gen/decisions", headers={"X-Provider-ID": AGENCY}, json=lib.after_gen_decision(
            agent, "approve", w.scope(not_after=w.clock.t + 86400), w.agency_key, "agent", now=w.clock.t)).json()["record"],
        w.reg.approve_after_gen(ask(w.s, w.g, "33" * 32), instruction=INSTRUCTION, factor="authenticator")]
    for rec, assent in zip(records, ("self", "agent", "registry")):
        out = w.c.get(f"/v2/after-gen/{rec}").json()
        checked = lib.check_after_gen(out["record"], directory, get_json)
        assert (checked["id"], checked["approval"]["assent"]) == (rec, assent)
        assert checked["status_url"] == f"https://test.example/v2/after-gen/{rec}"
        assert lib.check_after_gen_status(out["status"], out["record"], directory, get_json, now=w.clock.t)["state"] == "active"
    w.clock.t += 60
    w.reg.withdraw_after_gen(records[2], instruction=INSTRUCTION)
    out = w.c.get(f"/v2/after-gen/{records[2]}").json()
    assert lib.check_after_gen_status(out["status"], out["record"], directory, get_json, now=w.clock.t) == {
        "state": "withdrawn", "approved_at": w.clock.t - 60, "withdrawn_at": w.clock.t, "not_after": w.clock.t - 60 + 86400}
    w.clock.t += 86400                                                            # a directory a day old is loaded again
    directory = lib.verify_directory({**d, "signature": steward.sign(lib.canonical_json(d))}, steward.public_hex,
                                     now=w.clock.t)
    out = w.c.get(f"/v2/after-gen/{records[0]}").json()
    assert lib.check_after_gen_status(out["status"], out["record"], directory, get_json, now=w.clock.t)["state"] == "expired"


# ── a record is never an answer (vector 11), and the requester's authentication ──

def test_11_a_record_is_never_an_answer_or_cited_by_a_report():
    w = World()
    rec = w.decide(w.pending(subject=w.me)).json()["record"]
    a = w.p.answer(w.p.body(w.me, purpose="commercial"))
    assert a["body"]["basis"]["kind"] == "grant"
    r = w.p.report(a)
    body = {**a["body"]}
    forged = w.p.signed("pg.report.v1", {"request_id": body["request_id"], "answer": rec, "job_id": "job-1",
                                         "outcome": "generated", "output_hash": "e" * 64, "occurred_at": w.clock.t})
    refused(w.c.post("/v2/reports", headers=w.p.h, json=forged), "PG_MALFORMED", 422)
    assert r.status_code == 200


def test_requests_are_authenticated_fresh_and_in_shape():
    w = World()
    refused(w.ask(key=lib.new_private_key_hex()), "PG_NOT_AUTHENTICATED", 401)    # another key
    refused(w.ask(requester="https://other.example"), "PG_NOT_AUTHENTICATED", 401)
    refused(w.ask(issued_at=w.clock.t - 301), "PG_MALFORMED", 422)
    refused(w.ask(scope=w.scope(not_after=w.clock.t)), "PG_MALFORMED", 422)
    refused(w.ask(subject=code(1).lower()), "PG_MALFORMED", 422)
    territories = sorted(a + b for a in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" for b in "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    channels = [f"c{i:02d}" for i in range(65)]
    for scope in (w.scope(purposes=[]), w.scope(territories=["es"]), w.scope(territories=["*", "ES"]),
                  w.scope(channels=["Social"]), w.scope(project=""), w.scope(project="a\nb"),
                  {**w.scope(), "fee": 1}, w.scope(territories=["IT", "ES"]), w.scope(territories=territories[:251]),
                  w.scope(channels=channels)):                                  # at most 250 territories, 64 channels
        refused(w.ask(scope=scope), "PG_MALFORMED", 422)
    assert w.ask(scope=w.scope(territories=territories[:250], channels=channels[:64])).status_code == 200
    registered = Provider(w.reg, w.c)                                           # a credential alone is no party id:
    body = {"signers": [], **w.body(), "requester": registered.id}              # the record could not name it
    refused(w.c.post("/v2/after-gen/requests", headers=registered.h, json={"request": {
        "type": "pg.after_gen_request.v1", "body": body, "signatures": []}}), "PG_NOT_AUTHENTICATED", 401)
    assert w.reg.db.execute("SELECT COUNT(*) FROM after_gen_requests WHERE requester = ?",
                            (registered.id,)).fetchone()[0] == 0
    signer = [{"role": "requester", "key_id": w.p.key_id}]
    post = lambda path, v: w.c.post(path, content=json.dumps(v), headers={**w.p.h, "content-type": "application/json"})  # noqa: E731
    for bad in (1.5, 2**70, "\ud800"):                                           # unsignable JSON: refused, never a 500
        refused(post("/v2/after-gen/requests", {"request": {
            "type": "pg.after_gen_request.v1", "body": {"signers": signer, **w.body(), "nonce": bad},
            "signatures": ["00" * 64]}}), "PG_MALFORMED", 422)
        refused(post("/v2/requests", {"type": "pg.request.v1", "body": {
            "signers": [{**signer[0], "role": "provider"}], **w.p.body(code(1)), "job_id": bad},
            "signatures": ["00" * 64]}), "PG_MALFORMED", 422)
    body = w.body()
    first, again = w.ask(body=body).json(), w.ask(body=body).json()
    assert again == {k: first[k] for k in ("request", "state", "review_until")}  # the identical request: its state
    other = OpenProvider(w.reg, w.c, url="https://intruder.example")
    w.c.post("/v2/sandbox/party", json=other.doc)
    path = f"/v2/after-gen/requests/{first['request']}"
    h = {**other.h, "PG-Access": lib.pg_access(other.id, other.key, "https://test.example", "GET", path, now=w.clock.t)}
    refused(w.c.get(path, headers=h), "PG_NOT_FOUND", 404)                       # only the requester sees it


def test_an_unvetted_domain_learns_nothing_of_an_unpublished_subject():
    doc = {}
    clock = Clock()
    reg = Registry(Config(prefix="ABCD", name="R", api="https://r.example", providers="open", after_gen=True), Key(),
                   clock=clock, fetch_party=lambda url: doc[url])
    w = World.__new__(World)
    w.reg, w.c, w.clock = reg, TestClient(create_app(reg)), clock
    w.p = OpenProvider(reg, w.c)
    doc[w.p.id] = w.p.doc
    hidden = reg.add_subject("Hidden", level="verified")
    reg.opt_out(hidden)
    w.me, answers = None, []
    for s in (reg.add_subject("Fine", level="verified"), reg.add_subject("Kid", level="verified", minor=1), hidden):
        w.s, w.g = s, reg.add_grant(s, licensee_id="", purposes=("commercial",), categories=("advertising",))
        r = w.ask(scope=w.scope(categories=[]))                                  # P-5a: on an open licence, one
        answers.append((r.status_code, r.json()))                               # refusal whatever the subject's state
    assert answers == [(403, {"error": "PG_PROVIDER_NOT_ACCEPTED",
                              "error_description": "this registry has not accepted this provider (P-5)"})] * 3
    assert reg.db.execute("SELECT COUNT(*) FROM after_gen_requests").fetchone()[0] == 0
    w.g = reg.add_grant(hidden, licensee_id=w.p.id, purposes=("commercial",), categories=("advertising",))
    refused(w.ask(), "PG_SUBJECT_OPTED_OUT", 403)                                # its own licence: it may know
    r = w.ask()
    assert "review_url" not in r.text


def test_cors_only_on_the_two_public_reads(monkeypatch):
    w = World()
    rid = w.pending(subject=w.me)
    rec = w.decide(rid).json()["record"]
    for r in (w.c.get(f"/v2/after-gen?media={MEDIA}"), w.c.get(f"/v2/after-gen/{rec}"), w.c.get(f"/v2/after-gen/{'f' * 64}")):
        assert r.headers.get("access-control-allow-origin") == "*" and "access-control-allow-credentials" not in r.headers
    for r in (w.ask(media="cd" * 32), w.decide(rid), w.state(rid), w.c.get("/.well-known/pregen-registry.json")):
        assert "access-control-allow-origin" not in r.headers
    monkeypatch.setattr(app_module, "AFTER_GEN_REQUESTS_PER_HOUR", 1)            # and requests are rate-limited
    c = TestClient(create_app(w.reg))
    w.c = c
    refused(w.ask(media="ee" * 32, preview="http://x"), "PG_MALFORMED", 422)       # an invalid one takes no slot
    assert w.ask(media="ee" * 32).status_code == 200
    refused(w.ask(media="ff" * 32), "PG_RATE_LIMITED", 429)


# ── step 4 as of now, the decision kept, and what a decider learns ──────

def test_a_not_after_already_past_is_never_signed_and_takes_no_use():
    w = World(max_uses=3)
    late = w.pending(subject=w.me, scope=w.scope(not_after=w.clock.t + 60))
    w.clock.t += 7200                                                           # passed during the review
    refused(w.decide(late), "PG_SCOPE_VIOLATION", 403)
    with pytest.raises(ProtocolError, match="PG_SCOPE_VIOLATION"):
        w.reg.approve_after_gen(late, instruction=INSTRUCTION, factor="email")
    refused(w.decide(w.pending(subject=w.me, media="cd" * 32), scope=w.scope(not_after=w.clock.t)),
            "PG_SCOPE_VIOLATION", 403)                                          # a decision narrowing it to now
    assert w.reg.db.execute("SELECT COUNT(*) FROM after_gen_records").fetchone()[0] == 0
    assert record_body(w, w.pending(subject=w.me, media="ef" * 32))["use"] == {"n": 1, "of": 3}   # none was counted


def test_use_n_is_the_licences_count_when_signed_so_a_give_back_can_repeat_it():
    """after-gen.md, `use`: the count at signing, this record included; an allow given back lowers it."""
    w = World()
    w.reg.revoke_grant(w.g)
    g = w.licence(w.s, max_uses=3)
    allow = w.p.answer(w.p.body(w.s, purpose="commercial"))                      # use 1: an allow
    first = w.reg.approve_after_gen(w.pending(licence=g, media="11" * 32), instruction=INSTRUCTION, factor="email")
    assert w.p.report(allow, outcome="not_generated").status_code == 200        # the allow's use is given back
    second = w.reg.approve_after_gen(w.pending(licence=g, media="22" * 32), instruction=INSTRUCTION, factor="email")
    assert [w.status(r)[0]["use"] for r in (first, second)] == [{"n": 2, "of": 3}] * 2


def test_the_registry_keeps_the_decision_it_received_and_an_agent_without_a_mandate_learns_nothing():
    w = World()
    d = w.decision(own := w.pending(subject=w.me))
    w.mandate()
    a = w.decision(agent := w.pending(), role="agent")
    records = [w.decide(own, env=d).json()["record"], w.decide(agent, agent=AGENCY, env=a).json()["record"],
               w.reg.approve_after_gen(w.pending(media="cd" * 32), instruction=INSTRUCTION, factor="email")]
    kept = [w.reg.db.execute("SELECT decision FROM after_gen_records WHERE id = ?", (r,)).fetchone()[0] for r in records]
    assert [json.loads(k) if k else None for k in kept] == [d, a, None]
    assert set(w.c.get(f"/v2/after-gen/{records[0]}").json()) == {"record", "status"}         # kept, not published
    intruder = OpenProvider(w.reg, w.c, url="https://intruder.example")
    w.c.post("/v2/sandbox/party", json=intruder.doc)
    refused_ = w.pending(subject=w.me, media="ef" * 32, scope=w.scope(project="Secret"))
    w.decide(refused_, outcome="refuse")
    pending = w.pending(subject=w.me, media="11" * 32, scope=w.scope(project="Secret"))
    unknown = w.decide("f" * 64, role="agent", agent=intruder.id, key=intruder.key, scope=w.scope())
    for rid, scope in ((refused_, w.scope(project="Secret")), (pending, w.scope(project="guess")),
                       (pending, w.scope(project="Secret"))):
        r = w.decide(rid, role="agent", agent=intruder.id, key=intruder.key, scope=scope)
        assert (r.status_code, r.json()) == (unknown.status_code, unknown.json()) == (404, unknown.json())


def test_turned_off_it_takes_no_new_request_or_approval_but_its_records_still_answer():
    """after-gen.md step 5: status, lookup and withdrawal keep working for every record signed."""
    w = World()
    rec = w.decide(w.pending(subject=w.me)).json()["record"]
    pending = w.pending(subject=w.me, media="cd" * 32)
    w.reg.config.after_gen = False
    refused(w.ask(subject=w.me, media="ef" * 32), "PG_NOT_FOUND", 404)
    refused(w.decide(pending), "PG_NOT_FOUND", 404)
    with pytest.raises(ProtocolError, match="PG_NOT_FOUND"):
        w.reg.approve_after_gen(pending, instruction=INSTRUCTION, factor="email")
    assert w.c.get(f"/v2/after-gen?media={MEDIA}").json() == {"records": [rec]} and w.status(rec)[1]["state"] == "active"
    refused(w.c.post(f"/v2/after-gen/{rec}/withdraw", content="null", headers={"content-type": "application/json"}),
            "PG_MALFORMED", 422)                                                # never the instruction path
    good = sign(w.own, "subject", "pg.after_gen_withdrawal.v1", {"record": rec, "issued_at": w.clock.t})
    assert w.c.post(f"/v2/after-gen/{rec}/withdraw", json=good).status_code == 200
    assert w.status(rec)[1]["state"] == "withdrawn"


def test_the_public_reads_expire_an_undecided_request_and_drop_its_viewing_link():
    for read in (lambda w: w.c.get(f"/v2/after-gen?media={MEDIA}"), lambda w: w.c.get(f"/v2/after-gen/{'f' * 64}")):
        w = World()
        rid = w.pending(subject=w.me)
        w.clock.t += AG_REVIEW
        read(w)
        assert (w.row(rid)["state"], w.row(rid)["preview_url"], w.row(rid)["review_hash"]) == ("expired", None, None)
