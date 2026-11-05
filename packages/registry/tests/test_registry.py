"""The reference registry against PRE-GEN-CORE.md and the extensions, over HTTP."""
import json
import threading

import pytest
from fastapi.testclient import TestClient
from pregen import PregenError, canonical_json, fingerprint, verify_bytes

from pregen_registry.app import create_app
from pregen_registry.cli import main as cli
from pregen_registry.protocol import Key, check_body, message_id, mint_code, parse_code, seal, signing_input
from pregen_registry.registry import Config, Registry


class Clock:
    def __init__(self):
        self.t = 1_800_000_000

    def __call__(self):
        return self.t


def make(sandbox=True, prefix="TEST"):
    clock = Clock()
    reg = Registry(Config(prefix=prefix, name="Test", api="https://test.example", sandbox=sandbox), Key(), clock=clock)
    if sandbox:
        reg.seed_sandbox()
    return reg, TestClient(create_app(reg)), clock


class Provider:
    """A minimal provider: asks, checks answers, keeps a keyset, reports."""

    def __init__(self, reg, client, provider_id=None):
        self.reg, self.c = reg, client
        self.id, self.token = reg.add_provider(provider_id)
        self.key = Key()
        self.h = {"X-Provider-ID": self.id, "Authorization": f"Bearer {self.token}"}

    def body(self, subject, job="job-1", purpose="research", job_hash="a" * 64, **extra):
        return {"subject_ref": subject, "provider_id": self.id, "profile": "likeness/1", "use": {"purpose": purpose},
                "job_id": job, "job_hash": job_hash, **extra}

    def ask(self, body):
        return self.c.post("/v2/requests", headers=self.h, json={"type": "pg.request.v1", "body": body, "signatures": []})

    def answer(self, body):
        r = self.ask(body)
        assert r.status_code == 200, r.text
        env = r.json()["answer"]
        b = env["body"]
        check_body("answer", b)
        assert b["signers"] == [{"role": "registry", "key_id": self.reg.key.id}]
        assert verify_bytes(self.reg.key.public_hex, env["signatures"][0], signing_input(env["type"], b))
        assert b["request_id"] == message_id("pg.request.v1", body)
        return env

    def register(self):
        ks = seal("pg.keyset.v1", {"kind": "first", "provider_id": self.id, "previous": None, "recovery_registry": "",
                                   "keys": [{"key_id": self.key.id, "public_key_hex": self.key.public_hex,
                                             "status": "current"}]}, [("provider", self.key)])
        r = self.c.post("/v2/keys", headers=self.h, json=ks)
        assert r.status_code == 200, r.text
        return ks

    def report(self, answer=None, request=None, outcome="generated", key=None, **extra):
        body = {"request_id": answer["body"]["request_id"] if answer else message_id("pg.request.v1", request),
                "answer": message_id("pg.answer.v1", answer["body"]) if answer else None,
                "job_id": (request or {}).get("job_id") or json.loads(self.reg.db.execute(
                    "SELECT request FROM asks WHERE id = ?", (answer["body"]["request_id"],)).fetchone()[0])["job_id"],
                "outcome": outcome, "output_hash": "e" * 64 if outcome == "generated" else "",
                "occurred_at": 1_800_000_000, **extra}
        if answer is None:
            body["request"] = request
        return seal("pg.report.v1", body, [("provider", key or self.key)])

    def send(self, report):
        return self.c.post("/v2/reports", headers=self.h, json=report)


def code(n, prefix="TEST"):
    return mint_code(prefix, n)


# ── PG codes ────────────────────────────────────────────────────────────

def test_pg_codes_follow_pg_code_md():
    assert mint_code("", 42) == "PG-000042*" and mint_code("", 12345678) == "PG-12345678K"     # PG-CODE.md §5
    assert parse_code("PG-000042*") == ("", 42)
    assert parse_code(code(1)) == ("TEST", 1) and parse_code(code(1)[:-1] + "0") is None


# ── publication ─────────────────────────────────────────────────────────

def test_registry_document_and_signed_key_set():
    reg, c, _ = make()
    doc = c.get("/.well-known/pregen-registry.json").json()
    check_body("registry-document", doc)
    assert doc["prefix"] == "TEST" and doc["sandbox"] is True and "sandbox" in doc["extensions"]
    ks = c.get("/keys").json()
    body = {k: v for k, v in ks.items() if k != "signature"}
    assert ks["current_key_id"] == reg.key.id and verify_bytes(reg.key.public_hex, ks["signature"], canonical_json(body))


# ── core + likeness/1 + sandbox subjects ────────────────────────────────

@pytest.mark.parametrize("serial,status,reason", [
    (2, "deny", "PG_NO_LICENSE"), (3, "deny", "PG_SUBJECT_OPTED_OUT"), (4, "deny", "PG_USAGE_LIMIT"),
    (5, "deny", "PG_PROHIBITED_USE"), (6, "review", "PG_REVIEW_REQUIRED"), (7, "not_blocked", "PG_NO_LICENSE"),
    (8, "deny", "PG_UNKNOWN_SUBJECT")])
def test_standard_sandbox_refusals(serial, status, reason):
    reg, c, _ = make()
    p = Provider(reg, c)
    a = p.answer(p.body(code(serial)))["body"]
    assert (a["status"], a["reason"], a["ext"]) == (status, reason, {"sandbox": True}) and "basis" not in a


def test_allow_is_bound_to_its_request_and_names_a_verifiable_grant():
    reg, c, _ = make()
    p = Provider(reg, c)
    env = p.answer(p.body(code(1)))
    a = env["body"]
    assert a["status"] == "allow" and a["basis"]["grant"]["format"] == "pg.grant.v1" and 0 < a["expires_at"] - a["issued_at"] <= 900
    g = c.get(f"/v2/grants/{a['basis']['grant']['id']}").json()["grant"]
    check_body("grant", g["body"])
    assert message_id(g["type"], g["body"]) == a["basis"]["grant"]["id"]
    subject = c.get(f"/v2/codes/{code(1)}").json()
    assert subject["status"] == "active" and subject["subject_key"]["custody"] == "managed"
    data = signing_input(g["type"], g["body"])
    assert verify_bytes(subject["subject_key"]["public_key_hex"], g["signatures"][0], data)   # rights_holder
    assert verify_bytes(reg.key.public_hex, g["signatures"][1], data)                         # registry


def test_another_registrys_code_and_lookup():
    reg, c, _ = make()
    p = Provider(reg, c)
    assert p.answer(p.body(code(9, "NWRD")))["body"]["reason"] == "PG_OTHER_REGISTRY"
    assert c.get(f"/v2/codes/{code(9, 'NWRD')}").json()["status"] == "other_registry"
    assert c.get(f"/v2/codes/{code(8)}").json()["status"] == "unknown"
    assert c.get("/v2/codes/PG-000042X").status_code == 422


def test_authentication_profile_and_use():
    reg, c, _ = make()
    p = Provider(reg, c)
    bad = {**p.h, "Authorization": "Bearer nope"}
    r = c.post("/v2/requests", headers=bad, json={"type": "pg.request.v1", "body": p.body(code(1)), "signatures": []})
    assert r.status_code == 401 and r.json()["error"] == "PG_NOT_AUTHENTICATED"
    r = p.ask({**p.body(code(1)), "provider_id": "someone-else"})
    assert r.status_code == 401
    r = p.ask({**p.body(code(1)), "profile": "works/1"})
    assert r.status_code == 422 and r.json()["error"] == "PG_PROFILE_UNSUPPORTED"
    r = p.ask({**p.body(code(1)), "use": {"purpose": "spam"}})
    assert r.status_code == 422 and r.json()["error"] == "PG_MALFORMED"
    r = p.ask({**p.body(code(1)), "surprise": 1})
    assert r.status_code == 422


def test_floor_minor_and_immutable_denial():
    reg, c, _ = make(sandbox=False)
    kid = reg.add_subject("Young actor", minor=1)
    reg.add_grant(kid, purposes=["commercial"])
    adult = reg.add_subject("Actor", immutable_denials=["political"])
    reg.add_grant(adult, purposes=["commercial"])
    p = Provider(reg, c)
    assert p.answer(p.body(kid, job="j1", purpose="commercial"))["body"]["status"] == "allow"   # minors: not banned outright
    use = {"purpose": "commercial", "categories": ["sexual"]}
    a = p.answer({**p.body(kid, job="j2"), "use": use})["body"]
    assert a["reason"] == "PG_PROHIBITED_USE"
    a = p.answer({**p.body(adult, job="j3"), "use": {"purpose": "commercial", "categories": ["political"]}})["body"]
    assert a["reason"] == "PG_IMMUTABLE_DENIAL"
    assert p.answer(p.body(adult, job="j4", purpose="research"))["body"]["reason"] == "PG_SCOPE_VIOLATION"


def test_licensee_must_be_connected_outside_a_sandbox():
    reg, c, _ = make(sandbox=False)
    s = reg.add_subject("Maya")
    reg.add_grant(s, licensee_id="user-1", purposes=["commercial"])
    p = Provider(reg, c)
    assert p.ask(p.body(s, purpose="commercial", licensee_id="user-1")).status_code == 401
    reg.connect(p.id, "user-1")
    assert p.answer(p.body(s, purpose="commercial", licensee_id="user-1"))["body"]["status"] == "allow"
    assert p.answer(p.body(s, job="j2", purpose="commercial"))["body"]["reason"] == "PG_NO_LICENSE"   # the grant is user-1's


def test_opt_out_revoke_and_remove_take_effect_from_the_next_answer(tmp_path, capsys):
    reg, c, _ = make(sandbox=False)
    p = Provider(reg, c)
    s, t = reg.add_subject("Maya", level="verified"), reg.add_subject("Theo", level="verified")
    gid = reg.add_grant(s, purposes=["commercial"])
    reg.add_grant(t, purposes=["commercial"])
    assert p.answer(p.body(s, purpose="commercial"))["body"]["status"] == "allow"
    reg.revoke_grant(gid)
    assert p.answer(p.body(s, job="j2", purpose="commercial"))["body"]["reason"] == "PG_NO_LICENSE"
    reg.opt_out(t)
    assert p.answer(p.body(t, job="j3", purpose="commercial"))["body"]["reason"] == "PG_SUBJECT_OPTED_OUT"
    reg.remove_provider(p.id)
    assert p.ask(p.body(t, job="j4", purpose="commercial")).status_code == 401
    with pytest.raises(ValueError):
        reg.opt_out(code(99))
    cli(["init", "--dir", str(tmp_path), "--prefix", "TEST", "--name", "T", "--api", "https://t.example"])
    with pytest.raises(SystemExit, match="frame-ai:user-1"):
        cli(["connect", "--dir", str(tmp_path), "--provider", "frame-ai", "--licensee", "user-1"])


# ── extension jobs ──────────────────────────────────────────────────────

def test_one_hash_per_job_one_request_per_subject_same_answer_while_open():
    reg, c, clock = make()
    p = Provider(reg, c)
    first = p.answer(p.body(code(1)))
    assert p.answer(p.body(code(1))) == first                                    # identical request, open answer
    r = p.ask(p.body(code(1), purpose="commercial"))
    assert r.status_code == 409 and r.json()["error"] == "PG_ASK_CONFLICT"
    r = p.ask(p.body(code(2), job_hash="b" * 64))
    assert r.status_code == 409 and r.json()["error"] == "PG_JOB_CONFLICT"
    clock.t += 400                                                                # expired: a new answer
    assert p.answer(p.body(code(1))) != first


# ── extensions provider-keys and reports ────────────────────────────────

def test_keys_first_idempotent_rotation_and_bad_signature():
    reg, c, _ = make()
    p = Provider(reg, c)
    ks = p.register()
    assert c.post("/v2/keys", headers=p.h, json=ks).status_code == 200            # identical again
    other = Key()
    dup = seal("pg.keyset.v1", {**{k: v for k, v in ks["body"].items() if k != "signers"},
                                "keys": [{"key_id": other.id, "public_key_hex": other.public_hex, "status": "current"}]},
               [("provider", other)])
    assert c.post("/v2/keys", headers=p.h, json=dup).status_code == 409
    new = Key()
    rot_body = {"kind": "rotation", "provider_id": p.id, "previous": message_id("pg.keyset.v1", ks["body"]),
                "recovery_registry": "", "keys": [{"key_id": new.id, "public_key_hex": new.public_hex, "status": "current"},
                                                  {"key_id": p.key.id, "public_key_hex": p.key.public_hex, "status": "previous"}]}
    forged = seal("pg.keyset.v1", rot_body, [("provider", new), ("provider_previous", other)])
    assert c.post("/v2/keys", headers=p.h, json=forged).status_code == 401
    rot = seal("pg.keyset.v1", rot_body, [("provider", new), ("provider_previous", p.key)])
    assert c.post("/v2/keys", headers=p.h, json=rot).status_code == 200
    assert [k["body"]["kind"] for k in c.get(f"/v2/keys/{p.id}").json()["keysets"]] == ["first", "rotation"]


def test_a_small_order_key_is_never_recorded():
    """Stress test C1: with no private key behind it, a small-order key would sign as the provider or the person."""
    reg, c, _ = make()
    p = Provider(reg, c)
    pub = "01" + "00" * 31
    body = {"kind": "first", "provider_id": p.id, "previous": None, "recovery_registry": "",
            "keys": [{"key_id": fingerprint(pub), "public_key_hex": pub, "status": "current"}],
            "signers": [{"role": "provider", "key_id": fingerprint(pub)}]}
    r = c.post("/v2/keys", headers=p.h, json={"type": "pg.keyset.v1", "body": body, "signatures": ["01" + "00" * 63]})
    assert r.status_code == 422 and r.json()["error"] == "PG_MALFORMED", r.text
    p.register()                                                                       # control: an ordinary key
    with pytest.raises(PregenError):
        reg.add_subject("TEST person", holder_public=pub)


def test_rotation_keeps_every_key_so_earlier_answers_still_verify(tmp_path):
    """Stress test C2: /keys is the full history; a registry that starts on a new key retires the old one."""
    clock, db, k1, k2 = Clock(), str(tmp_path / "r.db"), Key(), Key()
    cfg = Config(prefix="TEST", name="Test", api="https://test.example", sandbox=True)
    reg = Registry(cfg, k1, db, clock=clock)
    reg.seed_sandbox()
    c = TestClient(create_app(reg))
    p = Provider(reg, c)
    old = p.answer(p.body(code(1)))                                          # signed by k1
    clock.t += 100
    reg2 = Registry(cfg, k2, db, clock=clock)
    keys = TestClient(create_app(reg2)).get("/keys").json()
    assert keys["current_key_id"] == k2.id
    assert [(k["key_id"], k["status"], k["deactivated_at"]) for k in keys["keys"]] == \
        [(k1.id, "retired", clock.t), (k2.id, "active", None)]
    listed = {k["key_id"]: k["public_key_hex"] for k in keys["keys"]}
    assert verify_bytes(listed[old["body"]["signers"][0]["key_id"]], old["signatures"][0],
                        signing_input(old["type"], old["body"]))                # the earlier answer still verifies
    assert verify_bytes(k2.public_hex, keys["signature"], canonical_json({k: v for k, v in keys.items() if k != "signature"}))
    with pytest.raises(ValueError):
        Registry(cfg, k1, db, clock=clock)                                     # a retired key never signs again


def test_cli_key_next_then_rotate(tmp_path, capsys):
    d = str(tmp_path / "reg")
    cli(["init", "--dir", d, "--prefix", "TEST", "--name", "Test", "--api", "https://test.example"])
    old = Key((tmp_path / "reg" / "operator.key").read_text().strip())
    with pytest.raises(SystemExit):
        cli(["key", "rotate", "--dir", d])                                     # nothing announced yet
    cli(["key", "next", "--dir", d])
    new = Key((tmp_path / "reg" / "operator.next.key").read_text().strip())
    assert new.id in capsys.readouterr().out
    from pregen_registry.cli import load
    announced = load(d).key_set()                                              # the steward matches it on our domain
    assert announced["current_key_id"] == old.id and \
        [(k["key_id"], k["status"]) for k in announced["keys"]] == [(old.id, "active"), (new.id, "next")]
    cli(["key", "rotate", "--dir", d])
    keys = load(d).key_set()
    assert keys["current_key_id"] == new.id and [k["status"] for k in keys["keys"]] == ["retired", "active"]
    assert {k["key_id"] for k in keys["keys"]} == {old.id, new.id}


@pytest.mark.parametrize("ref", [code(1) + "\u200d", code(1) + "\n", " " + code(1), code(1).lower(),
                                 "\ufeff" + code(1), "PG-\ufb06D-000123", "PG-TEST-", code(1) + "\x00"])
def test_a_non_canonical_subject_ref_gets_no_signed_answer(ref):
    """Stress test H5: another spelling of a code must not draw a signed answer that a verifier routes to the code's
    registry (an opt-out turned into not_blocked). It is malformed: 422, no answer."""
    reg, c, _ = make()
    p = Provider(reg, c)
    r = p.ask(p.body(ref))
    assert r.status_code == 422 and r.json()["error"] == "PG_MALFORMED" and "answer" not in r.json(), r.text
    assert p.ask(p.body(code(1), job="control")).status_code == 200


def test_reports_ack_conflicts_closed_ask_and_key_rules():
    reg, c, _ = make()
    p = Provider(reg, c)
    ans = p.answer(p.body(code(1)))
    rep = p.report(ans)
    assert p.send(rep).status_code == 401                                         # no key registered yet
    ks = p.register()
    r = p.send(rep)
    assert r.status_code == 200, r.text
    ack = r.json()["ack"]
    check_body("report_ack", ack["body"])
    assert verify_bytes(reg.key.public_hex, ack["signatures"][0], signing_input(ack["type"], ack["body"]))
    assert ack["body"]["report"] == message_id("pg.report.v1", rep["body"]) and ack["body"]["answer_status"] == "allow"
    assert ack["body"]["provider_key_id"] == p.key.id
    assert p.send(rep).json()["ack"] == ack                                       # identical report: stored ack
    assert p.send(p.report(ans, outcome="not_generated")).status_code == 409     # a different report for the answer
    r = p.ask(p.body(code(1)))
    assert r.status_code == 409 and r.json()["error"] == "PG_ASK_CLOSED" and r.json()["ack"] == ack
    # after a rotation the identical old report still gets its ack; a new report with the old key does not
    new = Key()
    body = {"kind": "rotation", "provider_id": p.id, "previous": message_id("pg.keyset.v1", ks["body"]), "recovery_registry": "",
            "keys": [{"key_id": new.id, "public_key_hex": new.public_hex, "status": "current"}]}
    assert c.post("/v2/keys", headers=p.h, json=seal("pg.keyset.v1", body, [("provider", new), ("provider_previous", p.key)])).status_code == 200
    assert p.send(rep).json()["ack"] == ack
    ans2 = p.answer(p.body(code(2), job="job-2"))
    assert p.send(p.report(ans2, outcome="not_generated")).status_code == 401
    assert p.send(p.report(ans2, outcome="not_generated", key=new)).status_code == 200


def test_report_without_an_answer_and_mode_rules():
    reg, c, _ = make()
    p = Provider(reg, c)
    p.register()
    req = p.body(code(2), job="obs-1", mode="observe")
    r = p.send(p.report(request=req, mode="observe"))
    assert r.status_code == 200 and r.json()["ack"]["body"]["answer_status"] == "none"
    assert p.ask(req).status_code == 409                                          # reported generated: closed
    ans = p.answer(p.body(code(1), job="obs-2", mode="observe"))
    assert p.send(p.report(ans, mode="enforce")).status_code == 422               # mode must match


# ── extension limits ────────────────────────────────────────────────────

def test_limits_reserve_count_and_give_back():
    reg, c, _ = make(sandbox=False)
    s = reg.add_subject("Maya")
    reg.add_grant(s, purposes=["commercial"], max_uses=2)
    p = Provider(reg, c)
    p.register()
    a1 = p.answer(p.body(s, job="j1", purpose="commercial"))
    a2 = p.answer(p.body(s, job="j2", purpose="commercial"))
    assert p.answer(p.body(s, job="j3", purpose="commercial"))["body"]["reason"] == "PG_USAGE_LIMIT"
    ack = p.send(p.report(a2, outcome="not_generated")).json()["ack"]["body"]
    assert ack["released"] == [message_id("pg.answer.v1", a2["body"])] and ack["counted"] is None
    assert p.answer(p.body(s, job="j4", purpose="commercial"))["body"]["status"] == "allow"
    ack = p.send(p.report(a1)).json()["ack"]["body"]
    assert ack["counted"] == message_id("pg.answer.v1", a1["body"])
    assert p.answer(p.body(s, job="j5", purpose="commercial"))["body"]["reason"] == "PG_USAGE_LIMIT"


def test_the_last_use_goes_to_exactly_one_of_twenty_concurrent_jobs():
    reg, c, _ = make(sandbox=False)
    s = reg.add_subject("Maya")
    reg.add_grant(s, purposes=["commercial"], max_uses=1)
    p = Provider(reg, c)
    results = []

    def go(i):
        results.append(p.answer(p.body(s, job=f"race-{i}", purpose="commercial"))["body"]["status"])
    threads = [threading.Thread(target=go, args=(i,)) for i in range(20)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(results).count("allow") == 1 and len(results) == 20


# ── sandbox access and the CLI ──────────────────────────────────────────

def test_sandbox_access_without_an_account_and_rate_limit():
    reg, c, _ = make()
    r = c.post("/v2/sandbox/access")
    assert r.status_code == 200
    creds = r.json()
    h = {"X-Provider-ID": creds["provider_id"], "Authorization": f"Bearer {creds['token']}"}
    body = {"subject_ref": code(1), "provider_id": creds["provider_id"], "profile": "likeness/1",
            "use": {"purpose": "research"}, "job_id": "x", "job_hash": "a" * 64}
    assert c.post("/v2/requests", headers=h, json={"type": "pg.request.v1", "body": body, "signatures": []}).status_code == 200
    codes = [c.post("/v2/sandbox/access").status_code for _ in range(12)]
    assert 429 in codes
    _, prod, _ = make(sandbox=False)
    assert prod.post("/v2/sandbox/access").status_code == 404


def test_cli_init_creates_a_sandbox_registry(tmp_path, capsys):
    cli(["init", "--dir", str(tmp_path / "r"), "--prefix", "TEST", "--name", "T", "--api", "https://t.example", "--sandbox"])
    assert (tmp_path / "r" / "operator.key").stat().st_mode & 0o777 == 0o600
    cli(["info", "--dir", str(tmp_path / "r")])
    assert '"prefix": "TEST"' in capsys.readouterr().out
    from pregen_registry.cli import load
    reg = load(str(tmp_path / "r"))
    assert reg.lookup(code(1))["status"] == "active" and reg.lookup(code(8))["status"] == "unknown"


# ── spec/test-vectors/messages.json ────────────────────────────────────

def test_message_vectors_match_this_implementation():
    from pathlib import Path
    vectors = json.loads((Path(__file__).resolve().parents[3] / "spec" / "test-vectors" / "messages.json").read_text())
    keys = {k["key_id"]: k["public_key_hex"] for k in vectors["keys"].values()}
    schema = {"pg.request.v1": "request", "pg.answer.v1": "answer", "pg.report.v1": "report",
              "pg.report_ack.v1": "report_ack", "pg.keyset.v1": "keyset", "pg.grant.v1": "grant"}
    for v in vectors["vectors"]:
        env = v["envelope"]
        check_body(schema[env["type"]], env["body"])
        assert canonical_json(env["body"]).decode() == v["canonical_body_utf8"]
        assert signing_input(env["type"], env["body"]).hex() == v["signing_input_hex"]
        assert message_id(env["type"], env["body"]) == v["message_id"]
        for signer, sig in zip(env["body"].get("signers", []), env["signatures"]):
            assert verify_bytes(keys[signer["key_id"]], sig, bytes.fromhex(v["signing_input_hex"])), v["name"]
    assert parse_code(vectors["vectors"][0]["envelope"]["body"]["subject_ref"]) == ("TEST", 1)


def test_vendored_schemas_are_the_spec_schemas():
    from pathlib import Path
    here = Path(__file__).resolve()
    spec, vendored = here.parents[3] / "spec" / "schemas", here.parents[1] / "pregen_registry" / "schemas"
    assert sorted(p.name for p in spec.glob("*.json")) == sorted(p.name for p in vendored.glob("*.json"))
    for p in spec.glob("*.json"):
        assert (vendored / p.name).read_text() == p.read_text(), p.name


def test_the_policy_page_is_served_from_policy_md(tmp_path):
    reg, _, _ = make()
    c = TestClient(create_app(reg, tmp_path / "policy.md"))
    assert c.get("/policy").status_code == 404
    (tmp_path / "policy.md").write_text("# Policy\nHow we verify rights holders.\n")
    r = c.get("/policy")
    assert r.status_code == 200 and r.text.startswith("# Policy") and r.headers["content-type"].startswith("text/markdown")
