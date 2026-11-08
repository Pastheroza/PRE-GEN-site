"""steward.py refuses to sign what verifiers would refuse, and its admission check refuses keys no one can be held to.
Run: python -m pytest spec/tools/test_steward.py (with pregen and cryptography importable)."""
import json
from argparse import Namespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, Encoding, PrivateFormat

import steward
from pregen_directory import fingerprint, public_hex

PASS = "test-steward-only"
API = "https://registry.example"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PREGEN_STEWARD_PASSPHRASE", PASS)
    key = Ed25519PrivateKey.generate()
    pem = tmp_path / "steward.pem"
    pem.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(PASS.encode())))
    op = Ed25519PrivateKey.generate()
    op_id = fingerprint(public_hex(op))
    live = {"keys": [{"key_id": op_id, "public_key_hex": public_hex(op)}], "current_key_id": op_id}
    live["signature"] = op.sign(steward.pregen.canonical_json(live)).hex()
    docs = {API + "/keys": live, API + "/.well-known/pregen-registry.json": {"prefix": "ABCD"}}
    monkeypatch.setattr(steward, "_get_json", lambda url: docs[url])
    return Namespace(pem=str(pem), key=key, d=tmp_path / "registries.json", op_id=op_id, live=live, tmp=tmp_path)


def add(e, prefix="ABCD", keys=None):
    steward.cmd_add(Namespace(keyfile=e.pem, directory=str(e.d), name="Example", prefix=prefix, api=API,
                              key_ids=keys or [e.op_id], first=True))
    return json.loads(e.d.read_text())


def sign(e, previous):
    steward.cmd_sign(Namespace(keyfile=e.pem, directory=str(e.d), previous=str(previous), first=False,
                               handover=False, old_steward=None))


def test_commands_sign_a_directory_verifiers_accept(env):
    d = add(env)
    assert d["sequence"] == 1 and d["registries"][0]["key_fingerprints"] == [env.op_id]
    steward.cmd_revoke_key(Namespace(keyfile=env.pem, directory=str(env.d), key_id=env.op_id, reason="stolen"))
    steward.cmd_false_claim(Namespace(keyfile=env.pem, directory=str(env.d), anchor="wikidata:Q1",
                                      code="PG-ABCD-000001N", reason="no proof"))
    steward.cmd_revoke_registry(Namespace(keyfile=env.pem, directory=str(env.d), prefix="ABCD", reason="test"))
    d = json.loads(env.d.read_text())
    assert d["sequence"] == 4 and d["revoked_keys"][0]["key_id"] == env.op_id
    assert d["false_claims"][0]["code"] == "PG-ABCD-000001N" and d["registries"][0]["revoked"]["reason"] == "test"
    steward.pregen.verify_directory(d, public_hex(env.key), successor_public_key_hex=None)


@pytest.mark.parametrize("drop", ["key", "false claim", "revocation"])
def test_sign_refuses_a_hand_edit_that_drops_history(env, drop):
    add(env)
    steward.cmd_false_claim(Namespace(keyfile=env.pem, directory=str(env.d), anchor="wikidata:Q1",
                                      code="PG-ABCD-000001N", reason="no proof"))
    steward.cmd_revoke_key(Namespace(keyfile=env.pem, directory=str(env.d), key_id=env.op_id, reason="stolen"))
    published = env.tmp / "published.json"
    published.write_text(env.d.read_text())
    d = json.loads(env.d.read_text())
    if drop == "key":
        d["registries"][0]["key_fingerprints"] = ["pg-ed25519:" + "0" * 32]
    elif drop == "false claim":
        d.pop("false_claims")
    else:
        d.pop("revoked_keys")
    env.d.write_text(json.dumps(d))
    with pytest.raises(SystemExit, match="Not signed"):
        sign(env, published)
    assert json.loads(env.d.read_text()) == d                                 # nothing written


def test_sign_refuses_a_broken_false_claims_shape(env):
    add(env)
    published = env.tmp / "published.json"
    published.write_text(env.d.read_text())
    d = json.loads(env.d.read_text())
    d["false_claims"] = [{"code": "PG-ABCD-000001N"}]
    env.d.write_text(json.dumps(d))
    with pytest.raises(SystemExit, match="false_claims"):
        sign(env, published)


def test_sign_without_an_earlier_directory_asks_for_one(env):
    add(env)
    with pytest.raises(SystemExit, match="--previous"):
        steward.cmd_sign(Namespace(keyfile=env.pem, directory=str(env.d), previous=None, first=False,
                                   handover=False, old_steward=None))


def test_an_edit_command_refuses_a_hand_edited_file(env):
    add(env)
    d = json.loads(env.d.read_text())
    d["registries"][0]["name"] = "Edited"
    env.d.write_text(json.dumps(d))
    with pytest.raises(SystemExit, match="not a directory signed by this key"):
        add(env, keys=[env.op_id])


def test_review_refuses_small_order_keys_and_keys_not_live(env):
    small = "01" + "00" * 31                                                    # the identity point
    env.live["keys"].append({"key_id": fingerprint(small), "public_key_hex": small})
    reasons = steward._review("ABCD", API, [env.op_id, fingerprint(small), "pg-ed25519:" + "1" * 32], {})
    assert any("small-order" in r for r in reasons)
    assert any("not in the live key set" in r for r in reasons)
    with pytest.raises(SystemExit, match="Not listed"):
        add(env, keys=[env.op_id, fingerprint(small)])
    assert not env.d.exists()


def test_review_refuses_a_prefix_the_registry_does_not_claim(env):
    assert any("names prefix 'ABCD', not WXYZ" in r for r in steward._review("WXYZ", API, [env.op_id], {}))
    assert steward._review("ABCD", API, [env.op_id], {}) == []


def test_review_refuses_a_key_another_registry_lists(env):
    other = {"registries": [{"name": "Other", "prefix": "WXYZ", "api": "https://other.example",
                             "key_fingerprints": [env.op_id]}]}
    assert any("is listed for Other" in r for r in steward._review("ABCD", API, [env.op_id], other))
    shared = {"registries": [{"name": "Same operator", "prefix": "", "api": API, "key_fingerprints": [env.op_id]}]}
    assert steward._review("ABCD", API, [env.op_id], shared) == []        # the bare namespace's own registry


def test_review_notes_a_missing_next_key(env):
    notes = []
    assert steward._review("ABCD", API, [env.op_id], {}, notes) == [] and "no next key" in notes[0]


def test_an_edit_command_refuses_a_missing_file_and_a_copy_behind_the_published_one(env):
    import subprocess
    with pytest.raises(SystemExit, match="does not exist"):
        steward.cmd_revoke_key(Namespace(keyfile=env.pem, directory=str(env.d), key_id=env.op_id, reason="x",
                                         first=False))
    add(env)
    old = env.d.read_text()
    steward.cmd_false_claim(Namespace(keyfile=env.pem, directory=str(env.d), anchor="wikidata:Q1",
                                      code="PG-ABCD-000001N", reason="no proof"))
    git = ["git", "-C", str(env.tmp), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(git[:3] + ["init", "-q"], check=True)
    subprocess.run(git + ["add", "registries.json"], check=True)
    subprocess.run(git + ["commit", "-qm", "published"], check=True)
    env.d.write_text(old)                                                     # a stale signed copy
    with pytest.raises(SystemExit, match="behind or differs from the published directory"):
        steward.cmd_revoke_registry(Namespace(keyfile=env.pem, directory=str(env.d), prefix="ABCD", reason="x"))


def test_a_handover_needs_the_published_successor(env, monkeypatch):
    add(env)
    monkeypatch.setattr(steward, "STEWARD_PUBLIC_KEY_HEX", public_hex(env.key))
    monkeypatch.setattr(steward.pregen, "STEWARD_SUCCESSOR_PUBLIC_KEY_HEX", public_hex(Ed25519PrivateKey.generate()))
    monkeypatch.delenv("PREGEN_STEWARD_PASSPHRASE")
    wrong = env.tmp / "wrong.pem"
    wrong.write_bytes(Ed25519PrivateKey.generate().private_bytes(Encoding.PEM, PrivateFormat.PKCS8,
                                                                 BestAvailableEncryption(PASS.encode())))
    monkeypatch.setattr(steward.getpass, "getpass", lambda *_: PASS)
    published = env.tmp / "published.json"
    published.write_text(env.d.read_text())
    with pytest.raises(SystemExit, match="not the published successor"):
        steward.cmd_sign(Namespace(keyfile=str(wrong), directory=str(env.d), previous=str(published), first=False,
                                   handover=True, old_steward=None))


def test_the_test_passphrase_variable_never_opens_the_real_steward_key(env, monkeypatch):
    monkeypatch.setattr(steward, "STEWARD_PUBLIC_KEY_HEX", public_hex(env.key))
    with pytest.raises(SystemExit, match="test steward key only"):
        steward._load(env.pem)


def fc(e, cmd, anchor="wikidata:Q1", code="PG-ABCD-000001N"):
    getattr(steward, cmd)(Namespace(keyfile=e.pem, directory=str(e.d), anchor=anchor, code=code, reason="r"))
    return steward.pregen.verify_directory(json.loads(e.d.read_text()), public_hex(e.key), successor_public_key_hex=None)


def test_a_false_claim_is_reversed_and_recorded_again_under_its_own_anchor(env, monkeypatch):
    add(env)
    clock = iter(range(60))                                                   # one second per reading
    monkeypatch.setattr(steward, "_now", lambda: f"2026-11-06T00:00:{next(clock):02d}Z")
    assert fc(env, "cmd_false_claim").is_false_claim("PG-ABCD-000001N", "wikidata:Q1")
    assert fc(env, "cmd_false_claim", anchor="wikidata:Q2").is_false_claim("PG-ABCD-000001N", "wikidata:Q2")
    d = fc(env, "cmd_reverse_false_claim")
    assert not d.is_false_claim("PG-ABCD-000001N", "wikidata:Q1") and d.is_false_claim("PG-ABCD-000001N")
    with pytest.raises(SystemExit, match="nothing to reverse"):
        fc(env, "cmd_reverse_false_claim")
    assert fc(env, "cmd_false_claim").is_false_claim("PG-ABCD-000001N", "wikidata:Q1")
    with pytest.raises(SystemExit, match="already a false claim"):
        fc(env, "cmd_false_claim")


def test_a_reversal_in_the_same_second_is_refused(env, monkeypatch):
    add(env)
    monkeypatch.setattr(steward, "_now", lambda: "2026-11-06T00:00:00Z")
    fc(env, "cmd_false_claim")
    before = env.d.read_text()
    with pytest.raises(SystemExit, match="this very second"):
        fc(env, "cmd_reverse_false_claim")
    assert env.d.read_text() == before


def test_a_freeze_lasts_the_days_given_and_is_never_dropped(env, monkeypatch):
    add(env)
    monkeypatch.setattr(steward, "_now", lambda: "2026-11-06T00:00:00Z")
    steward.cmd_freeze(Namespace(keyfile=env.pem, directory=str(env.d), anchor="wikidata:Q1", days=7, reason="harm"))
    published = env.tmp / "published.json"
    published.write_text(env.d.read_text())
    d = steward.pregen.verify_directory(json.loads(published.read_text()), public_hex(env.key), successor_public_key_hex=None)
    assert d.frozen("wikidata:Q1", 1794527999) and not d.frozen("wikidata:Q1", 1794528000)   # until 2026-11-13T00:00:00Z
    edited = json.loads(published.read_text())
    edited.pop("freezes")
    env.d.write_text(json.dumps(edited))
    with pytest.raises(SystemExit, match="Not signed"):
        sign(env, published)
