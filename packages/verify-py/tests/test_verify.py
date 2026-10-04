import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pregen import PregenError, canonical_json, check_decision, fingerprint, verify_decision, verify_directory  # noqa: E402


class Key:
    def __init__(self):
        self.k = Ed25519PrivateKey.generate()
        self.pub = self.k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        self.id = fingerprint(self.pub)

    def sign(self, obj, field):
        body = {k: v for k, v in obj.items() if k != field}
        return {**obj, field: self.k.sign(canonical_json(body)).hex()}


steward, origin, other = Key(), Key(), Key()
KEY_SETS = {"https://origin.test/keys": {"keys": [{"key_id": origin.id, "public_key_hex": origin.pub}]},
            "https://other.test/keys": {"keys": [{"key_id": other.id, "public_key_hex": other.pub}]}}


def directory(sequence=2, registries=None):
    return steward.sign({"schema": "pregen.registries.v2", "sequence": sequence, "steward_key_id": steward.id,
                         "registries": registries or [
                             {"name": "Origin", "prefix": "", "api": "https://origin.test",
                              "keys": "https://origin.test/keys", "key_fingerprints": [origin.id]},
                             {"name": "Other", "prefix": "NWRD", "api": "https://other.test",
                              "keys": "https://other.test/keys", "key_fingerprints": [other.id]}]}, "signature")


def load(d, min_sequence=0):
    return verify_directory(d, steward.pub, min_sequence)


def test_directory_signed_by_pinned_steward_is_accepted():
    assert load(directory()).sequence == 2


def test_tampered_foreign_older_or_malformed_directory_is_refused():
    d = directory()
    with pytest.raises(PregenError):
        load({**d, "registries": d["registries"][:1]})
    with pytest.raises(PregenError, match="different steward"):
        verify_directory(d)  # the default pin is the real steward key
    with pytest.raises(PregenError, match="older"):
        load(d, 3)
    with pytest.raises(PregenError, match="HTTPS"):
        load(directory(registries=[{"name": "X", "prefix": "", "api": "http://x.test", "keys": "https://x.test/k",
                                    "key_fingerprints": [origin.id]}]))


def test_namespaces_are_symmetric():
    dir_ = load(directory())
    assert dir_.check_signer("PG-000042*", origin.id) == "valid"
    assert dir_.check_signer("PG-000042*", other.id) == "issuer_mismatch"
    assert dir_.check_signer("PG-NWRD-000042-K", other.id) == "valid"
    assert dir_.check_signer("PG-NWRD-000042-K", origin.id) == "issuer_mismatch"
    assert dir_.check_signer("PG-ABCD-000042-K", origin.id) == "unknown_issuer"


def test_decision_is_genuine_only_from_the_namespace_owner():
    dir_ = load(directory())
    get = KEY_SETS.__getitem__
    decision = origin.sign({"decision_id": "d1", "allowed": True, "license_id": "PG-RND-000042-ZZZZZZ1",
                            "operator_key_id": origin.id}, "operator_signature")
    assert verify_decision(decision, decision["license_id"], dir_, get) is True
    assert verify_decision({**decision, "allowed": False}, decision["license_id"], dir_, get) is False
    forged = other.sign({"decision_id": "d2", "allowed": True, "operator_key_id": other.id}, "operator_signature")
    with pytest.raises(PregenError, match="issuer_mismatch"):
        verify_decision(forged, "PG-000042*", dir_, get)
    swapped = {"https://origin.test/keys": {"keys": [{"key_id": origin.id, "public_key_hex": other.pub}]}}
    with pytest.raises(PregenError, match="no key"):
        verify_decision(decision, decision["license_id"], dir_, swapped.__getitem__)


def test_canonical_json_refuses_unportable_values():
    for bad in ({"x": 1.5}, {"x": 2**53}, {"x": "\ud800"}, {"x": object()}):
        with pytest.raises(PregenError):
            canonical_json(bad)



def test_stolen_steward_key_cannot_add_a_key_to_the_pinned_origin():
    thief = Key()
    d = directory(3, [{"name": "Origin", "prefix": "", "api": "https://origin.test",
                       "keys": "https://origin.test/keys", "key_fingerprints": [origin.id, thief.id]}])
    pinned = verify_directory(d, steward.pub, origin_key_fingerprints=[origin.id])
    assert pinned.check_signer("PG-000042*", thief.id) == "issuer_mismatch"
    assert pinned.check_signer("PG-000042*", origin.id) == "valid"


def test_newer_directory_may_add_but_never_remove_or_fork():
    prev = directory(2)
    extra = {"name": "New", "prefix": "ABCD", "api": "https://n.test", "keys": "https://n.test/k",
             "key_fingerprints": [other.id]}
    with pytest.raises(PregenError, match="removed"):
        verify_directory(directory(3, prev["registries"][:1]), steward.pub, previous=prev)
    with pytest.raises(PregenError, match="removed"):
        verify_directory(directory(3, [{**prev["registries"][0], "key_fingerprints": [other.id]},
                                       prev["registries"][1]]), steward.pub, previous=prev)
    with pytest.raises(PregenError, match="same sequence"):
        verify_directory(directory(2, prev["registries"] + [extra]), steward.pub, previous=prev)
    assert verify_directory(directory(3, prev["registries"] + [extra]), steward.pub, previous=prev).sequence == 3


def test_revoked_registry_or_key_signs_nothing_valid_and_cannot_be_unrevoked():
    prev = directory(2)
    revoked = directory(3, [prev["registries"][0],
                            {**prev["registries"][1], "revoked": {"at": "2026-10-04T00:00:00Z", "reason": "fake rights holders"}}])
    dir_ = verify_directory(revoked, steward.pub, previous=prev)
    assert dir_.check_signer("PG-NWRD-000042-K", other.id) == "revoked"
    assert dir_.check_signer("PG-000042*", origin.id) == "valid"
    decision = other.sign({"decision_id": "d9", "operator_key_id": other.id}, "operator_signature")
    with pytest.raises(PregenError, match="revoked"):
        verify_decision(decision, "PG-NWRD-000042-K", dir_, KEY_SETS.__getitem__)
    with pytest.raises(PregenError, match="undone"):
        verify_directory(directory(4, prev["registries"]), steward.pub, previous=revoked)

    def with_revoked_keys(seq, keys):
        body = {k: v for k, v in directory(seq).items() if k != "signature"}
        return steward.sign({**body, "revoked_keys": keys}, "signature")
    stolen = with_revoked_keys(3, [{"key_id": origin.id, "at": "2026-10-04T00:00:00Z"}])
    assert verify_directory(stolen, steward.pub, previous=prev).check_signer("PG-000042*", origin.id) == "revoked"
    with pytest.raises(PregenError, match="undone"):
        verify_directory(directory(4), steward.pub, previous=stolen)
    with pytest.raises(PregenError, match="revoked_keys"):
        load(with_revoked_keys(3, [{"key_id": "x"}]))


def test_check_decision_refuses_unknown_critical_members_and_unverified_authority_on_request():
    dir_ = load(directory())
    now = 1_800_000_000
    request = {"subject_id": "s", "provider_id": "p", "licensee_id": "l", "prompt_hash": "h", "model": "m",
               "modality": "image"}
    base = {**request, "schema_version": "pg.decision.v1", "decision_id": "d1", "allowed": True, "disposition": "allow",
            "license_id": "PG-RND-000042-ZZZZZZ1", "subject_authority": "self", "issued_at": now - 1,
            "expires_at": now + 60, "operator_key_id": origin.id}
    signed = lambda **patch: origin.sign({**base, **patch}, "operator_signature")  # noqa: E731
    get = KEY_SETS.__getitem__
    assert check_decision(signed(critical=["obligations"]), request, dir_, get, now)
    with pytest.raises(PregenError, match="critical"):
        check_decision(signed(critical=["x_nwrd_geofence"]), request, dir_, get, now)
    with pytest.raises(PregenError, match="not verified"):
        check_decision(signed(), request, dir_, get, now, require_verified_authority=True)
    assert check_decision(signed(subject_authority="verified"), request, dir_, get, now, require_verified_authority=True)


def test_check_decision_covers_everything_before_generating():
    dir_ = load(directory())
    now = 1_800_000_000
    request = {"subject_id": "sub_1", "provider_id": "acme", "licensee_id": "lic-1", "prompt_hash": "a" * 64,
               "model": "m", "modality": "image", "intended_use": {"use_case": "commercial", "categories": ["ads"]},
               "provider_user_id": "u1"}
    base = {"schema_version": "pg.decision.v1", "decision_id": "d1", "allowed": True, "disposition": "allow", "license_id": "PG-RND-000042-ZZZZZZ1",
            "subject_id": "sub_1", "provider_id": "acme", "licensee_id": "lic-1", "prompt_hash": "a" * 64,
            "model": "m", "modality": "image",
            "intended_use": {"use_case": "commercial", "categories": ["ads"], "channel": "", "territory": ""},
            "provider_user_binding": "verified", "provider_identity_link_id": "link-1",
            "issued_at": now - 10, "expires_at": now + 60, "operator_key_id": origin.id}

    def check(patch, req=request):
        return check_decision(origin.sign({**base, **patch}, "operator_signature"), req, dir_,
                              KEY_SETS.__getitem__, now)

    assert check({})["decision_id"] == "d1"
    for patch, reason in [({"allowed": False, "disposition": "deny"}, "not an allow"),
                          ({"expires_at": now}, "expired"), ({"expires_at": 0}, "expires_at"),
                          ({"issued_at": now + 3600, "expires_at": now + 7200}, "issued_at"),
                          ({"provider_id": ""}, "provider_id"), ({"prompt_hash": "b" * 64}, "prompt_hash"),
                          ({"intended_use": {**base["intended_use"], "channel": "tv"}}, "intended_use.channel"),
                          ({"provider_user_binding": "unbound"}, "binding"),
                          ({"provider_identity_link_id": ""}, "binding"), ({"license_id": None}, "license"),
                          ({"schema_version": "pg.decision.v999"}, "schema_version"),
                          ({"issued_at": None}, "issued_at"),
                          ({"issued_at": now - 10, "expires_at": now + 3590}, "at most 900")]:
        with pytest.raises(PregenError, match=reason):
            check(patch)
    tampered = {**origin.sign(base, "operator_signature"), "model": "other"}
    with pytest.raises(PregenError, match="bad signature"):
        check_decision(tampered, {**request, "model": "other"}, dir_, KEY_SETS.__getitem__, now)


def test_successor_steward_takes_over_whatever_the_thiefs_sequence():
    successor = Key()
    thief_dir = directory(50)
    body = {k: v for k, v in directory(3).items() if k != "signature"}
    body["steward_key_id"] = successor.id
    handover = successor.sign(body, "signature")
    taken = verify_directory(handover, steward.pub, min_sequence=50, previous=thief_dir,
                             successor_public_key_hex=successor.pub)
    assert taken.sequence == 3
    with pytest.raises(PregenError, match="handed over"):
        verify_directory(thief_dir, steward.pub, previous=taken, successor_public_key_hex=successor.pub)
    shrunk = successor.sign({**body, "sequence": 4, "registries": body["registries"][:1]}, "signature")
    with pytest.raises(PregenError, match="removed"):
        verify_directory(shrunk, steward.pub, previous=taken, successor_public_key_hex=successor.pub)
    with pytest.raises(PregenError, match="different steward"):
        verify_directory(handover, steward.pub)

    # A handover restarts the sequence but keeps every listing and revocation.
    rk = [{"key_id": other.id, "at": "2026-10-04T00:00:00Z"}]
    revoked = steward.sign({**{k: v for k, v in directory(5).items() if k != "signature"}, "revoked_keys": rk}, "signature")
    with pytest.raises(PregenError, match="undone"):
        verify_directory(successor.sign({**body, "sequence": 1}, "signature"), steward.pub, previous=revoked,
                         successor_public_key_hex=successor.pub)
    keeps = successor.sign({**body, "sequence": 1, "revoked_keys": rk}, "signature")
    assert verify_directory(keeps, steward.pub, previous=revoked, successor_public_key_hex=successor.pub) \
        .check_signer("PG-NWRD-000042-K", other.id) == "revoked"

    # A thief's revocation, signed after the declared compromise, can be annulled; an earlier one cannot.
    thief = steward.sign({**{k: v for k, v in directory(6).items() if k != "signature"},
                          "revoked_keys": [{"key_id": other.id, "at": "2026-10-10T00:00:00Z"}]}, "signature")

    def annul(since):
        return successor.sign({**body, "sequence": 1, "steward_compromised_since": since,
                               "annulled": [{"key_id": other.id, "reason": "stolen steward key"}]}, "signature")
    ok = verify_directory(annul("2026-10-09T00:00:00Z"), steward.pub, previous=thief, successor_public_key_hex=successor.pub)
    assert ok.check_signer("PG-NWRD-000042-K", other.id) == "valid"
    with pytest.raises(PregenError, match="undone"):
        verify_directory(annul("2026-10-11T00:00:00Z"), steward.pub, previous=thief, successor_public_key_hex=successor.pub)


def test_simulator_runs_the_whole_pipeline_offline_and_is_never_trusted_for_real():
    from pregen import Simulator
    sim = Simulator()
    request = {"subject_id": "sbx-allowed", "prompt_hash": "a" * 64, "model": "m", "modality": "image",
               "intended_use": {"use_case": "research"}}
    decision = sim.verify(request, "acme", "lic-1")
    check_decision(decision, {**request, "provider_id": "acme", "licensee_id": "lic-1"}, sim.directory, sim.get_json)
    assert sim.receipt(decision["decision_id"])["simulator"] is True
    with pytest.raises(PregenError, match="already"):
        sim.receipt(decision["decision_id"])
    for subject, reason in [("sbx-revoked", "PG_NO_LICENSE"), ("sbx-exhausted", "PG_USAGE_LIMIT"),
                            ("sbx-optedout", "PG_SUBJECT_OPTED_OUT"), ("sbx-unknown", "PG_NO_SUBJECT")]:
        d = sim.verify({**request, "subject_id": subject}, "acme", "lic-1")
        assert d["reason"] == reason
        with pytest.raises(PregenError, match="not an allow"):
            check_decision(d, {**request, "subject_id": subject, "provider_id": "acme", "licensee_id": "lic-1"},
                           sim.directory, sim.get_json)
    with pytest.raises(PregenError, match="different steward"):
        verify_directory(sim.directory.to_json())
