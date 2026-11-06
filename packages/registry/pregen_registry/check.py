"""pregen-registry check: a registry's live self-test, from the outside, as a provider and a verifier see it.

It checks the registry document, the signed key set, the error shape of an unauthenticated request and, given the
directory and its steward key, that the steward lists this registry with its current key. With a provider credential
and a subject code, it also asks and checks the answer as a provider must (core rule 5). It changes nothing.
"""
from __future__ import annotations

import json
import secrets
import time
import urllib.error
import urllib.request
from email.utils import parsedate_to_datetime

import pregen

EXTENSIONS_NEEDED = ("reports", "provider-keys")


def _get(url, headers=None):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=10) as r:
        if headers is not None:
            headers["Date"] = r.headers.get("Date")                  # HTTPMessage looks names up in any case
        return json.loads(r.read())


def _post(url, env, headers):
    req = urllib.request.Request(url, data=json.dumps(env).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def check(api: str, directory_url: str | None = None, steward: str | None = None, provider_id: str | None = None,
          token: str | None = None, subject: str | None = None, purpose: str = "commercial", licensee: str = ""):
    """Yields (ok, what) lines."""
    api = api.rstrip("/")
    served = {}
    try:
        doc = _get(api + "/.well-known/pregen-registry.json", served)
    except Exception as e:  # noqa: BLE001 — any failure to reach it is the finding
        yield False, f"GET {api}/.well-known/pregen-registry.json: {e}"
        return
    if served.get("Date"):                                # answers and give-back windows are timed by its clock
        skew = round(parsedate_to_datetime(served["Date"]).timestamp() - time.time())
        yield abs(skew) <= 60, f"the registry's clock is {abs(skew)} s {'ahead of' if skew > 0 else 'behind'} this one"
    missing = [k for k in ("prefix", "name", "api", "keys", "profiles", "extensions", "policy", "complaints", "sandbox")
               if k not in doc]
    yield not missing, "registry document" + (f": missing {missing}" if missing else
                                              f": prefix {doc['prefix']}, profiles {doc['profiles']}")
    yield doc.get("api", "").rstrip("/") == api, f"document api is {doc.get('api')!r}"
    yield "likeness/1" in doc.get("profiles", []), "answers under likeness/1"
    yield all(x in doc.get("extensions", []) for x in EXTENSIONS_NEEDED), f"declares {', '.join(EXTENSIONS_NEEDED)}"
    try:
        with urllib.request.urlopen(doc.get("policy", ""), timeout=10) as r:
            yield r.status == 200, f"the policy page answers: {doc.get('policy')}"
    except Exception as e:  # noqa: BLE001
        yield False, f"the policy page does not answer: {doc.get('policy')!r} ({e})"
    try:
        ks = _get(doc["keys"])
    except Exception as e:  # noqa: BLE001
        yield False, f"GET {doc.get('keys')}: {e}"
        return
    keys = ks.get("keys") or []
    current = next((k for k in keys if k.get("key_id") == ks.get("current_key_id")), None)
    yield current is not None, f"key set: current key {ks.get('current_key_id')}, {len(keys)} key(s) in its history"
    if current is None:
        return
    good = True
    for k in keys:
        try:
            pregen.check_public_key(k["public_key_hex"])
            good &= pregen.fingerprint(k["public_key_hex"]) == k["key_id"]
        except (pregen.PregenError, KeyError):
            good = False
    yield good, "every key id is its key's fingerprint, and no key is small-order"
    yield pregen.verify_signed(ks, current["public_key_hex"], "signature"), "key set signed by its current key"
    from .registry import mint_code
    probe = {"subject_ref": mint_code(doc.get("prefix", "TEST"), 1), "provider_id": "pregen-check-nobody",
             "profile": "likeness/1", "use": {"purpose": "commercial"}, "job_id": "pregen-check", "job_hash": "0" * 64}
    status, err = _post(api + "/v2/requests", pregen.sign_envelope("pg.request.v1", probe),
                        {"X-Provider-ID": "pregen-check-nobody", "Authorization": "Bearer " + secrets.token_hex(8)})
    yield status == 401 and err.get("error") == "PG_NOT_AUTHENTICATED", \
        f"a request with an unknown credential is refused: HTTP {status} {err.get('error')}"
    if "identity" in doc.get("extensions", []):           # a hidden list would hide an opt-out from every provider
        try:
            env = _get(api + "/v2/anchors")
            b = env.get("body") or {}
            signed = env.get("type") == "pg.anchors.v1" and b.get("registry") == doc.get("prefix") and \
                [s.get("key_id") for s in b.get("signers", [])] == [current["key_id"]] and \
                pregen.verify_bytes(current["public_key_hex"], (env.get("signatures") or [""])[0],
                                    pregen.signing_input(env["type"], b))
            yield signed, f"anchors list signed by the current key: {len(b.get('anchors') or [])} public person(s)"
        except Exception as e:  # noqa: BLE001
            yield False, f"GET {api}/v2/anchors: {e}"
    directory = None
    if directory_url:
        try:
            directory = pregen.load_directory(directory_url, **({"steward_public_key_hex": steward} if steward else {}))
        except Exception as e:  # noqa: BLE001
            yield False, f"directory {directory_url}: {e}"
            return
        entry = next((r for r in directory.registries if r["prefix"] == doc.get("prefix")), None)
        yield entry is not None, f"the directory (sequence {directory.sequence}) lists prefix {doc.get('prefix')}" + (
            f" with keys {', '.join(entry['key_fingerprints'])}" if entry else "")
        if entry:
            yield entry["api"].rstrip("/") == api and entry["keys"] == doc["keys"], "listed with this api and keys URL"
            yield current["key_id"] in entry["key_fingerprints"], "listed with the current key"
    if provider_id and token and subject:
        body = {"subject_ref": subject, "provider_id": provider_id, "profile": "likeness/1",
                "use": {"purpose": purpose}, "job_id": "pregen-check-" + secrets.token_hex(4), "job_hash": "0" * 64,
                **({"licensee_id": licensee} if licensee else {})}
        request = pregen.sign_envelope("pg.request.v1", body)
        status, res = _post(api + "/v2/requests", request, {"X-Provider-ID": provider_id,
                                                           "Authorization": "Bearer " + token})
        answer = res.get("answer")
        yield status == 200 and answer is not None, f"POST /v2/requests for {subject}, purpose {purpose}" + (
            f", licensee {licensee}" if licensee else "") + f": HTTP {status}" + (
            f", {answer['body']['status']} {answer['body'].get('reason') or ''}".rstrip() if answer else f" {res}")
        if answer and directory:
            try:
                pregen.verify_answer(answer, request, directory, testing=bool(doc.get("sandbox")))
                yield True, "the answer verifies through the directory (core rule 5)"
            except pregen.PregenError as e:
                yield False, f"the answer does not verify: {e}"
