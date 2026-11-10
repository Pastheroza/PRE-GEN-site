#!/usr/bin/env python3
"""Level 1 conformance runner — replays spec/test-vectors/vectors.json
against any implementation that speaks the adapter protocol described in
spec/conformance/README.md.

Usage:
    python3 run_conformance.py --adapter "python3 adapters/backend_adapter.py"
    python3 run_conformance.py --adapter "node_modules/.bin/sucrase-node adapters/typescript_sdk_adapter.ts" --cwd ../../../sdk/typescript

One subprocess per request (simple, robust, no persistent-process state to
leak between cases — vector counts here are in the dozens, not thousands,
so the per-call spawn cost doesn't matter). An adapter answers
{"unsupported": true} for an op it doesn't implement; such cases are
SKIPPED, not failed, and reported separately in the summary.

Vectors v3 (pregen 0.14): no verify_license and no pg_code cases. PG code is
incompatible and a pg.license.v2 holds a PG id in its signed bytes, so no
verifier accepts one; vectors v2 stay frozen at test-vectors/vectors.v2.json.
"""

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
VECTORS_PATH = REPO_ROOT / "spec" / "test-vectors" / "vectors.json"
V5_DIR = REPO_ROOT / "spec" / "test-vectors"
# The v5 operations (PRE-GEN-CORE.md, Messages and rule 5). Required unless --allow-missing-v5: before they were part
# of Level 1, an implementation with every v5 message id wrong passed it (stress test M2).
V5_OPS = ["message_id", "signing_input", "verify_envelope", "check_answer"]


def _call(adapter_cmd: str, cwd: str | None, extra_env: dict, request: dict) -> dict:
    env = {**os.environ, **extra_env}
    proc = subprocess.run(
        shlex.split(adapter_cmd),
        input=json.dumps(request),
        capture_output=True,
        text=True,
        cwd=cwd,
        env=env,
        timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"adapter exited {proc.returncode}: {proc.stderr.strip()}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"adapter did not print valid JSON: {proc.stdout!r} ({e})")


def _check(name: str, ok: bool, detail: str, results: list) -> None:
    results.append((name, ok, detail))


def run(adapter_cmd: str, cwd: str | None, extra_env: dict | None = None,
        required_ops: list[str] | None = None) -> list[tuple[str, bool, str]]:
    extra_env = extra_env or {}
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    results: list[tuple[str, bool, str]] = []

    # ── canonical_json ──
    for case in vectors["canonical_json"]:
        resp = _call(adapter_cmd, cwd, extra_env, {"op": "canonical_json", "input": case["input"]})
        if resp.get("unsupported"):
            _check(f"canonical_json:{case['name']}", True, "skipped (unsupported)", results)
            continue
        ok = (resp.get("canonical_utf8") == case["canonical_utf8"]
              and resp.get("sha256_hex") == case["sha256_hex"])
        _check(f"canonical_json:{case['name']}", ok,
               "" if ok else f"got {resp}, want canonical_utf8={case['canonical_utf8']!r}", results)

    # ── signing: canonicalization + signature verification, never signing itself ──
    pubkey_hex = vectors["operator_key"]["public_hex"]
    for case in vectors["signing"]:
        resp = _call(adapter_cmd, cwd, extra_env, {"op": "canonical_json", "input": case["body"]})
        if resp.get("unsupported"):
            _check(f"signing_canonical:{case['name']}", True, "skipped (unsupported)", results)
        else:
            ok = (resp.get("canonical_utf8") == case["canonical_utf8"]
                  and resp.get("sha256_hex") == case["sha256_hex"])
            _check(f"signing_canonical:{case['name']}", ok,
                   "" if ok else f"got {resp}", results)

        resp = _call(adapter_cmd, cwd, extra_env, {
            "op": "verify_signature", "message": case["body"],
            "public_key_hex": pubkey_hex, "signature_hex": case["signature_hex"],
        })
        if resp.get("unsupported"):
            _check(f"signing_verify:{case['name']}", True, "skipped (unsupported)", results)
        else:
            ok = resp.get("valid") is True
            _check(f"signing_verify:{case['name']}", ok,
                   "" if ok else f"expected valid signature, got {resp}", results)
            resp = _call(adapter_cmd, cwd, extra_env, {
                "op": "verify_signature", "message": {**case["body"], "conformance_tampered": True},
                "public_key_hex": pubkey_hex, "signature_hex": case["signature_hex"],
            })
            _check(f"signing_reject_tampered:{case['name']}", resp.get("valid") is False,
                   "" if resp.get("valid") is False else f"accepted a tampered body: {resp}", results)

    # ── namespace: the signed registry directory and who may issue which codes (V-10, V-12) ──
    ns = vectors.get("namespace")
    if ns:
        for case in ns["directory_cases"]:
            resp = _call(adapter_cmd, cwd, extra_env, {
                "op": "verify_directory", "directory": case["directory"],
                "steward_public_key_hex": ns["steward_public_key_hex"], "min_sequence": case["min_sequence"]})
            name = f"namespace_directory:{case['name']}"
            if resp.get("unsupported"):
                _check(name, True, "skipped (unsupported)", results)
            else:
                ok = resp.get("valid") is case["valid"]
                _check(name, ok, "" if ok else f"got {resp}, want valid={case['valid']}", results)
        for case in ns["namespace_cases"]:
            resp = _call(adapter_cmd, cwd, extra_env, {
                "op": "check_namespace", "directory": ns["directory"],
                "steward_public_key_hex": ns["steward_public_key_hex"],
                "code": case["code"], "signer_key_id": case["signer_key_id"]})
            name = f"namespace_issuer:{case['name']}"
            if resp.get("unsupported"):
                _check(name, True, "skipped (unsupported)", results)
            else:
                ok = resp.get("result") == case["result"]
                _check(name, ok, "" if ok else f"got {resp}, want {case['result']!r}", results)
        for case in ns.get("revocation_cases", []):  # V-14, each with its own signed directory
            resp = _call(adapter_cmd, cwd, extra_env, {
                "op": "check_namespace", "directory": case["directory"],
                "steward_public_key_hex": ns["steward_public_key_hex"],
                "code": case["code"], "signer_key_id": case["signer_key_id"]})
            name = f"namespace_issuer:{case['name']}"
            if resp.get("unsupported"):
                _check(name, True, "skipped (unsupported)", results)
            else:
                ok = resp.get("result") == case["result"]
                _check(name, ok, "" if ok else f"got {resp}, want {case['result']!r}", results)

    _run_v5(adapter_cmd, cwd, extra_env, results)

    # Probe each explicitly required operation using an existing valid vector.
    probes = {
        "canonical_json": {"op": "canonical_json", "input": {}},
        "verify_signature": {"op": "verify_signature", "message": vectors["signing"][0]["body"],
                             "public_key_hex": pubkey_hex, "signature_hex": vectors["signing"][0]["signature_hex"]},
    }
    if ns:
        probes["verify_directory"] = {"op": "verify_directory", "directory": ns["directory"],
                                     "steward_public_key_hex": ns["steward_public_key_hex"], "min_sequence": 0}
        probes["check_namespace"] = {"op": "check_namespace", "directory": ns["directory"],
                                    "steward_public_key_hex": ns["steward_public_key_hex"],
                                    "code": ns["namespace_cases"][0]["code"],
                                    "signer_key_id": ns["namespace_cases"][0]["signer_key_id"]}
    msg = json.loads((V5_DIR / "messages.json").read_text(encoding="utf-8"))["vectors"][0]["envelope"]
    ans = json.loads((V5_DIR / "answers.json").read_text(encoding="utf-8"))
    probes["message_id"] = {"op": "message_id", "type": msg["type"], "body": msg["body"]}
    probes["signing_input"] = {"op": "signing_input", "type": msg["type"], "body": msg["body"]}
    probes["verify_envelope"] = {"op": "verify_envelope", "envelope": msg, "public_keys": {}}
    probes["check_answer"] = _answer_request(ans, ans["cases"][0])
    coverage = {
        "message_id": ("v5_message_id:",),
        "signing_input": ("v5_signing_input:",),
        "verify_envelope": ("v5_envelope:", "v5_small_order:"),
        "check_answer": ("v5_check_answer:",),
        "canonical_json": ("canonical_json:", "signing_canonical:"),
        "verify_signature": ("signing_verify:", "signing_reject_tampered:"),
        "verify_directory": ("namespace_directory:",),
        "check_namespace": ("namespace_issuer:",),
    }
    for op in required_ops or []:
        if op == "verify_license":
            _check(f"required_op:{op}", False, "retired in vectors v3: no verifier accepts a pg.license.v2", results)
        elif op not in probes:
            _check(f"required_op:{op}", False, "unknown required operation", results)
        else:
            resp = _call(adapter_cmd, cwd, extra_env, probes[op])
            skipped = any(name.startswith(coverage[op]) and detail.startswith("skipped")
                          for name, _, detail in results)
            ok = not resp.get("unsupported") and not skipped
            _check(f"required_op:{op}", ok, "required operation skipped applicable cases" if not ok else "", results)
    return results


def _answer_request(ans: dict, case: dict) -> dict:
    return {"op": "check_answer", "answer": case["answer"], "request": case["request"], "directory": ans["directory"],
            "steward_public_key_hex": ans["steward_public_key_hex"], "key_sets": ans["key_sets"], "now": ans["now"],
            "testing": case["testing"]}


def _run_v5(adapter_cmd: str, cwd: str | None, extra_env: dict, results: list) -> None:
    """v5 messages: ids, signing input, envelopes (with the C1 small-order forgery) and the answer check."""
    def ask(name: str, request: dict, judge) -> None:
        resp = _call(adapter_cmd, cwd, extra_env, request)
        if resp.get("unsupported"):
            _check(name, True, "skipped (unsupported)", results)
        else:
            ok, detail = judge(resp)
            _check(name, ok, "" if ok else detail, results)

    msgs = json.loads((V5_DIR / "messages.json").read_text(encoding="utf-8"))
    keys = {k["key_id"]: k["public_key_hex"] for k in msgs["keys"].values()}
    for v in msgs["vectors"]:
        env, n = v["envelope"], v["name"]
        ask(f"v5_message_id:{n}", {"op": "message_id", "type": env["type"], "body": env["body"]},
            lambda r, v=v: (r.get("message_id") == v["message_id"], f"expected {v['message_id']}, got {r}"))
        ask(f"v5_signing_input:{n}", {"op": "signing_input", "type": env["type"], "body": env["body"]},
            lambda r, v=v: (r.get("signing_input_hex") == v["signing_input_hex"], f"got {str(r)[:120]}"))
        if not env["signatures"]:
            continue
        pubs = {s["key_id"]: keys[s["key_id"]] for s in env["body"]["signers"]}
        for label, e, want in (("valid", env, True),
                               ("tampered_body", {**env, "body": {**env["body"], "conformance_tampered": True}}, False),
                               ("other_type", {**env, "type": env["type"] + "x"}, False),
                               ("no_signatures", {**env, "signatures": []}, False)):
            ask(f"v5_envelope:{n}:{label}", {"op": "verify_envelope", "envelope": e, "public_keys": pubs},
                lambda r, want=want: (r.get("valid") is want, f"expected valid={want}, got {r}"))
    small = json.loads((V5_DIR / "small-order-keys.json").read_text(encoding="utf-8"))
    for i, k in enumerate(small["refuse"]):
        pub = k["public_key_hex"]
        kid = "pg-ed25519:" + hashlib.sha256(bytes.fromhex(pub)).hexdigest()[:32]
        forged = {"type": "pg.report.v1", "body": {"signers": [{"role": "provider", "key_id": kid}], "outcome": "generated"},
                  "signatures": ["01" + "00" * 63]}
        ask(f"v5_small_order:{i}", {"op": "verify_envelope", "envelope": forged, "public_keys": {kid: pub}},
            lambda r: (r.get("valid") is False, f"a small-order key verified a forgery: {r}"))
    ans = json.loads((V5_DIR / "answers.json").read_text(encoding="utf-8"))
    for c in ans["cases"]:
        ask(f"v5_check_answer:{c['name']}", _answer_request(ans, c),
            lambda r, c=c: (r.get("ok") is c["ok"], f"expected ok={c['ok']}, got {r}"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", required=True, help="shell command to invoke the adapter")
    parser.add_argument("--cwd", default=None, help="working directory to run the adapter from")
    parser.add_argument("--env", action="append", default=[],
                        help="extra KEY=VALUE env var for the adapter process, repeatable")
    parser.add_argument("--require-op", action="append", default=[],
                        help="fail rather than skip when this operation is unsupported (repeatable)")
    parser.add_argument("--allow-missing-v5", action="store_true",
                        help="do not require the v5 operations (a pre-v5 implementation: it is not v5 conformant)")
    args = parser.parse_args()

    extra_env = dict(kv.split("=", 1) for kv in args.env)
    required = list(dict.fromkeys(args.require_op + ([] if args.allow_missing_v5 else V5_OPS)))
    results = run(args.adapter, args.cwd, extra_env, required)
    passed = sum(1 for _, ok, _ in results if ok)
    skipped = sum(1 for _, ok, detail in results if ok and detail.startswith("skipped"))
    failed = [(name, detail) for name, ok, detail in results if not ok]

    v5 = sum(1 for name, ok, detail in results if name.startswith("v5_") and ok and not detail.startswith("skipped"))
    print(f"{passed - skipped} passed, {len(failed)} failed, {skipped} skipped ({len(results)} total); v5: {v5} passed")
    for name, detail in failed:
        print(f"  FAIL {name}: {detail}")
    if passed - skipped == 0:
        print("  FAIL nothing ran: the adapter implements no operation")
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
