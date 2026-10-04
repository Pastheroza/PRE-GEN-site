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
{"unsupported": true} for an op it doesn't implement (e.g. the SDKs never
mint PG codes — spec/README.md documents this as backend-only); such cases
are SKIPPED, not failed, and reported separately in the summary.
"""

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
VECTORS_PATH = REPO_ROOT / "spec" / "test-vectors" / "vectors.json"


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

    # ── license: subject signature + operator countersignature (§1.2) ──
    lc = vectors.get("license_countersignature")
    if lc:
        good = {"op": "verify_license", "body": lc["body"], "license_id": lc["license_id"],
                "subject_public_key_hex": lc["subject_public_key_hex"],
                "subject_signature_hex": lc["subject_signature_hex"],
                "operator_public_key_hex": pubkey_hex,
                "operator_signature_hex": lc["operator_signature_hex"]}
        resp = _call(adapter_cmd, cwd, extra_env, good)
        if resp.get("unsupported"):
            _check("license_countersignature:valid", True, "skipped (unsupported)", results)
        else:
            ok = resp.get("subject_valid") is True and resp.get("operator_valid") is True
            _check("license_countersignature:valid", ok, "" if ok else f"got {resp}", results)
            # The countersignature covers the license id: another id must fail.
            other = dict(good, license_id=lc["license_id"][:-1] + ("A" if lc["license_id"][-1] != "A" else "B"))
            resp = _call(adapter_cmd, cwd, extra_env, other)
            ok = resp.get("subject_valid") is True and resp.get("operator_valid") is False
            _check("license_countersignature:binds_license_id", ok, "" if ok else f"got {resp}", results)

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

    # ── pg_code: check_char, subject_code, license_id, rejects ──
    pg = vectors["pg_code"]
    for case in pg["check_char"]:
        resp = _call(adapter_cmd, cwd, extra_env, {"op": "pg_check_char", "body": case["body"]})
        if resp.get("unsupported"):
            _check(f"pg_check_char:{case['body']}", True, "skipped (unsupported)", results)
        else:
            ok = resp.get("check_char") == case["check_char"]
            _check(f"pg_check_char:{case['body']}", ok,
                   "" if ok else f"got {resp}, want {case['check_char']!r}", results)

    for case in pg["subject_code"]:
        resp = _call(adapter_cmd, cwd, extra_env, {"op": "pg_subject_code", "serial": case["serial"]})
        if resp.get("unsupported"):
            _check(f"pg_subject_code:{case['serial']}", True, "skipped (unsupported)", results)
        else:
            ok = resp.get("code") == case["code"]
            _check(f"pg_subject_code:{case['serial']}", ok,
                   "" if ok else f"got {resp}, want {case['code']!r}", results)

    for case in pg["license_id"]:
        resp = _call(adapter_cmd, cwd, extra_env, {
            "op": "pg_license_id", "license_class": case["license_class"],
            "subject_serial": case["subject_serial"], "tail": case["tail"],
        })
        if resp.get("unsupported"):
            _check(f"pg_license_id:{case['license_id']}", True, "skipped (unsupported)", results)
        else:
            ok = resp.get("license_id") == case["license_id"]
            _check(f"pg_license_id:{case['license_id']}", ok,
                   "" if ok else f"got {resp}, want {case['license_id']!r}", results)

    for case in pg["rejects"]:
        resp = _call(adapter_cmd, cwd, extra_env, {
            "op": "pg_verify_check_char", "body": case["body"], "check_char": case["check_char"],
        })
        if resp.get("unsupported"):
            _check(f"pg_rejects:{case['kind']}", True, "skipped (unsupported)", results)
        else:
            ok = resp.get("valid") is False
            _check(f"pg_rejects:{case['kind']}", ok,
                   "" if ok else f"expected a corrupted code to fail verification, got {resp}", results)

    # ── issuer prefix (PG-CODE.md §9) ──
    for case in pg.get("issuer_subject_code", []):
        resp = _call(adapter_cmd, cwd, extra_env, {"op": "pg_issuer_subject_code",
                                                   "issuer": case["issuer"], "serial": case["serial"]})
        name = f"pg_issuer_subject_code:{case['code']}"
        if resp.get("unsupported"):
            _check(name, True, "skipped (unsupported)", results)
        else:
            ok = resp.get("code") == case["code"]
            _check(name, ok, "" if ok else f"got {resp}, want {case['code']!r}", results)

    for case in pg.get("issuer_license_id", []):
        resp = _call(adapter_cmd, cwd, extra_env, {
            "op": "pg_issuer_license_id", "issuer": case["issuer"], "license_class": case["license_class"],
            "subject_serial": case["subject_serial"], "tail": case["tail"]})
        name = f"pg_issuer_license_id:{case['license_id']}"
        if resp.get("unsupported"):
            _check(name, True, "skipped (unsupported)", results)
        else:
            ok = resp.get("license_id") == case["license_id"]
            _check(name, ok, "" if ok else f"got {resp}, want {case['license_id']!r}", results)

    for case in pg.get("issuer_rejects", []):
        resp = _call(adapter_cmd, cwd, extra_env, {
            "op": "pg_verify_check_char", "body": case["body"], "check_char": case["check_char"]})
        name = f"pg_issuer_rejects:{case['kind']}"
        if resp.get("unsupported"):
            _check(name, True, "skipped (unsupported)", results)
        else:
            ok = resp.get("valid") is False
            _check(name, ok, "" if ok else f"expected a corrupted prefix to fail verification, got {resp}", results)

    # Maximum body length (PG-CODE.md §4.2): 36 passes, 37 fails even with the formula's check.
    for want, key in ((True, "length_accepts"), (False, "length_rejects")):
        for case in pg.get(key, []):
            resp = _call(adapter_cmd, cwd, extra_env, {
                "op": "pg_verify_check_char", "body": case["body"], "check_char": case["check_char"]})
            name = f"pg_{key}:{case['kind']}"
            if resp.get("unsupported"):
                _check(name, True, "skipped (unsupported)", results)
            else:
                ok = resp.get("valid") is want
                _check(name, ok, "" if ok else f"expected valid={want}, got {resp}", results)

    # Probe each explicitly required operation using an existing valid vector.
    probes = {
        "canonical_json": {"op": "canonical_json", "input": {}},
        "verify_signature": {"op": "verify_signature", "message": vectors["signing"][0]["body"],
                             "public_key_hex": pubkey_hex, "signature_hex": vectors["signing"][0]["signature_hex"]},
    }
    if lc:
        probes["verify_license"] = good
    if ns:
        probes["verify_directory"] = {"op": "verify_directory", "directory": ns["directory"],
                                     "steward_public_key_hex": ns["steward_public_key_hex"], "min_sequence": 0}
        probes["check_namespace"] = {"op": "check_namespace", "directory": ns["directory"],
                                    "steward_public_key_hex": ns["steward_public_key_hex"],
                                    "code": ns["namespace_cases"][0]["code"],
                                    "signer_key_id": ns["namespace_cases"][0]["signer_key_id"]}
    coverage = {
        "canonical_json": ("canonical_json:", "signing_canonical:"),
        "verify_signature": ("signing_verify:", "signing_reject_tampered:"),
        "verify_license": ("license_countersignature:",),
        "verify_directory": ("namespace_directory:",),
        "check_namespace": ("namespace_issuer:",),
    }
    for op in required_ops or []:
        if op not in probes:
            _check(f"required_op:{op}", False, "unknown required operation", results)
        else:
            resp = _call(adapter_cmd, cwd, extra_env, probes[op])
            skipped = any(name.startswith(coverage[op]) and detail.startswith("skipped")
                          for name, _, detail in results)
            ok = not resp.get("unsupported") and not skipped
            _check(f"required_op:{op}", ok, "required operation skipped applicable cases" if not ok else "", results)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", required=True, help="shell command to invoke the adapter")
    parser.add_argument("--cwd", default=None, help="working directory to run the adapter from")
    parser.add_argument("--env", action="append", default=[],
                        help="extra KEY=VALUE env var for the adapter process, repeatable")
    parser.add_argument("--require-op", action="append", default=[],
                        help="fail rather than skip when this operation is unsupported (repeatable)")
    args = parser.parse_args()

    extra_env = dict(kv.split("=", 1) for kv in args.env)
    results = run(args.adapter, args.cwd, extra_env, args.require_op)
    passed = sum(1 for _, ok, _ in results if ok)
    skipped = sum(1 for _, ok, detail in results if ok and detail.startswith("skipped"))
    failed = [(name, detail) for name, ok, detail in results if not ok]

    print(f"{passed - skipped} passed, {len(failed)} failed, {skipped} skipped ({len(results)} total)")
    for name, detail in failed:
        print(f"  FAIL {name}: {detail}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
