"""Level 1 conformance adapter (spec/conformance/README.md): one JSON request on stdin, one answer on stdout.
  python3 spec/conformance/level1/run_conformance.py --adapter "python3 packages/verify-py/tests/conformance_adapter.py" \
    --require-op canonical_json --require-op verify_signature --require-op verify_license \
    --require-op verify_directory --require-op check_namespace
The v5 operations (message_id, signing_input, verify_envelope, check_answer) are required by default.
"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pregen  # noqa: E402

req = json.load(sys.stdin)
op = req.get("op")
if op == "canonical_json":
    raw = pregen.canonical_json(req["input"])
    out = {"canonical_utf8": raw.decode("utf-8"), "sha256_hex": hashlib.sha256(raw).hexdigest()}
elif op == "verify_signature":
    out = {"valid": pregen.verify_bytes(req["public_key_hex"], req["signature_hex"], pregen.canonical_json(req["message"]))}
elif op == "verify_license":
    out = pregen.verify_license(req["body"], req["license_id"], req["subject_public_key_hex"],
                                req["subject_signature_hex"], req["operator_public_key_hex"], req["operator_signature_hex"])
elif op == "verify_directory":
    try:
        pregen.verify_directory(req["directory"], req["steward_public_key_hex"], req["min_sequence"])
        out = {"valid": True}
    except pregen.PregenError:
        out = {"valid": False}
elif op == "check_namespace":
    d = pregen.verify_directory(req["directory"], req["steward_public_key_hex"])
    out = {"result": d.check_signer(req["code"], req["signer_key_id"])}
elif op == "message_id":
    out = {"message_id": pregen.message_id(req["type"], req["body"])}
elif op == "signing_input":
    out = {"signing_input_hex": pregen.signing_input(req["type"], req["body"]).hex()}
elif op == "verify_envelope":
    env = req["envelope"]
    signers, sigs = env["body"].get("signers") or [], env.get("signatures") or []
    data = pregen.signing_input(env["type"], env["body"])
    try:
        out = {"valid": bool(signers) and len(sigs) == len(signers) and all(
            pregen.verify_bytes(req["public_keys"][s["key_id"]], sig, data) for s, sig in zip(signers, sigs))}
    except (KeyError, pregen.PregenError):
        out = {"valid": False}
elif op == "check_answer":
    try:
        d = pregen.verify_directory(req["directory"], req["steward_public_key_hex"], now=req["now"])
        pregen.check_answer(req["answer"], req["request"], d, lambda url: req["key_sets"][url], now=req["now"],
                            testing=req["testing"])
        out = {"ok": True}
    except (KeyError, pregen.PregenError) as e:
        out = {"ok": False, "error": str(e)}
elif op == "pg_check_char":           # PG-CODE §4.1 on a PG body: the frozen table (TOG-CODE §4.1)
    out = {"check_char": pregen.check_char(req["body"], pregen.CROCKFORD)}
elif op == "pg_verify_check_char":
    try:
        out = {"valid": pregen.check_char(req["body"], pregen.CROCKFORD) == req["check_char"]}
    except pregen.NotACode:
        out = {"valid": False}
else:
    out = {"unsupported": True}
print(json.dumps(out))
