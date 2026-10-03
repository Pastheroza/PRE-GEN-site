"""The PRE-GEN registry directory: who may issue which PG codes.

PG-CODE.md §9.1 and PRE-GEN-SPEC.md §5.4 / §5.7 are the normative text; this
file is a reference implementation of it, with no dependency beyond the
`cryptography` package. Used by `steward.py` (signing), by
`generate_vectors.py` (the `namespace` vectors) and by the conformance
adapters.

One namespace, one registry, one set of keys: the bare namespace belongs to
the origin registry, each four-letter prefix to exactly one other registry,
and a code is valid only when a key of the registry owning its namespace
signed it. The same rule for every registry.
"""

import hashlib
import json
import re
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SCHEMA = "pregen.registries.v2"
_PREFIX = re.compile(r"[ABCDEFGHJKMNPQRSTVWXYZ]{4}")
_FINGERPRINT = re.compile(r"pg-ed25519:[0-9a-f]{32}")
# After "PG-": a four-letter issuer followed by "-" (three letters is a licence
# class or a legacy STD/SUB shape, both in the bare namespace).
_ISSUER_IN_CODE = re.compile(r"^PG-([ABCDEFGHJKMNPQRSTVWXYZ]{4})-")


class DirectoryError(ValueError):
    """The directory is not one a verifier may use."""


def canonical_json(obj) -> bytes:
    """PRE-GEN-SPEC.md §2."""
    def validate(value):
        if value is None or type(value) is bool:
            return
        if type(value) is int and abs(value) <= 2**53 - 1:
            return
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError as e:
                raise DirectoryError("invalid Unicode in signed JSON") from e
        elif isinstance(value, list):
            for item in value:
                validate(item)
        elif isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise DirectoryError("signed JSON keys must be strings")
                validate(key)
                validate(item)
        else:
            raise DirectoryError("signed JSON must use only JSON values and safe integer numbers")
    validate(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def fingerprint(public_key_hex: str) -> str:
    """PRE-GEN-SPEC.md §2.1."""
    if not isinstance(public_key_hex, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", public_key_hex):
        raise DirectoryError("public key must be exactly 32 bytes in hex")
    return "pg-ed25519:" + hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:32]


def public_hex(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def signed_bytes(directory: dict) -> bytes:
    return canonical_json({k: v for k, v in directory.items() if k != "signature"})


def check_invariants(directory: dict) -> None:
    """Raise DirectoryError unless the directory has the v2 shape and rules."""
    if not isinstance(directory, dict):
        raise DirectoryError("directory must be an object")
    if directory.get("schema") != SCHEMA:
        raise DirectoryError(f"schema must be {SCHEMA!r}")
    seq = directory.get("sequence")
    if not isinstance(seq, int) or isinstance(seq, bool) or not 1 <= seq <= 2**53 - 1:
        raise DirectoryError("sequence must be a positive integer")
    if not _FINGERPRINT.fullmatch(str(directory.get("steward_key_id", ""))):
        raise DirectoryError("steward_key_id must be a pg-ed25519 fingerprint")
    regs = directory.get("registries")
    if not isinstance(regs, list) or not regs:
        raise DirectoryError("registries must be a non-empty list")
    seen = set()
    for r in regs:
        if not isinstance(r, dict):
            raise DirectoryError("registry entry must be an object")
        if not isinstance(r.get("name"), str) or not r["name"].strip():
            raise DirectoryError("registry name must be nonempty")
        for field in ("api", "keys"):
            value = r.get(field)
            if not isinstance(value, str):
                raise DirectoryError(f"registry {field} must be a URL")
            try:
                url = urlsplit(value)
                if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
                    raise DirectoryError(f"registry {field} must use HTTPS without credentials, query or fragment")
                url.port  # Reject invalid port encodings.
            except ValueError as e:
                raise DirectoryError(f"invalid registry {field} URL") from e
        prefix = r.get("prefix")
        if prefix != "" and not (isinstance(prefix, str) and _PREFIX.fullmatch(prefix)):
            raise DirectoryError(f"bad prefix {prefix!r}: empty, or four letters of the PG alphabet")
        if prefix in seen:
            raise DirectoryError("the bare namespace is listed twice" if prefix == "" else f"prefix {prefix} is listed twice")
        seen.add(prefix)
        fps = r.get("key_fingerprints")
        if not isinstance(fps, list) or not fps or not all(_FINGERPRINT.fullmatch(str(f)) for f in fps):
            raise DirectoryError(f"registry {r.get('name')!r}: key_fingerprints must list pg-ed25519 fingerprints")
    if "" not in seen:
        raise DirectoryError("no registry holds the bare namespace")


def sign_directory(directory: dict, private_key: Ed25519PrivateKey) -> dict:
    out = {k: v for k, v in directory.items() if k != "signature"}
    out["steward_key_id"] = fingerprint(public_hex(private_key))
    check_invariants(out)
    out["signature"] = private_key.sign(signed_bytes(out)).hex()
    return out


def verify_directory(directory: dict, steward_public_key_hex: str, min_sequence: int = 0) -> dict:
    """V-12: accept the directory only with the pinned steward's signature, its
    invariants, and a sequence no lower than one already seen."""
    if type(min_sequence) is not int or not 0 <= min_sequence <= 2**53 - 1:
        raise DirectoryError("min_sequence must be a nonnegative integer")
    check_invariants(directory)
    if directory["steward_key_id"] != fingerprint(steward_public_key_hex):
        raise DirectoryError("signed by a different steward key")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(steward_public_key_hex)).verify(
            bytes.fromhex(str(directory.get("signature", ""))), signed_bytes(directory))
    except (InvalidSignature, ValueError):
        raise DirectoryError("bad steward signature")
    if directory["sequence"] < min_sequence:
        raise DirectoryError(f"sequence {directory['sequence']} is older than {min_sequence} already seen")
    return directory


def issuer_of(code: str) -> str:
    """The namespace of a PG code: its four-letter prefix, or "" for the bare
    namespace (PG-CODE.md §9 rule 5 — the one thing a code may be read for)."""
    if not isinstance(code, str):
        raise DirectoryError("PG code must be a string")
    normalized = code.strip().upper()
    m = _ISSUER_IN_CODE.match(normalized)
    if not m and not re.match(r"^PG-(?:(?:STD|SUB|PRM|RND)-)?[0-9]", normalized):
        raise DirectoryError("unrecognized PG namespace")
    return m.group(1) if m else ""


def check_namespace(directory: dict, code: str, signer_key_id: str) -> str:
    """V-10 for a directory already accepted by verify_directory():
    "valid", "unknown_issuer" (no registry holds the namespace) or
    "issuer_mismatch" (the signer is not a key of the namespace's owner)."""
    try:
        issuer = issuer_of(code)
    except DirectoryError:
        return "unknown_issuer"
    owner = next((r for r in directory["registries"] if r["prefix"] == issuer), None)
    if owner is None:
        return "unknown_issuer"
    return "valid" if signer_key_id in owner["key_fingerprints"] else "issuer_mismatch"
