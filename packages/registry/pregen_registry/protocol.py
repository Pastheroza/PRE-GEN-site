"""PRE-GEN messages: envelope, signatures, message ids and person codes.

Spec: spec/PRE-GEN-CORE.md (Messages), TOG-CODE.md §5.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from importlib import resources

import jsonschema
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pregen import CROCKFORD, PregenError, canonical_json as canonical, check_char, fingerprint, parse_code, verify_bytes
from referencing import Registry, Resource

__all__ = ["ProtocolError", "Key", "canonical", "message_id", "signing_input", "seal", "check_envelope",
           "check_body", "mint_code", "mint_serial", "sha256_hex"]


class ProtocolError(Exception):
    """An HTTP error the registry returns as {"error", "error_description"}."""

    def __init__(self, code: str, detail: str = "", status: int = 422, **extra):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail, self.status, self.extra = code, detail, status, extra


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def signing_input(type_: str, body: dict) -> bytes:
    return b"PREGEN-V5\x00" + type_.encode() + b"\x00" + canonical(body)


def message_id(type_: str, body: dict) -> str:
    """Covers type and body, never the signatures."""
    return sha256_hex(b"PREGEN-V5-ID\x00" + type_.encode() + b"\x00" + canonical(body))


class Key:
    """An Ed25519 key; `id` is the PRE-GEN key id (pg-ed25519:…)."""

    def __init__(self, private_hex: str | None = None):
        self._sk = (Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex)) if private_hex
                    else Ed25519PrivateKey.generate())
        self.public_hex = self._sk.public_key().public_bytes_raw().hex()
        self.id = fingerprint(self.public_hex)

    @property
    def private_hex(self) -> str:
        return self._sk.private_bytes_raw().hex()

    def sign(self, data: bytes) -> str:
        return self._sk.sign(data).hex()


def seal(type_: str, body: dict, signers: list[tuple[str, Key]]) -> dict:
    body = {**body, "signers": [{"role": role, "key_id": key.id} for role, key in signers]}
    data = signing_input(type_, body)
    return {"type": type_, "body": body, "signatures": [key.sign(data) for _, key in signers]}


def _load_schemas() -> dict:
    folder = resources.files("pregen_registry").joinpath("schemas")
    schemas = {f.name[:-5]: json.loads(f.read_text()) for f in folder.iterdir() if f.name.endswith(".json")}
    refs = Registry().with_resources((s["$id"], Resource.from_contents(s)) for s in schemas.values())
    return {name: jsonschema.Draft202012Validator(s, registry=refs) for name, s in schemas.items()}


_SCHEMAS = _load_schemas()


def _schema(name: str):
    return _SCHEMAS[name]


def check_body(name: str, body) -> None:
    """Validate a body against spec/schemas/<name>.json."""
    error = next(iter(_schema(name).iter_errors(body)), None)
    if error is not None:
        where = "/".join(str(p) for p in error.absolute_path) or "body"
        raise ProtocolError("PG_MALFORMED", f"{name}: {where}: {error.message}")


def check_envelope(env, type_: str, roles: tuple[str, ...], key_for) -> dict:
    """Shape, type, signers against the roles, then each signature. `key_for(role, key_id)` returns the
    public key hex or None. A bad signature is PG_NOT_AUTHENTICATED (401): the signer is not who it says."""
    if not isinstance(env, dict) or set(env) != {"type", "body", "signatures"} or env.get("type") != type_ \
            or not isinstance(env["body"], dict) or not isinstance(env["signatures"], list):
        raise ProtocolError("PG_MALFORMED", f"expected a {type_} envelope")
    signers = env["body"].get("signers", [])
    if not isinstance(signers, list) or [s.get("role") if isinstance(s, dict) else None for s in signers] != list(roles) \
            or len({s.get("key_id") for s in signers}) != len(signers) or len(env["signatures"]) != len(signers):
        raise ProtocolError("PG_MALFORMED", f"{type_} is signed by {list(roles) or 'no one'}")
    try:
        data = signing_input(type_, env["body"])
    except PregenError as e:                    # an unsafe integer, a float, a lone surrogate: nothing to sign
        raise ProtocolError("PG_MALFORMED", f"{type_}: {e}") from None
    for signer, sig in zip(signers, env["signatures"]):
        pub = key_for(signer["role"], signer.get("key_id"))
        if pub is None or not isinstance(sig, str) or not verify_bytes(pub, sig, data):
            raise ProtocolError("PG_NOT_AUTHENTICATED", f"the {signer['role']} signature does not verify", status=401)
    return env["body"]


# ── Person codes (TOG-CODE.md §5). Reading, folding and act codes are the library's (pregen.parse_code, code_key,
# code_for); the registry only mints. ──────────────────────────────────────────────────────────────────────────────

RESERVED_SERIAL = 900_000_000       # TOG-CODE §11: the floor of PG-CODE §11, never issued


def mint_code(prefix: str, serial: int) -> str:
    """A person's code, written TOG-. A serial under 10^8 is a PG-born person respelled by its marker (the sandbox's
    fixed test subjects, PG-CODE §5): same digits, same check. A new person has 9 digits (mint_serial). Raises
    PregenError for a code no shape holds: a symbol check on 9 digits, or a prefix the old shapes cannot carry."""
    digits = f"{serial:06d}"
    code = f"TOG-{prefix + '-' if prefix else ''}{digits}{check_char(prefix + digits)}"
    parse_code(code)
    return code


def mint_serial(prefix: str) -> int:
    """A new person's serial: 9 digits at random below the reserved floor, so a gap means nothing and there is no
    registration order to read; one whose check would be a symbol is skipped (TOG-CODE §5). The caller skips taken."""
    while True:
        serial = 100_000_000 + secrets.randbelow(RESERVED_SERIAL - 100_000_000)
        if check_char(prefix + str(serial)) in CROCKFORD:
            return serial
