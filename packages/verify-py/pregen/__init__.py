"""pregen — check PRE-GEN signatures against the signed registry directory
(PG-CODE.md §9.1, PRE-GEN-SPEC.md §2, V-9 to V-12). The PRE-GEN steward key is
built in. Same API as the npm package @pregen/verify.
"""

import hashlib
import json
import re
import urllib.request
from copy import deepcopy
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__version__ = "0.2.1"
__all__ = [
    "STEWARD_PUBLIC_KEY_HEX", "DIRECTORY_URL", "PregenError", "Directory", "canonical_json",
    "fingerprint", "verify_bytes", "verify_signed", "verify_license", "issuer_of",
    "verify_directory", "load_directory", "verify_decision", "check_decision", "ORIGIN_KEY_FINGERPRINTS",
]

STEWARD_PUBLIC_KEY_HEX = "5cb949aab04186e3e216ec541b847c912fc3f78138c0ec3cb2560b2dad0d1f1b"
DIRECTORY_URL = "https://www.pregen.org/registries.json"
# The origin registry's (PRAMPTA's) operator keys, pinned here as well as in the
# directory: a stolen steward key cannot add its own key to the bare namespace.
# A new origin key needs a new release of this library (threat model T4).
ORIGIN_KEY_FINGERPRINTS = ("pg-ed25519:1904514fd2ac442f0a5388d13cc313a0",)
SCHEMA = "pregen.registries.v2"
_MAX_INT = 2**53 - 1
_PREFIX = re.compile(r"[ABCDEFGHJKMNPQRSTVWXYZ]{4}")
_FINGERPRINT = re.compile(r"pg-ed25519:[0-9a-f]{32}")
_ISSUER_IN_CODE = re.compile(r"^PG-([ABCDEFGHJKMNPQRSTVWXYZ]{4})-")
_BARE_CODE = re.compile(r"^PG-(?:[A-Z]{3}-)?[0-9]")


class PregenError(ValueError):
    """Not something a verifier may accept."""


def canonical_json(value) -> bytes:
    """Canonical JSON (PRE-GEN-SPEC.md §2), UTF-8 encoded."""
    def check(v):
        if v is None or type(v) is bool:
            return
        if type(v) is int:
            if abs(v) > _MAX_INT:
                raise PregenError("signed JSON numbers must be safe integers")
        elif isinstance(v, str):
            try:
                v.encode("utf-8")
            except UnicodeError as e:
                raise PregenError("invalid Unicode in signed JSON") from e
        elif isinstance(v, list):
            for item in v:
                check(item)
        elif isinstance(v, dict):
            for k, item in v.items():
                if not isinstance(k, str):
                    raise PregenError("signed JSON keys must be strings")
                check(k)
                check(item)
        else:
            raise PregenError("signed JSON must contain only JSON values and integers")
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def fingerprint(public_key_hex: str) -> str:
    """"pg-ed25519:" + first 32 hex of SHA-256(raw public key) (§2.1)."""
    if not isinstance(public_key_hex, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", public_key_hex):
        raise PregenError("public key must be 32 bytes of hex")
    return "pg-ed25519:" + hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:32]


def verify_bytes(public_key_hex: str, signature_hex: str, message: bytes) -> bool:
    """Ed25519 over raw bytes. False on any bad signature or key encoding."""
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(
            bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def verify_signed(obj: dict, public_key_hex: str, signature_field: str, exclude=None) -> bool:
    """Verify obj[signature_field] over the canonical JSON of obj without the excluded fields."""
    if not isinstance(obj, dict):
        return False
    exclude = exclude or [signature_field]
    body = {k: v for k, v in obj.items() if k not in exclude}
    return verify_bytes(public_key_hex, str(obj.get(signature_field, "")), canonical_json(body))


def verify_license(body: dict, license_id: str, subject_public_key_hex: str, subject_signature_hex: str,
                   operator_public_key_hex: str, operator_signature_hex: str) -> dict:
    """A license (§1.2): subject signature over the body; operator countersignature over
    canonical body || subject signature (64 raw bytes) || license id (ASCII)."""
    body_bytes = canonical_json(body)
    subject_valid = verify_bytes(subject_public_key_hex, subject_signature_hex, body_bytes)
    try:
        message = body_bytes + bytes.fromhex(subject_signature_hex) + str(license_id).encode("utf-8")
        operator_valid = len(bytes.fromhex(subject_signature_hex)) == 64 and verify_bytes(
            operator_public_key_hex, operator_signature_hex, message)
    except (ValueError, TypeError):
        operator_valid = False
    return {"subject_valid": subject_valid, "operator_valid": operator_valid}


def issuer_of(code: str) -> str:
    """The namespace of a PG code: its four-letter prefix, or "" for the bare namespace."""
    if not isinstance(code, str):
        raise PregenError("PG code must be a string")
    c = code.strip().upper()
    m = _ISSUER_IN_CODE.match(c)
    if m:
        return m.group(1)
    if not _BARE_CODE.match(c):
        raise PregenError("unrecognized PG namespace")
    return ""


def _https_url(value, field):
    try:
        url = urlsplit(value)
        url.port  # rejects invalid ports
    except (ValueError, TypeError, AttributeError) as e:
        raise PregenError(f"registry {field} must be a URL") from e
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise PregenError(f"registry {field} must use HTTPS without credentials, query or fragment")


def _check_invariants(d):
    if not isinstance(d, dict):
        raise PregenError("directory must be an object")
    if d.get("schema") != SCHEMA:
        raise PregenError(f"schema must be {SCHEMA}")
    seq = d.get("sequence")
    if type(seq) is not int or not 1 <= seq <= _MAX_INT:
        raise PregenError("sequence must be a positive integer")
    if not _FINGERPRINT.fullmatch(str(d.get("steward_key_id", ""))):
        raise PregenError("steward_key_id must be a pg-ed25519 fingerprint")
    regs = d.get("registries")
    if not isinstance(regs, list) or not regs:
        raise PregenError("registries must be a non-empty list")
    seen = set()
    for r in regs:
        if not isinstance(r, dict):
            raise PregenError("registry entry must be an object")
        if not isinstance(r.get("name"), str) or not r["name"].strip():
            raise PregenError("registry name must be nonempty")
        _https_url(r.get("api"), "api")
        _https_url(r.get("keys"), "keys")
        prefix = r.get("prefix")
        if prefix != "" and not (isinstance(prefix, str) and _PREFIX.fullmatch(prefix)):
            raise PregenError(f"bad prefix {prefix!r}")
        if prefix in seen:
            raise PregenError("the bare namespace is listed twice" if prefix == "" else f"prefix {prefix} is listed twice")
        seen.add(prefix)
        fps = r.get("key_fingerprints")
        if not isinstance(fps, list) or not fps or not all(_FINGERPRINT.fullmatch(str(f)) for f in fps):
            raise PregenError(f"registry {r.get('name')!r}: key_fingerprints must list pg-ed25519 fingerprints")
    if "" not in seen:
        raise PregenError("no registry holds the bare namespace")


def _get_json(url: str):
    # urllib follows redirects; a registry key set or directory has no reason to redirect.
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise PregenError(f"refusing redirect from {url}")
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=10) as res:
        return json.loads(res.read().decode("utf-8"))


class Directory:
    """A directory accepted under V-12. Get one from verify_directory() or load_directory()."""

    def __init__(self, directory: dict, _token=None, _origin_pin=None):
        if _token is not _TOKEN:
            raise PregenError("use verify_directory() or load_directory()")
        self._d = deepcopy(directory)
        self._origin_pin = tuple(_origin_pin) if _origin_pin is not None else None

    @property
    def sequence(self) -> int:
        """Store it and pass it back as min_sequence, so an older directory is refused."""
        return self._d["sequence"]

    @property
    def registries(self) -> list:
        return deepcopy(self._d["registries"])

    def to_json(self) -> dict:
        """The signed directory itself: persist it and pass it back as `previous`."""
        return deepcopy(self._d)

    def registry_for(self, code: str):
        """The registry that owns a code's namespace (resolve codes only there, V-11), or None."""
        try:
            issuer = issuer_of(code)
        except PregenError:
            return None
        r = next((x for x in self._d["registries"] if x["prefix"] == issuer), None)
        return deepcopy(r) if r else None

    def check_signer(self, code: str, signer_key_id: str) -> str:
        """V-10: "valid", "unknown_issuer" or "issuer_mismatch"."""
        r = self.registry_for(code)
        if r is None:
            return "unknown_issuer"
        if signer_key_id not in r["key_fingerprints"]:
            return "issuer_mismatch"
        if r["prefix"] == "" and self._origin_pin is not None and signer_key_id not in self._origin_pin:
            return "issuer_mismatch"
        return "valid"

    def public_key(self, code: str, key_id: str, get_json=_get_json) -> str:
        """The owner's public key for key_id, from its key set, checked against the listed fingerprint."""
        verdict = self.check_signer(code, key_id)
        if verdict != "valid":
            raise PregenError(f"{key_id} may not sign {code}: {verdict}")
        keys = get_json(self.registry_for(code)["keys"]).get("keys") or []
        entry = next((k for k in keys if isinstance(k, dict) and k.get("key_id") == key_id), None)
        if entry is None or fingerprint(entry.get("public_key_hex")) != key_id:
            raise PregenError(f"no key {key_id} in the key set")
        return entry["public_key_hex"]


_TOKEN = object()


def _check_continuity(new: dict, previous: dict) -> None:
    """A newer directory may add registries and keys, never remove or move them (PG-CODE.md §9.1)."""
    if new["sequence"] < previous["sequence"]:
        raise PregenError(f"sequence {new['sequence']} is older than {previous['sequence']} already seen")
    if new["sequence"] == previous["sequence"]:
        if canonical_json(new) != canonical_json(previous):
            raise PregenError("a different directory with the same sequence")
        return
    for old in previous["registries"]:
        now = next((r for r in new["registries"] if r["prefix"] == old["prefix"]), None)
        if now is None:
            raise PregenError(f"namespace {old['prefix'] or '(bare)'} was removed")
        for f in old["key_fingerprints"]:
            if f not in now["key_fingerprints"]:
                raise PregenError(f"key {f} was removed from {now['name']}")


_DEFAULT = object()


def verify_directory(directory: dict, steward_public_key_hex: str = STEWARD_PUBLIC_KEY_HEX,
                     min_sequence: int = 0, previous=None, origin_key_fingerprints=_DEFAULT) -> Directory:
    """V-12: accept the directory only with the pinned steward's signature, its invariants,
    a sequence no lower than one already seen and, given the last accepted directory,
    nothing removed from it. With the built-in steward key the origin keys are pinned too."""
    if type(min_sequence) is not int or not 0 <= min_sequence <= _MAX_INT:
        raise PregenError("min_sequence must be a nonnegative integer")
    _check_invariants(directory)
    if directory["steward_key_id"] != fingerprint(steward_public_key_hex):
        raise PregenError("signed by a different steward key")
    if not verify_signed(directory, steward_public_key_hex, "signature"):
        raise PregenError("bad steward signature")
    if directory["sequence"] < min_sequence:
        raise PregenError(f"sequence {directory['sequence']} is older than {min_sequence} already seen")
    if previous is not None:
        _check_continuity(directory, previous.to_json() if isinstance(previous, Directory) else previous)
    if origin_key_fingerprints is _DEFAULT:
        origin_key_fingerprints = ORIGIN_KEY_FINGERPRINTS if steward_public_key_hex == STEWARD_PUBLIC_KEY_HEX else None
    return Directory(directory, _TOKEN, origin_key_fingerprints)


def load_directory(url: str = DIRECTORY_URL, min_sequence: int = 0, get_json=_get_json, previous=None) -> Directory:
    """Download and verify the directory from pregen.org. Pass the last accepted one as `previous`."""
    return verify_directory(get_json(url), min_sequence=min_sequence, previous=previous)


def verify_decision(decision: dict, code: str, directory: Directory = None, get_json=_get_json) -> bool:
    """Is this registry decision genuine, and signed by a key of the registry that owns `code`?
    Signatures only: use check_decision() before generating."""
    directory = directory or load_directory(get_json=get_json)
    key = directory.public_key(code, (decision or {}).get("operator_key_id"), get_json=get_json)
    return verify_signed(decision, key, "operator_signature")


_ECHOED = ("subject_id", "provider_id", "licensee_id", "prompt_hash", "model", "modality")


def _empty(v) -> bool:
    return v is None or v == "" or v == []


def check_decision(decision: dict, request: dict, directory: Directory = None, get_json=_get_json, now=None) -> dict:
    """Everything a provider must check before generating on a decision (PRE-GEN-SPEC.md §5.4):
    a genuine signature by the owner of the license's namespace (V-1, V-2, V-10), the decision
    answers exactly this request (V-4), it is within its validity window (V-3), it carries a
    verified user binding when a user was named (V-13), and it is a license-backed allow (P-5).
    `request` is what you sent: the /v1/verify body plus provider_id and licensee_id.
    Raises PregenError with the reason; returns the decision when you may generate."""
    import time
    now = int(time.time()) if now is None else now
    if not isinstance(decision, dict) or not isinstance(request, dict):
        raise PregenError("decision and request must be objects")
    if decision.get("allowed") is not True or decision.get("disposition") != "allow":
        raise PregenError(f"not an allow: {decision.get('disposition')}")
    if not isinstance(decision.get("license_id"), str) or not decision["license_id"]:
        raise PregenError("an allow must name its license")

    exp, iat = decision.get("expires_at"), decision.get("issued_at")
    if type(exp) is not int or exp <= 0:
        raise PregenError("expires_at must be a positive integer")
    if iat is not None and (type(iat) is not int or iat <= 0 or iat >= exp or iat > now + 60):
        raise PregenError("issued_at must be a positive integer before expires_at and not in the future")
    if exp <= now:
        raise PregenError("decision expired")

    for f in _ECHOED:
        if (decision.get(f) or "") != (request.get(f) or ""):
            raise PregenError(f"{f} does not match the request")
    got, sent = decision.get("intended_use") or {}, request.get("intended_use") or {}
    if not isinstance(got, dict) or not isinstance(sent, dict):
        raise PregenError("intended_use must be an object")
    for k in set(got) | set(sent):
        # Empty and absent are the same.
        ok = _empty(got.get(k)) if _empty(sent.get(k)) else canonical_json(got.get(k)) == canonical_json(sent[k])
        if not ok:
            raise PregenError(f"intended_use.{k} does not match the request")
    for f in ("generation_id", "provider_identity_link_id"):
        if not _empty(request.get(f)) and decision.get(f) != request[f]:
            raise PregenError(f"{f} does not match the request")
    if not _empty(request.get("provider_user_id")) or not _empty(request.get("provider_identity_link_id")):
        if decision.get("provider_user_binding") != "verified" or _empty(decision.get("provider_identity_link_id")):
            raise PregenError("no verified binding to the user you named")

    if not verify_decision(decision, decision["license_id"], directory, get_json):
        raise PregenError("bad signature")
    return decision
