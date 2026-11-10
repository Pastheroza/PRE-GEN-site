"""pregen — check PRE-GEN signatures against the signed registry directory
(PG-CODE.md §9.1, PRE-GEN-SPEC.md §2, V-9 to V-12). The PRE-GEN steward key is
built in. Same API as the npm package @pregen/verify.
"""

import hashlib
import itertools
import json
import math
import re
import unicodedata
import urllib.request
from copy import deepcopy
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__version__ = "0.14.0"
__all__ = [
    "STEWARD_PUBLIC_KEY_HEX", "DIRECTORY_URL", "PregenError", "Directory", "canonical_json",
    "fingerprint", "check_public_key", "verify_bytes", "verify_signed", "verify_license", "issuer_of", "normalize_code",
    "verify_directory", "load_directory", "verify_decision", "check_decision", "check_answer", "verify_answer", "message_id", "DIRECTORY_MAX_AGE", "decide_identity",
    "verify_anchors", "check_channel_proof", "wikidata_official_urls", "SETTLED_AFTER", "check_proof", "FLOOR_REASONS", "REPORT_GRACE", "STEWARD_SUCCESSOR_PUBLIC_KEY_HEX", "Simulator",
    "signing_input", "sign_envelope", "new_private_key_hex", "public_key_hex",
    "check_provider_url", "sandbox_provider_url", "party_document", "pg_access",
    "CATEGORIES", "PROHIBITED_FOR_MINORS", "INTIMATE", "floor", "forbids", "terms_opens", "check_terms",
    "NotACode", "Mistyped", "AskRegistry", "CROCKFORD", "TOG_VALUES", "BARE_ISSUER", "FIXTURE_PREFIXES", "check_char",
    "parse_code", "kind_of", "describe", "code_key", "normalize_typed", "find_codes", "code_for", "metadata_ok", "code_verdict",
    "check_parties", "admission_refusal", "DIRECTORY_V2_URL", "CodeError",
]

STEWARD_PUBLIC_KEY_HEX = "5cb949aab04186e3e216ec541b847c912fc3f78138c0ec3cb2560b2dad0d1f1b"
# The successor steward key, created in advance and kept apart (PG-CODE.md §9.1). A directory it
# signs replaces every directory signed by the current steward key, whatever their sequence.
STEWARD_SUCCESSOR_PUBLIC_KEY_HEX = "658544163d6abd5fef046407980d249817875d87d8cf4b67879a2e265fa5612f"  # pg-ed25519:3e5e20729ce8485eea274c4cb33721d6, created 2026-10-03
# The directory (PRE-GEN-CORE.md rule 2, TOG-CODE.md §9.2): v3 lists prefixes of 4 to 8 letters, legal entities and
# dated roles. The v2 file stays frozen at DIRECTORY_V2_URL, with the PG-era entries only, for clients before 0.14;
# this library verifies both.
DIRECTORY_URL = "https://www.pregen.org/registries.v3.json"
DIRECTORY_V2_URL = "https://www.pregen.org/registries.json"
SCHEMA = "pregen.registries.v2"
SCHEMA_V3 = "pregen.registries.v3"
_ROLES = ("home", "market", "wallet", "log_operator", "witness")
_MAX_INT = 2**53 - 1
_PREFIX = re.compile(r"[ABCDEFGHJKMNPQRSTVWXYZ]{4}")
_FINGERPRINT = re.compile(r"pg-ed25519:[0-9a-f]{32}")
# The curve's 8 small-order points, sign bit cleared; y = p and p + 1 are 0 and 1 again (as libsodium lists them).
# Under such a key a signature checks out for any message with no private key behind it, and OpenSSL takes it
# (stress test C1, 2026-10-28). The same list as PRAMPTA's verify_ed25519.
_SMALL_ORDER = frozenset(bytes.fromhex(h) for h in (
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
))
_P = 2**255 - 19


class PregenError(ValueError):
    """Not something a verifier may accept."""


def _ints(v):
    """JSON numbers by value, as every JavaScript parser reads them: 1.0 and 1e0 are the integer 1 (PL1), so both
    libraries verify the same bytes. Any other float is left for canonical_json to refuse."""
    if type(v) is float and v.is_integer() and abs(v) <= _MAX_INT:
        return int(v)
    if isinstance(v, list):
        return [_ints(x) for x in v]
    if isinstance(v, dict):
        return {k: _ints(x) for k, x in v.items()}
    return v


def canonical_json(value) -> bytes:
    """Canonical JSON (PRE-GEN-SPEC.md §2), UTF-8 encoded."""
    value = _ints(value)

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


def check_public_key(public_key_hex: str) -> bytes:
    """The raw key, or PregenError for a key no one can be held to: a small-order point in any encoding, or a
    non-canonical encoding (y >= p). Call it wherever a key is first recorded; verify_bytes calls it too."""
    if not isinstance(public_key_hex, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", public_key_hex):
        raise PregenError("public key must be 32 bytes of hex")
    raw = bytes.fromhex(public_key_hex)
    y = raw[:31] + bytes([raw[31] & 0x7F])
    if y in _SMALL_ORDER or int.from_bytes(y, "little") >= _P:
        raise PregenError("public key is a small-order or non-canonical point: anyone could sign under it")
    return raw


def verify_bytes(public_key_hex: str, signature_hex: str, message: bytes) -> bool:
    """Ed25519 over raw bytes. False on any bad signature or key encoding, and under a key check_public_key refuses."""
    try:
        Ed25519PublicKey.from_public_bytes(check_public_key(public_key_hex)).verify(
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


# ── ToG code (spec/TOG-CODE.md) ──────────────────────────────────────────────────
# One family, one written spelling: TOG-. A PG- string is legacy input only; code_key() folds it to its one TOG
# spelling, and nothing here returns a PG- string. A code is a handle, never proof: an act's code is recomputed from
# its record (code_for) and compared. Shared vectors: spec/test-vectors/tog-code.json, also run by verify-js.

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"   # PG-CODE §3, frozen: serials, tails, PG bodies
TOG_VALUES = CROCKFORD + "ILOU"                  # TOG bodies: I L O U take 32-35 (TOG-CODE §3)
_CHECKS = CROCKFORD + "*~$=!"                    # PG-CODE §3.1, frozen; new codes never end in a symbol
_MAX_BODY = 36
_TAIL = 11                                       # 55 bits of a message id
_KINDS = {"LIC": "license", "PG": "generated", "AG": "approved_after"}
_FIVE = ("PG", "PG-LIC", "AG", "AG-LIC", "LIC")  # the kind digit is the 1-based index
_KIND_OF_TYPE = {"pg.grant.v1": "LIC", "pg.license.v2": "LIC", "pg.answer.v1": "PG", "pg.after_gen.v1": "AG"}
_RESERVED_SERIAL, _RESERVED_TAIL = 900_000_000, "ZZZZ"
BARE_ISSUER = "PRAM"       # the bare PG- namespace belongs to the first registry, which also holds PRAM
FIXTURE_PREFIXES = ("NWRD", "HLWD", "USAD", "VELR", "SKAN", "KAST", "TGOV", "HYBR", "OMNI", "KINO",
                    "KOBEMK", "LYONMK", "RIOMKT", "PUNEMK", "OSLOMK", "ZYXW", "ABCD", "TEST")   # reserved forever

_C = "0-9A-HJKMNP-TV-Z"
_K = rf"[{_C}*~$=!]"
_TOG_PREFIX = "(?!LIC|L[A-Z]IC(?![A-Z])|LI[A-Z]C(?![A-Z]))[A-Z]{4,8}(?<!LIC)"
_OLDP = "[A-HJKMNP-TV-Z]{4}"
_SHAPES = (  # (shape, marker, kind, regex): exactly one matches any valid code (TOG-CODE §7.1)
    ("person", "TOG", "subject", re.compile(rf"TOG-({_TOG_PREFIX})-([1-9][0-9]{{8}})([{_C}])")),
    ("event", "TOG", None, re.compile(rf"TOG-(LIC|(?:PG|AG)(?:-LIC)?)-({_TOG_PREFIX})(?:-({_TOG_PREFIX}))?"
                                      rf"-([{_C}]{{4}}-[{_C}]{{4}}-[{_C}]{{3}})([{_C}])")),
    ("old_person", "TOG", "subject", re.compile(rf"TOG-({_OLDP})-([0-9]{{6,7}})({_K})")),
    ("old_bare_person", "TOG", "subject", re.compile(rf"TOG-()([0-9]{{6,}})({_K})")),
    ("old_no_check", "TOG", "subject", re.compile(r"TOG-(STD|SUB)-([0-9]{6,})")),
    ("pg_person", "PG", "subject", re.compile(rf"PG-({_OLDP})-([0-9]{{6,}})({_K})")),
    ("pg_licence", "PG", "license", re.compile(rf"PG-({_OLDP})-([A-Z]{{3}})-([0-9]{{6,}})-([{_C}]{{6}})({_K})")),
    ("bare_person", "PG", "subject", re.compile(rf"PG-()([0-9]{{6,}})({_K})")),
    ("bare_licence", "PG", "license", re.compile(rf"PG-()([A-Z]{{3}})-([0-9]{{6,}})-([{_C}]{{6}})({_K})")),
    ("no_check", "PG", "subject", re.compile(r"PG-([A-Z]{3})-([0-9]{6,})")),
)
_FIND = re.compile(r"(?<![A-Za-z0-9-])(?:TOG|PG)-[A-Z0-9]+(?:-[A-Z0-9]+)*[*~$=!]?(?![A-Za-z0-9])")


class CodeError(PregenError):
    """A string that is not a code, or a record that gives none. `reason`: "malformed", "mistyped", "ask_registry" or
    "no_code" (as the vectors write it); catch the subclasses, or this and read `reason`."""
    reason = "no_code"


class NotACode(CodeError):
    """Malformed: not a code at all. `hints` lists the codes a typed string could mean when more than one fits."""
    reason = "malformed"

    def __init__(self, message="not a code", hints=()):
        super().__init__(message)
        self.hints = list(hints)


class Mistyped(CodeError):
    """The shape matches, the check character does not: distinct from not found and from not a code."""
    reason = "mistyped"


class AskRegistry(CodeError):
    """An old PG licence id with no record at hand: only its registry knows its TOG-LIC code."""
    reason = "ask_registry"


def check_char(body: str, values: str = TOG_VALUES) -> str:
    """PG-CODE §4.1: the sum of each value times its 1-based position, mod 37. `values` is TOG_VALUES for a TOG body,
    CROCKFORD for a PG body. Raises NotACode for a body over 36 characters or outside the table."""
    if not isinstance(body, str) or len(body) > _MAX_BODY or any(c not in values for c in body):
        raise NotACode("body too long or outside the alphabet")
    return _CHECKS[sum(values.index(c) * (i + 1) for i, c in enumerate(body)) % 37]


def _verifies(body, chk, values) -> bool:
    try:
        return check_char(body, values) == chk
    except NotACode:
        return False


def _event_body(kind, issuer, home, tail) -> str:
    return f"{len(issuer)}{len(home or '')}{_FIVE.index(kind) + 1}{issuer}{home or ''}{tail}"


def parse_code(code: str, check: bool = True) -> dict:
    """The one reading of a code exactly as it stands (TOG-CODE §7): no trimming, case change or folding. Offline:
    shape, kind ("subject", "license", "generated", "approved_after"), basis of an event ("terms", "licence" or None),
    issuer (the registry to ask; "" for the bare namespace), home, example, and `key`, the TOG spelling (None for an
    old PG licence id: see code_key). check=False reads the shape only, for routing; it never says a code is real.
    Raises NotACode or Mistyped."""
    if not isinstance(code, str) or not code.isascii():
        raise NotACode("not an ASCII string")
    hits = [(s, mk, k, m) for s, mk, k, rx in _SHAPES if (m := rx.fullmatch(code))]
    if len(hits) != 1:
        raise NotACode(f"not a code: {code!r}")
    shape, marker, kind, m = hits[0]
    g = m.groups()
    out = {"shape": shape, "marker": marker, "kind": kind, "home": None, "key": code if marker == "TOG" else None}
    if marker == "PG" and kind == "subject":
        # Legacy input: its one spelling is TOG- + the rest. With no valid TOG spelling it was never issued.
        if check and shape != "no_check" and not _verifies(g[0] + g[1], g[2], CROCKFORD):
            raise Mistyped(f"mistyped code: {code}")
        if check and not _valid("TOG" + code[2:]):
            raise NotACode(f"never issued in any spelling: {code}")
        out["key"] = "TOG" + code[2:]
    if shape in ("no_check", "old_no_check"):
        return dict(out, issuer="", cls=g[0], serial=g[1], example=False)
    if shape == "event":
        kind, issuer, home, tail, chk = g
        tail = tail.replace("-", "")
        if home == issuer:
            raise NotACode("a registry is written once")
        if check and not _verifies(_event_body(kind, issuer, home, tail), chk, TOG_VALUES):
            raise Mistyped(f"mistyped code: {code}")
        basis = None if kind == "LIC" else "licence" if kind.endswith("-LIC") else "terms"
        return dict(out, kind=_KINDS[kind[:3].rstrip("-")], basis=basis, issuer=issuer, home=home,
                    example=tail.startswith(_RESERVED_TAIL))
    prefix, *rest, chk = g
    if check and not _verifies(prefix + "".join(rest), chk, TOG_VALUES if marker == "TOG" else CROCKFORD):
        raise Mistyped(f"mistyped code: {code}")
    serial = rest[-1] if kind == "subject" else rest[1]
    return dict(out, issuer=prefix, cls="", serial=serial, example=int(serial) >= _RESERVED_SERIAL)


def _valid(s) -> bool:
    try:
        parse_code(s)
        return True
    except PregenError:
        return False


def kind_of(code: str) -> str:
    """"subject", "license", "generated" or "approved_after", from the string alone (no network)."""
    return parse_code(code)["kind"]


def describe(code: str) -> str:
    """What the string claims, for support tools (TOG-CODE §15): never shown beside a video, where party names come
    only from a record that fits the file. Raises NotACode or Mistyped."""
    p = parse_code(code)
    home = f" · home {p['home']}" if p["home"] else ""
    basis = {"licence": " under a licence", "terms": " under the person's terms"}.get(p.get("basis"), "")
    ex = " · EXAMPLE, never issued" if p["example"] else ""
    if p["marker"] == "PG":
        ex += f" · old spelling of {p['key']}" if p["key"] else " · old licence number: its registry gives its TOG code"
    return f"claims {p['kind']}{basis} · issued by {p['issuer'] or 'the bare legacy namespace'}{home} · not checked{ex}"


def code_key(code: str, licences: dict = None) -> str:
    """The one TOG spelling (TOG-CODE §7.3). Compare, hash and look up codes only by it. A TOG code is its own key; a PG
    person folds by its marker; an old PG licence id folds through its record: `licences` maps that id to the signed
    pg.license.v2 as {type, id (its message id), signer (prefix), subject_ref, license_id}. Without it: AskRegistry.
    Never returns a PG- string."""
    p = parse_code(code)
    if p["key"]:
        return p["key"]
    rec = (licences or {}).get(code)
    if not isinstance(rec, dict) or rec.get("license_id") != code:
        raise AskRegistry(f"ask its registry for the code of {code}")
    return code_for(rec)


def _k(code):
    """code_key where there is one, else the string as it stands: a comparison never splits one code in two."""
    try:
        return code_key(code)
    except PregenError:
        return code


def issuer_of(code: str) -> str:
    """The registry to ask about a code: its first prefix, or "" for the bare namespace. The shape only, like 0.13
    (TOG-CODE §8); TOG and PG spellings alike. Anything else is refused, never repaired: lower case, spaces,
    invisible or non-ASCII characters (PG-CODE §7). Pass what a person typed through normalize_typed first."""
    return parse_code(code, check=False)["issuer"]


def find_codes(text: str) -> list:
    """Every well-formed code in free text, as it stands there (TOG-CODE §13). A PG- string found is legacy input:
    pass it through code_key before comparing or showing it."""
    found = (c if _valid(c) else c[:-1] for c in _FIND.findall(text))
    return [c for c in found if _valid(c)]


_DASHES = dict.fromkeys(map(ord, "‐‑‒–—―−﹣"), "-")
_DROP = dict.fromkeys(map(ord, "­​‌‍⁠﻿\\"))
_LOOKALIKE = str.maketrans("АВСЕНІКМОРТХаеорсхіктмΑΒΕΗΙΚΜΝΟΡΤΧΥΖ", "ABCEHIKMOPTXAEOPCXIKTMABEHIKMNOPTXYZ")
_AS_DIGIT = str.maketrans("OIL", "011")
_MAX_READINGS = 4096


def _readings(g, letters=True) -> set:
    out = {g, g.translate(_AS_DIGIT)}
    if letters and len(g) <= 8 and set(g) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ01"):
        out |= {"".join(x) for x in itertools.product(*("IL" if c == "1" else "O" if c == "0" else c for c in g))}
    if letters and re.fullmatch("[1IL]{2}C", g):
        out.add("LIC")
    return out


def normalize_typed(typed: str, licences: dict = None) -> str:
    """Only where a person types, pastes or scans a code (TOG-CODE §7.4), never on a code from a message: the one code
    meant, in its TOG spelling, to show as "Did you mean ...?". Folds width, dashes, invisibles, Cyrillic and Greek
    look-alikes, case, a resolver URL, trailing punctuation, then O/0 and I/L/1 by slot, then the PG spelling.
    Raises NotACode when no reading is a code, or more than one is (their codes in `hints`), or the readings exceed
    4096; Mistyped when the string as typed has the shape but not the check; AskRegistry for an old licence id whose
    record (`licences`, as for code_key) is not at hand, with the folded old id as `folded`."""
    if not isinstance(typed, str):
        raise NotACode("a code is a string")
    s = unicodedata.normalize("NFKC", typed).translate(_DASHES).translate(_DROP).translate(_LOOKALIKE).strip()
    if "/" in s:
        s = s.split("#")[0].rstrip("/").rsplit("/", 1)[-1]
    s = s.rstrip(".,;:)]\"'").upper()
    if "-" in s:
        groups = ["".join(x.split()) for x in s.split("-")]
    elif s.split() and s.split()[0] in ("PG", "TOG"):          # the display form 'PG 000 042 *' (PG-CODE §13)
        groups = s.split()
        groups = [groups[0], "".join(groups[1:])] if len(groups) > 2 and not groups[1].isalpha() else groups
    else:
        groups = [s]
    tail_from = len(groups) - 3 if "TOG" in _readings(groups[0]) and len(groups) >= 6 else len(groups)
    readings = [_readings(g, i < tail_from) for i, g in enumerate(groups)]
    if math.prod(map(len, readings)) > _MAX_READINGS:
        raise NotACode("too many readings: type the code again")
    found = set()
    for combo in itertools.product(*readings):
        if _valid(c := "-".join(combo)):
            try:
                found.add(code_key(c, licences))
            except AskRegistry:
                found.add(c)
    if len(found) > 1:
        raise NotACode("more than one code fits: ask which", sorted(found))
    if not found:
        parse_code("-".join(groups))     # the honest error for the string as typed
        raise NotACode(f"not a code: {typed!r}")
    c = found.pop()
    if c.startswith("PG-"):
        e = AskRegistry(f"ask its registry for the code of {c}")
        e.folded = c                     # the old id as folded here, for asking its registry (never for showing)
        raise e
    return c


def _tail_of(message_id_hex) -> str:
    if not isinstance(message_id_hex, str) or not _HEX64.fullmatch(message_id_hex):
        raise CodeError("a message id is 64 lowercase hex")
    n = int(message_id_hex, 16) >> (256 - 5 * _TAIL)
    return "".join(CROCKFORD[(n >> (5 * (_TAIL - 1 - i))) & 31] for i in range(_TAIL))


def code_for(act: dict) -> str:
    """The code of an act, computed from its record, never read off a string (TOG-CODE §6.1). act = {type, id (its
    message id), signer (the signer's prefix), subject_ref, grant?: {id, signer} of the licence it was made under,
    cosign?: {id, home, home_in_code} of the home's countersignature}. Without a cosign (the flat model) the signer
    must be the registry the person's code was born at. Raises PregenError when the record gives no code."""
    try:
        kind = _KIND_OF_TYPE[act["type"]]
        grant = act.get("grant")
        if grant:
            if kind == "LIC" or grant["signer"] != act["signer"]:
                raise CodeError("a licence has no basis; the grant behind an act is signed by the act's own signer")
            kind += "-LIC"
        cs = act.get("cosign")
        if cs is None:
            if (issuer_of(act["subject_ref"]) or BARE_ISSUER) != act["signer"]:
                raise CodeError("no home countersignature: only the person's own registry may sign alone")
            issuer, home, mid = act["signer"], None, act["id"]
        else:
            issuer, home, mid = act["signer"], cs["home"] if cs.get("home_in_code") else None, cs["id"]
    except (KeyError, TypeError, AttributeError):
        raise CodeError("not an act record")
    home = None if home == issuer else home
    tail = _tail_of(mid)
    if tail.startswith(_RESERVED_TAIL):
        raise CodeError("a reserved tail: never issued")
    if not isinstance(issuer, str) or not (home is None or isinstance(home, str)):
        raise CodeError("not an act record")
    chk = check_char(_event_body(kind, issuer, home, tail))
    if chk not in CROCKFORD:
        raise CodeError("a symbol check: never issued")
    t = tail + chk
    code = f"TOG-{kind}-{issuer}{'-' + home if home else ''}-{t[:4]}-{t[4:8]}-{t[8:]}"
    parse_code(code)
    return code


def _same(a, b) -> bool:
    try:
        return code_key(a) == code_key(b)
    except PregenError:
        return False


def _matches(code, act) -> bool:
    try:
        return code_for(act) == code
    except PregenError:
        return False


def metadata_ok(meta: dict, act: dict, licence: dict = None) -> bool:
    """The readable copies beside a signed record (TOG-CODE §14): meta = {"Code", "Licence"}, either may be absent.
    Both are recomputed (code_for on the act, and on `licence`, the record its grant names) and any mismatch refuses
    the file. A Licence copy without a licence basis, or whose licence is not at hand, is a mismatch."""
    try:
        want = {"Code": code_for(act), "Licence": None}
        if act.get("grant") and licence is not None and licence.get("id") == act["grant"]["id"]:
            want["Licence"] = code_for(licence)
    except (PregenError, KeyError, TypeError, AttributeError):
        return False
    return all(want[k] is not None and want[k] == v for k, v in meta.items() if k in want)


_COVERS = " It covers the named person only, and says nothing about anyone else in the file."


def code_verdict(file_hash: str, act: dict = None, caption: str = None, ingredient: str = None) -> str:
    """What a verifier may say before it checks signatures and the chain (TOG-CODE §15). `act` is the record carried
    with the file, with its `media_hash`; `caption` the code shown beside it, checked against the record, never the
    other way round; `ingredient` the hash an edited file's C2PA manifest cites. A result starting "fits: " means the
    record fits this file and this code: now verify the signatures and the chain, then show the outcome."""
    p = None
    if caption is not None:
        try:
            p = parse_code(caption)
        except Mistyped:
            return "Mistyped code."
        except NotACode:
            return "Not a code."
        if p["example"]:
            return "Example code from the specification. Never issued."
    if act is None:
        if p is None:
            return "No record. This says nothing either way."
        if p["shape"] != "event" or p["kind"] == "license":
            return f"This code names a {p['kind']}. It says nothing about this file."
        return "Unchecked: no record at hand. This says nothing either way."
    edit = False
    if act.get("media_hash") != file_hash:
        if ingredient is None or ingredient != act.get("media_hash"):
            return "This code belongs to a different file. It does not show that this video is allowed."
        edit = True
    if p is not None and not (_matches(caption, act) if p["shape"] == "event" else _same(caption, act.get("subject_ref"))):
        return "The code does not match its record."
    try:
        kind = _KINDS[_KIND_OF_TYPE[act["type"]]]
        code_for(act)
    except (PregenError, KeyError, TypeError):
        return "The code does not match its record."
    if edit:
        return "An editor states this was made from an approved file. Only the editor says so."
    return f"fits: {kind}; now verify signatures and the chain (V-H)." + _COVERS


def _held(span, at) -> bool:
    return span is not None and (at is None or (span["from"] <= at and (span["until"] is None or at < span["until"])))


def check_parties(code: str, entries: dict, at=None, provider: str = None) -> dict:
    """{"ok", "facts"}: a code's parties against directory v3 entries {prefix: {entity, group, government, roles:
    {role: {from, until}}, provider_domains, void_from?, closed?}}, read at `at` (the witnessed time of the act) or,
    with no record, at no time (TOG-CODE §9.2). A revoked, closed or re-roled party is a fact, never "not a code";
    ok is False only when a slot names an unlisted party, one without the slot's role at `at`, or one whose listing
    was void at `at`. Times compare as numbers. For support tools, never shown beside a video."""
    p = parse_code(code)
    if p["shape"] != "event":
        slots = [("issuer", p["issuer"] or BARE_ISSUER, ())]
    elif p["home"]:
        slots = [("issuer", p["issuer"], ("market",)), ("home", p["home"], ("home",))]
    else:
        slots = [("issuer", p["issuer"], ("market",) if p["kind"] == "license" else ("home", "market"))]
    ok, facts = True, []
    for slot, prefix, roles in slots:
        e = entries.get(prefix)
        if e is None or ("GOV" in prefix) != e.get("government", False):
            ok = False
            facts.append(f"! {prefix} is not a listed registry")
            continue
        if roles and not any(_held(e.get("roles", {}).get(r), at) for r in roles):
            ok = False
            facts.append(f"! {prefix} did not hold the role {' or '.join(roles)}" + (" at the act" if at else ""))
        v = e.get("void_from")
        if v is not None:
            if at is not None and at >= v:
                ok = False
                facts.append(f"! {prefix} listing void from {v}; the act is after it")
            else:
                facts.append(f"{prefix} listing void from {v}" + ("; the act predates it" if at is not None else ""))
        if e.get("closed") is not None:
            facts.append(f"{prefix} closed at {e['closed']}; ask the home")
        facts.append(f"{slot} {prefix} ({e['entity']})")
    listed = [entries[x] for _, x, _ in slots if x in entries]
    if len(listed) == 2 and listed[0].get("group") == listed[1].get("group"):
        facts.append("issuer and home are one group")
    for _, x, _ in slots:
        if provider and x in entries and provider in entries[x].get("provider_domains", ()):
            facts.append(f"{x} also generated it ({provider})")
    return {"ok": ok, "facts": facts}


_SKELETON = str.maketrans("CGQDJLVNRF", "OOOOIIUMPE")   # visual groups: CGOQD, IJL, UV, MN, PR, EF
_RESERVED_WORDS = (
    "PREGEN", "AFTERGEN", "TOGCODE", "STEWARD", "HOME", "MARKET", "BRANCH", "PROVIDER", "WALLET",
    "ALLOW", "APPROV", "AUTHORI", "VERIF", "VALID", "LEGAL", "LAWFUL", "LICENS", "OFFICIAL", "CERTIF", "GENUIN",
    "NOTFAKE", "TRUST", "DENIED", "DENY", "REFUS", "REVOK", "BLOCK", "BANNED", "POLICE", "COURT", "STATE",
    "ADULT", "PORN", "NSFW", "XXX", "EROTIC", "NUDE")


def _skeleton(s) -> str:
    return s.replace("VV", "W").replace("RN", "M").replace("CL", "D").translate(_SKELETON)


def _osa(a, b) -> int:
    """Edit distance with adjacent swaps (optimal string alignment)."""
    d = [[i + j if i * j == 0 else 0 for j in range(len(b) + 1)] for i in range(len(a) + 1)]
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] != b[j - 1]))
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def admission_refusal(new: str, entity: str, government: bool, directory: dict, reserved=FIXTURE_PREFIXES) -> str:
    """The steward's check of a new prefix (TOG-CODE §9.1): "" if it may be listed for this legal entity, else the
    reason. `directory` maps every listed prefix to {"entity": ...}. Refused or not is normative, the wording is not.
    Human judgement (others' marks, offensive words, sensitive categories in other words) comes on top."""
    if not isinstance(new, str) or not re.fullmatch(_TOG_PREFIX, new):
        return "4 to 8 letters A-Z, never LIC at either end, never LIC with one letter added"
    if new in directory or new in reserved:
        return "taken or reserved: a prefix is never reassigned"
    if government != ("GOV" in new):
        return "GOV is for governments, and governments hold only prefixes with GOV"
    sk = _skeleton(new)
    if not government and "OOU" in sk:
        return "looks like GOV"
    if re.match("T[OQCGD][CGQ]|[PRA][CGQ]|[IJL]{2}[CGQ]", new) or re.search("[IJL]{2}[CGQ]$", new) \
            or len(new) == 4 and re.search("[IJL].?[IJL].?[CGQ]", new) or new.endswith(("PG", "TOG")):
        return "reads as a marker or a kind"
    if any(_skeleton(w) in sk for w in _RESERVED_WORDS):
        return "contains a reserved word"
    if any(e.get("entity") == entity for e in directory.values()):
        return "one prefix per legal entity"
    for old in directory:
        so = _skeleton(old)
        if _osa(new, old) <= 1 or _osa(sk, so) <= 1 or so in sk or sk in so:
            return f"too close to {old}"
    return ""


def normalize_code(typed: str) -> str:
    """Deprecated: use normalize_typed, which folds look-alikes and gives the TOG spelling. Surrounding ASCII spaces
    trimmed and lower case raised, nothing else; the spelling is kept as typed (PG-CODE.md §7)."""
    if not isinstance(typed, str):
        raise PregenError("PG code must be a string")
    s = typed.strip(" \t\r\n")
    if not s.isascii():
        raise PregenError("a PG code is ASCII: retype it")
    issuer_of(s.upper())
    return s.upper()


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
    if d.get("schema") not in (SCHEMA, SCHEMA_V3):
        raise PregenError(f"schema must be {SCHEMA} or {SCHEMA_V3}")
    v3 = d["schema"] == SCHEMA_V3
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
        if prefix != "" and not (isinstance(prefix, str) and re.fullmatch(_TOG_PREFIX if v3 else _PREFIX, prefix)):
            raise PregenError(f"bad prefix {prefix!r}")
        if prefix in seen:
            raise PregenError("the bare namespace is listed twice" if prefix == "" else f"prefix {prefix} is listed twice")
        seen.add(prefix)
        fps = r.get("key_fingerprints")
        if not isinstance(fps, list) or not fps or not all(_FINGERPRINT.fullmatch(str(f)) for f in fps):
            raise PregenError(f"registry {r.get('name')!r}: key_fingerprints must list pg-ed25519 fingerprints")
    # Revocation (PG-CODE.md §9.1): a revoked registry keeps its entry; a revoked key keeps its listing.
    for r in regs:
        rev = r.get("revoked")
        if rev is not None and not (isinstance(rev, dict) and isinstance(rev.get("at"), str)):
            raise PregenError(f"registry {r.get('name')!r}: revoked must be an object with 'at'")
    if v3:
        _check_v3(d)
    rk = d.get("revoked_keys")
    if rk is not None and not (isinstance(rk, list) and all(
            isinstance(k, dict) and _FINGERPRINT.fullmatch(str(k.get("key_id", ""))) and isinstance(k.get("at"), str)
            for k in rk)):
        raise PregenError("revoked_keys must list {key_id, at}")
    # identity.md: steward findings on one person, every member required, times in RFC 3339.
    for field, members in (("false_claims", ("anchor", "code", "at", "reason")),
                           ("false_claim_reversals", ("anchor", "code", "at", "reason")),
                           ("freezes", ("anchor", "at", "until", "reason"))):
        v = d.get(field)
        if v is not None and not (isinstance(v, list) and all(
                isinstance(f, dict) and all(isinstance(f.get(m), str) and f[m] for m in members) for f in v)):
            raise PregenError(f"{field} must list {{{', '.join(members)}}}")
        for f in v or []:
            for t in (f[m] for m in ("at", "until") if m in members):
                if not _RFC3339.fullmatch(t):
                    raise PregenError(f"{field}: not an RFC 3339 time")
                _when(t)                 # a real instant: no February 30, 24:00 or second 60, read alike in verify-js
    for f in d.get("freezes") or []:
        if not 0 < _when(f["until"]) - _when(f["at"]) <= SETTLED_AFTER:
            raise PregenError("a freeze lasts more than nothing and at most 7 days")


def _v3_time(v, field, nullable=False):
    if v is None and nullable:
        return
    if not (isinstance(v, str) and _RFC3339.fullmatch(v)):
        raise PregenError(f"{field}: not an RFC 3339 time")
    _when(v)


def _check_v3(d):
    """The members directory v3 adds (TOG-CODE.md §9.2), each checked when present; times in RFC 3339 as in v2."""
    for r in d["registries"]:
        name = r.get("name")
        for f in ("entity", "group"):
            if f in r and not (isinstance(r[f], str) and r[f]):
                raise PregenError(f"registry {name!r}: {f} must be a nonempty string")
        if "government" in r and type(r["government"]) is not bool:
            raise PregenError(f"registry {name!r}: government must be true or false")
        roles, domains = r.get("roles", {}), r.get("provider_domains", [])
        if not (isinstance(roles, dict) and all(k in _ROLES and isinstance(x, dict) and set(x) <= {"from", "until"}
                                                for k, x in roles.items())):
            raise PregenError(f"registry {name!r}: roles maps {', '.join(_ROLES)} to {{from, until}}")
        if not (isinstance(domains, list) and all(isinstance(x, dict) and set(x) <= {"domain", "from", "until"}
                                                  and isinstance(x.get("domain"), str) and x["domain"] for x in domains)):
            raise PregenError(f"registry {name!r}: provider_domains lists {{domain, from, until}}")
        for x in [*roles.values(), *domains]:
            _v3_time(x.get("from"), f"registry {name!r}")
            _v3_time(x.get("until"), f"registry {name!r}", nullable=True)
        for f in ("void_from", "closed"):
            if f in r:
                _v3_time(r[f], f"registry {name!r}: {f}")
    if "resolver" in d:
        _https_url(d["resolver"], "resolver")
    if "min_library" in d and not (isinstance(d["min_library"], str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", d["min_library"])):
        raise PregenError("min_library must be a version")


_RFC3339 = re.compile(r"(?!0000)[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{3})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])")
SETTLED_AFTER = 7 * 86_400   # identity.md: a new channel permits after 7 days; a steward freeze lasts at most 7 days


def _get_json(url: str):
    # urllib follows redirects; a registry key set or directory has no reason to redirect.
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise PregenError(f"refusing redirect from {url}")
    opener = urllib.request.build_opener(_NoRedirect)
    # Wikidata (identity) answers 403 to an anonymous Python client: say who is asking.
    headers = {"Accept": "application/json", "User-Agent": f"pregen-python/{__version__} (+https://www.pregen.org)"}
    with opener.open(urllib.request.Request(url, headers=headers), timeout=10) as res:
        return json.loads(res.read().decode("utf-8"))


class Directory:
    """A directory accepted under V-12. Get one from verify_directory() or load_directory()."""

    def __init__(self, directory: dict, _token=None, _pins=None, _loaded_at=0):
        if _token is not _TOKEN:
            raise PregenError("use verify_directory() or load_directory()")
        self._d = deepcopy(directory)
        self.loaded_at = _loaded_at  # Unix seconds when it was accepted; check_answer wants it under a day old
        # The caller's own pins, prefix -> fingerprints; no registry is pinned by default (PG-CODE.md §9.1).
        self._pins = {k: tuple(v) for k, v in (_pins or {}).items()}

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

    def is_false_claim(self, code: str, anchor: str = None) -> bool:
        """The steward found `code` a false claim under `anchor` and has not reversed it (identity.md): drop that
        claim. For one anchor and code the latest entry of false_claims and false_claim_reversals by `at` decides; a
        tie stays false. Without `anchor`, under any anchor: a code asked as a private person is then never generated.
        Codes compare by code_key: a ruling on one spelling holds for the other (identity.md)."""
        latest, key = {}, _k(code)
        for is_false, field in ((True, "false_claims"), (False, "false_claim_reversals")):
            for f in self._d.get(field) or []:
                if _k(f["code"]) == key and anchor in (None, f["anchor"]):
                    latest[f["anchor"]] = max(latest.get(f["anchor"], (float("-inf"), False)), (_when(f["at"]), is_false))
        return any(is_false for _, is_false in latest.values())

    def frozen(self, anchor: str, now=None):
        """The steward's freeze of `anchor` in effect at `now` (at <= now < until), or None (identity.md rule 0).
        Pass it to decide_identity(frozen=...)."""
        import time
        now = int(time.time()) if now is None else now
        return next((deepcopy(f) for f in self._d.get("freezes") or []
                     if f["anchor"] == anchor and _when(f["at"]) <= now < _when(f["until"])), None)

    def parties(self, code: str, at=None, provider: str = None) -> dict:
        """Offline party check of `code` (TOG-CODE.md §9.2, see check_parties) against this v3 directory, read at `at`
        (Unix seconds: the act's witnessed time, or None). Returns {"ok", "facts"}; for support tools, never beside a
        video."""
        if self._d["schema"] != SCHEMA_V3:
            raise PregenError("party checks need directory v3")

        def t(v):
            x = None if v is None else _when(v)
            return int(x) if x is not None and x.is_integer() else x
        entries = {r["prefix"]: {
            "entity": r.get("entity", r["name"]), "group": r.get("group"), "government": r.get("government", False),
            "provider_domains": [x["domain"] for x in r.get("provider_domains", [])],
            "roles": {k: {"from": t(x.get("from")), "until": t(x.get("until"))} for k, x in r.get("roles", {}).items()},
            **({"void_from": t(r["void_from"])} if "void_from" in r else {}),
            **({"closed": t(r["closed"])} if "closed" in r else {})} for r in self._d["registries"]}
        return check_parties(code, entries, at, provider)

    def check_signer(self, code: str, signer_key_id: str) -> str:
        """V-10, V-14: "valid", "unknown_issuer", "issuer_mismatch" or "revoked"."""
        r = self.registry_for(code)
        if r is None:
            return "unknown_issuer"
        if r.get("revoked") or any(k["key_id"] == signer_key_id for k in self._d.get("revoked_keys") or []):
            return "revoked"
        if signer_key_id not in r["key_fingerprints"]:
            return "issuer_mismatch"
        pin = self._pins.get(r["prefix"])
        if pin is not None and signer_key_id not in pin:
            return "issuer_mismatch"
        return "valid"

    def public_key(self, code: str, key_id: str, get_json=_get_json, at=None) -> str:
        """The owner's public key for key_id, from its key set, checked against the listed fingerprint. Given `at`
        (the signed time of the message), a key its key set says was retired (`deactivated_at`) before then is
        refused: a retired key keeps verifying what it signed while current, and nothing it signs later."""
        verdict = self.check_signer(code, key_id)
        if verdict != "valid":
            raise PregenError(f"{key_id} may not sign {code}: {verdict}")
        keys = get_json(self.registry_for(code)["keys"]).get("keys") or []
        entry = next((k for k in keys if isinstance(k, dict) and k.get("key_id") == key_id), None)
        if entry is None or fingerprint(entry.get("public_key_hex")) != key_id:
            raise PregenError(f"no key {key_id} in the key set")
        retired = entry.get("deactivated_at")
        if type(at) is int and type(retired) is int and at >= retired:
            raise PregenError(f"{key_id} was retired before this was signed")
        return entry["public_key_hex"]


_TOKEN = object()


def _check_continuity(new: dict, previous: dict) -> None:
    """A newer directory may add registries and keys, never remove or move them (PG-CODE.md §9.1)."""
    if _cross_schema(new, previous):
        return
    if new["sequence"] < previous["sequence"]:
        raise PregenError(f"sequence {new['sequence']} is older than {previous['sequence']} already seen")
    if new["sequence"] == previous["sequence"]:
        if canonical_json(new) != canonical_json(previous):
            raise PregenError("a different directory with the same sequence")
        return
    _keeps_history(new, previous)


def _cross_schema(new: dict, previous: dict) -> bool:
    """v2 and v3 are two lines, each with its own sequence: none is compared across them, and a v2 directory after a
    v3 one is refused (it would hide registries listed only in v3)."""
    if new["schema"] == previous["schema"]:
        return False
    if previous["schema"] == SCHEMA_V3:
        raise PregenError("a v3 directory was already accepted: load registries.v3.json")
    return True


def _when(value) -> float:
    from datetime import datetime
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        raise PregenError(f"not an RFC 3339 time: {value!r}")


def _annulments(d: dict) -> list:
    """Revocations a successor's first directory may drop (PG-CODE.md §9.1)."""
    if "annulled" not in d:
        return []
    if not isinstance(d["annulled"], list):
        raise PregenError("annulled needs a list and steward_compromised_since")
    since = _when(d.get("steward_compromised_since"))
    return [{**a, "since": since} for a in d["annulled"]]


def _annulled_at(annulled: list, field: str, value, at) -> bool:
    return any(a.get(field) == value and _when(at) >= a["since"] for a in annulled)


def _keeps_history(new: dict, previous: dict, annulled=()) -> None:
    for a in previous.get("annulled") or []:
        if a not in (new.get("annulled") or []):
            raise PregenError("an annulment was removed")
    for old in previous["registries"]:
        now = next((r for r in new["registries"] if r["prefix"] == old["prefix"]), None)
        if now is None:
            raise PregenError(f"namespace {old['prefix'] or '(bare)'} was removed")
        for f in old["key_fingerprints"]:
            if f not in now["key_fingerprints"]:
                raise PregenError(f"key {f} was removed from {now['name']}")
        if old.get("revoked") and now.get("revoked") != old["revoked"] \
                and not _annulled_at(annulled, "prefix", old["prefix"], old["revoked"]["at"]):
            raise PregenError(f"the revocation of {old['name']} was undone")
    for f in previous.get("false_claims") or []:
        if f not in (new.get("false_claims") or []):
            raise PregenError(f"the false claim {f.get('code')} was removed")
    for f in previous.get("false_claim_reversals") or []:
        if f not in (new.get("false_claim_reversals") or []):
            raise PregenError(f"the reversal of the false claim {f.get('code')} was removed")
    for f in previous.get("freezes") or []:
        if f not in (new.get("freezes") or []):
            raise PregenError(f"the freeze of {f.get('anchor')} was removed")
    for k in previous.get("revoked_keys") or []:
        if k not in (new.get("revoked_keys") or []) and not _annulled_at(annulled, "key_id", k["key_id"], k["at"]):
            raise PregenError(f"the revocation of key {k['key_id']} was undone")


_DEFAULT = object()


def verify_directory(directory: dict, steward_public_key_hex: str = STEWARD_PUBLIC_KEY_HEX,
                     min_sequence: int = 0, previous=None, pinned_keys=None, origin_key_fingerprints=None,
                     successor_public_key_hex=_DEFAULT, now=None) -> Directory:
    """V-12: accept the directory only with the pinned steward's signature, its invariants,
    a sequence no lower than one already seen and, given the last accepted directory,
    nothing removed from it. No registry is pinned unless you pass pinned_keys."""
    if type(min_sequence) is not int or not 0 <= min_sequence <= _MAX_INT:
        raise PregenError("min_sequence must be a nonnegative integer")
    _check_invariants(directory)
    if successor_public_key_hex is _DEFAULT:
        successor_public_key_hex = (STEWARD_SUCCESSOR_PUBLIC_KEY_HEX
                                    if steward_public_key_hex == STEWARD_PUBLIC_KEY_HEX else None)
    successor_id = fingerprint(successor_public_key_hex) if successor_public_key_hex else None
    by_successor = successor_id is not None and directory["steward_key_id"] == successor_id
    if directory["steward_key_id"] != fingerprint(steward_public_key_hex) and not by_successor:
        raise PregenError("signed by a different steward key")
    signer = successor_public_key_hex if by_successor else steward_public_key_hex
    if not verify_signed(directory, signer, "signature"):
        raise PregenError("bad steward signature")
    prev = previous.to_json() if isinstance(previous, Directory) else previous
    if prev is not None and successor_id is not None and prev["steward_key_id"] == successor_id and not by_successor:
        raise PregenError("the steward key was handed over; directories signed by the old key are refused")
    # Handover: the successor's first directory replaces the old key's line, whatever its sequence
    # (a thief holding the old key may have raised it). Within one key's line the usual rules hold.
    handover = by_successor and (prev is None or prev["steward_key_id"] != successor_id)
    if not handover:
        if directory["sequence"] < min_sequence:
            raise PregenError(f"sequence {directory['sequence']} is older than {min_sequence} already seen")
        if prev is not None:
            _check_continuity(directory, prev)
    elif prev is not None and not _cross_schema(directory, prev):
        # A handover may restart the sequence, never drop a listing or a revocation, except
        # revocations the old key signed after it was compromised, named in `annulled`.
        _keeps_history(directory, prev, _annulments(directory))
    import time
    pins = dict(pinned_keys or {})
    if origin_key_fingerprints is not None:   # deprecated alias: a pin for the bare namespace
        pins.setdefault("", list(origin_key_fingerprints))
    return Directory(directory, _TOKEN, pins, int(time.time()) if now is None else now)


def load_directory(url: str = DIRECTORY_URL, min_sequence: int = 0, get_json=_get_json, previous=None,
                   steward_public_key_hex: str = STEWARD_PUBLIC_KEY_HEX) -> Directory:
    """Download and verify the directory from pregen.org, or from any mirror: the steward's signature is what
    counts. Pass the last accepted one as `previous`. Load it again at least once a day (DIRECTORY_MAX_AGE).
    `steward_public_key_hex` is for testing only: a test directory signed by a test steward key
    (extensions/sandbox.md). Nothing it lists is ever accepted under the real steward key."""
    return verify_directory(get_json(url), steward_public_key_hex, min_sequence=min_sequence, previous=previous)


def verify_decision(decision: dict, code: str, directory: Directory = None, get_json=_get_json) -> bool:
    """Is this registry decision genuine, and signed by a key of the registry that owns `code`?
    Signatures only: use check_decision() before generating."""
    directory = directory or load_directory(get_json=get_json)
    key = directory.public_key(code, (decision or {}).get("operator_key_id"), get_json=get_json)
    return verify_signed(decision, key, "operator_signature")


_ECHOED = ("subject_id", "provider_id", "licensee_id", "prompt_hash", "model", "modality")


_MAX_DECISION_LIFETIME = 900
# PRE-GEN-CORE.md rule 2: reload the directory at least daily. This bounds how long a copy is kept, not how
# old its content is: a stale copy can still hide a newer revocation.
DIRECTORY_MAX_AGE = 86_400
# A proof's occurred_at is the provider's word; the registry-signed received_at bounds it (stress test H1).
REPORT_GRACE = 86_400


def _empty(v) -> bool:
    return v is None or v == "" or v == []


# Members this library knows how to handle: the core (PRE-GEN-SPEC.md §1.1) and the origin
# registry's (PRE-GEN-EXTENSIONS.md X.2). A `critical` member outside this set makes an allow unusable.
_UNDERSTOOD = frozenset({
    "schema_version", "decision_id", "nonce", "disposition", "allowed", "reason", "policy_version", "subject_id",
    "licensee_id", "provider_id", "license_id", "prompt_hash", "model", "modality", "intended_use", "obligations",
    "generation_id", "issued_at", "expires_at", "critical", "operator_key_id", "operator_signature",
    "subject_authority", "rules_text", "rules_text_hash", "watermark_payload", "is_hard_refusal", "revocation_epoch",
    "max_cache_age_seconds", "cache_scope", "provider_user_binding", "provider_identity_link_id", "detection_id",
    "remediation"})


def check_decision(decision: dict, request: dict, directory: Directory = None, get_json=_get_json, now=None,
                   require_verified_authority: bool = False) -> dict:
    """Everything a provider must check before generating on a decision (PRE-GEN-SPEC.md §5.4):
    a genuine signature by the owner of the license's namespace (V-1, V-2, V-10), the decision
    answers exactly this request (V-4), it is within its validity window (V-3), it carries a
    verified user binding when a user was named (V-13), it is a license-backed allow (P-5), its
    registry and key are not revoked (V-14) and it lists no `critical` member this library does
    not understand (E-3). `require_verified_authority` also refuses a subject whose authority is
    not "verified". `request` is what you sent: the /v1/verify body plus provider_id and licensee_id.
    Raises PregenError with the reason; returns the decision when you may generate."""
    import time
    now = int(time.time()) if now is None else now
    if not isinstance(decision, dict) or not isinstance(request, dict):
        raise PregenError("decision and request must be objects")
    if decision.get("allowed") is not True or decision.get("disposition") != "allow":
        raise PregenError(f"not an allow: {decision.get('disposition')}")
    if not isinstance(decision.get("license_id"), str) or not decision["license_id"]:
        raise PregenError("an allow must name its license")
    if "critical" in decision:
        if not isinstance(decision["critical"], list):
            raise PregenError("critical must be a list")
        unknown = [m for m in decision["critical"] if m not in _UNDERSTOOD]
        if unknown:  # E-3
            raise PregenError(f"critical members this library does not understand: {', '.join(map(str, unknown))}")
    if require_verified_authority and decision.get("subject_authority") != "verified":
        raise PregenError(f"the subject's authority is {decision.get('subject_authority') or 'not stated'}, not verified")

    if decision.get("schema_version") != "pg.decision.v1":
        raise PregenError(f"unsupported schema_version: {decision.get('schema_version')}")
    exp, iat = decision.get("expires_at"), decision.get("issued_at")
    if type(exp) is not int or exp <= 0:
        raise PregenError("expires_at must be a positive integer")
    if type(iat) is not int or iat <= 0 or iat >= exp or iat > now + 60:
        raise PregenError("issued_at must be a positive integer before expires_at and not in the future")
    if exp - iat > _MAX_DECISION_LIFETIME:  # PRE-GEN §1.1
        raise PregenError(f"a decision lives at most {_MAX_DECISION_LIFETIME} seconds")
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


def message_id(type_: str, body: dict) -> str:
    """A PRE-GEN v5 message id (PRE-GEN-CORE.md, Messages). Signatures are not part of it."""
    return hashlib.sha256(b"PREGEN-V5-ID\x00" + type_.encode() + b"\x00" + canonical_json(body)).hexdigest()


def signing_input(type_: str, body: dict) -> bytes:
    """The bytes a v5 signature covers: "PREGEN-V5" 0x00 type 0x00 canonical(body) (PRE-GEN-CORE.md, Messages)."""
    return b"PREGEN-V5\x00" + type_.encode() + b"\x00" + canonical_json(body)


def new_private_key_hex() -> str:
    """A new Ed25519 private key: 32 random bytes (the RFC 8032 seed), as hex. Keep it secret, server-side."""
    import os
    return os.urandom(32).hex()


def public_key_hex(private_key_hex: str) -> str:
    """The raw 32-byte public key of an Ed25519 private key (seed), as hex. Its key id is fingerprint() of it."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def sign_envelope(type_: str, body: dict, *private_key_hexes: str) -> dict:
    """A v5 envelope {type, body, signatures}: one signature per private key, in the order of body["signers"]. With
    no key, `signatures` is empty (a request a registry authenticates by its credential)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    data = signing_input(type_, body)
    return {"type": type_, "body": body, "signatures": [
        Ed25519PrivateKey.from_private_bytes(bytes.fromhex(k)).sign(data).hex() for k in private_key_hexes]}


# ── extension provider-identity: a provider known by its domain, with no account anywhere ──────────────

_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]")


def check_provider_url(url, allow_port: bool = False) -> str:
    """A provider URL (extensions/provider-identity.md): `https://` + the app's own domain, lower case, ASCII (an
    IDN in its xn-- form), with no path, query, fragment, credentials, port or trailing dot. One app, one id: no other
    spelling of the domain is an id. A sandbox (allow_port) also takes a port (no leading zero, never 443) and, on
    your own machine, only `<32 hex of the key id>.localhost` (sandbox_provider_url), never a bare `localhost`."""
    if not isinstance(url, str) or not url.startswith("https://"):
        raise PregenError("a provider URL is https://<your domain>")
    u = urlsplit(url)
    host, _, port = u.netloc.partition(":")
    local = allow_port and re.fullmatch(r"[0-9a-f]{32}\.localhost", host)
    if "@" in u.netloc or u.path or u.query or u.fragment or url != "https://" + u.netloc or host == "localhost" \
            or not (_HOST.fullmatch(host) or local) or (port and not (allow_port and re.fullmatch(r"[1-9][0-9]{0,4}", port)
                                                                       and int(port) < 65536 and port != "443")):
        raise PregenError(f"not a provider URL: {url!r} (https://<domain>, lower case, no path, port, query or fragment)")
    return url


def sandbox_provider_url(private_key_hex: str, port: int | None = None) -> str:
    """A test id for a sandbox, on your own machine (provider-identity, Sandboxes): bound to your key, so two people's
    tests never collide. `https://<32 hex of the key id>.localhost[:port]`."""
    if port is not None and (type(port) is not int or not 0 < port < 65536):
        raise PregenError("port is an integer from 1 to 65535")
    host = fingerprint(public_key_hex(private_key_hex)).split(":")[1] + ".localhost"
    return check_provider_url(f"https://{host}" + (f":{port}" if port not in (None, 443) else ""), allow_port=True)


def party_document(provider_url: str, name: str, private_key_hex: str, *, redirect_uris=(), bind_initiate_uri: str = "",
                   policy: str = "", contact: str = "") -> dict:
    """The document a provider serves at `{provider_url}/.well-known/pregen-party.json` (provider-identity): who it is
    and its signing key, as a `first` keyset signed by that key. The same key gives the same document every time, so
    build it at deploy time or on each start. To change the key later, append a `rotation` keyset (provider-keys)."""
    check_provider_url(provider_url, allow_port=True)
    pub = public_key_hex(private_key_hex)
    kid = fingerprint(pub)
    keyset = sign_envelope("pg.keyset.v1", {
        "signers": [{"role": "provider", "key_id": kid}], "kind": "first", "provider_id": provider_url,
        "previous": None, "recovery_registry": "",
        "keys": [{"key_id": kid, "public_key_hex": pub, "status": "current"}]}, private_key_hex)
    doc = {"party_id": provider_url, "name": name, "roles": ["provider"], "keysets": [keyset]}
    if redirect_uris:
        doc["redirect_uris"] = list(redirect_uris)
    if bind_initiate_uri:
        doc["bind_initiate_uri"] = bind_initiate_uri
    if policy:
        doc["policy"] = policy
    if contact:
        doc["contact"] = contact
    return doc


def pg_access(provider_url: str, private_key_hex: str, aud: str, method: str, path: str, now=None) -> str:
    """The `PG-Access` header value for a GET by a provider known by its domain (provider-identity): a `pg.access.v1`
    envelope over {provider_id, aud (the registry's api, from the directory), method, path (with its query string),
    issued_at}, signed with the current key, as base64url. A registry accepts it within 60 seconds of `issued_at`, for
    itself only: a header signed for another registry is refused."""
    import base64
    import time
    kid = fingerprint(public_key_hex(private_key_hex))
    env = sign_envelope("pg.access.v1", {"signers": [{"role": "provider", "key_id": kid}], "provider_id": provider_url,
                                         "aud": aud.rstrip("/"), "method": method.upper(), "path": path,
                                         "issued_at": int(time.time() if now is None else now)}, private_key_hex)
    return base64.urlsafe_b64encode(canonical_json(env)).decode().rstrip("=")


def _registry_signed(env: dict, type_: str, code: str, directory: Directory, get_json) -> dict:
    """A message signed by exactly one registry key that the directory lists for `code`'s prefix
    (core rules 1-2). Returns its body."""
    if not isinstance(env, dict) or env.get("type") != type_ or set(env) != {"type", "body", "signatures"} \
            or not isinstance(env["body"], dict):
        raise PregenError(f"not a {type_} envelope")
    body, sigs = _ints(env["body"]), env["signatures"]
    signers = body.get("signers")
    if not isinstance(signers, list) or len(signers) != 1 or not isinstance(signers[0], dict) \
            or signers[0].get("role") != "registry" or not isinstance(sigs, list) or len(sigs) != 1:
        raise PregenError(f"a {type_} is signed by exactly one registry key")
    key = directory.public_key(code, signers[0].get("key_id"), get_json=get_json,
                               at=body.get("issued_at", body.get("received_at")))
    if not verify_bytes(key, sigs[0], signing_input(type_, body)):
        raise PregenError("bad signature")
    return body


_HEX64 = re.compile(r"[0-9a-f]{64}")


def _check_status_shape(body: dict) -> None:
    """PRE-GEN-CORE.md rule 4: an allow names its basis — a policy rule or a grant — and no reason;
    every other status gives a reason and no basis (schemas/answer.json)."""
    status = body.get("status")
    if status not in ("allow", "deny", "review", "not_blocked"):
        raise PregenError(f"unknown status: {status!r}")
    if status == "allow":
        basis = body.get("basis")
        policy = isinstance(basis, dict) and set(basis) == {"kind", "rule"} and basis["kind"] == "policy" \
            and isinstance(basis["rule"], str) and basis["rule"] != ""
        grant = isinstance(basis, dict) and set(basis) == {"kind", "grant"} and basis["kind"] == "grant" \
            and isinstance(basis["grant"], dict) and {"format", "id"} <= set(basis["grant"]) <= {"format", "id", "license_id"} \
            and isinstance(basis["grant"]["format"], str) and isinstance(basis["grant"]["id"], str) \
            and bool(_HEX64.fullmatch(basis["grant"]["id"]))
        if not (policy or grant):
            raise PregenError("an allow must name its basis: a policy rule or a grant")
        if "reason" in body:
            raise PregenError("an allow carries no reason")
    else:
        if not isinstance(body.get("reason"), str) or body["reason"] == "":
            raise PregenError(f"a {status} answer must give a reason")
        if "basis" in body:
            raise PregenError(f"a {status} answer carries no basis")


# The members an answer body may carry (spec/schemas/answer.json; PRE-GEN-CORE.md: unknown members are rejected).
# A registry's own members go in `ext`.
_ANSWER_MEMBERS = frozenset({"signers", "request_id", "profile", "status", "reason", "basis", "issued_at", "expires_at",
                             "level", "obligations", "ext", "critical"})


def verify_answer(answer: dict, request: dict, directory: Directory = None, get_json=_get_json, now=None,
                  testing: bool = False) -> dict:
    """Is this a genuine, current answer to this request, whatever its status? Everything check_answer()
    checks except that it is an allow and that the steward recorded no false claim on the code (verify_anchors drops
    those per anchor): use it to weigh refusals from several registries (decide_identity).
    Like check_answer(), it compares `profile` only as a name, and nothing about a version of a registry's rules."""
    import time
    now = int(time.time()) if now is None else now
    if not isinstance(request, dict) or request.get("type") != "pg.request.v1" or not isinstance(request.get("body"), dict):
        raise PregenError("request must be the pg.request.v1 envelope you sent")
    asked = request["body"]
    directory = directory or load_directory(get_json=get_json)
    if now - directory.loaded_at > DIRECTORY_MAX_AGE:
        raise PregenError("the directory was loaded more than 24 hours ago: load it again")
    if testing and directory.to_json().get("steward_key_id") in (fingerprint(STEWARD_PUBLIC_KEY_HEX),
                                                                 fingerprint(STEWARD_SUCCESSOR_PUBLIC_KEY_HEX)):
        raise PregenError("testing is for a test directory only: the PRE-GEN steward's directory never accepts a sandbox answer")
    body = _registry_signed(answer, "pg.answer.v1", asked.get("subject_ref"), directory, get_json)
    unknown = sorted(set(body) - _ANSWER_MEMBERS)
    if unknown:
        raise PregenError(f"the answer carries members the core does not define: {', '.join(unknown)}")
    _check_status_shape(body)
    if body.get("request_id") != message_id("pg.request.v1", asked):
        raise PregenError("the answer is for another request")
    if body.get("profile") != asked.get("profile"):
        raise PregenError("the answer is under another profile")
    iat, exp = body.get("issued_at"), body.get("expires_at")
    if type(iat) is not int or type(exp) is not int or not 1 <= exp - iat <= _MAX_DECISION_LIFETIME:
        raise PregenError(f"an answer lives 1 to {_MAX_DECISION_LIFETIME} seconds")
    if iat > now + 60:
        raise PregenError("issued in the future")
    if exp <= now:
        raise PregenError("answer expired")
    ext = body.get("ext") or {}
    if isinstance(ext, dict) and ext.get("sandbox") and not testing:
        raise PregenError("a sandbox answer is accepted only when testing")
    if body.get("critical"):
        raise PregenError(f"critical extensions this library does not understand: {body['critical']}")
    return body


def check_answer(answer: dict, request: dict, directory: Directory = None, get_json=_get_json, now=None,
                 testing: bool = False) -> dict:
    """PRE-GEN-CORE.md rule 5: may I generate on this answer? `request` is the pg.request.v1 envelope you
    sent. Checks that a key the directory lists for the subject's prefix signed it (and is not revoked),
    that it answers exactly this request under the same profile, that it is within its lifetime, that it
    is not a sandbox answer outside testing, that the steward recorded no unreversed false claim on the code under
    any anchor, and that it is an `allow`. `profile` is compared as a name: the
    fixed name of a vocabulary of uses (`likeness/1`), never a version of anyone's policy; nothing that names
    a version, hash or counter of a registry's rules is carried or compared. Raises PregenError with the reason; returns the answer body when you may
    generate. Keep the answer with the output."""
    directory = directory or load_directory(get_json=get_json)
    code = (request.get("body") or {}).get("subject_ref") if isinstance(request, dict) else None
    if isinstance(code, str) and directory.is_false_claim(code):   # identity.md: the steward ruled it false
        raise PregenError(f"{code} is a false claim the steward recorded: never generated")
    body = verify_answer(answer, request, directory, get_json, now, testing)
    if body.get("status") != "allow":
        raise PregenError(f"not an allow: {body.get('status')} {body.get('reason') or ''}".strip())
    return body


# ── extension identity (spec/extensions/identity.md) ─────────────────────────────

# likeness/1 refusals that come from the person, not from a missing licence: across one person's
# registries, any of them refuses for all.
FLOOR_REASONS = frozenset({"PG_SUBJECT_OPTED_OUT", "PG_SUBJECT_UNAVAILABLE", "PG_PROHIBITED_USE",
                           "PG_IMMUTABLE_DENIAL", "PG_PERSONAL_SIGNATURE_REQUIRED"})


def verify_anchors(envelope: dict, prefix: str, directory: Directory, get_json=_get_json, now=None) -> list:
    """A registry's signed anchor list (pg.anchors.v1), checked through the directory and at most a day old, so
    an old copy cannot hide a new opt-out. Returns its entries, each code in its TOG spelling (a PG- line of an older
    list folds by code_key), without those the steward found false under their own anchor (a false claim under
    another anchor silences no one). An entry naming another registry's code is dropped, not the whole list: one
    foreign line must not make the list fail. An entry that is not a person code (unknown shape, mistyped, a licence
    or an event) fails the whole list: dropping it could lose a refusal. A list naming one of its codes twice, in
    either spelling, is refused: its anchor would depend on which line a client read last."""
    import time
    now = int(time.time()) if now is None else now
    # The code only names the prefix, so the directory finds the registry's keys (any prefix length).
    body = _registry_signed(envelope, "pg.anchors.v1", f"TOG-{prefix}-1000000000", directory, get_json)
    entries = body.get("anchors")
    if body.get("registry") != prefix or not isinstance(entries, list) or type(body.get("issued_at")) is not int:
        raise PregenError("not an anchor list of this registry")
    if not -60 <= now - body["issued_at"] <= DIRECTORY_MAX_AGE:
        raise PregenError("the anchor list is more than 24 hours old")
    if not all(isinstance(e, dict) and isinstance(e.get("code"), str) for e in entries):
        raise PregenError("an anchor list entry is {anchor, code, level, proof_url, status}")
    try:
        parsed = [parse_code(e["code"]) for e in entries]
    except PregenError:
        parsed = None
    if parsed is None or any(p["kind"] != "subject" for p in parsed):
        raise PregenError("an anchor list entry of unknown shape fails the whole list: not a person code")
    own = [dict(e, code=p["key"]) for e, p in zip(entries, parsed) if p["issuer"] == prefix]
    if len({e["code"] for e in own}) != len(own):
        raise PregenError("an anchor list names each code once")
    return [e for e in own if not directory.is_false_claim(e["code"], e.get("anchor"))]


def decide_identity(claims: list, allow_unconfirmed: bool = False, frozen=None) -> dict:
    """One public person, held by several registries (spec/extensions/identity.md). `claims` lists, for every
    code the anchor lists name (false claims already removed), {"code", "confirmed", "answer", "settled",
    "refusal_only"}: `confirmed` is whether the person confirmed this code on a current official channel;
    `settled` whether that channel was also official SETTLED_AFTER (7 days) earlier: only a settled claim's allow
    permits, so a fresh Wikidata edit can refuse at once and permit only after a week (missing: not settled);
    `refusal_only` that it still counts, for a refusal of the person only, because its line stands at a channel
    official 7 days earlier and no longer, or you saw it confirmed in the last 7 days and its line is gone (a recent
    refusal survives a channel change); `answer` is the body
    verify_answer() returned for this generation, or None when there is none to weigh: the code's registry gave no
    valid answer, or its anchor list failed (pass the entries of its last verified list with answer None, so a
    broken list blocks only the people it held). Rule: not who came first, but who proved it.
    A subject is a person who confirmed; before that PRE-GEN says nothing either way,
    so an unconfirmed claim neither permits nor refuses (`allow_unconfirmed` no longer permits anything). The
    verdict never depends on the order of the claims. `frozen` is directory.frozen(anchor): while the steward
    freezes the person, the result is deny, PG_SUBJECT_UNAVAILABLE. Returns {"status": "allow" | "deny" | "review" |
    "not_blocked", "reason", "code"}: generate only on "allow". Raises PregenError (no decision: do not generate)
    when a confirmed or refusal-only claim has no answer and no other such claim refuses the person."""
    if frozen is not None and frozen is not False:  # rule 0: a steward freeze decides first, even an empty one
        return {"status": "deny", "reason": "PG_SUBJECT_UNAVAILABLE", "code": None}
    counted = sorted((c for c in claims if c.get("confirmed") or c.get("refusal_only")), key=lambda c: c["code"])
    for c in counted:                    # one person: a refusal of the person in any registry holds everywhere
        a = c.get("answer")
        if a is not None and a.get("status") != "allow" and a.get("reason") in FLOOR_REASONS:
            return {"status": "deny", "reason": a["reason"], "code": c["code"]}
    if any(c.get("answer") is None for c in counted):  # it may hold the person's refusal: unknown is not unconfirmed
        raise PregenError("no decision: a claim the person confirmed has no answer")
    group = [c for c in counted if not c.get("refusal_only")]
    allowed = next((c for c in group if c["answer"].get("status") == "allow" and c.get("settled")), None)
    if allowed:
        return {"status": "allow", "reason": None, "code": allowed["code"]}
    refusals = [c for c in group if c["answer"].get("status") != "allow"]
    if not refusals:                     # nobody confirmed, or only on channels younger than a week
        return {"status": "not_blocked", "reason": "PG_IDENTITY_UNCONFIRMED" if claims else "PG_UNKNOWN_SUBJECT",
                "code": None}
    worst = min(refusals, key=lambda c: _SEVERITY.get(c["answer"].get("status"), len(_SEVERITY)))
    return {"status": worst["answer"].get("status"), "reason": worst["answer"].get("reason"), "code": worst["code"]}


_SEVERITY = {"deny": 0, "review": 1}     # no allow: the strongest refusal, ties by code, never by claim order

# A proof URL or official channel, exactly as written: https, a lower-case ASCII host, no credentials, port, query,
# fragment, percent-escape or dot segment, at most 512 characters, so every client reads the same page (stress B-9, D-1).
_CHANNEL_URL = re.compile(r"https://([a-z0-9.-]{1,253})((?:/(?!\.\.?(?:/|$))[A-Za-z0-9._~@-]+)*/?)")
_WELL_KNOWN = "/.well-known/pregen"


def _channel_url(url):
    m = _CHANNEL_URL.fullmatch(url) if isinstance(url, str) and len(url) <= 512 else None
    return (m.group(1), m.group(2)) if m and _HOST.fullmatch(m.group(1)) else None


def check_channel_proof(code: str, proof_url: str, official_urls: list, get_text, seen_confirmed: bool = False) -> bool:
    """Did the person confirm `code` on an official channel (`official_urls`, for example from
    wikidata_official_urls())? Only two places count, never any other page on the host:
    - an official website ("https://<host>", no path): exactly https://<host>/.well-known/pregen, whose text
      `get_text` returns as a string;
    - an official account ("https://x.com/<handle>" and the like): a post or profile at or below that path, for which
      `get_text` returns {"author": <handle or channel id>, "text": <what the account itself wrote there>} from the
      platform's own record of who wrote it. The author must be the account (letter case aside); a string, a comment
      or another account's post confirms nothing.
    The text must have a line "PRE-GEN: <code>", the whole code in either spelling (code_key), alone or followed by a space and more words; a
    line "PRE-GEN: <code> withdraw <party>" confirms nothing. `proof_url` is taken exactly as written: https, a
    lower-case host, no credentials, port, query, fragment, percent-escape or dot segment, at most 512 characters;
    `get_text` must not follow redirects (treat a 3xx like a 404: return ""). If `get_text` raises (the
    page cannot be read), the claim is unconfirmed, unless `seen_confirmed` (you saw it confirmed at the last check):
    then the error is raised, and you have no decision for this person."""
    p = _channel_url(proof_url)
    account = None
    for o in map(_channel_url, official_urls):
        if not o or o[0] != (p or ("",))[0]:
            continue
        base, path = o[1].rstrip("/"), p[1].rstrip("/")
        if not base and p[1] == _WELL_KNOWN:
            break
        if base and (path == base or path.startswith(base + "/")):
            account = base.rsplit("/", 1)[1].lstrip("@").lower()
            break
    else:
        return False
    try:
        got = get_text(proof_url)
    except Exception:
        if seen_confirmed:
            raise
        return False
    if account is not None:
        author = got.get("author") if isinstance(got, dict) else None
        if not (isinstance(author, str) and re.fullmatch(r"[A-Za-z0-9._-]+", author) and author.lower() == account):
            return False
        got = got.get("text")
    for line in (got if isinstance(got, str) else "").split("\n"):
        words = re.split(r"[ \t]+", line.strip(" \t\r"))
        if words[0] == "PRE-GEN:" and len(words) > 1 and _k(words[1]) == _k(code) and words[2:3] != ["withdraw"]:
            return True
    return False


# Wikidata properties naming a person's own channels (official website, X, Instagram, YouTube channel, TikTok), each
# with the value it must have: anything else is dropped, never repaired (stress B-11).
_OFFICIAL = {"P2002": (r"[A-Za-z0-9_]{1,15}", "https://x.com/{}"),
             "P2003": (r"[A-Za-z0-9_][A-Za-z0-9._]{0,29}", "https://www.instagram.com/{}"),
             "P2397": (r"UC[0-9A-Za-z_-]{22}", "https://www.youtube.com/channel/{}"),
             "P7085": (r"[A-Za-z0-9_][A-Za-z0-9._]{0,23}", "https://www.tiktok.com/@{}")}


def _wd_day(snak):
    """A Wikidata time qualifier as (year, month, day), month and day 0 below that precision; None if it has none."""
    t = ((snak.get("datavalue") or {}).get("value") or {}).get("time") if snak.get("snaktype") == "value" else None
    m = re.fullmatch(r"([+-])0*([0-9]{1,16})-([0-9]{2})-([0-9]{2})T[0-9:]{8}Z", t) if isinstance(t, str) else None
    return m and (int(m.group(2)) * (-1 if m.group(1) == "-" else 1), int(m.group(3)), int(m.group(4)))


def _current(statement, today) -> bool:
    """Not deprecated, not ended (an end time today or before, or an unknown one), not yet to start (stress B-1)."""
    q = statement.get("qualifiers") or {}
    ended = any(s.get("snaktype") != "novalue" and ((_wd_day(s) or today) <= today) for s in q.get("P582", []))
    started = all(s.get("snaktype") != "value" or (_wd_day(s) or (10**17,)) <= today for s in q.get("P580", []))
    return statement.get("rank") != "deprecated" and not ended and started


def wikidata_official_urls(anchor: str, get_json=_get_json, now=None, at=None) -> list:
    """The official channels Wikidata currently lists for an anchor "wikidata:Q…": statements that are not
    deprecated, have not ended and have started, with a value of the property's own form. A website counts by its
    host alone ("https://<host>"): only its /.well-known/pregen can confirm (check_channel_proof).
    Given `at` (Unix seconds, normally now - SETTLED_AFTER), the channels of the item as it stood then, from its
    last revision at or before `at` ([] if the item did not exist yet), current as of that day: a claim is settled
    when its channel is in both lists, and its refusal survives when its line stands at a channel only in this one."""
    import time
    qid = anchor.removeprefix("wikidata:")
    if not re.fullmatch(r"Q[0-9]+", qid):
        raise PregenError("not a wikidata anchor")
    url = f"https://www.wikidata.org/wiki/Special:EntityData/{qid}.json"
    if at is not None:
        now = at = int(at)
        found = get_json("https://www.wikidata.org/w/api.php?action=query&format=json&formatversion=2&prop=revisions"
                         f"&rvprop=ids&rvdir=older&rvlimit=1&titles={qid}&rvstart="
                         + time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(at)))
        pages = (found.get("query") or {}).get("pages")
        page = pages[0] if isinstance(pages, list) and pages and isinstance(pages[0], dict) else None
        if page is None or page.get("missing"):
            raise PregenError(f"wikidata: no entity {qid} (merged or redirected)")
        revs = page.get("revisions")
        if not revs:
            return []                    # no revision at or before `at`: the item had no channels then
        revid = revs[0].get("revid") if isinstance(revs, list) and isinstance(revs[0], dict) else None
        if type(revid) is not int:
            raise PregenError(f"wikidata: no revision of {qid} to read")
        url += f"?revision={revid}"
    entity = (get_json(url).get("entities") or {}).get(qid)
    if not isinstance(entity, dict):
        raise PregenError(f"wikidata: no entity {qid} (merged or redirected)")
    g = time.gmtime(int(time.time()) if now is None else now)
    today, claims, urls = (g.tm_year, g.tm_mon, g.tm_mday), entity.get("claims") or {}, []
    for prop in ("P856", *_OFFICIAL):
        for c in claims.get(prop, []):
            if not isinstance(c, dict):
                continue
            v = ((c.get("mainsnak") or {}).get("datavalue") or {}).get("value")
            if not isinstance(v, str) or not _current(c, today):
                continue
            if prop == "P856":
                m = re.fullmatch(r"https?://([A-Za-z0-9.-]+)(?:[/?#][!-~]*)?", v)
                if m and _HOST.fullmatch(m.group(1).lower()):
                    urls.append("https://" + m.group(1).lower())
            elif re.fullmatch(_OFFICIAL[prop][0], v):
                urls.append(_OFFICIAL[prop][1].format(v))
    return urls


# ── extension terms (spec/extensions/terms.md) ──────────────────────────────────

# likeness/1's closed vocabulary of content categories (spec/profiles/likeness-1.md). A request that accepts a person's
# terms names only these; any other word or spelling is refused, never normalised or passed (stress test TC1, TH1).
CATEGORIES = frozenset({"adult", "advertising", "alcohol", "cannabis", "drugs", "endorsement", "fashion", "financial",
                        "gambling", "health", "political", "religion", "sexual", "tobacco", "violence", "weapons"})
PROHIBITED_FOR_MINORS = frozenset({"sexual", "adult", "violence"})   # never a minor's likeness, whatever the licence
INTIMATE = frozenset({"sexual", "adult"})            # only on a grant the person signs with their own key, never on terms
_PURPOSES = ("personal", "educational", "research", "editorial", "commercial")


def _categories(use) -> set:
    cats = use.get("categories", []) if isinstance(use, dict) else None
    if not isinstance(cats, list) or not all(isinstance(c, str) for c in cats):
        raise PregenError("use.categories is a list of words")
    return set(cats)


def floor(use: dict, minor: bool):
    """likeness/1's fixed protections, which no terms and no licence lift: a minor's likeness in a prohibited category
    gives "PG_PROHIBITED_USE", then any intimate category "PG_PERSONAL_SIGNATURE_REQUIRED". None when neither applies.
    A word outside CATEGORIES matches nothing here: refuse it before."""
    categories = _categories(use)
    if minor is True and categories & PROHIBITED_FOR_MINORS:
        return "PG_PROHIBITED_USE"
    return "PG_PERSONAL_SIGNATURE_REQUIRED" if categories & INTIMATE else None


def forbids(rules: dict, use: dict):
    """The first part of a declared use that a person's rules rule out, or None: a purpose they do not allow, then the
    categories they exclude. An absent `excluded_categories` excludes nothing."""
    if use.get("purpose") not in rules["purposes"]:
        return "purpose " + canonical_json(use.get("purpose")).decode()
    excluded = _categories(use) & set(rules.get("excluded_categories", []))
    return "categories " + canonical_json(sorted(excluded)).decode() if excluded else None


def terms_opens(old, new: dict) -> bool:
    """Whether a version of a person's terms opens anything (rule 5): a first version (`old` is None), a purpose added,
    an exclusion removed, another template, or `minor` going from true to false. A version that opens takes the
    person's own press with a second factor; all else only narrows. `old` and `new` are pg.terms.v1 bodies, or just
    {rules, minor}."""
    if old is None:
        return True
    r, s = old["rules"], new["rules"]
    return bool(set(s["purposes"]) - set(r["purposes"])
                or set(r.get("excluded_categories", [])) - set(s.get("excluded_categories", []))
                or old.get("template") != new.get("template")
                or old.get("minor") is True and new.get("minor") is not True)


_TERMS_MEMBERS = frozenset({"signers", "subject_ref", "profile", "version", "amends", "template", "legal", "rules",
                            "minor", "assent", "instruction", "factor", "issued_at"})
_TEMPLATE_ID = re.compile(r"[a-z0-9-]{1,40}")
_URL = re.compile(r"https://[!-~]{1,2040}")         # printable ASCII, no space (spec/schemas/terms.json)


def _printable(v) -> bool:
    """No control or format character in any member name or string: a zero-width joiner hides inside a word (TC1), and
    a trailing newline slips past a pattern that ends in `$` (TL2)."""
    if isinstance(v, dict):
        return all(_printable(k) and _printable(x) for k, x in v.items())
    if isinstance(v, list):
        return all(_printable(x) for x in v)
    return not isinstance(v, str) or v.isprintable()


def _words(v, vocabulary, at_least=0) -> bool:
    """A sorted list of distinct words from `vocabulary`."""
    return isinstance(v, list) and len(v) >= at_least and all(isinstance(x, str) and x in vocabulary for x in v) \
        and v == sorted(set(v))


def _count(v, low=1) -> bool:
    return type(v) is int and low <= v <= _MAX_INT


def check_terms(env: dict, code: str, directory: Directory = None, get_json=_get_json) -> dict:
    """A person's terms (pg.terms.v1, spec/extensions/terms.md) as their registry published them: signed by exactly one
    key the directory lists for the code's prefix (PM10), for `code` itself (PM1), every member in shape and every
    string printable, `amends` present exactly when it is not the first version, and a first version naming its second
    factor. `assent` is always "registry": the registry's word on the person's authenticated instruction, never the
    person's own key. It shows what was signed, not that this version still stands. Raises PregenError; returns the
    body. Its message id, message_id("pg.terms.v1", body), is what a request accepts in `terms`."""
    directory = directory or load_directory(get_json=get_json)
    b = _registry_signed(env, "pg.terms.v1", code, directory, get_json)
    if _k(b.get("subject_ref")) != _k(code):   # one person, either spelling (TOG-CODE §7.3)
        raise PregenError("these terms are another person's")
    if not _TERMS_MEMBERS - {"amends", "factor"} <= set(b) <= _TERMS_MEMBERS or not _printable(b) \
            or set(b["signers"][0]) != {"role", "key_id"}:
        raise PregenError("not a pg.terms.v1 body: a member missing or unknown, or a control or format character")
    if b["assent"] != "registry" or b["profile"] != "likeness/1":
        raise PregenError("terms are the registry's word under likeness/1 (assent \"registry\")")
    if not _count(b["version"]) or ("amends" in b) != (b["version"] > 1) \
            or "amends" in b and not (isinstance(b["amends"], str) and _HEX64.fullmatch(b["amends"])):
        raise PregenError("a later version names the message id of the one it amends, and a first version names none")
    if b.get("factor", "email") not in ("authenticator", "email") or b["version"] == 1 and "factor" not in b:
        raise PregenError("a first version, and any that opens, names the second factor the registry checked")
    t, legal, rules = b["template"], b["legal"], b["rules"]
    if not (isinstance(b["instruction"], str) and _HEX64.fullmatch(b["instruction"]) and type(b["minor"]) is bool
            and _count(b["issued_at"], 0)
            and isinstance(t, dict) and set(t) == {"id", "version", "jurisdiction"}
            and isinstance(t["id"], str) and _TEMPLATE_ID.fullmatch(t["id"]) and _count(t["version"])
            and isinstance(t["jurisdiction"], str) and re.fullmatch(r"[A-Z]{2}", t["jurisdiction"])
            and isinstance(legal, dict) and set(legal) == {"sha256", "url"}
            and isinstance(legal["sha256"], str) and _HEX64.fullmatch(legal["sha256"])
            and isinstance(legal["url"], str) and _URL.fullmatch(legal["url"])
            and isinstance(rules, dict) and set(rules) == {"purposes", "excluded_categories"}
            and _words(rules["purposes"], _PURPOSES, 1) and _words(rules["excluded_categories"], CATEGORIES)):
        raise PregenError("not a pg.terms.v1 body: instruction, minor, issued_at, template, legal or rules")
    return b


def _terms_finding(item: dict, asked: dict, basis, code: str, directory: Directory, get_json) -> dict:
    """What a proof shows about the terms the provider's signed request accepted: "absent" when it accepted none;
    "unverified" when the record is not carried, not the one accepted, or not validly signed; "outside" when the use
    reaches the floor, names a word outside CATEGORIES, or, on a policy basis, is outside the person's rules (a grant
    decides its own scope); else "ok"."""
    if "terms" not in asked:
        return {"terms": "absent", "terms_assent": None}
    try:
        terms = check_terms(item.get("terms"), code, directory, get_json)
        if message_id("pg.terms.v1", terms) != asked["terms"]:
            raise PregenError("not the terms the request accepted")
    except PregenError:
        return {"terms": "unverified", "terms_assent": None}
    use, policy = asked.get("use"), isinstance(basis, dict) and basis.get("kind") == "policy"
    try:
        out = bool(floor(use, terms["minor"]) or not _categories(use) <= CATEGORIES
                   or policy and forbids(terms["rules"], use))
    except PregenError:
        out = True
    return {"terms": "outside" if out else "ok", "terms_assent": terms["assent"]}


# ── extension proof (spec/extensions/proof.md) ──────────────────────────────────

def _copies_ok(item: dict, answer: dict, code: str) -> bool:
    """proof.md step 3 (TOG-CODE §14): the entry's readable copies `code` and `licence` equal the codes recomputed
    from the signed answer, and the `licence` from the pg.grant.v1 in `grant` whose message id the answer's basis
    names. Flat model: the answer's signer is the registry of the person's prefix. No copy, nothing to check."""
    meta = {m: item[n] for m, n in (("Code", "code"), ("Licence", "licence")) if n in item}
    if not meta:
        return True
    signer = issuer_of(code) or BARE_ISSUER
    basis = answer.get("basis") or {}
    g = basis.get("grant") if basis.get("kind") == "grant" else None
    act = {"type": "pg.answer.v1", "id": message_id("pg.answer.v1", answer), "signer": signer, "subject_ref": code,
           "grant": {"id": g["id"], "signer": signer} if g else None}
    env, licence = item.get("grant"), None
    if g and g.get("format") == "pg.grant.v1" and isinstance(env, dict) and env.get("type") == "pg.grant.v1" \
            and isinstance(env.get("body"), dict) and message_id("pg.grant.v1", _ints(env["body"])) == g["id"]:
        licence = {"type": "pg.grant.v1", "id": g["id"], "signer": signer, "subject_ref": env["body"].get("subject_ref")}
    return metadata_ok(meta, act, licence)


def check_proof(bundle: dict, directory: Directory = None, get_json=_get_json, output_sha256: str = None,
                now=None, testing: bool = False) -> dict:
    """A pg.proof.v1 bundle carried with an output: was every subject of the job allowed at the moment it was
    generated, did each registry acknowledge the provider's report of this output, and (given its SHA-256)
    is it this file? Raises PregenError with the reason; returns {"output_hash", "job_id", "subjects"}. Each subject also
    says what the proof shows about the terms its request accepted (`terms`: "absent", "ok", "outside" or "unverified",
    and `terms_assent`, "registry" for a record that checked out): what was signed, not that those terms still stand.
    A subject's readable copies `code` and `licence` must equal the codes recomputed from its record (TOG-CODE §14)."""
    import time
    now = int(time.time()) if now is None else now
    directory = directory or load_directory(get_json=get_json)
    if now - directory.loaded_at > DIRECTORY_MAX_AGE:
        raise PregenError("the directory was loaded more than 24 hours ago: load it again")
    items = bundle.get("subjects") if isinstance(bundle, dict) and bundle.get("format") == "pg.proof.v1" else None
    if not isinstance(items, list) or not items:
        raise PregenError("not a pg.proof.v1 bundle")
    outputs, jobs, subjects = set(), set(), []
    for it in items:
        req, report = it.get("request"), it.get("report")
        code = (req or {}).get("body", {}).get("subject_ref")
        rbody = (report or {}).get("body")
        if not isinstance(rbody, dict) or report.get("type") != "pg.report.v1":
            raise PregenError("each subject needs its report")
        if isinstance(code, str) and directory.is_false_claim(code):   # identity.md: the steward ruled it false
            raise PregenError(f"{code} is a false claim the steward recorded: never generated")
        # The answer had to be valid when the output was made, not today.
        answer = verify_answer(it.get("answer"), req, directory, get_json, now=rbody.get("occurred_at"), testing=testing)
        if answer.get("status") != "allow":
            raise PregenError(f"{code}: not an allow: {answer.get('status')} {answer.get('reason') or ''}".strip())
        ack = _registry_signed(it.get("ack"), "pg.report_ack.v1", code, directory, get_json)
        if ack.get("report") != message_id("pg.report.v1", rbody) or ack.get("answer") != message_id("pg.answer.v1", answer) \
                or rbody.get("answer") != ack.get("answer") or rbody.get("outcome") != "generated":
            raise PregenError(f"{code}: the registry's acknowledgement does not match this report and answer (one was changed) or names no generation")
        if not _copies_ok(it, answer, code):
            raise PregenError(f"{code}: a readable copy (code, licence) differs from the code computed from its record")
        received = ack.get("received_at")
        if type(received) is not int or received > answer.get("expires_at", 0) + REPORT_GRACE:
            raise PregenError(f"{code}: reported more than 24 hours after the allow expired, so when the output was "
                              "made is only the provider's word")
        outputs.add(rbody.get("output_hash"))
        jobs.add(rbody.get("job_id"))
        subjects.append({"code": code, "level": answer.get("level"), "basis": answer.get("basis"),
                         **_terms_finding(it, req["body"], answer.get("basis"), code, directory, get_json)})
    if len(outputs) != 1 or len(jobs) != 1:
        raise PregenError("the reports are about different outputs")
    output_hash = outputs.pop()
    if output_sha256 is not None and output_sha256 != output_hash:
        raise PregenError("the proof belongs to another file")
    return {"output_hash": output_hash, "job_id": jobs.pop(), "subjects": subjects}


class Simulator:
    """An offline sandbox registry for tests and CI: no network, no secret, throwaway keys.
    Its directory is signed by a throwaway steward key, so nothing it signs is ever accepted
    by the real directory. Answers the documented sandbox subjects:
    sbx-allowed -> allow; sbx-revoked, sbx-expired -> PG_NO_LICENSE; sbx-exhausted ->
    PG_USAGE_LIMIT; sbx-optedout -> PG_SUBJECT_OPTED_OUT; anything else -> PG_NO_SUBJECT.
    Pass `sim.directory` and `sim.get_json` to check_decision."""

    _ANSWERS = {"sbx-allowed": ("allow", None), "sbx-revoked": ("deny", "PG_NO_LICENSE"),
                "sbx-expired": ("deny", "PG_NO_LICENSE"), "sbx-exhausted": ("deny", "PG_USAGE_LIMIT"),
                "sbx-optedout": ("deny", "PG_SUBJECT_OPTED_OUT")}

    def __init__(self, base_url: str = "https://simulator.pregen.invalid"):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        self.base_url = base_url
        self._steward, self._operator = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        pub = lambda k: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        self.operator_public_key_hex = pub(self._operator)
        self._operator_id = fingerprint(self.operator_public_key_hex)
        steward_pub = pub(self._steward)
        body = {"schema": SCHEMA, "sequence": 1, "steward_key_id": fingerprint(steward_pub), "simulator": True,
                "registries": [{"name": "PRE-GEN simulator (not a registry)", "prefix": "TEST", "api": base_url,
                                "keys": base_url + "/keys", "key_fingerprints": [self._operator_id]}]}
        body["signature"] = self._steward.sign(canonical_json(body)).hex()
        self.directory = verify_directory(body, steward_pub, successor_public_key_hex=None,
                                          pinned_keys={"TEST": [self._operator_id]})
        self._decisions, self._receipts, self._n = {}, {}, 0

    def get_json(self, url: str) -> dict:
        if url == self.base_url + "/keys":
            return {"current_key_id": self._operator_id,
                    "keys": [{"key_id": self._operator_id, "public_key_hex": self.operator_public_key_hex, "status": "active"}]}
        raise PregenError(f"not simulated: {url}")

    def verify(self, request: dict, provider_id: str, licensee_id: str = "") -> dict:
        """What POST /v1/verify/ returns, signed by the simulator's throwaway key."""
        import time
        disposition, reason = self._ANSWERS.get(request.get("subject_id"), ("deny", "PG_NO_SUBJECT"))
        self._n += 1
        now = int(time.time())
        named = not _empty(request.get("provider_user_id")) or not _empty(request.get("provider_identity_link_id"))
        body = {"schema_version": "pg.decision.v1", "decision_id": f"sim-{self._n}", "simulator": True,
                "allowed": disposition == "allow", "disposition": disposition, "reason": reason,
                "is_hard_refusal": reason == "PG_SUBJECT_OPTED_OUT",
                "subject_id": request.get("subject_id", ""), "provider_id": provider_id, "licensee_id": licensee_id,
                "license_id": "TOG-LIC-TEST-ZZZZ-0000-001K" if disposition == "allow" else None,
                "prompt_hash": request.get("prompt_hash", ""), "model": request.get("model", ""),
                "modality": request.get("modality", ""), "intended_use": request.get("intended_use", {}),
                "generation_id": request.get("generation_id", ""),
                "provider_user_binding": "verified" if named else "unbound",
                "provider_identity_link_id": request.get("provider_identity_link_id") or ("sim-link" if named else ""),
                "issued_at": now, "expires_at": now + 300, "cache_scope": "not_cacheable",
                "max_cache_age_seconds": 0, "operator_key_id": self._operator_id}
        self._decisions[body["decision_id"]] = body
        return {**body, "operator_signature": self._operator.sign(canonical_json(body)).hex()}

    def receipt(self, receipt: dict, provider_id: str, licensee_id: str) -> tuple:
        """What POST /v1/receipts/ answers, as (HTTP status, body), by PRAMPTA's rules (R-10): a receipt needs an
        allow issued to this pair for the same prompt_hash; the identical receipt again gets the first answer,
        a different one is a conflict. receipt_hash binds the answer to the bytes sent."""
        d = self._decisions.get(receipt.get("decision_id"))
        if not d or d["disposition"] != "allow":
            return 400, {"detail": "No authorized decision found for this decision_id"}
        if d["prompt_hash"] != receipt.get("prompt_hash"):
            return 400, {"detail": "prompt_hash does not match the authorized decision"}
        if (d["provider_id"], d["licensee_id"]) != (provider_id, licensee_id):
            return 403, {"detail": "This decision was not issued to your provider/licensee pair"}
        if not str(receipt.get("output_hash") or "").strip():
            return 400, {"detail": "output_hash is required to identify the reported output"}
        v = receipt.get("schema_version") or receipt.get("v") or "pg.receipt.v2"
        if v not in ("pg.receipt.v2", "pg.receipt.v3"):
            return 400, {"detail": "Unsupported receipt schema version"}
        body = {"v": v, "decision_id": d["decision_id"], "subject_id": d["subject_id"], "licensee_id": licensee_id,
                "provider_id": provider_id, "prompt_hash": receipt["prompt_hash"], "output_hash": receipt["output_hash"],
                "model": receipt.get("model", ""), "obligations_applied": receipt.get("obligations_applied", {}),
                "watermark_embedded": receipt.get("watermark_embedded", False), "generated_at": receipt.get("generated_at", 0)}
        if v == "pg.receipt.v3":
            body["event_type"] = receipt.get("event_type", "output_accepted")
        receipt_hash = hashlib.sha256(canonical_json(body)).hexdigest()
        stored = self._receipts.get(d["decision_id"])
        if stored is not None:
            if stored != receipt_hash:
                return 409, {"detail": {"error": "receipt_conflict",
                                        "error_description": "A different receipt for this decision already exists."}}
            return 200, {"status": "already_recorded", "decision_id": d["decision_id"], "receipt_hash": receipt_hash,
                         "compliant": True, "provider_signature_verified": False}
        self._receipts[d["decision_id"]] = receipt_hash
        return 200, {"schema_version": v, "status": "recorded", "decision_id": d["decision_id"], "receipt_hash": receipt_hash,
                     "compliant": True, "obligation_violations": [], "provider_signature_verified": False,
                     "provider_signed_event_type": False}

    def release(self, decision_id: str, provider_id: str, licensee_id: str) -> tuple:
        """What POST /v1/receipts/{decision_id}/release answers. The sandbox licences have no usage limit, as on
        PRAMPTA, so there is nothing to release; after a receipt it is refused."""
        d = self._decisions.get(decision_id)
        if not d or d["disposition"] != "allow":
            return 404, {"detail": "No authorized decision found for this decision_id"}
        if (d["provider_id"], d["licensee_id"]) != (provider_id, licensee_id):
            return 403, {"detail": "This decision was not issued to your provider/licensee pair"}
        if decision_id in self._receipts:
            return 409, {"detail": {"error": "already_receipted", "error_description": "A receipt says this decision was used."}}
        return 409, {"detail": {"error": "nothing_to_release",
                                "error_description": "This licence has no usage limit; nothing was reserved."}}
