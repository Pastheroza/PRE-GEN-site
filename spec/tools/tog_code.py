#!/usr/bin/env python3
"""ToG code: the reference model of spec/TOG-CODE.md.

Spec: TOG-CODE.md. Vectors: tog_vectors.py writes test-vectors/tog-code.json from this model.
Run: python3 -I spec/tools/tog_code.py   (no dependencies, a few seconds)

The code layer only: grammar, check character, kinds, the TOG spelling (code_key), codes computed from records, the
verdict a verifier may give, offline party checks against a dated directory, prefix admission, the private person's
secret. Signatures and the home chain are out of scope: a code is never proof (TOG-CODE.md section 1).

Event codes put the kind first: TOG-<KIND>-<ISSUER>[-<HOME>]-XXXX-XXXX-XXXX, KIND = PG, AG or LIC; PG and AG carry a
second marker LIC when made under a licence (TOG-PG-LIC-...).

Hard switch (TOG-CODE.md section 1): every code is written TOG- only. A PG-born person is respelled by its marker,
PG-<P>-<serial><check> -> TOG-<P>-<serial><check>, same check. An old licence's code is TOG-LIC, computed from its
signed object's message id like a new one. A PG- string is legacy input only: code_key() folds it to its one TOG
spelling, and nothing here ever returns a PG- string.

Optional cross-check: set PG_CODE_PY to the path of a registry's pg_code.py (with compute_check_char and
format_subject_code) and the self-check compares the check character with it byte for byte.

Software may read from a code: its marker, its kind, and its prefixes with their slot. The first prefix is always the
registry to ask. The tail is never decoded; it is recomputed from a record and compared. Everything else is resolved,
never parsed (PG-CODE.md section 8).
"""
import hashlib
import importlib.util
import itertools
import json
import math
import os
import random
import re
import string
import time
import unicodedata

# ── Alphabets and limits ───────────────────────────────────────────────────────────────────────────────────────────
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"   # PG-CODE section 3, frozen: serials, tails, secrets
VALUES = CROCKFORD + "ILOU"                      # I L O U take 32-35, in TOG bodies only (TOG-CODE.md section 3)
CHECK = CROCKFORD + "*~$=!"                      # PG-CODE section 3.1, frozen; new shapes use CROCKFORD only
MAX_BODY = 36                                    # PG-CODE section 4.2, frozen
MAX_NEW_BODY = 35          # new shapes: at body length 36 the last body character swapped with the check always passes
TAIL = 11                  # 55 bits of a message id; with the check, three groups of 4: XXXX-XXXX-XXXX
SECRET = 26                # 130 bits, beside the code, never in it
KINDS = {"LIC": "license", "PG": "generated", "AG": "approved_after"}   # one word per kind, PG licences included
FIVE = ("PG", "PG-LIC", "AG", "AG-LIC", "LIC")   # five meanings, one spelling each; "-LIC" = made under a licence
KIND_OF_TYPE = {"pg.grant.v1": "LIC", "pg.license.v2": "LIC", "pg.answer.v1": "PG", "pg.after_gen.v1": "AG"}
RESERVED_SERIAL = 900_000_000                    # PG-CODE section 11, unchanged: at or above it, PG or TOG, an example
RESERVED_TAIL = "ZZZZ"                           # examples only: never issued
BARE_ISSUER = "PRAM"       # the bare PG- namespace belongs to the first registry, which also holds PRAM

_C = "0-9A-HJKMNP-TV-Z"
_K = rf"[{_C}*~$=!]"                             # frozen check set (PG shapes)
# TOG prefix: 4-8 of all 26 letters. LIC is never at its start or end, and no 4-letter prefix is LIC with one letter
# added (LxIC, LIxC): one inserted or deleted letter can then never turn the marker LIC into a prefix or back.
_P = "(?!LIC|L[A-Z]IC(?![A-Z])|LI[A-Z]C(?![A-Z]))[A-Z]{4,8}(?<!LIC)"
_OLDP = "[A-HJKMNP-TV-Z]{4}"                     # PG prefix, frozen
_SERIAL_TOG = r"[1-9][0-9]{8}"                   # exactly 9 digits: a dropped or doubled digit is malformed
_SERIAL_PG = r"[0-9]{6,}"                        # frozen 6*DIGIT, unchanged
_SERIAL_OLD = r"[0-9]{6,7}"     # a respelled PG-born person under a prefix: no prefixed PG person had 8 or more digits

SHAPES = (  # (shape, marker, kind, regex). Exactly one matches any valid code; the self-check proves it.
    ("person", "TOG", "subject", re.compile(rf"TOG-({_P})-({_SERIAL_TOG})([{_C}])")),
    ("event", "TOG", None, re.compile(rf"TOG-(LIC|(?:PG|AG)(?:-LIC)?)-({_P})(?:-({_P}))?"
                                      rf"-([{_C}]{{4}}-[{_C}]{{4}}-[{_C}]{{3}})([{_C}])")),
    # PG-born persons, respelled by the marker only (hard switch): same body, same check, the serial keeps its length.
    ("old_person", "TOG", "subject", re.compile(rf"TOG-({_OLDP})-({_SERIAL_OLD})({_K})")),
    ("old_bare_person", "TOG", "subject", re.compile(rf"TOG-()({_SERIAL_PG})({_K})")),
    ("old_no_check", "TOG", "subject", re.compile(r"TOG-(STD|SUB)-([0-9]{6,})")),   # the only two ever issued
    # PG shapes: legacy input only (old signed records, printed cards, typed). Folded by code_key, never written.
    ("pg_person", "PG", "subject", re.compile(rf"PG-({_OLDP})-({_SERIAL_PG})({_K})")),
    ("pg_licence", "PG", "license", re.compile(rf"PG-({_OLDP})-([A-Z]{{3}})-({_SERIAL_PG})-([{_C}]{{6}})({_K})")),
    ("bare_person", "PG", "subject", re.compile(rf"PG-()({_SERIAL_PG})({_K})")),
    ("bare_licence", "PG", "license", re.compile(rf"PG-()([A-Z]{{3}})-({_SERIAL_PG})-([{_C}]{{6}})({_K})")),
    ("no_check", "PG", "subject", re.compile(r"PG-([A-Z]{3})-([0-9]{6,})")),   # PG-STD-/PG-SUB-, PG-CODE 2.1
)
# Verbatim from packages/verify-py/pregen/__init__.py 0.13.0: old verifiers must refuse every TOG code.
PUBLISHED_RE = re.compile(rf"PG-(?:([ABCDEFGHJKMNPQRSTVWXYZ]{{4}})-)?(?:[0-9]{{6,}}{_K}"
                          rf"|[A-Z]{{3}}-[0-9]{{6,}}-[0-9A-HJKMNP-TV-Z]{{6}}{_K})|PG-[A-Z]{{3}}-[0-9]{{6,}}")
# Free text (captions, pages, transcripts): a marker never follows a letter, digit or dash. Candidates, then parse().
FIND_RE = re.compile(r"(?<![A-Za-z0-9-])(?:TOG|PG)-[A-Z0-9]+(?:-[A-Z0-9]+)*[*~$=!]?(?![A-Za-z0-9])")


class NotACode(ValueError):
    """Malformed: not a code at all (resolver 400 invalid_format). Never repaired in a message."""


class Mistyped(ValueError):
    """The grammar matches, the check character does not (resolver 400 mistyped, distinct from not found)."""


class AskRegistry(ValueError):
    """An old PG licence id with no record at hand: only its registry knows its TOG-LIC code."""


# ── Check character: the frozen algorithm ──────────────────────────────────────────────────────────────────────────
def check_char(body: str, values: str = VALUES) -> str:
    """PG-CODE 4.1: sum of value x 1-based position, mod 37. Byte-identical to pg_code.compute_check_char on every
    Crockford body (self-check 1). The TOG table (I L O U = 32-35) is a second table, never pg_code's own."""
    if len(body) > MAX_BODY or any(c not in values for c in body):
        raise NotACode("body too long or outside the alphabet")
    return CHECK[sum(values.index(c) * (i + 1) for i, c in enumerate(body)) % 37]


def _verifies(body: str, chk: str, values: str) -> bool:
    try:
        return check_char(body, values) == chk
    except NotACode:
        return False


def event_body(kind: str, issuer: str, home: str, tail: str) -> str:
    """Two length digits (issuer, home; 0 for no home), one kind digit (1-5, FIVE order), then issuer, home and tail
    without dashes. A relabel (PG, PG-LIC, AG, AG-LIC, LIC) changes only the kind digit: one substitution at a fixed
    position, always caught. A dash moved, dropped or added between issuer and home leaves the letters as they are
    and changes only the two length digits: moved by k, the sum moves by k; dropped, by -len(home) (4 to 8); added,
    the reverse. Never 0 mod 37, so it is always caught. Every other dash is fixed by the grammar. At most 30 symbols."""
    return f"{len(issuer)}{len(home or '')}{FIVE.index(kind) + 1}{issuer}{home or ''}{tail}"


def spell(kind: str, issuer: str, home: str, tail: str, chk: str) -> str:
    """The one spelling: kind first, then issuer, home if shown, then tail and check in three groups of 4."""
    t = tail + chk
    return f"TOG-{kind}-{issuer}{'-' + home if home else ''}-{t[:4]}-{t[4:8]}-{t[8:]}"


# ── Parsing ────────────────────────────────────────────────────────────────────────────────────────────────────────
def parse(code: str, check: bool = True) -> dict:
    """The one reading of a code exactly as it stands in a message: no trimming, case change or folding.
    check=False reads the shape only (routing, as 0.13 issuer_of does); it never says a code is real."""
    if not isinstance(code, str) or not code.isascii():
        raise NotACode("not an ASCII string")
    hits = [(s, mk, k, m) for s, mk, k, rx in SHAPES if (m := rx.fullmatch(code))]
    if len(hits) != 1:
        raise NotACode(code)
    shape, marker, kind, m = hits[0]
    g = m.groups()
    out = {"shape": shape, "marker": marker, "kind": kind, "home": None, "key": code if marker == "TOG" else None}
    if marker == "PG" and kind == "subject":
        # Legacy input: the person's one spelling is TOG- + the rest. A PG person string with no valid TOG spelling
        # (8 or more digits under a prefix, a 9-digit one with a symbol check or a leading zero, a class never
        # issued) was never issued in any spelling: not a code.
        if check and shape != "no_check" and not _verifies(g[0] + g[1], g[2], CROCKFORD):
            raise Mistyped(code)
        if check and not _valid("TOG" + code[2:]):
            raise NotACode("never issued in any spelling")
        out["key"] = "TOG" + code[2:]
    if shape in ("no_check", "old_no_check"):
        return dict(out, issuer="", cls=g[0], serial=g[1], example=False)
    if shape == "event":
        kind, issuer, home, tail, chk = g
        tail = tail.replace("-", "")
        if home == issuer:
            raise NotACode("a registry is written once")
        if check and not _verifies(event_body(kind, issuer, home, tail), chk, VALUES):
            raise Mistyped(code)
        basis = None if kind == "LIC" else "licence" if kind.endswith("-LIC") else "terms"
        return dict(out, kind=KINDS[kind[:3].rstrip("-")], basis=basis, issuer=issuer, home=home,
                    example=tail.startswith(RESERVED_TAIL))
    prefix, *rest, chk = g
    values = VALUES if marker == "TOG" else CROCKFORD   # a PG body outside Crockford never verifies (frozen)
    if check and not _verifies(prefix + "".join(rest), chk, values):
        raise Mistyped(code)
    serial = rest[-1] if kind == "subject" else rest[1]
    return dict(out, issuer=prefix, cls="", serial=serial, example=int(serial) >= RESERVED_SERIAL)


def _valid(s: str) -> bool:
    try:
        parse(s)
        return True
    except (NotACode, Mistyped):
        return False


def code_key(code: str, licences: dict = None) -> str:
    """The one TOG spelling. Every comparison, hash key, pointer-log key and refusal check uses it, so one person never
    has two chains and a refusal cannot be bypassed by spelling. A TOG code is its own key. A PG person folds by its
    marker (same check). An old PG licence folds through its registry's record: licences = {old id: the signed
    pg.license.v2 object, whose `license_id` is that id}; its key is code_for() of that object, a TOG-LIC code from the
    message id, exactly like a new licence. Never returns a PG- string."""
    p = parse(code)
    if p["key"]:
        return p["key"]
    rec = (licences or {}).get(code)
    if rec is None or rec.get("license_id") != code:
        raise AskRegistry(code)
    return code_for(rec)


def kind_of(code: str) -> str:
    return parse(code)["kind"]


def issuer_of(code: str) -> str:
    """The registry to ask: always the first prefix ('' for the bare legacy namespace). Shape only, as published."""
    return parse(code, check=False)["issuer"]


def describe(code: str) -> str:
    """What the string claims. Never shown beside a video: party names come only from a record that fits the file."""
    p = parse(code)
    home = f" · home {p['home']}" if p["home"] else ""
    basis = {"licence": " under a licence", "terms": " under the person's terms"}.get(p.get("basis"), "")
    ex = " · EXAMPLE, never issued" if p["example"] else ""
    if p["marker"] == "PG":
        ex += f" · old spelling of {p['key']}" if p["key"] else " · old licence number: its registry gives its TOG code"
    return f"claims {p['kind']}{basis} · issued by {p['issuer'] or 'the bare legacy namespace'}{home} · not checked{ex}"


def find_codes(text: str) -> list:
    """Every well-formed code in free text, as it stands there. A marker inside a word (TOG-SHOPG-9...) is not a code.
    A PG- string found is legacy input: pass it through code_key before comparing or showing it."""
    found = (c if _valid(c) else c[:-1] for c in FIND_RE.findall(text))   # '*' may be markup, not a check
    return [c for c in found if _valid(c)]


# ── Minting ────────────────────────────────────────────────────────────────────────────────────────────────────────
def person_code(prefix: str, serial: int) -> str:
    code = f"TOG-{prefix}-{serial}{check_char(prefix + str(serial))}"
    parse(code)                       # raises if the width is wrong or the check is a symbol
    return code


def mint_person(prefix: str, taken: set, rng=random.SystemRandom()) -> str:
    """A new person: a random unused 9-digit serial below the reserved block. Gaps carry no information, nothing to
    walk, no registration order. Serials whose check would be a symbol are skipped (about 1 in 7)."""
    while True:
        s = rng.randrange(100_000_000, RESERVED_SERIAL)
        if s not in taken and check_char(prefix + str(s)) in CROCKFORD:
            taken.add(s)
            return person_code(prefix, s)


def tail_of(message_id_hex: str) -> str:
    """The first 55 bits of a SHA-256 message id, as 11 Crockford symbols, most significant first."""
    if not re.fullmatch(r"[0-9a-f]{64}", message_id_hex):
        raise ValueError("a message id is 64 lowercase hex")
    n = int(message_id_hex, 16) >> (256 - 5 * TAIL)
    return "".join(CROCKFORD[(n >> (5 * (TAIL - 1 - i))) & 31] for i in range(TAIL))


def event_code(kind: str, issuer: str, home: str = None, message_id: str = None, tail: str = None) -> str:
    """kind is one of FIVE. `home` equal to `issuer`, or None, gives one prefix. `tail` directly only for examples."""
    home = None if home == issuer else home
    if message_id is not None:
        tail = tail_of(message_id)
        if tail.startswith(RESERVED_TAIL):
            raise ValueError("reserved tail: re-sign with a new nonce")
        if check_char(event_body(kind, issuer, home, tail)) not in CROCKFORD:
            raise ValueError("symbol check: re-sign with a new nonce")
    code = spell(kind, issuer, home, tail, check_char(event_body(kind, issuer, home, tail)))
    parse(code)
    return code


class Home:
    """Every tail is the message id of an object the home signed (its cosign, or the act itself), so the home sees
    every tail of its people and refuses one it has already used, under any kind. Its set is kept for life."""

    def __init__(self, prefix):
        self.prefix, self.tails = prefix, set()

    def sign(self, message_id):
        t = tail_of(message_id)
        if t in self.tails:
            raise ValueError("duplicate tail: re-sign with a new nonce")
        self.tails.add(t)
        return message_id


def issue(code: str, issued: set) -> str:
    """The issuer refuses a code it has already issued (the home re-countersigns with a new nonce). Needed at 55 bits:
    with the home hidden, the tails of two different homes can meet under one issuer, and the home sees only its own."""
    if code in issued:
        raise ValueError("duplicate code: ask the home to countersign again")
    issued.add(code)
    return code


def person_key(code: str) -> tuple:
    """What a registry looks a person up by: (issuer, legacy class, number). Not a spelling: records and lists carry
    the TOG spelling; this only lets a registry see that a request used an over-padded number of one person."""
    p = parse(code)
    if p["kind"] != "subject":
        raise ValueError("not a person code")
    return p["issuer"], p["cls"], int(p["serial"])


def registry_answer(asked: str, issued: dict) -> str:
    """issued = {person_key: the TOG spelling}. The TOG spelling, or its PG legacy input (same code_key), is found and
    answered in TOG. An over-padded number (PG-STD-0000123) gets PG_MALFORMED with the TOG spelling as a hint, never
    a signed answer. A miss costs the same time as a hit (no timing oracle)."""
    hit = issued.get(person_key(asked))
    if hit is None:
        return "not_found"
    return f"found {hit}" if code_key(asked) == hit else f"PG_MALFORMED hint={hit}"


# ── Typed input (never inside a message) ───────────────────────────────────────────────────────────────────────────
_DASHES = dict.fromkeys(map(ord, "‐‑‒–—―−﹣"), "-")
_DROP = dict.fromkeys(map(ord, "­​‌‍⁠﻿\\"))
_FOLD = str.maketrans("АВСЕНІКМОРТХаеорсхіктмΑΒΕΗΙΚΜΝΟΡΤΧΥΖ", "ABCEHIKMOPTXAEOPCXIKTMABEHIKMNOPTXYZ")  # non-exhaustive
_AS_DIGIT = str.maketrans("OIL", "011")
MAX_READINGS = 4096        # 12 typed 1s in the prefixes; more is refused, not searched (the readings grow as 2^n)


def _group_variants(g: str, letters: bool = True) -> set:
    """The group as typed, read with digits (serial, tail), and, for a group that can be a marker or a prefix, every
    per-character reading of 0 as O and 1 as I or L (T11U can be TILU), and L1C, LlC, 1IC read as the marker LIC.
    The three tail groups of a TOG event get the digit reading only. The check picks one reading, or none."""
    out = {g, g.translate(_AS_DIGIT)}
    if letters and len(g) <= 8 and set(g) <= set(string.ascii_uppercase + "01"):
        out |= {"".join(x) for x in itertools.product(*("IL" if c == "1" else "O" if c == "0" else c for c in g))}
    if letters and re.fullmatch("[1IL]{2}C", g):
        out.add("LIC")
    return out


def normalize_typed(typed: str, licences: dict = None) -> str:
    """Where a person types, pastes or scans: returns the one code meant, in its TOG spelling, for a 'Did you mean
    ...?' prompt. Folds width, dashes, invisibles, look-alikes, case, display spaces, a resolver URL, trailing
    punctuation, then O/0 and I/L/1 by slot, then the old PG spelling (code_key). Raises NotACode if no reading, or
    more than one, is a valid code; AskRegistry for an old licence id whose record is not at hand."""
    s = unicodedata.normalize("NFKC", typed).translate(_DASHES).translate(_DROP).translate(_FOLD).strip()
    if "/" in s:
        s = s.split("#")[0].rstrip("/").rsplit("/", 1)[-1]
    s = s.rstrip(".,;:)]\"'").upper()
    if "-" in s:
        groups = ["".join(x.split()) for x in s.split("-")]
    elif s.split() and s.split()[0] in ("PG", "TOG"):          # PG-CODE 13 display form 'PG 000 042 *'
        groups = s.split()
        groups = [groups[0], "".join(groups[1:])] if len(groups) > 2 and not groups[1].isalpha() else groups
    else:
        groups = [s]
    tail_from = len(groups) - 3 if "TOG" in _group_variants(groups[0]) and len(groups) >= 6 else len(groups)
    readings = [_group_variants(g, i < tail_from) for i, g in enumerate(groups)]
    if math.prod(map(len, readings)) > MAX_READINGS:
        raise NotACode("too many readings: type the code again")
    found = set()
    for combo in itertools.product(*readings):
        if _valid(c := "-".join(combo)):
            try:
                found.add(code_key(c, licences))          # PG-ZYXW-1234567R and TOG-ZYXW-1234567R: one reading
            except AskRegistry:
                found.add(c)                              # an old licence id: only its registry knows its code
    if len(found) > 1:
        raise NotACode(f"ambiguous: {sorted(found)}")    # both readings are the hints
    if not found:
        parse("-".join(groups))                           # the honest error for the string as typed
        raise NotACode(typed)
    if (c := found.pop()).startswith("PG-"):
        raise AskRegistry(c)
    return c


# ── The private person's secret (beside the code, never in it, never on a shareable surface) ──────────────────────
def mint_secret(random_bytes: bytes = None) -> str:
    while True:
        n = int.from_bytes(random_bytes or os.urandom(17), "big") >> (17 * 8 - 5 * SECRET)
        body = "".join(CROCKFORD[(n >> (5 * (SECRET - 1 - i))) & 31] for i in range(SECRET))
        if check_char(body) in CROCKFORD:
            return body + check_char(body)
        random_bytes = None


def secret_ok(s: str) -> bool:
    return bool(re.fullmatch(rf"[{_C}]{{{SECRET + 1}}}", s)) and check_char(s[:-1]) == s[-1]


def card_qr(resolver: str, code: str) -> str:
    """Every shareable surface (card image, card QR, NFC tap, receipt): the steward's neutral resolver, code only."""
    return f"{resolver}/v2/codes/{code_key(code)}"


def recovery_qr(resolver: str, code: str, secret: str) -> str:
    """The paper recovery sheet and the wallet only. The fragment never reaches a server."""
    return card_qr(resolver, code) + f"#s={secret}"


# ── Codes against records (offline, no keys) ───────────────────────────────────────────────────────────────────────
def code_for(act: dict) -> str:
    """Computed from an act, never read off a code. act = {type, id, signer, subject_ref, cosign?, grant?}.
    cosign = the home's pg.home_cosign.v1: {id, home, home_in_code}. grant = the licence the act was made under,
    {id, signer}: it adds the marker LIC; its number stays in the record, never in the code. An old pg.license.v2 is a
    licence act like pg.grant.v1; its id is grants.md's SHA-256 over body, subject signature and its PG id; with no
    countersignature it is the flat model, and if that gives a symbol check or a reserved tail the home countersigns
    it once (the licence itself is never re-signed). Kind from the act type,
    issuer = the signer, home and tail from the cosign. With no cosign (the flat model), the signer must be the
    registry the person's code was born at, and the tail is the act's own id."""
    kind = KIND_OF_TYPE[act["type"]]
    grant = act.get("grant")
    if grant:
        if kind == "LIC" or grant["signer"] != act["signer"]:
            raise ValueError("a licence has no basis; the grant behind an act is signed by the act's own signer")
        kind += "-LIC"
    cs = act.get("cosign")
    if cs is None:
        if (issuer_of(act["subject_ref"]) or BARE_ISSUER) != act["signer"]:
            raise ValueError("no home countersignature: only the person's own registry may sign alone")
        return event_code(kind, act["signer"], None, message_id=act["id"])
    home = cs["home"] if cs.get("home_in_code") else None
    return event_code(kind, act["signer"], home, message_id=cs["id"])


def _same(a: str, b: str) -> bool:
    """One code, compared by its TOG spelling: a caption and an old signed record may spell one person differently."""
    try:
        return code_key(a) == code_key(b)
    except (NotACode, Mistyped, AskRegistry):
        return False


def matches(code: str, act: dict) -> bool:
    try:
        return code_for(act) == code
    except (KeyError, ValueError):
        return False


COVERS = " It covers the named person only, and says nothing about anyone else in the file."
WORDS = {
    "no record": "No record. This says nothing either way.",
    "other file": "This code belongs to a different file. It does not show that this video is allowed.",
    "code differs": "The code does not match its record.",
    "example": "Example code from the specification. Never issued.",
    "mistyped": "Mistyped code.",
    "not a code": "Not a code.",
    "edit claim": "An editor states this was made from an approved file. Only the editor says so.",
}


def verdict(file_hash: str, act: dict = None, caption: str = None, ingredient: str = None) -> str:
    """What a verifier may say before signatures and V-H. The act comes from the file (C2PA) or from ?media=; the
    caption is checked against it, never the other way round. file_hash and act['media_hash'] are media/1 hashes.
    No party name is ever shown unless the act fits the file and the chain verifies.
    ingredient = the media/1 hash an edited file's C2PA manifest cites: only the editor's claim, since anyone holding
    the real file can cite it (or provide it). It names no one, so it gets no coverage line. More needs an AG record."""
    p = None
    if caption is not None:
        try:
            p = parse(caption)
        except Mistyped:
            return WORDS["mistyped"]
        except NotACode:
            return WORDS["not a code"]
        if p["example"]:
            return WORDS["example"]
    if act is None:
        if p is None:
            return WORDS["no record"]
        if p["shape"] != "event" or p["kind"] == "license":
            return f"This code names a {p['kind']}. It says nothing about this file."
        return "Unchecked: no record at hand. This says nothing either way."
    edit = False
    if act.get("media_hash") != file_hash:
        if ingredient is None or ingredient != act.get("media_hash"):
            return WORDS["other file"]
        edit = True
    if p is not None and not (matches(caption, act) if p["shape"] == "event" else _same(caption, act["subject_ref"])):
        return WORDS["code differs"]
    try:
        kind = KINDS[KIND_OF_TYPE[act["type"]]]
        code_for(act)
    except (KeyError, ValueError):
        return WORDS["code differs"]
    if edit:
        return WORDS["edit claim"]
    return f"fits: {kind}; now verify signatures and the chain (V-H)." + COVERS


def metadata_ok(meta: dict, act: dict, licence: dict = None) -> bool:
    """The readable copies beside the signed record in a file (TOG-CODE.md section 14): pgag:Code and pgag:Licence in
    the AFTER-GEN XMP, the same two values in the proof's C2PA assertion org.pregen.proof. meta = {"Code", "Licence"},
    either may be absent. Copies, never authority: both are recomputed from the signed record, and any mismatch
    refuses the file. act["grant"] stands for basis {kind: licence, licence, use}, no grant for basis {kind: terms,
    terms}; `licence` is the pg.grant.v1 the basis names. A Licence copy without a licence basis is a mismatch."""
    try:
        want = {"Code": code_for(act), "Licence": None}
        if act.get("grant") and licence is not None and licence["id"] == act["grant"]["id"]:
            want["Licence"] = code_for(licence)
    except (KeyError, ValueError):
        return False
    return all(want[k] is not None and want[k] == v for k, v in meta.items() if k in want)


# ── The dated directory ────────────────────────────────────────────────────────────────────────────────────────────
def _held(span, at) -> bool:
    return span is not None and (at is None or (span[0] <= at and (span[1] is None or at < span[1])))


def check_parties(code: str, directory: dict, at: int = None, provider: str = None) -> tuple:
    """(ok, facts) from a well-formed string and the signed directory, read at `at` (the witnessed checkpoint time of
    the record's bundle) or, with no record, at no time. A string is never 'not a code' because of a party: a
    revoked, closed or re-roled party is a fact. ok is False only if a slot names an unlisted party, a party without
    the slot's role at `at`, or a party whose listing was void at `at`. For support tools, never beside a video."""
    p = parse(code)
    if p["shape"] != "event":
        slots = [("issuer", p["issuer"] or BARE_ISSUER, ())]
    elif p["home"]:
        slots = [("issuer", p["issuer"], ("market",)), ("home", p["home"], ("home",))]
    else:
        slots = [("issuer", p["issuer"], ("market",) if p["kind"] == "license" else ("home", "market"))]
    ok, facts = True, []
    for slot, prefix, roles in slots:
        e = directory.get(prefix)
        if e is None or ("GOV" in prefix) != e.get("government", False):
            ok = False
            facts.append(f"! {prefix} is not a listed registry")
            continue
        if roles and not any(_held(e["roles"].get(r), at) for r in roles):
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
    listed = [directory[x] for _, x, _ in slots if x in directory]
    if len(listed) == 2 and listed[0]["group"] == listed[1]["group"]:
        facts.append("issuer and home are one group")
    for _, x, _ in slots:
        if provider and x in directory and provider in directory[x].get("provider_domains", ()):
            facts.append(f"{x} also generated it ({provider})")
    return ok, facts


# ── Prefix admission (the steward) ─────────────────────────────────────────────────────────────────────────────────
_SKELETON = str.maketrans("CGQDJLVNRF", "OOOOIIUMPE")   # visual groups: CGOQD, IJL, UV, MN, PR, EF
RESERVED_WORDS = (  # refused anywhere in a prefix, after folding: protocol, role, verdict, authority, sensitive words
    "PREGEN", "AFTERGEN", "TOGCODE", "STEWARD", "HOME", "MARKET", "BRANCH", "PROVIDER", "WALLET",
    "ALLOW", "APPROV", "AUTHORI", "VERIF", "VALID", "LEGAL", "LAWFUL", "LICENS", "OFFICIAL", "CERTIF", "GENUIN",
    "NOTFAKE", "TRUST", "DENIED", "DENY", "REFUS", "REVOK", "BLOCK", "BANNED", "POLICE", "COURT", "STATE",
    "ADULT", "PORN", "NSFW", "XXX", "EROTIC", "NUDE")
FIXTURES = ("NWRD", "HLWD", "USAD", "VELR", "SKAN", "KAST", "TGOV", "HYBR", "OMNI", "KINO",
            "KOBEMK", "LYONMK", "RIOMKT", "PUNEMK", "OSLOMK", "ZYXW", "ABCD", "TEST")   # reserved forever


def _skeleton(s: str) -> str:
    return s.replace("VV", "W").replace("RN", "M").replace("CL", "D").translate(_SKELETON)


def _osa(a: str, b: str) -> int:
    d = [[i + j if i * j == 0 else 0 for j in range(len(b) + 1)] for i in range(len(a) + 1)]
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] != b[j - 1]))
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def admission_refusal(new: str, entity: str, government: bool, directory: dict, reserved=FIXTURES) -> str:
    """'' if the steward may list `new` for this legal entity, else the reason. Human judgement (marks of others,
    offensive words, sensitive categories in other words) comes on top."""
    if not re.fullmatch(_P, new):
        return "4 to 8 letters A-Z, never LIC at either end, never LIC with one letter added"
    if new in directory or new in reserved:
        return "taken or reserved: a prefix is never reassigned"
    if government != ("GOV" in new):
        return "GOV is for governments, and governments hold only prefixes with GOV"
    sk = _skeleton(new)
    if not government and "OOU" in sk:
        return "looks like GOV"
    # The kind test with the visual groups of _skeleton: T + O-group + C/G/Q, P/R + C/G/Q, A + C/G/Q, I/J/L twice + C/G/Q
    # (TQGAB, TOCAB, PCLIC, ACLIC, LJCA). The last letter is C, G or Q only, so TGOV and PORTO stay admissible.
    # The marker LIC and its look-alikes also never end a prefix (NLJC) or make up 4 letters with one added (LJGA):
    # one indel could otherwise move the marker into a prefix and change the kind.
    if re.match("T[OQCGD][CGQ]|[PRA][CGQ]|[IJL]{2}[CGQ]", new) or re.search("[IJL]{2}[CGQ]$", new) \
            or len(new) == 4 and re.search("[IJL].?[IJL].?[CGQ]", new) or new.endswith(("PG", "TOG")):
        return "reads as a marker or a kind"
    if any(_skeleton(w) in sk for w in RESERVED_WORDS):
        return "contains a reserved word"
    if any(e["entity"] == entity for e in directory.values()):
        return "one prefix per legal entity"
    for old in directory:
        so = _skeleton(old)
        if _osa(new, old) <= 1 or _osa(sk, so) <= 1 or so in sk or sk in so:   # one edit before or after folding
            return f"too close to {old}"
    return ""


# ── Fixtures and examples (every code printed in TOG-CODE.md) ────────────────────────────────────────────────────
def _ex_person(prefix: str, start: int) -> str:
    s = start
    while check_char(prefix + str(s)) not in CROCKFORD:
        s += 1
    return person_code(prefix, s)


def _ex(kind, issuer, home=None, label=""):
    label = label or f"{kind}{issuer}{home}"
    while True:
        tail = RESERVED_TAIL + tail_of(hashlib.sha256(label.encode()).hexdigest())[:TAIL - len(RESERVED_TAIL)]
        if check_char(event_body(kind, issuer, home, tail)) in CROCKFORD:
            return event_code(kind, issuer, home, tail=tail)
        label += "'"


ALWAYS = (0, None)
DIRECTORY = {  # test fixtures except PRAM; roles as in TOG-CODE.md section 9.2; spans (from, until)
    "PRAM": {"roles": {"home": ALWAYS, "market": ALWAYS}, "entity": "PRAMPTA Inc.", "group": "g1"},
    "NWRD": {"roles": {"market": ALWAYS}, "entity": "Newroad", "group": "g2"},
    "HLWD": {"roles": {"market": ALWAYS}, "entity": "Hollywood market", "group": "g3"},
    "USAD": {"roles": {"market": ALWAYS}, "entity": "US ads market", "group": "g4"},
    "VELR": {"roles": {"market": ALWAYS}, "entity": "18+ market (per-use grants only)", "group": "g5"},
    "SKAN": {"roles": {"home": ALWAYS, "market": ALWAYS}, "entity": "Skan", "group": "g6"},
    "KAST": {"roles": {"home": ALWAYS, "market": ALWAYS}, "entity": "Kast agency", "group": "g7"},
    "TGOV": {"roles": {"home": ALWAYS}, "entity": "Test government", "group": "g8", "government": True},
    "HYBR": {"roles": {"market": ALWAYS}, "entity": "Hybr", "group": "g9", "provider_domains": {"https://hybr.example"}},
    "OMNI": {"roles": {"home": ALWAYS, "market": ALWAYS}, "entity": "Omni", "group": "g10",
             "provider_domains": {"https://omni.example"}},
    "KINO": {"roles": {"home": ALWAYS}, "entity": "Kino", "group": "g11"},
    "KOBEMK": {"roles": {"market": ALWAYS}, "entity": "Kobe market KK", "group": "g12"},
    "LYONMK": {"roles": {"market": ALWAYS}, "entity": "Lyon market SAS", "group": "g12"},   # one group, 5 entities
    "RIOMKT": {"roles": {"market": ALWAYS}, "entity": "Rio market Ltda", "group": "g12"},
    "PUNEMK": {"roles": {"market": ALWAYS}, "entity": "Pune market Pvt", "group": "g12"},
    "OSLOMK": {"roles": {"market": ALWAYS}, "entity": "Oslo market AS", "group": "g12"},
}


def examples() -> dict:
    p = _ex_person
    return {
        "home only": [p("PRAM", 900000037), _ex("LIC", "PRAM"), _ex("PG-LIC", "PRAM")],
        "standing terms, no deal": [_ex("PG", "PRAM", label="Gterms")],
        "home + market": [_ex("LIC", "NWRD", "PRAM"), _ex("PG-LIC", "NWRD", "PRAM")],
        "market, home hidden": [_ex("PG-LIC", "NWRD", label="hidden")],
        "five markets": [_ex("LIC", "HLWD", "PRAM"), _ex("LIC", "USAD", "PRAM"), _ex("LIC", "NWRD", "PRAM", "L2"),
                         _ex("LIC", "KOBEMK", "PRAM"), _ex("PG-LIC", "VELR")],
        "market + provider": [_ex("LIC", "HYBR", "PRAM"), _ex("PG-LIC", "HYBR", "PRAM")],
        "home + market + provider": [p("OMNI", 900000005), _ex("LIC", "OMNI"), _ex("PG-LIC", "OMNI")],
        "agency registry": [p("KAST", 900000012), _ex("LIC", "KAST"), _ex("LIC", "NWRD", label="kastclient"),
                            _ex("LIC", "KAST", "PRAM")],
        "government home, markets in five countries": [
            p("TGOV", 900000101), _ex("LIC", "KOBEMK", "TGOV"), _ex("LIC", "LYONMK", "TGOV"),
            _ex("LIC", "RIOMKT", "TGOV"), _ex("LIC", "PUNEMK", "TGOV"), _ex("LIC", "OSLOMK", "TGOV"),
            _ex("PG", "TGOV")],
        "moved home": [p("PRAM", 900000041), _ex("LIC", "NWRD", "PRAM", "Lold"), _ex("LIC", "NWRD", "SKAN"),
                       _ex("PG-LIC", "NWRD", "SKAN")],
        "joined codes": [p("PRAM", 900000052), p("KINO", 900000007)],
        "private person": [p("PRAM", 900000063)],
        "after-gen": [_ex("AG", "PRAM"), _ex("AG-LIC", "NWRD", "PRAM")],
        "two people in one video": [_ex("PG-LIC", "NWRD", "PRAM", "G2a"), _ex("PG-LIC", "HLWD", "SKAN", "G2b")],
        "respelled": [code_key(c) for c in LEGACY_INPUT if parse(c)["kind"] == "subject"],
    }


_SB = "ZZZZSABR24PA3EYWN7RHYG5G07"        # an earlier example secret body, kept as printed
EXAMPLE_SECRET = _SB + check_char(_SB)   # an example secret: starts ZZZZ, never minted (mint_secret is random)

# Pinned: the example strings of TOG-CODE.md. A change here is a change of the specification.
PINNED = {
    "home only": [
        "TOG-PRAM-900000037K", "TOG-LIC-PRAM-ZZZZ-QH28-TDQ8", "TOG-PG-LIC-PRAM-ZZZZ-8RD8-3EQ9"],
    "standing terms, no deal": [
        "TOG-PG-PRAM-ZZZZ-K6X4-RZJB"],
    "home + market": [
        "TOG-LIC-NWRD-PRAM-ZZZZ-84RN-RT04", "TOG-PG-LIC-NWRD-PRAM-ZZZZ-VGDY-WCWV"],
    "market, home hidden": [
        "TOG-PG-LIC-NWRD-ZZZZ-WNJB-820Q"],
    "five markets": [
        "TOG-LIC-HLWD-PRAM-ZZZZ-FN2C-3M5V", "TOG-LIC-USAD-PRAM-ZZZZ-M1BM-P1DE", "TOG-LIC-NWRD-PRAM-ZZZZ-TXHN-9P2X",
        "TOG-LIC-KOBEMK-PRAM-ZZZZ-BYAV-K2AQ", "TOG-PG-LIC-VELR-ZZZZ-Q4VE-P7E4"],
    "market + provider": [
        "TOG-LIC-HYBR-PRAM-ZZZZ-F7CJ-E8TX", "TOG-PG-LIC-HYBR-PRAM-ZZZZ-VGQ3-ZGQH"],
    "home + market + provider": [
        "TOG-OMNI-9000000055", "TOG-LIC-OMNI-ZZZZ-EKC0-Z18T", "TOG-PG-LIC-OMNI-ZZZZ-7387-XZBA"],
    "agency registry": [
        "TOG-KAST-9000000125", "TOG-LIC-KAST-ZZZZ-FJ4Y-SM2N", "TOG-LIC-NWRD-ZZZZ-134C-2NDD",
        "TOG-LIC-KAST-PRAM-ZZZZ-3NX4-F2GH"],
    "government home, markets in five countries": [
        "TOG-TGOV-9000001014", "TOG-LIC-KOBEMK-TGOV-ZZZZ-8TZ3-VGMV", "TOG-LIC-LYONMK-TGOV-ZZZZ-QGK5-QC4C",
        "TOG-LIC-RIOMKT-TGOV-ZZZZ-XMNA-3NP7", "TOG-LIC-PUNEMK-TGOV-ZZZZ-VQ6V-KQWF",
        "TOG-LIC-OSLOMK-TGOV-ZZZZ-C6DZ-WS45", "TOG-PG-TGOV-ZZZZ-DHMW-8C2S"],
    "moved home": [
        "TOG-PRAM-900000041V", "TOG-LIC-NWRD-PRAM-ZZZZ-82V2-YJHT", "TOG-LIC-NWRD-SKAN-ZZZZ-37NF-0EAS",
        "TOG-PG-LIC-NWRD-SKAN-ZZZZ-X9RS-BBKX"],
    "joined codes": [
        "TOG-PRAM-900000052F", "TOG-KINO-900000007B"],
    "private person": [
        "TOG-PRAM-9000000633"],
    "after-gen": [
        "TOG-AG-PRAM-ZZZZ-T8JE-WDJX", "TOG-AG-LIC-NWRD-PRAM-ZZZZ-ZJGH-HQH3"],
    "two people in one video": [
        "TOG-PG-LIC-NWRD-PRAM-ZZZZ-PE6X-E06A", "TOG-PG-LIC-HLWD-SKAN-ZZZZ-M0PE-BKHE"],
    "respelled": [
        "TOG-ZYXW-1234567R", "TOG-000042*", "TOG-STD-000123"],
}
# Published PG strings used as legacy input: the persons fold by marker, the licences through a record.
LEGACY_INPUT = ["PG-ZYXW-1234567R", "PG-000042*", "PG-STD-000123", "PG-NWRD-RND-000042-ZZZZZZJ", "PG-STD-000001-K7M2QX9"]
NEW_SHAPES = ("person", "event")         # minted from now on; the respelled shapes are frozen and closed


def must_reject() -> list:
    """(string, error class, why). Every one fails parse() with exactly that class."""
    t = RESERVED_TAIL + "7QX2M9K"
    w = lambda k, i, h=None, tail=t: spell(k, i, h, tail,   # noqa: E731  (an unknown kind gets PG's check)
                                           check_char(event_body(k if k in FIVE else "PG", i, h, tail)))
    g = _ex("PG-LIC", "NWRD", "PRAM", "mr")
    pg, ag, lic = _ex("PG", "PRAM", label="mr"), _ex("AG-LIC", "NWRD", "PRAM", "mr"), _ex("LIC", "NWRD", label="mr")
    one = w("PG-LIC", "ABCDE")                        # TOG-PG-LIC-ABCDE-…
    tl = g[-14:]                                      # XXXX-XXXX-XXXX
    flat = tl.replace("-", "")
    return [
        (w("PG", "PRAM", "PRAM"), NotACode, "one registry written twice"),
        ("TOG-ABCD-PRM-1234567-A1B2C3A", NotACode, "old licence shape under TOG"),
        ("TOG-00042" + check_char("00042"), NotACode, "a bare person of 5 digits: the PG grammar had 6 or more"),
        ("TOG-ABC-000123", NotACode, "a no-check class never issued (only STD and SUB)"),
        ("TOG-LIC-000123", NotACode, "a no-check shape under a kind"),
        ("PG-ABC-000123", NotACode, "PG input: a no-check class never issued has no TOG spelling"),
        (pg[4:], NotACode, "TOG- dropped from a PG code: never a PG person"),
        (g[4:], NotACode, "TOG- dropped from a PG-LIC code: never a PG licence"),
        (ag[4:], NotACode, "TOG- dropped from an AG-LIC code"),
        (lic[4:], NotACode, "TOG- dropped from a LIC code"),
        ("TOG-ZYXW-12345678" + check_char("ZYXW12345678"), NotACode, "8 digits under a PG-born prefix: no shape"),
        ("TOG-TILU-1234567" + check_char("TILU1234567"), NotACode, "6 or 7 digits only under a 4-letter PG prefix"),
        ("TOG-PRAMS-123456" + check_char("PRAMS123456"), NotACode, "6 or 7 digits under a 5-letter prefix"),
        ("PG-ZYXW-01234567" + check_char("ZYXW01234567", CROCKFORD), NotACode,
         "PG input, over-padded: its TOG spelling has 8 digits, never issued in any spelling"),
        ("PG-PRAM-412345691!", NotACode, "PG input, 9 digits and a symbol check: no TOG spelling"),
        ("PG-PRAM-0123456789", NotACode, "PG input, 10 digits with a leading zero: no TOG spelling"),
        ("TOG-PRAM-90000003" + check_char("PRAM90000003"), NotACode, "8-digit serial: a dropped digit"),
        ("TOG-PRAM-9000000371" + check_char("PRAM9000000371"), NotACode, "10-digit serial: a doubled digit"),
        ("TOG-PRAM-090000037" + check_char("PRAM090000037"), NotACode, "leading zero: a second spelling"),
        ("TOG-PRAM-123456789012" + check_char("PRAM123456789012"), NotACode, "12-digit serial: not in this design"),
        ("TOG-PRAM-1234567890123" + check_char("PRAM1234567890123"), NotACode, "13-digit serial"),
        ("TOG-PRA-900000037K", NotACode, "three-letter prefix"),
        ("TOG-ABCDEFGHJ-900000037" + check_char("ABCDEFGHJ900000037"), NotACode, "nine-letter prefix"),
        ("TOG-PR4M-900000037K", NotACode, "digit in a prefix"),
        (w("XG", "NWRD", "PRAM"), NotACode, "unknown kind"),
        (w("G", "NWRD", "PRAM"), NotACode, "a one-letter kind of revision 3"),
        ("TOG-NWRD-PRAM-G-ZZZZ85JNFXJ7MJ", NotACode, "the revision 3 shape: kind after the prefixes"),
        (w("LIC-PG", "NWRD", "PRAM"), NotACode, "LIC-PG: the marker comes after the kind"),
        (w("LIC-AG", "NWRD", "PRAM"), NotACode, "LIC-AG: the marker comes after the kind"),
        (w("PG-AG", "NWRD", "PRAM"), NotACode, "PG and AG together"),
        (w("PG-PG", "NWRD", "PRAM"), NotACode, "a doubled kind"),
        (w("PG-LIC-LIC", "NWRD", "PRAM"), NotACode, "a doubled marker"),
        (w("LIC-LIC", "NWRD", "PRAM"), NotACode, "a licence under a licence"),
        (one.replace("-LIC-ABCDE-", "-LICA-BCDE-"), NotACode, "the marker's dash moved: no prefix begins with LIC"),
        (one.replace("-LIC-ABCDE-", "-LICABCDE-"), NotACode, "the marker's dash dropped"),
        (w("PG", "LICX"), NotACode, "a prefix beginning with LIC"),
        (w("PG", "ACMELIC"), NotACode, "a prefix ending with LIC"),
        # One letter inserted into the marker of TOG-PG-LIC-PRAM-ZZZZ-8RD8-3EQ9: each passes the check, so in an earlier
        # draft each read as a PG code (issuer NLIC, LGIC or LIZC; home PRAM): the kind and basis changed.
        ("TOG-PG-NLIC-PRAM-ZZZZ-8RD8-3EQ9", NotACode, "a letter inserted before the marker LIC"),
        ("TOG-PG-LGIC-PRAM-ZZZZ-8RD8-3EQ9", NotACode, "a letter inserted into the marker LIC"),
        ("TOG-PG-LIZC-PRAM-ZZZZ-8RD8-3EQ9", NotACode, "a letter inserted into the marker LIC"),
        (g.replace("TOG-PG-LIC-", "TOG-PGLIC-"), NotACode, "the marker glued to the kind"),
        (pg.replace("TOG-PG-", "TOG-PG"), NotACode, "the kind glued to the issuer"),
        (w("PG-LIC", "NWRD", "PRAM").replace("PRAM-", "PRAM-FRME-"), NotACode, "a provider has no slot"),
        (g[:-14] + flat[:3] + "-" + flat[3:7] + "-" + flat[7:], NotACode, "tail regrouped 3-4-5"),
        (g[:-14] + flat, NotACode, "tail with no dashes"),
        (g[:-14] + tl[:9] + tl[10:], NotACode, "tail 4-8: a dash dropped"),
        (g[:-14] + tl[:10] + "0000-" + tl[10:], NotACode, "tail with an extra group"),
        (g[:-2] + g[-1], NotACode, "10-symbol fingerprint: last group of 3"),
        (g[:-1] + "0" + g[-1], NotACode, "12-symbol fingerprint: last group of 5"),
        (g[:-3] + "L" + g[-2:], NotACode, "L in a tail"),
        (g[:-1] + "*", NotACode, "a symbol check under TOG"),
        (g.lower(), NotACode, "lower case in a message"),
        (" " + g, NotACode, "leading space in a message"),
        (g + "\u200b", NotACode, "invisible character appended"),
        (g.replace("-LIC-", "-L1C-"), NotACode, "L1C in a message (folded only where typed)"),
        ("TOG-PR\u0410M-900000037K", NotACode, "Cyrillic A in a message"),
        ("TOG-PRAM-900000037K#s=" + EXAMPLE_SECRET, NotACode, "a QR fragment is not part of the code"),
        (EXAMPLE_SECRET, NotACode, "a secret is never a code"),
        ("TOG-PRAM-900000037M", Mistyped, "wrong check character"),
        (g.replace("TOG-PG-", "TOG-AG-"), Mistyped, "a generation passed off as an approval after the fact"),
        (ag.replace("TOG-AG-", "TOG-PG-"), Mistyped, "an approval after the fact passed off as a generation"),
        ("PG-OWN-000001-K7M2QX" + check_char("OWN000001K7M2QX", VALUES), Mistyped,
         "the TOG letter values never revive a PG body"),
    ]


# ── Self-check ─────────────────────────────────────────────────────────────────────────────────────────────────────
def _try(fn, *a) -> bool:
    try:
        fn(*a)
        return True
    except ValueError:
        return False


def _expect(err, fn, *a):
    try:
        fn(*a)
    except err:
        return
    raise AssertionError(f"{fn.__name__}{a} did not raise {err.__name__}")


def _self_check() -> dict:
    stats = {}

    # 1. The check character is byte-identical to pg_code.py on every Crockford body; every published vector holds.
    published = ["PG-0000016", "PG-000042*", "PG-099999*", "PG-9999994", "PG-10000001", "PG-12345678K",
                 "PG-STD-000001-K7M2QX9", "PG-RND-000042-ZZZZZZ1", "PG-PRM-999999-0000000", "PG-NWRD-000042=",
                 "PG-NWRD-RND-000042-ZZZZZZJ", "PG-PRAM-000037J", "PG-ZYXW-1234567R", "PG-ABCD-PRM-1234567-A1B2C3A",
                 "PG-STD-000123", "PG-SUB-000123"]
    vec = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "test-vectors", "vectors.json")
    if os.path.exists(vec):
        v = json.load(open(vec))["pg_code"]
        published += [x["code"] for x in v["subject_code"] + v["issuer_subject_code"]]
        published += [x["license_id"] for x in v["license_id"] + v["issuer_license_id"]]
        for x in v["check_char"] + v["length_accepts"]:
            assert check_char(x["body"], CROCKFORD) == x["check_char"], x
        for x in v["rejects"] + v["issuer_rejects"]:
            assert check_char(x["body"], CROCKFORD) != x["check_char"], x
        for x in v["length_rejects"]:
            assert not _verifies(x["body"], x["check_char"], CROCKFORD), x
    rng = random.Random(2026_11_09)
    bodies = ["".join(rng.choice(CROCKFORD) for _ in range(rng.randint(1, MAX_BODY))) for _ in range(5000)]
    prod = os.environ.get("PG_CODE_PY")   # optional: a registry's pg_code.py to compare with byte for byte
    if prod:
        spec = importlib.util.spec_from_file_location("pg_code_prod", prod)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for b in bodies:
            assert mod.compute_check_char(b) == check_char(b) == check_char(b, CROCKFORD), b
        for c in published:
            p = parse(c)
            if p["shape"] in ("pg_person", "bare_person"):
                assert mod.format_subject_code(int(c.split("-")[-1][:-1]), p["issuer"]) == c, c
        stats["byte_identical_bodies"] = len(bodies)
    for c in published:
        assert parse(c)["marker"] == "PG" and PUBLISHED_RE.fullmatch(c), c
    stats["published"] = len(published)

    # 2. The hard switch: every code is written TOG-. A PG person folds by its marker to exactly one TOG spelling with
    #    the same check; an old licence folds through its record to a TOG-LIC code from the grant's message id.
    #    PG- is legacy input only: nothing returns it.
    published = list(dict.fromkeys(published))
    msgid = lambda s: hashlib.sha256(s.encode()).hexdigest()     # noqa: E731
    licences, keys = {}, {}
    for c in published:
        p = parse(c)
        if p["kind"] == "subject":
            k = code_key(c)
            # Same check character (the TOG table equals Crockford on every PG body), same person, a frozen shape.
            assert k == "TOG" + c[2:] and k[-1] == c[-1] and parse(k)["shape"].startswith("old_"), c
            assert person_key(k) == person_key(c), c
        else:
            # The signed pg.license.v2 behind it (grants.md "Older licences": id = SHA-256 over body, subject signature
            # and the PG id). Here a stand-in id; a real one comes from the registry's record. The flat model: the
            # licence's registry signed it. A symbol check or a reserved tail would need the home's countersignature.
            _expect(AskRegistry, code_key, c)                                # offline: only its registry knows
            n = ""
            while True:
                rec = {"type": "pg.license.v2", "id": msgid(c + n), "signer": p["issuer"] or BARE_ISSUER,
                       "subject_ref": f"PG-{p['issuer'] + '-' if p['issuer'] else ''}000042" +
                                      check_char(p["issuer"] + "000042", CROCKFORD), "license_id": c}
                try:
                    k = code_key(c, {c: rec})
                    break
                except ValueError:
                    n += "'"
            assert k == event_code("LIC", rec["signer"], message_id=rec["id"]) and kind_of(k) == "license", c
            assert normalize_typed(c.lower(), {c: rec}) == k, c
            _expect(AskRegistry, normalize_typed, c.lower())
            _expect(AskRegistry, code_key, c, {c: dict(rec, license_id=c + "X")})   # the record names another id
            licences[c] = rec
        assert normalize_typed(c.lower(), licences) == k and normalize_typed(c, licences) == k, c
        keys[c] = k
    assert len(set(keys.values())) == len(keys)                         # exactly one TOG spelling each, no two alike
    stats["published_folded"] = len(keys)
    # A legacy licence whose message id gives a symbol check: no flat code; the home countersigns it once.
    sym = next(h for h in (msgid(str(i)) for i in range(999))
               if check_char(event_body("LIC", "NWRD", None, tail_of(h))) not in CROCKFORD)
    old_l = dict(licences["PG-NWRD-RND-000042-ZZZZZZJ"], id=sym)
    _expect(ValueError, code_for, old_l)
    cs = next(h for h in (msgid("cs" + str(i)) for i in range(999))
              if check_char(event_body("LIC", "NWRD", None, tail_of(h))) in CROCKFORD)
    assert code_for(dict(old_l, cosign={"id": cs, "home": "NWRD", "home_in_code": True})) == \
        event_code("LIC", "NWRD", message_id=cs)
    # An allow that names an old licence carries the marker LIC, like one naming a pg.grant.v1.
    old_allow = {"type": "pg.answer.v1", "id": msgid("old allow"), "signer": "NWRD", "subject_ref": "PG-NWRD-000042=",
                 "grant": {"id": licences["PG-NWRD-RND-000042-ZZZZZZJ"]["id"], "signer": "NWRD"}}
    while not _try(code_for, old_allow):
        old_allow["id"] = msgid(old_allow["id"])
    assert code_for(old_allow).startswith("TOG-PG-LIC-NWRD-")
    # A respelled person and its PG input are one key: one pointer-log entry, one refusal, one registry answer.
    tp = _ex_person("PRAM", 900000037)                                    # TOG-PRAM-900000037K, the example person
    for pg_in, tog in (("PG-ZYXW-1234567R", "TOG-ZYXW-1234567R"), ("PG" + tp[3:], tp), ("PG-000042*", "TOG-000042*"),
                       ("PG-STD-000123", "TOG-STD-000123"), ("PG-NWRD-000042=", "TOG-NWRD-000042=")):
        assert code_key(pg_in) == code_key(tog) == tog, pg_in
        refusals = {code_key(pg_in)}                                      # a refusal listed under the old spelling
        assert code_key(tog) in refusals and len({code_key(pg_in), code_key(tog)}) == 1
        assert hashlib.sha256(code_key(pg_in).encode()).digest() == hashlib.sha256(code_key(tog).encode()).digest()
    for typed in ("  tog-zyxw-1234567r \n", "TOG–ZYXW–1234567R", "ＴＯＧ－ＺＹＸＷ－１２３４５６７Ｒ", "T0G-ZYXW-l234567R",
                  "https://resolver.example/v2/codes/TOG-ZYXW-1234567R#x", "PG-ZYXW-1234567R.", "ТОG-ZYХW-1234567R",
                  "pg-zyxw-1234567r", "https://api2.prampta.com/v1/pg/PG-ZYXW-1234567R"):
        assert normalize_typed(typed) == "TOG-ZYXW-1234567R", typed
    assert normalize_typed("PG 000 042 *") == "TOG-000042*" == normalize_typed("tog-000042*")
    assert "old spelling of TOG-ZYXW-1234567R" in describe("PG-ZYXW-1234567R")
    # Any PG person string with no valid TOG spelling was never issued in any spelling: not a code, typed or not.
    for bad in ("PG-PRAM-412345691!",
                "PG-PRAM-0123456789", "tog-pram-412345691!", "PG-ZYXW-01234567" + check_char("ZYXW01234567")):
        _expect(NotACode, normalize_typed, bad)
        assert verdict("aa", caption=bad) in (WORDS["not a code"], WORDS["mistyped"]), bad
    # One example rule for PG and TOG (PG-CODE section 11 floor, unchanged): 900 000 000 and above.
    assert parse(_ex_person("PRAM", 900000000))["example"] and not parse(_ex_person("PRAM", 899999000))["example"]
    assert not _valid("TOG-PRAM-123456789012" + check_char("PRAM123456789012"))       # no 12-digit width
    # Typed 1 and 0 fold per character in a prefix: T11U is TILU, U01I is UOLI.
    tilu = _ex_person("TILU", 142000000)
    assert normalize_typed(tilu.replace("TILU", "T11U").lower()) == tilu
    tilu_h = _ex("AG", "TILU", "UOLI")
    assert normalize_typed(tilu_h.replace("TILU", "T1LU").replace("UOLI", "U01I")) == tilu_h
    # The marker typed L1C, LlC or 1IC folds to LIC where a person types; parse() never folds it (must-reject).
    lic_ex = _ex("AG-LIC", "NWRD", "PRAM", "typed")
    for typo in ("-L1C-", "-LlC-", "-1IC-", "-lic-"):
        assert normalize_typed(lic_ex.replace("-LIC-", typo)) == lic_ex and not _valid(lic_ex.replace("-LIC-", typo))
    # A tail full of 1s is read as digits only: never refused as "too many readings".
    ones = next(spell("PG", "PRAM", None, "1" * 10 + c, k) for c in CROCKFORD
                if (k := check_char(event_body("PG", "PRAM", None, "1" * 10 + c))) in CROCKFORD)
    assert normalize_typed(ones.lower()) == ones
    # Typed T0G is still the marker TOG, so the tail keeps digit readings only.
    ones2 = "TOG-AG-LIC-NWRD-PRAM-1111-1111-111" + check_char(event_body("AG-LIC", "NWRD", "PRAM", "1" * TAIL))
    assert normalize_typed(ones2.replace("TOG", "T0G", 1).lower()) == ones2
    # Two readings pass (111A is IILA and LLIA, one check): refused with both as hints.
    amb = _ex_person("IILA", 412345678)
    try:
        normalize_typed(amb.replace("IILA", "111A"))
        raise AssertionError("ambiguous input accepted")
    except NotACode as e:
        assert "ambiguous" in str(e) and amb in str(e) and amb.replace("IILA", "LLIA") in str(e), e
    t0 = time.perf_counter()                                              # 2^n readings are capped, not searched
    _expect(NotACode, normalize_typed, "TOG-11111111-11111111-11111111-1")
    assert time.perf_counter() - t0 < 1
    # A registry: found by either spelling, answered in TOG; an over-padded number gets the TOG hint.
    issued = {person_key(c): c for c in ("TOG-ZYXW-1234567R", "TOG-STD-000123", tp)}
    for asked, hit in (("PG-ZYXW-1234567R", "TOG-ZYXW-1234567R"), ("TOG-ZYXW-1234567R", "TOG-ZYXW-1234567R"),
                       ("PG-STD-000123", "TOG-STD-000123"), ("PG" + tp[3:], tp), (tp, tp)):
        assert registry_answer(asked, issued) == f"found {hit}", asked
    for other, hit in (("PG-STD-0000123", "TOG-STD-000123"), ("TOG-STD-0000123", "TOG-STD-000123")):
        assert registry_answer(other, issued) == f"PG_MALFORMED hint={hit}", other
    assert registry_answer(_ex_person("PRAM", 412345999), issued) == "not_found"
    _expect(NotACode, registry_answer, "PG-ZYXW-01234567" + check_char("ZYXW01234567"), issued)
    for bad in ("tog-abcd-prm-1234567-a1b2c3a", "tog-std-000001-k7m2qx9"):   # a licence is never respelled by marker
        _expect(NotACode, normalize_typed, bad)
    # Nothing ever emits PG-: every function that returns a code or text, over every input, old and new.
    def no_pg(out):
        assert not any(x.startswith("PG-") for x in FIND_RE.findall(str(out))), out
    for c in published + LEGACY_INPUT + [c for cs in PINNED.values() for c in cs]:
        if _try(code_key, c, licences):
            no_pg(code_key(c, licences))
            no_pg(normalize_typed(c.lower(), licences))
            no_pg(describe(c))
            no_pg(verdict("aa", caption=c))
            if parse(c)["kind"] == "subject":
                no_pg(registry_answer(c, {person_key(c): code_key(c)}))
                no_pg(card_qr("https://resolver.example", c))
    no_pg(examples())
    no_pg([code_for(r) for r in licences.values()])
    stats["never_emits_pg"] = True

    # 3. Examples: reproduced, pinned, one shape each, reserved range, flagged as examples, old verifiers fail closed.
    ex = examples()
    if PINNED:
        assert ex == PINNED, {k: v for k, v in ex.items() if PINNED.get(k) != v}
    allcodes = [c for cs in ex.values() for c in cs]
    for c in allcodes:
        assert sum(1 for *_, rx in SHAPES if rx.fullmatch(c)) == 1, c
        assert normalize_typed(c.lower()) == c, c
        assert find_codes(f"*{c}*, see ({c}).") == [c, c] or c[-1] in "*~$=!", c
        assert c.startswith("TOG-") and not PUBLISHED_RE.fullmatch(c), c
        if parse(c)["shape"] in NEW_SHAPES:
            assert parse(c)["example"] and c[-1] in CROCKFORD, c
            # TOG- dropped: never a PG code, never anything valid, old or new, typed or not.
            assert not PUBLISHED_RE.fullmatch(c[4:]) and not _valid(c[4:]), c
            _expect(NotACode, normalize_typed, c[4:])
            assert describe(c).endswith("EXAMPLE, never issued") and verdict("aa", caption=c) == WORDS["example"]
    assert [kind_of(c) for c in ex["home only"]] == ["subject", "license", "generated"]
    assert kind_of("PG-NWRD-RND-000042-ZZZZZZJ") == "license"           # one word for a licence, any era
    assert [kind_of(c) for c in ex["after-gen"]] == ["approved_after"] * 2
    assert [parse(c)["basis"] for c in ex["after-gen"]] == ["terms", "licence"]
    assert parse(ex["standing terms, no deal"][0])["basis"] == "terms" and parse(ex["home only"][1])["basis"] is None
    assert {k for c in allcodes if c.startswith("TOG-") and (k := c.split("-")[1]) in ("PG", "AG", "LIC")} \
        == {"PG", "AG", "LIC"} and all(any(f"TOG-{k}-" in c for c in allcodes) for k in FIVE)   # five kinds shown
    assert describe(ex["home + market"][1]).startswith(
        "claims generated under a licence · issued by NWRD · home PRAM · not checked")
    assert issuer_of(ex["moved home"][3]) == "NWRD" and parse(ex["moved home"][3])["home"] == "SKAN"
    for c in allcodes:              # the first prefix (first group of 4 or more letters) is always the one to ask
        g1 = next((x for x in c.split("-")[1:2 if c.startswith("PG-") else 4] if x.isalpha() and len(x) >= 4), "")
        assert issuer_of(c) == g1, c
    assert issuer_of("PG-PRAM-0000000") == "PRAM"                        # shape only, as 0.13 (wrong check kept)
    n = next(n for n in range(900000059, 900009999)                # a TOG code hiding a valid bare PG code
             if check_char("SHOPG" + str(n)) == check_char(str(n), CROCKFORD) and check_char(str(n)) in CROCKFORD)
    hiding = person_code("SHOPG", n)
    assert _valid(hiding[4:].replace("SHO", "", 1)) and find_codes(f"see {hiding}.") == [hiding]
    stats["examples"] = len(allcodes)

    # 4. Must-reject strings fail with exactly their class.
    rejects = must_reject()
    for s, err, why in rejects:
        try:
            parse(s)
            raise AssertionError(f"accepted: {why}: {s}")
        except (NotACode, Mistyped) as e:
            assert type(e) is err, (why, s, type(e).__name__)
    stats["must_reject_strings"] = len(rejects)

    # 5. Every single substitution and adjacent transposition of a new code is refused; so is every single insertion
    #    or deletion after the prefixes (tail, check, serial). Every insertion and deletion is tried, at every place,
    #    over every pinned example and the edge codes. In the kind and prefix part, an indel that passes (counters
    #    prefix_indels_passing_check of prefix_indels_tried) is asserted to keep the kind and the basis, to change
    #    exactly one prefix by one letter inserted or deleted, and to be refused by admission next to the listed
    #    prefix it came from: the directory catches it. In an earlier draft a letter inserted into or before the marker LIC
    #    also passed (TOG-PG-NLIC-PRAM-...: a PG code, issuer NLIC): no prefix may hold LIC that way now.
    edge = [_ex_person("ZZZZZZZZ", 899999990), _ex_person("TILU", 142000000), _ex_person("GOVTEST", 123456789),
            _ex("PG-LIC", "ABCDEFGH", "JKMNPQRS"), _ex("LIC", "PRAL", "OSLU"), _ex("AG-LIC", "TILU", "UOLI"),
            _ex("PG", "PRAMU"), _ex("AG", "ABCD", "EFGH"), _ex("PG-LIC", "ABCDE")]
    for _ in range(300):
        pf = lambda: "".join(rng.choice(string.ascii_uppercase) for _ in range(rng.randint(4, 8)))   # noqa: E731
        h, s, k = pf(), pf(), rng.choice(FIVE)
        tail = "".join(rng.choice(CROCKFORD) for _ in range(TAIL))
        hm = s if rng.random() < .7 and s != h else None
        c = spell(k, h, hm, tail, check_char(event_body(k, h, hm, tail)))
        if c[-1] in CROCKFORD and _valid(c):          # a prefix beginning with LIC is not a code: skipped
            edge.append(c)
        n = rng.randrange(100_000_000, 900_000_000)
        if check_char(h + str(n)) in CROCKFORD:
            edge.append(person_code(h, n))
    chars = string.ascii_uppercase + string.digits + "*~$=!-"
    mutations = indels = prefix_indels = prefix_tried = 0
    for code in [c for c in allcodes if parse(c)["shape"] in NEW_SHAPES] + edge:
        muts = {code[:i] + ch + code[i + 1:] for i in range(len(code)) for ch in chars if ch != code[i]}
        muts |= {code[:i] + code[i + 1] + code[i] + code[i + 2:] for i in range(len(code) - 1)
                 if code[i] != code[i + 1]}
        for m in muts:
            assert sum(1 for *_, rx in SHAPES if rx.fullmatch(m)) <= 1, m
            assert not _valid(m), (code, m)
        mutations += len(muts)
        limit = len(code) - 15 if parse(code)["shape"] == "event" else code.rfind("-")   # the dash before the tail
        dels = {(i, code[:i] + code[i + 1:]) for i in range(len(code))}
        ins = {(i, code[:i] + ch + code[i:]) for i in range(len(code) + 1) for ch in chars}
        for i, m in dels | ins:
            if m == code:
                continue
            if i <= limit:
                prefix_tried += 1
                if _valid(m):
                    prefix_indels += 1
                    p, q = parse(code), parse(m)
                    assert (q["kind"], q.get("basis")) == (p["kind"], p.get("basis")), (code, m)
                    diff = [(a, b) for a, b in itertools.zip_longest((p["issuer"], p["home"]), (q["issuer"], q["home"]))
                            if a != b]
                    assert len(diff) == 1 and diff[0][0] and diff[0][1], (code, m)   # one prefix; no dash moved
                    a, b = diff[0]
                    short, long_ = sorted((a, b), key=len)
                    assert any(long_[:j] + long_[j + 1:] == short for j in range(len(long_))), (code, m)
                    assert admission_refusal(b, "X", "GOV" in b, {a: {"entity": "Y"}}, reserved=()) != "", (code, m)
                continue
            assert not _valid(m), (code, m)
            indels += 1
    stats["substitutions_transpositions_refused"] = mutations
    stats["indels_refused"] = indels
    stats["prefix_indels_tried"] = prefix_tried
    stats["prefix_indels_passing_check"] = prefix_indels

    # 6. The dash between issuer and home, exhaustively over the five kinds, prefix lengths and crossing letters:
    #    moved by 1 to 4, dropped (4+4 letters become one prefix of 8) or added. The two length digits catch all.
    #    Every other dash is fixed by the grammar (kind, LIC, a prefix never beginning with LIC, tail 4-4-4).
    moved = 0
    for kind in FIVE:
        for la in range(4, 9):
            for lb in range(4, 9):
                for ch in string.ascii_uppercase:
                    for a, b in ((ch * la, "B" * lb), ("A" * la, ch * lb)):
                        b = b if b != a else "C" * lb
                        chk = check_char(event_body(kind, a, b, "7" * TAIL))
                        other = [(a2, b2) for k in (1, 2, 3, 4) for a2, b2 in ((a[:-k], a[-k:] + b), (a + b[:k], b[k:]))
                                 if 4 <= len(a2) <= 8 and 4 <= len(b2) <= 8]
                        other += [(a + b, None)] if la + lb <= 8 else []
                        for a2, b2 in other:
                            moved += 1
                            assert check_char(event_body(kind, a2, b2, "7" * TAIL)) != chk, (kind, a, b, a2, b2)
    stats["moved_dropped_added_dashes_refused"] = moved
    for n in range(300):                    # why new shapes stop at 35
        body = f"{n:035d}" + CROCKFORD[(n % 31) + 1]
        k = check_char(body)
        if k in CROCKFORD and k != body[-1]:
            assert check_char(body[:-1] + k) == body[-1]
    assert max(len(event_body("PG-LIC", "ABCDEFGH", "JKMNPQRS", "Z" * TAIL)), 8 + 9) == 30 < MAX_NEW_BODY

    # 7. Kinds are injective: distinct (kind, marker, issuer, home, tail) give distinct codes and read back as such;
    #    kind and marker are in the check as one digit, so every relabel is one substitution: none passes (asserted).
    #    The record catches them too (code_for, section 8).
    seen, meaning = {}, {}
    for k in FIVE:
        for i in ("NWRD", "NWRDX", "TILU"):
            for h in (None, "PRAM", "PRAMS"):
                for t in ("0" * TAIL, "1" + "0" * (TAIL - 1), "2" + "0" * (TAIL - 1)):
                    if check_char(event_body(k, i, h, t)) in CROCKFORD:
                        c = event_code(k, i, h, tail=t)
                        p = parse(c)
                        assert (p["issuer"], p["home"]) == (i, h) and c not in seen
                        seen[c] = 1
                        meaning.setdefault(k, set()).add((p["kind"], p["basis"]))
    assert all(len(v) == 1 for v in meaning.values()) and len(set.union(*meaning.values())) == 5, meaning
    relabels = relabels_passing = 0
    for code in [c for c in allcodes + edge if parse(c)["shape"] == "event"]:
        p = parse(code)
        kind = next(k for k in FIVE if code.startswith(f"TOG-{k}-{p['issuer']}"))
        tail = code[-14:].replace("-", "")[:-1]
        for k in FIVE:
            if k != kind:
                relabels += 1
                relabels_passing += _valid(spell(k, p["issuer"], p["home"], tail, code[-1]))
    assert relabels_passing == 0, relabels_passing
    stats["marker_relabels_refused"] = relabels

    # 8. Codes against acts: computed, never read. Tail from the home's cosign: one allow, one PG code. The marker
    #    LIC comes from the record (the grant behind the act); the licence's number stays in the record.
    def mid(s, uses=(("PG-LIC", "NWRD", "PRAM"), ("PG-LIC", "NWRD", None), ("PG-LIC", "KAST", None))):
        while True:                         # a message id whose code has a letter check (the issuer re-signs)
            h = hashlib.sha256(s.encode()).hexdigest()
            try:
                for k, i, hm in uses:
                    event_code(k, i, hm, message_id=h)
                return h
            except ValueError:
                s += "'"
    person = mint_person("PRAM", set(), random.Random(1))              # a real-shaped person, not printed anywhere
    allow = {"type": "pg.answer.v1", "id": mid("allow", (("PG", "PRAM", None),)), "signer": "NWRD",
             "subject_ref": person, "grant": {"id": "11" * 32, "signer": "NWRD"},
             "cosign": {"id": mid("cosign"), "home": "PRAM", "home_in_code": True}, "media_hash": "aa" * 32}
    g = code_for(allow)
    assert g == event_code("PG-LIC", "NWRD", "PRAM", message_id=allow["cosign"]["id"]) and kind_of(g) == "generated"
    assert g.startswith("TOG-PG-LIC-NWRD-PRAM-") and "11" * 5 not in g     # the licence number is not in the code
    hidden = dict(allow, cosign=dict(allow["cosign"], home_in_code=False))
    assert parse(code_for(hidden))["home"] is None and issuer_of(code_for(hidden)) == "NWRD"
    assert verdict("aa" * 32, allow, g).startswith("fits: generated") and verdict("aa" * 32, allow, g).endswith(COVERS)
    assert verdict("aa" * 32, allow).startswith("fits")                    # proof, no caption
    assert verdict("aa" * 32, allow, person).startswith("fits")            # caption names the act's person
    assert verdict("bb" * 32, allow, g) == WORDS["other file"]             # no party name on a mismatch
    # An edit citing the real file as its C2PA ingredient: only the editor's claim. It names no one: no coverage line.
    assert verdict("bb" * 32, allow, g, ingredient="aa" * 32) == WORDS["edit claim"]
    assert verdict("bb" * 32, allow, g, ingredient="cc" * 32) == WORDS["other file"]
    # The home signs the act itself (its own sale, or an allow under standing terms): the home is the issuer and shows,
    # whatever home_in_code says. Hiding works only when a market issues.
    own = dict(allow, signer="KAST", subject_ref="TOG-KAST-9000000125",
               cosign={"id": allow["cosign"]["id"], "home": "KAST", "home_in_code": False})
    own = dict(own, grant={"id": "11" * 32, "signer": "KAST"})
    assert issuer_of(code_for(own)) == "KAST" and code_for(own).startswith("TOG-PG-LIC-KAST-")
    for lie in (dict(allow, cosign=dict(allow["cosign"], home="SKAN")), dict(allow, signer="HLWD"),
                dict(allow, type="pg.after_gen.v1"), dict(allow, cosign=dict(allow["cosign"], id=mid("other"))),
                dict(allow, grant=dict(allow["grant"], signer="HLWD")),   # a grant signed by another market
                dict(allow, grant=None)):                                # LIC claimed, the record says ToG terms
        assert verdict("aa" * 32, lie, g) == WORDS["code differs"], lie
    terms = dict(allow, grant=None)                                      # and the reverse: the marker dropped
    assert verdict("aa" * 32, terms, code_for(terms)).startswith("fits") and code_for(terms).startswith("TOG-PG-NWRD-")
    assert verdict("aa" * 32, allow, code_for(terms)) == WORDS["code differs"]
    _expect(ValueError, code_for, dict(allow, type="pg.grant.v1"))       # a licence has no basis marker
    # Readable copies in the file's metadata (pgag:Code, pgag:Licence; org.pregen.proof): recomputed, never trusted.
    lic_act = {"type": "pg.grant.v1", "id": allow["grant"]["id"], "signer": "NWRD", "subject_ref": person,
               "cosign": {"id": mid("grant", (("LIC", "NWRD", "PRAM"),)), "home": "PRAM", "home_in_code": True}}
    lic_code = code_for(lic_act)
    assert lic_code.startswith("TOG-LIC-NWRD-PRAM-")
    assert metadata_ok({"Code": g, "Licence": lic_code}, allow, lic_act) and metadata_ok({}, allow, lic_act)
    assert not metadata_ok({"Code": code_for(terms)}, allow, lic_act)              # not the recomputed code
    assert not metadata_ok({"Code": g, "Licence": lic_code[:-1] + "0"}, allow, lic_act)
    assert not metadata_ok({"Code": g, "Licence": lic_code}, allow)                # no grant at hand: cannot recompute
    assert metadata_ok({"Code": code_for(terms)}, terms)
    assert not metadata_ok({"Code": code_for(terms), "Licence": lic_code}, terms, lic_act)   # LIC copy, terms basis
    # 55-bit tails: two homes' cosigns can meet under one issuer when the home is hidden (here built by hand, in the
    # wild about N^2/2^56 for N codes). The home sees only its own; the issuer refuses a code it already issued.
    c1 = dict(hidden, cosign=dict(hidden["cosign"], home="PRAM"))
    c2 = dict(hidden, cosign=dict(hidden["cosign"], home="SKAN",
                                  id=hidden["cosign"]["id"][:14] + format(int(hidden["cosign"]["id"][14], 16) ^ 1, "x")
                                  + hidden["cosign"]["id"][15:]))
    assert c1["cosign"]["id"] != c2["cosign"]["id"] and code_for(c1) == code_for(c2)
    issued_codes = set()
    issue(code_for(c1), issued_codes)
    _expect(ValueError, issue, code_for(c2), issued_codes)
    # A market posing as the home: signs alone for a person it did not issue. No code at all.
    assert verdict("aa" * 32, dict(allow, signer="SKAN", cosign=None)) == WORDS["code differs"]
    _expect(ValueError, code_for, dict(allow, signer="SKAN", cosign=None))
    flat = dict(allow, signer="PRAM", cosign=None, grant=None)
    assert code_for(flat) == event_code("PG", "PRAM", message_id=allow["id"])
    assert code_for(dict(flat, subject_ref="PG-000042*")) == code_for(flat)   # the bare namespace is PRAM's
    assert code_for(dict(flat, subject_ref="TOG-000042*")) == code_for(flat)  # respelled: the same
    # A caption in one spelling, an old signed record in the other: one person (code_key), so the record fits.
    old_rec = dict(allow, subject_ref="PG-ZYXW-1234567R")
    assert verdict("aa" * 32, old_rec, "TOG-ZYXW-1234567R").startswith("fits")
    assert verdict("aa" * 32, dict(allow, subject_ref="TOG-ZYXW-1234567R"), "PG-ZYXW-1234567R").startswith("fits")
    real_l = next(event_code("LIC", "NWRD", "PRAM", tail=t) for t in (f"{n:011d}" for n in range(99))
                  if check_char(event_body("LIC", "NWRD", "PRAM", t)) in CROCKFORD)
    real_p = person
    assert verdict("aa" * 32, caption=real_p) == "This code names a subject. It says nothing about this file."
    assert verdict("aa" * 32, caption=real_l).startswith("This code names a license")
    assert verdict("aa" * 32, caption=g).startswith("Unchecked") and verdict("aa" * 32) == WORDS["no record"]
    assert verdict("aa" * 32, caption=g[:-1] + ("0" if g[-1] != "0" else "1")) == WORDS["mistyped"]
    home = Home("PRAM")
    home.sign(allow["cosign"]["id"])
    _expect(ValueError, home.sign, allow["cosign"]["id"])                  # one tail, one object, under any kind
    _expect(ValueError, event_code, "PG", "NWRD", "PRAM", "f" * 64)       # reserved example tail
    symbol = next(h for h in (hashlib.sha256(str(i).encode()).hexdigest() for i in range(999))
                  if check_char(event_body("PG", "NWRD", "PRAM", tail_of(h))) not in CROCKFORD)
    _expect(ValueError, event_code, "PG", "NWRD", "PRAM", symbol)         # symbol check: the issuer re-signs

    # 9. Party checks against the dated directory: a revoked or closed party is a fact, never "not a code".
    d = {k: dict(v) for k, v in DIRECTORY.items()}
    assert check_parties(ex["home + market"][1], d) == (True, ["issuer NWRD (Newroad)", "home PRAM (PRAMPTA Inc.)"])
    assert "HYBR also generated it (https://hybr.example)" in check_parties(ex["market + provider"][1], d,
                                                                              provider="https://hybr.example")[1]
    omni_front = _ex("PG-LIC", "NWRD", "OMNI")      # a home generating through a front market
    assert "OMNI also generated it (https://omni.example)" in check_parties(omni_front, d,
                                                                             provider="https://omni.example")[1]
    assert "issuer and home are one group" in check_parties(_ex("LIC", "LYONMK", "KOBEMK"), d)[1]
    for bad in (_ex("LIC", "TGOV"),                     # a home that does not sell, minting licences
                _ex("PG", "PRAM", "NWRD"),              # NWRD in the home slot
                _ex("LIC", "XXXX", "PRAM")):            # an unlisted issuer
        assert check_parties(bad, d)[0] is False, bad
    d["NWRD"] = dict(d["NWRD"], void_from=2029, closed=2029)
    ok, facts = check_parties(ex["home + market"][0], d)                 # string only: a warning, still a code
    assert ok and "NWRD listing void from 2029" in facts and "NWRD closed at 2029; ask the home" in facts
    assert check_parties(ex["home + market"][0], d, at=2027)[0]          # act before the revocation: stands
    assert not check_parties(ex["home + market"][0], d, at=2030)[0]      # act after it: fails
    d["KAST"] = dict(d["KAST"], roles={"home": (0, 2028), "market": ALWAYS})
    assert check_parties(ex["agency registry"][1], d, at=2027)[0]       # KAST stopped being a home later
    d["FAKEGOV"] = {"roles": {"home": ALWAYS}, "entity": "Not a government", "group": "g99"}
    assert check_parties(_ex_person("FAKEGOV", 900000001), d)[0] is False

    # 10. Admission: fixtures admissible in order; squatting, look-alikes, superstrings, words, markers, GOV both ways.
    built = {}
    for prefix, e in DIRECTORY.items():
        assert admission_refusal(prefix, e["entity"], e.get("government", False), built, reserved=()) == "", prefix
        built[prefix] = e
    for new, entity, gov in (("PRAN", "X", False), ("PRAMS", "X", False), ("PRMA", "X", False), ("BRAM", "X", False),
                             ("PPAM", "X", False), ("NWRO", "X", False), ("HLWO", "X", False), ("USGOV", "X", False),
                             ("CQVES", "X", False), ("SPAIN", "Spain", True), ("FRAME", "Newroad", False),
                             ("PRAM", "X", False), ("PRA", "X", False), ("KOBEMQ", "X", False),
                             ("PRAMPTA", "X", False), ("OMNIUM", "X", False), ("NWRDPRAM", "X", False),
                             ("HLVVD", "X", False), ("NVVRD", "X", False), ("TGOVX", "Y", True),
                             ("OFFICIAL", "X", False), ("VERIFIED", "X", False), ("LICENSED", "X", False),
                             ("LEGALCO", "X", False), ("PREGEN", "X", False), ("POLICE", "X", False),
                             ("HOMEX", "X", False), ("SHOPG", "X", False), ("TOGCO", "X", False),
                             ("ADULTCO", "X", False), ("NWRD", "X", False), ("LICX", "X", False),
                             ("LLCA", "X", False), ("IICO", "X", False), ("PGLIC", "X", False), ("AGLIC", "X", False),
                             ("PGAB", "X", False), ("AGENTS", "X", False), ("PCLIC", "X", False),
                             ("ACLIC", "X", False), ("TQGAB", "X", False), ("TOCAB", "X", False),
                             ("RGAB", "X", False), ("LJCA", "X", False), ("NLIC", "X", False), ("LGIC", "X", False),
                             ("LIZC", "X", False), ("ACMELIC", "X", False), ("NLJC", "X", False), ("LJGA", "X", False),
                             ("ACMELLC", "X", False)):
        assert admission_refusal(new, entity, gov, built) != "", new
    assert admission_refusal("ESGOV", "Spain", True, built) == ""
    assert admission_refusal("PORTO", "Porto", False, built) == ""                  # P + O is not a kind
    assert admission_refusal("KPGOV", "B", True, {"KRGOV": {"entity": "A"}}) != ""   # no exemption for governments
    assert admission_refusal("BRMKT", "B", False, {"JPMKT": {"entity": "J"}}) != ""  # formulaic names collide
    assert admission_refusal("VELR", "V", False, {}) != ""                          # fixtures reserved forever

    # 11. Persons are random: nothing to walk. The secret: never a code, never on a shareable surface.
    taken = set()
    minted = [mint_person("PRAM", taken, random.Random(7)) for _ in range(500)]
    assert len(set(minted)) == 500 and all(not parse(c)["example"] and c[-1] in CROCKFORD for c in minted)
    s = mint_secret()
    assert secret_ok(s) and secret_ok(EXAMPLE_SECRET) and not _valid(s) and s[-1] in CROCKFORD
    assert not secret_ok(s[:-1] + ("0" if s[-1] != "0" else "1"))
    assert "#" not in card_qr("https://resolver.example", minted[0]) and s not in card_qr("https://r.example", minted[0])
    url = recovery_qr("https://resolver.example", minted[0], s)
    assert url.split("#")[0] == card_qr("https://resolver.example", minted[0]) and "?" not in url

    # 12. Known fixtures that fail the check, with their correct spelling.
    found = {}
    for c in ("PG-PRAM-000123K", "PG-PRAM-000130M", "PG-PRAM-000456Q", "PG-PRAM-000789D", "PG-TEST-000001N"):
        try:
            parse(c)
        except Mistyped:
            found[c] = f"TOG-{c[3:7]}-{c[8:14]}{check_char(c[3:7] + c[8:14], CROCKFORD)}"   # the one spelling now
    stats["broken_fixtures"] = found
    return stats


if __name__ == "__main__":
    st = _self_check()
    for mix, codes in examples().items():
        print(f"{mix:44} " + "  ".join(codes))
    print("secret example:", EXAMPLE_SECRET)
    print("fixtures that fail the check -> correct spelling:", st.pop("broken_fixtures"))
    print("self-check passed:", st)
