#!/usr/bin/env python3
"""Generate spec/test-vectors/tog-generator.json (the ToG funnel's shared vectors, UNRELEASED) from the approved
reference spec/tools/tog_generator.py; contract: spec/drafts/tog-funnel.md.

Every rule and card value is computed by the reference; this file adds only what the funnel defines on top of it:
the `tog=v1` fragment (encode / strict decode: a person, a company, a minor's representative), the company card, the
common legal text every card links to (tog/1.0/legal-code.txt) and the registry chooser. Deterministic, no dependencies, about 25 s (the reference's own exhaustive check):

    python3 -I spec/tools/tog_generator_vectors.py > spec/test-vectors/tog-generator.json
"""
import base64
import hashlib
import json
import random
import re
import sys
from itertools import product
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import tog_generator as g  # noqa: E402

REFERENCE_SHA256 = "1e3c4cf745a27d02eb282bfa66ff0591ea39d611031bfe288972d3cb16ec1547"   # PRE-GEN-Drafts copy, 2026-11-09
_ref = (HERE / "tog_generator.py").read_bytes().split(b"\n", 2)[2]      # the copy minus its two header lines
if hashlib.sha256(_ref).hexdigest() != REFERENCE_SHA256:
    sys.exit("spec/tools/tog_generator.py is not the approved reference; copy it again, do not edit it here")

# ---- the fragment `tog=v1` (PLAN §2.1) ----------------------------------------------------------------------------
AGES = ("18+", "13-17")             # 13-17 only ever decodes as "minor": a representative registers a minor
WHO = ("company", "child")          # a person answering for themself has no `who`
LEGAL = {"id": "ToG-1.0", "sha256": hashlib.sha256((HERE.parents[1] / "tog" / "1.0" / "legal-code.txt").read_bytes())
         .hexdigest(), "url": "https://www.pregen.org/tog/1.0"}
DECISIONS = ("no", "approve_all", "rules")
FLOORS = ("each", "project", "video")
MAX_FRAGMENT = 1024


def _canon(a) -> str:
    return json.dumps(a, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def _b64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).rstrip(b"=").decode()


def _ordered(v, keys) -> bool:
    """A list of known keys in the reference's own order, no duplicates."""
    return type(v) is list and all(type(x) is str and x in keys for x in v) and v == [k for k in keys if k in v]


def who_ok(a) -> bool:
    """A company's or a minor's representative's answers: never an age, a domain or a name; a minor's only a no."""
    if a["who"] == "child":
        return set(a) == {"who", "decision"} and a["decision"] == "no"
    if a["who"] != "company" or type(a.get("decision")) is not str or a["decision"] not in DECISIONS:
        return False
    if a["decision"] == "no":
        return set(a) == {"who", "decision"}
    return set(a) == {"who", "decision", "for", "never"} and _ordered(a["for"], g.FOR) and bool(a["for"]) \
        and _ordered(a["never"], g.NEVER)


def answers_ok(a) -> bool:
    """The exact member set for the decision, every value in its closed set (age rule not applied here)."""
    if type(a) is dict and "who" in a:
        return who_ok(a)
    if type(a) is not dict or type(a.get("age")) is not str or a["age"] not in AGES \
            or type(a.get("decision")) is not str or a["decision"] not in DECISIONS:
        return False
    if a["decision"] == "no":
        return set(a) == {"age", "decision"}
    f = a.get("for")
    if not _ordered(f, g.FOR) or not f or not _ordered(a.get("never"), g.NEVER) or type(a.get("voice")) is not bool:
        return False
    paid = "paid" in f
    if set(a) != {"age", "decision", "for", "never", "voice"} | ({"floor"} if paid else set()):
        return False
    return not paid or (type(a["floor"]) is str and a["floor"] in FLOORS)


def encode(a: dict) -> str:
    """Fragment without the leading '#'. The encoder never makes a minor's own answers."""
    assert answers_ok(a) and a.get("age") != "13-17", a
    f = "tog=v1." + _b64(_canon(a))
    assert len(f) <= MAX_FRAGMENT
    return f


def decode(f) -> dict:
    """Strict, never repairs (rule 6): {"result": "ok", "answers"} | unknown_version | malformed | minor."""
    bad = {"result": "malformed"}
    if type(f) is not str or len(f) > MAX_FRAGMENT or not f.startswith("tog="):
        return bad
    if not f.startswith("tog=v1."):
        return {"result": "unknown_version"}
    p = f[len("tog=v1."):]
    if not re.fullmatch(r"[A-Za-z0-9_-]*", p):
        return bad
    try:
        a = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)).decode("utf-8"))
    except ValueError:                       # binascii.Error, UnicodeDecodeError, JSONDecodeError
        return bad
    if not answers_ok(a) or "tog=v1." + _b64(_canon(a)) != f:   # canonical bytes and canonical base64 only
        return bad
    if a.get("age") == "13-17":            # only a parent, guardian or representative registers a minor
        return {"result": "minor"}
    return {"result": "ok", "answers": a}


def rules_of(a: dict) -> dict:
    """Fragment answers -> rules (age and floor do not enter the rules)."""
    return g.rules_from_answers({k: a[k] for k in ("decision", "for", "never", "voice") if k in a})


# ---- the company card and statement body (PLAN §3.1, draft wording, en) -------------------------------------------
_CO = "our marks, products and characters"
CO_L = {**{k: (v["1"] if isinstance(v, dict) else v) for k, v in g.L["en"].items()},
        "no": "**No AI generation of our marks, products or characters.**",
        "no2": "Not for fun, not for news, not for ads, and no training of AI models on our marks.",
        "all_approve": f"AI may make {_CO} **only with our approval of each one**.",
        "only": f"AI may make {_CO} **only for {{list}}**.",
        "mixed": f"AI may make {_CO} for {{open}}, and **for {{approve}} only with our approval of each one**.",
        "paid": "Ads and paid work: only under a deal we sign.",
        "endorsement": "\"we recommend it\" (endorsements)",
        "advertising+endorsement": "ads and \"we recommend it\" (endorsements)", "3d": "3D",
        "train_no": "Training AI models on our marks: no.",
        "real": "Never presented as our own advertising or statement.",
        "except": "Exceptions only by a deal we sign, and never for sexual or adult content.",
        "binds": "This covers only what we own. It never licenses any real person shown with it. It does not stop uses "
                 "the law allows without a licence."}
CO_MODALITIES = ["3d", "image", "video"]


def company_rules(a: dict) -> dict:
    """Company answers {decision, for, never}: the person's rules with forms pictures, video, 3D (no voice question)."""
    r = g.rules_from_answers({**a, "voice": False})
    return r if not r["uses"] else g.validate({**r, "modalities": CO_MODALITIES})


def card_company(r: dict) -> list:
    """card()'s structure for profile marks/1 (draft): no voice line, the company lines."""
    t = CO_L
    assert not r["training"] and set(r["modalities"]) <= set(CO_MODALITIES)
    if not r["uses"]:
        return [t["no"], t["no2"], t["except"], t["binds"]]
    ps = lambda modes: g._join(g._items({p for p, m in r["uses"].items() if m in modes}, g.PURPOSE_ORDER, t,
                                        lambda grp: "rnd" if len(grp) == 3 else grp[0]), t)
    modes = set(r["uses"].values())
    if modes == {"approve"}:
        lines = [t["all_approve"], t["for"].format(list=ps({"approve"}))]
    elif modes == {"open"}:
        lines = [t["only"].format(list=ps({"open"}))]
    else:
        lines = [t["mixed"].format(open=ps({"open"}), approve=ps({"approve"}))]
    if "commercial" in r["uses"]:
        lines.append(t["paid"])
    lines.append(t["as"].format(list=g._join(g._items(set(r["modalities"]), g.MODALITY_ORDER, t), t, ", ")))
    lines.append(t["never"].format(list=g._join(g._items(set(r["excluded_categories"]), g.CATEGORY_ORDER, t), t)))
    return lines + [t["train_no"], t["real"], t["except"], t["binds"]]


# PLAN §1.1: every screen that names the legal text says it is a draft until the founder freezes it.
DRAFT = {"en": ("legal text prampta-likeness v2 ·", "legal text prampta-likeness v2 (draft) ·"),
         "ru": ("юридический текст prampta-likeness v2 ·", "юридический текст prampta-likeness v2 (черновик) ·")}


def frame_shown(r, lang, *a) -> list:
    """The reference frame() with the draft mark on the meta line."""
    lines = g.frame(r, lang, *a)
    old, new = DRAFT[lang]
    assert lines[-1].count(old) == 1
    return lines[:-1] + [lines[-1].replace(old, new)]


# ---- the registry chooser (PLAN §2.2) -----------------------------------------------------------------------------
LOCAL_HOSTS = ("localhost", "127.0.0.1")


def _origin(u, local: bool):
    """(scheme, host, port) of an https URL (http only for localhost in local mode); None if refused."""
    try:
        s = urlsplit(u) if type(u) is str else None
        if not s or not s.hostname or s.username is not None or s.password is not None:
            return None
        if not (s.scheme == "https" or (local and s.scheme == "http" and s.hostname in LOCAL_HOSTS)):
            return None
        return s.scheme, s.hostname, s.port or {"https": 443, "http": 80}[s.scheme]
    except ValueError:
        return None


def offered(registries: list, local: bool) -> list:
    out = []
    for e in registries:
        start = e.get("tog_start")
        o = _origin(start, local)
        if (e.get("prefix") and e.get("revoked") is None and o and o == _origin(e.get("website"), local)
                and not urlsplit(start).query and "#" not in start):
            out.append({"name": e["name"], "prefix": e["prefix"], "start": start})
    return out


# ---- vectors --------------------------------------------------------------------------------------------------------
def L(t):
    return list(t)


def answer_sets():
    """~120 reference answer sets (input of rules_from_answers), named."""
    fors = [tuple(k for k, b in zip(g.FOR, bits) if b) for bits in product((False, True), repeat=len(g.FOR))][1:]
    out = [("NO", {"decision": "no"}),
           ("nothing ticked on Q2 is no", {"decision": "rules", "for": [], "never": [], "voice": False})]
    for d, v, f in product(("rules", "approve_all"), (False, True), fors):
        out.append((f"default {d} voice={v} for={'+'.join(f)}",
                    {"decision": d, "for": L(f), "never": L(g.default_never(f)), "voice": v}))
    for f, chip in product(fors, g.NEVER):
        d = set(g.default_never(f)) ^ {chip}
        out.append((f"default rules for={'+'.join(f)} flip {chip}",
                    {"decision": "rules", "for": L(f), "never": [k for k in g.NEVER if k in d], "voice": False}))
    for name in ("NEWS", "FANS", "ADS"):
        p = g.PRESETS[name]
        out.append((name, {**p, "for": L(p["for"]), "never": L(p["never"])}))
    rng = random.Random(20261110)
    for i in range(16):
        f = rng.choice(fors)
        out.append((f"random {i}", {"decision": rng.choice(("rules", "approve_all")), "for": L(f),
                                    "never": [k for k in g.NEVER if rng.random() < 0.5], "voice": rng.random() < 0.5}))
    return out


def main():
    g._check()                                                   # the reference's exhaustive self-check first
    sets = answer_sets()
    answers = [{"name": n, "answers": a, "rules": g.rules_from_answers(a),
                "card": {lang: g.card(g.rules_from_answers(a), lang, "1") for lang in ("en", "ru")}} for n, a in sets]

    never_lines = []
    for bits in product((False, True), repeat=len(g.NEVER)):
        chips = [k for k, b in zip(g.NEVER, bits) if b]
        r = g.rules_from_answers({"decision": "rules", "for": ["fun"], "never": chips, "voice": False})
        line = {lang: g.card(r, lang, "1")[2] for lang in ("en", "ru")}
        assert line["en"].startswith("Never: ") and line["ru"].startswith("Никогда: ")
        never_lines.append({"never": chips, **line})

    codes = {"NO, unconfirmed": "TOG-PRAM-9000001233", "NO, filed for someone else and confirmed": "TOG-PRAM-900000130D",
             "NEWS": "TOG-PRAM-9000004560", "ADS": "TOG-PRAM-9000007903"}
    frames = []
    for (title, code), (preset, v, level, display) in zip(codes.items(), (
            ("NO", 1, "claimed", None), ("NO", 1, "verified", None), ("NEWS", 1, "verified", "Anna Karpova"),
            ("ADS", 2, "channel-official", "@mila.models"))):
        r, tid = g.rules_from_answers(g.PRESETS[preset]), hashlib.sha256(code.encode()).hexdigest()[:12]
        frames.append({"name": title, "rules": r, "who": "1", "code": code, "version": v, "level": level,
                       "display": display, "terms_id": tid, "date": {"en": "9 NOV 2026", "ru": "9 НОЯБРЯ 2026"},
                       "lines": {lang: frame_shown(r, lang, "1", code, v, date, tid, level, display)
                                 for lang, date in (("en", "9 NOV 2026"), ("ru", "9 НОЯБРЯ 2026"))}})

    for bad in g.REJECT:
        try:
            g.validate(bad)
            raise AssertionError(bad)
        except ValueError:
            pass
    assert len(g.REJECT) == 28

    levels = ("claimed", "channel", "channel-official", "verified")
    named = {n: g.rules_from_answers(p) for n, p in g.PRESETS.items()}
    named["ADS without politics excluded"] = {**named["ADS"], "excluded_categories": [
        c for c in named["ADS"]["excluded_categories"] if c != "political"]}
    named["ADS with training"] = {**named["ADS"], "training": True}
    policy = {"levels": L(levels),
              "rules": [{"name": n, "rules": r, "prampta_policy": g.prampta_policy(r),
                         "may_sign": {lv: {"by_person": g.may_sign(r, lv, True), "by_other": g.may_sign(r, lv, False)}
                                      for lv in levels}} for n, r in named.items()],
              "opens": [{"old": o, "new": n, "opens": g.opens(o and named[o], named[n])}
                        for o in (None, *g.PRESETS) for n in g.PRESETS]}

    # fragment.encode: every encodable answer set as an adult, floors in turn; the two exact examples of PLAN §2.1
    enc, i = [], 0
    for n, a in [("NO", {"age": "18+", "decision": "no"})] + [(n, {"age": "18+", **a}) for n, a in sets[2:]]:
        if "paid" in a.get("for", ()):
            a, i = {**a, "floor": FLOORS[i % 3]}, i + 1
        enc.append({"name": n, "answers": a, "fragment": encode(a)})
    assert enc[0]["fragment"] == "tog=v1.eyJhZ2UiOiIxOCsiLCJkZWNpc2lvbiI6Im5vIn0"
    ads = {"age": "18+", "decision": "rules", "floor": "each", "for": ["fun", "news", "paid"], "voice": False,
           "never": ["vice", "weapons", "violence", "gambling", "money", "health", "religion", "endorse"]}
    assert len(encode(ads)) - len("tog=") == 238 and any(e["answers"] == ads for e in enc)
    co_ads = {"who": "company", "decision": "rules", "for": ["fun", "news", "paid"], "never": ["vice", "endorse"]}
    for n, a in [("company NO", {"who": "company", "decision": "no"}), ("company ADS", co_ads),
                 ("company approve_all", {"who": "company", "decision": "approve_all", "for": ["paid"], "never": []}),
                 ("a minor's representative: NO", {"who": "child", "decision": "no"})]:
        enc.append({"name": n, "answers": a, "fragment": encode(a)})
    biggest = {"age": "18+", "decision": "approve_all", "for": L(g.FOR), "never": L(g.NEVER), "voice": True,
               "floor": "project"}

    no = encode({"age": "18+", "decision": "no"})
    p_no = no[len("tog=v1."):]
    raw = lambda s: "tog=v1." + base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")
    rawb = lambda b: "tog=v1." + base64.urlsafe_b64encode(b).decode().rstrip("=")
    ads_wo = lambda **kw: _canon({**{k: v for k, v in ads.items() if k not in kw.get("drop", ())},
                                  **{k: v for k, v in kw.items() if k != "drop"}})
    cases = [
        ("ok: no, adult", no), ("minor: a 13-17 no", raw('{"age":"13-17","decision":"no"}')), ("ok: ADS", encode(ads)),
        ("ok: everything ticked, the longest fragment", encode(biggest)),
        ("v2.", "tog=v2." + p_no), ("V1.", "tog=V1." + p_no), ("no dot after v1", "tog=v1" + p_no),
        ("tog= alone", "tog="),
        ("empty", ""), ("other key", "toq=v1." + p_no), ("empty payload", "tog=v1."),
        ("padding", no + "="), ("standard base64 +", no[:-2] + "+" + no[-1]),
        ("standard base64 /", no[:-2] + "/" + no[-1]),
        ("a query glued on", no + "&x=1"), ("trailing space", no + " "),
        ("non-canonical trailing bits", no[:-1] + "1"), ("one character flipped", no[:20] + "x" + no[21:]),
        ("spaces in JSON", raw(json.dumps({"age": "18+", "decision": "no"}, sort_keys=True))),
        ("key order", raw('{"decision":"no","age":"18+"}')),
        ("duplicate key", raw('{"age":"18+","age":"18+","decision":"no"}')),
        ("escaped letter", raw('{"age":"18+","decision":"n\\u006f"}')),
        ("not UTF-8", rawb(b'{"age":"18+","decision":"\xff"}')), ("not an object", raw("[]")),
        ("extra member on a no", raw('{"age":"18+","decision":"no","voice":false}')),
        ("extra member name", raw(_canon({**ads, "name": "x"}))),
        ("missing voice", raw(ads_wo(drop=("voice",)))), ("missing age", raw('{"decision":"no"}')),
        ("voice: 0", raw(ads_wo(voice=0))), ("for: [] with a yes", raw(ads_wo(drop=("floor",), **{"for": []}))),
        ("for: [ads]", raw(ads_wo(drop=("floor",), **{"for": ["ads"]}))),
        ("unsorted for", raw(ads_wo(**{"for": ["news", "fun", "paid"]}))),
        ("unsorted never", raw(ads_wo(never=["weapons", "vice"]))),
        ("duplicate chip", raw(ads_wo(never=["vice", "vice"]))),
        ("floor without paid", raw(ads_wo(**{"for": ["fun", "news"]}))),
        ("paid without floor", raw(ads_wo(drop=("floor",)))), ("floor amount", raw(ads_wo(floor="50"))),
        ("decision maybe", raw('{"age":"18+","decision":"maybe"}')), ("age 12", raw('{"age":"12","decision":"no"}')),
        ("teen yes", raw(_canon({**ads, "age": "13-17"}))),
        ("1025 chars, v1", "tog=v1." + "A" * (MAX_FRAGMENT + 1 - len("tog=v1."))),
        ("1025 chars, v2", "tog=v2." + "A" * (MAX_FRAGMENT + 1 - len("tog=v2."))),
        ("ok: company no", encode({"who": "company", "decision": "no"})), ("ok: company ADS", encode(co_ads)),
        ("ok: a minor's representative, no", encode({"who": "child", "decision": "no"})),
        ("a minor's representative: a yes", raw(_canon({**co_ads, "who": "child"}))),
        ("a minor's representative with an age", raw('{"age":"13-17","decision":"no","who":"child"}')),
        ("company with an age", raw('{"age":"18+","decision":"no","who":"company"}')),
        ("company with a voice", raw(_canon({**co_ads, "voice": False}))),
        ("company with a floor", raw(_canon({**co_ads, "floor": "each"}))),
        ("company with a domain", raw('{"decision":"no","domain":"northwind.example","who":"company"}')),
        ("company yes, for: []", raw(_canon({**co_ads, "for": []}))),
        ("company yes without never", raw(_canon({k: v for k, v in co_ads.items() if k != "never"}))),
        ("who: brand", raw('{"decision":"no","who":"brand"}')), ("who: me", raw('{"decision":"no","who":"me"}')),
    ]
    dec = [{"name": n, "fragment": f, **decode(f)} for n, f in cases]
    want = {"ok": 6, "unknown_version": 4, "minor": 2}
    got = {r: sum(d["result"] == r for d in dec) for r in ("ok", "unknown_version", "minor", "malformed")}
    assert all(got[k] == v for k, v in want.items()) and got["malformed"] == len(cases) - 12, got
    assert all(decode(e["fragment"]) == {"result": "ok", "answers": e["answers"]} for e in enc)

    co_sets = [("NO", {"decision": "no"}), ("nothing ticked on Q2 is no", {"decision": "rules", "for": [], "never": []})]
    fors = [list(f) for f in ([("fun",), ("news",), ("paid",), ("fun", "news"), ("fun", "paid"), ("news", "paid"),
                               ("fun", "news", "paid")])]
    co_sets += [(f"default {d} for={'+'.join(f)}", {"decision": d, "for": f, "never": L(g.default_never(tuple(f)))})
                for d, f in product(("rules", "approve_all"), fors)]
    co_sets += [("no chip", {"decision": "rules", "for": ["fun", "news"], "never": []}),
                ("every chip", {"decision": "rules", "for": ["fun", "news", "paid"], "never": L(g.NEVER)}),
                ("ads chip with paid", {"decision": "approve_all", "for": ["paid"], "never": ["ads", "fashion"]}),
                ("vice only", {"decision": "rules", "for": ["news"], "never": ["vice"]})]
    company = []
    for n, a in co_sets:
        r = company_rules(a)
        c = card_company(r)
        assert sum(line.count("**") for line in c) == 2
        company.append({"name": n, "answers": a, "rules": r, "card": {"en": c}})
    assert len({tuple(c["card"]["en"]) for c in company}) == len({json.dumps(c["rules"]) for c in company})

    def reg(**kw):
        return {"name": "PRAMPTA", "prefix": "PRAM", "website": "https://prampta.com",
                "tog_start": "https://prampta.com/start", **kw}
    local = {"name": "PRAMPTA", "prefix": "PRAM", "website": "http://localhost:3100",
             "tog_start": "http://localhost:3100/start"}
    ch = [("PRAM offered", False, [reg()]),
          ("no tog_start", False, [{k: v for k, v in reg().items() if k != "tog_start"}]),
          ("no website", False, [{k: v for k, v in reg().items() if k != "website"}]),
          ("tog_start not a string", False, [reg(tog_start=123)]),
          ("http", False, [reg(tog_start="http://prampta.com/start")]),
          ("javascript:", False, [reg(tog_start="javascript:alert(1)")]),
          ("other origin: the API host", False, [reg(tog_start="https://api2.prampta.com/start")]),
          ("look-alike host", False, [reg(tog_start="https://prampta.com.evil.example/start")]),
          ("other port", False, [reg(tog_start="https://prampta.com:8443/start")]),
          ("default port written out", False, [reg(tog_start="https://prampta.com:443/start")]),
          ("host in capitals", False, [reg(tog_start="https://PRAMPTA.com/start")]),
          ("credentials", False, [reg(tog_start="https://user@prampta.com/start")]),
          ("query", False, [reg(tog_start="https://prampta.com/start?ref=pregen")]),
          ("fragment", False, [reg(tog_start="https://prampta.com/start#tog")]),
          ("bare legacy prefix", False, [reg(prefix="")]),
          ("revoked registry", False, [reg(revoked={"at": "2026-11-01"})]),
          ("localhost outside local mode", False, [local]),
          ("localhost in local mode", True, [local]),
          ("127.0.0.1 in local mode", True, [{**local, "website": "http://127.0.0.1:3100",
                                               "tog_start": "http://127.0.0.1:3100/start"}]),
          ("localhost, other port", True, [{**local, "tog_start": "http://localhost:3200/start"}]),
          ("http on a public host in local mode", True, [reg(website="http://prampta.com",
                                                             tog_start="http://prampta.com/start")]),
          ("https still offered in local mode", True, [reg()]),
          ("directory order kept, legacy skipped", False, [reg(prefix=""), reg(), {
              "name": "Example Registry", "prefix": "ABCD", "website": "https://registry.example",
              "tog_start": "https://registry.example/tog"}])]
    chooser = [{"name": n, "local": lc, "registries": rs, "offered": offered(rs, lc)} for n, lc, rs in ch]

    out = {
        "description": "UNRELEASED. ToG funnel shared vectors (PRE-GEN-Drafts/tog-funnel/PLAN.md §2-§3). Generated by "
                       "spec/tools/tog_generator_vectors.py from the approved reference spec/tools/tog_generator.py; "
                       "do not edit by hand. Cards are body lines with ** around the one bold phrase; frames are DESIGN "
                       "§4.2's four cards with TOG-PRAM codes (PG codes are retired) and '(draft)' on the meta line "
                       "(PLAN §1.1). A fragment is "
                       "location.hash without the leading '#'. Company wording and profile marks/1 are drafts. Every "
                       "card links the one common legal text, meta.legal.",
        "meta": {"reference_sha256": REFERENCE_SHA256, "profile": "likeness/2", "vocab": L(g.VOCAB),
                 "floor": L(g.FLOOR), "registry_lock": L(g.REGISTRY_LOCK), "purposes": L(g.PURPOSES),
                 "modes": L(g.MODES), "modalities": L(g.MODALITIES),
                 "for": {k: L(v) for k, v in g.FOR.items()}, "never": {k: L(v) for k, v in g.NEVER.items()},
                 "fragment": {"prefix": "tog=", "version": "v1.", "max_length": MAX_FRAGMENT,
                              "longest_encoded": len(encode(biggest)), "ages": L(AGES), "who": L(WHO),
                              "decisions": L(DECISIONS), "floors": L(FLOORS)},
                 "company": {"profile": "marks/1", "modalities": CO_MODALITIES}, "legal": LEGAL},
        "answers": answers, "never_lines": never_lines, "frames": frames,
        "reject_rules": g.REJECT, "policy": policy,
        "fragment": {"encode": enc, "decode": dec},
        "company": company, "chooser": chooser,
    }
    print(json.dumps(out, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
