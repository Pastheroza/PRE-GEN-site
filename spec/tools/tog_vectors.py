#!/usr/bin/env python3
"""Generate spec/test-vectors/tog-code.json (TOG-CODE.md §10) from the reference model spec/tools/tog_code.py.

Every value is computed by the model; nothing here decides a result. Deterministic, no dependencies:

    python3 -I spec/tools/tog_vectors.py > spec/test-vectors/tog-code.json

Run the model's own exhaustive self-check first (python3 -I spec/tools/tog_code.py, about 6 s).
"""
import ast
import hashlib
import json
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tog_code as t  # noqa: E402

ERR = {t.NotACode: "malformed", t.Mistyped: "mistyped"}


def run(fn, *a):
    """{"result": …} or {"error": "malformed" | "mistyped" | "no_code"}; "message" when a typed PG string gets the
    one retired message."""
    try:
        return {"result": fn(*a)}
    except (t.NotACode, t.Mistyped) as e:
        out = {"error": ERR[type(e)]}
        if str(e).startswith("ambiguous: "):
            out["hints"] = ast.literal_eval(str(e)[len("ambiguous: "):])
        if str(e) == t.RETIRED:
            out["message"] = t.RETIRED
        return out
    except ValueError:
        return {"error": "no_code"}


def run_record(fn, *a):
    """A record gives a code or none: every refusal of a record is no_code (a PG id in it included)."""
    try:
        return {"result": fn(*a)}
    except (KeyError, ValueError):
        return {"error": "no_code"}


def msgid(s):
    return hashlib.sha256(s.encode()).hexdigest()


def body_of(code):
    p = t.parse(code)
    if p["shape"] == "event":
        kind = code.split("-")[1] + ("-LIC" if code.split("-")[2] == "LIC" and code.split("-")[1] != "LIC" else "")
        tail = code[-14:].replace("-", "")[:-1]
        return t.event_body(kind, p["issuer"], p["home"], tail)
    return p["issuer"] + p["serial"]


def published():
    """Every PG string the published spec and its vectors hold (as in the model's self-check, step 1)."""
    out = ["PG-0000016", "PG-000042*", "PG-099999*", "PG-9999994", "PG-10000001", "PG-12345678K",
           "PG-STD-000001-K7M2QX9", "PG-RND-000042-ZZZZZZ1", "PG-PRM-999999-0000000", "PG-NWRD-000042=",
           "PG-NWRD-RND-000042-ZZZZZZJ", "PG-PRAM-000037J", "PG-ZYXW-1234567R", "PG-ABCD-PRM-1234567-A1B2C3A",
           "PG-STD-000123", "PG-SUB-000123", "PG-TEST-000001N"]
    v = json.load(open(Path(__file__).resolve().parents[1] / "test-vectors" / "vectors.v2.json"))["pg_code"]
    out += [x["code"] for x in v["subject_code"] + v["issuer_subject_code"]]
    out += [x["license_id"] for x in v["license_id"] + v["issuer_license_id"]]
    return list(dict.fromkeys(out))


def old_licence_record(c):
    """A stand-in for the signed pg.license.v2 behind an old licence id, as its own registry holds it (grants.md
    "Older licences"): its message id here is a hash of the id; a real one is SHA-256 over body, subject signature and
    the id. Flat model. Only the registry's own migration reads it; no verifier accepts it."""
    iss = c.split("-")[1] if len(c.split("-")[1]) == 4 else ""
    n = ""
    while True:
        rec = {"type": "pg.license.v2", "id": msgid(c + n), "signer": iss or t.BARE_ISSUER,
               "subject_ref": f"PG-{iss + '-' if iss else ''}000042" + t.check_char(iss + "000042", t.CROCKFORD),
               "license_id": c}
        if "result" in run_record(t.registry_migrate, c, rec):
            return rec
        n += "'"


def mid(s, uses=(("PG-LIC", "NWRD", "PRAM"), ("PG-LIC", "NWRD", None), ("PG-LIC", "KAST", None))):
    while True:
        h = msgid(s)
        if all("result" in run(t.event_code, k, i, hm, h) for k, i, hm in uses):
            return h
        s += "'"


def acts():
    """The acts of the model's self-check step 8, named."""
    person = t.mint_person("NWRD", set(), random.Random(1))   # a real-shaped person under a fixture prefix
    allow = {"type": "pg.answer.v1", "id": mid("allow", (("PG", "PRAM", None),)), "signer": "NWRD",
             "subject_ref": person, "grant": {"id": "11" * 32, "signer": "NWRD"},
             "cosign": {"id": mid("cosign"), "home": "PRAM", "home_in_code": True}, "media_hash": "aa" * 32}
    hidden = dict(allow, cosign=dict(allow["cosign"], home_in_code=False))
    own = dict(allow, signer="KAST", subject_ref="TOG-KAST-9000000125", grant={"id": "11" * 32, "signer": "KAST"},
               cosign={"id": allow["cosign"]["id"], "home": "KAST", "home_in_code": False})
    terms = dict(allow, grant=None)
    flat = dict(allow, signer="NWRD", cosign=None, grant=None)
    lic = {"type": "pg.grant.v1", "id": allow["grant"]["id"], "signer": "NWRD", "subject_ref": person,
           "cosign": {"id": mid("grant", (("LIC", "NWRD", "PRAM"),)), "home": "PRAM", "home_in_code": True}}
    c1 = dict(hidden, cosign=dict(hidden["cosign"], home="PRAM"))
    cid = hidden["cosign"]["id"]
    c2 = dict(hidden, cosign=dict(hidden["cosign"], home="SKAN",
                                  id=cid[:14] + format(int(cid[14], 16) ^ 1, "x") + cid[15:]))
    old = old_licence_record("PG-NWRD-RND-000042-ZZZZZZJ")
    sym = next(h for h in (msgid(str(i)) for i in range(999))
               if t.check_char(t.event_body("LIC", "NWRD", None, t.tail_of(h))) not in t.CROCKFORD)
    cs = next(h for h in (msgid("cs" + str(i)) for i in range(999))
              if t.check_char(t.event_body("LIC", "NWRD", None, t.tail_of(h))) in t.CROCKFORD)
    old_allow = {"type": "pg.answer.v1", "id": msgid("old allow"), "signer": "NWRD", "subject_ref": "PG-NWRD-000042=",
                 "grant": {"id": old["id"], "signer": "NWRD"}}
    return {
        "allow under a licence, home shown": allow,
        "allow under a licence, home hidden": hidden,
        "the home signs its own sale: issuer, shown whatever home_in_code says": own,
        "allow under the person's terms": terms,
        "flat model: the person's own registry signs alone": flat,
        "flat model, a PG subject_ref: no code": dict(flat, signer="PRAM", subject_ref="PG-000042*"),
        "flat model, bare person respelled": dict(flat, signer="PRAM", subject_ref="TOG-000042*"),
        "flat model, bare person, another signer": dict(flat, subject_ref="TOG-000042*"),
        "licence (pg.grant.v1) countersigned by the home": lic,
        "a licence names no basis": dict(allow, type="pg.grant.v1"),
        "a market signs alone for a person it did not issue": dict(allow, signer="SKAN", cosign=None),
        "the grant behind the act signed by another market": dict(allow, grant=dict(allow["grant"], signer="HLWD")),
        "after-gen record under a licence": dict(allow, type="pg.after_gen.v1"),
        "two homes' countersignatures meet under one issuer (1)": c1,
        "two homes' countersignatures meet under one issuer (2): the issuer refuses the second": c2,
        "old pg.license.v2: its bytes hold a PG id, no code": old,
        "old pg.license.v2, countersigned by its home: still no code": dict(old, id=sym, cosign={
            "id": cs, "home": "NWRD", "home_in_code": True}),
        "an old allow naming a PG person and an old licence: no code": old_allow,
    }, allow, terms, lic, person


def parties_directories():
    def entry(e):
        out = {"entity": e["entity"], "group": e["group"], "government": e.get("government", False),
               "roles": {r: {"from": s[0], "until": s[1]} for r, s in e["roles"].items()},
               "provider_domains": sorted(e.get("provider_domains", ()))}
        for k in ("void_from", "closed"):
            if k in e:
                out[k] = e[k]
        return out
    base = {k: dict(v) for k, v in t.DIRECTORY.items()}
    later = {k: dict(v) for k, v in t.DIRECTORY.items()}
    later["NWRD"] = dict(later["NWRD"], void_from=2029, closed=2029)
    later["KAST"] = dict(later["KAST"], roles={"home": (0, 2028), "market": t.ALWAYS})
    later["FAKEGOV"] = {"roles": {"home": t.ALWAYS}, "entity": "Not a government", "group": "g99"}
    return base, later, {"base": {k: entry(v) for k, v in base.items()},
                         "later": {k: entry(v) for k, v in later.items()}}


def main():
    ex = t.examples()
    assert ex == t.PINNED
    pinned = [c for cs in ex.values() for c in cs]
    pub = published()
    out = {
        "description": "TOG-CODE.md: the ToG code family. Generated by spec/tools/tog_vectors.py from the reference "
                       "model spec/tools/tog_code.py; do not edit by hand. Errors: malformed (not a code), mistyped "
                       "(the check fails), no_code (a record that gives no code). A PG- string is not a code "
                       "anywhere; typed, it gets `message`, the one retired message, and no TOG suggestion. "
                       "`migrate` is a registry's own migration of its own rows; `proxy` is pregen.org's lookup "
                       "proxy shim. Times in `parties` are plain ordered numbers.",
        "alphabet": {"crockford": t.CROCKFORD, "tog_values": t.VALUES, "check": t.CHECK,
                     "max_body": t.MAX_BODY, "max_new_body": t.MAX_NEW_BODY, "tail_symbols": t.TAIL,
                     "kind_digit": {k: i + 1 for i, k in enumerate(t.FIVE)},
                     "reserved_serial": t.RESERVED_SERIAL, "reserved_tail": t.RESERVED_TAIL,
                     "bare_issuer": t.BARE_ISSUER, "fixture_prefixes": list(t.FIXTURES)},
        "examples": ex,
    }

    # Check characters: every pinned body, both tables. null = the body is outside that table: it never verifies.
    bodies = [body_of(c) for c in pinned] + ["TILU142000000", "OSLU900000000", "OWN000001K7M2QX", "ZYXW1234567",
                                              "000042", "PRAM90000003"]
    out["check_char"] = [{"body": b, "tog": run(t.check_char, b).get("result"),
                          "pg": run(t.check_char, b, t.CROCKFORD).get("result")} for b in dict.fromkeys(bodies)]

    # parse(): the one reading of a string exactly as it stands in a message.
    edge = [t._ex_person("ZZZZZZZZ", 899999990), t._ex_person("TILU", 142000000), t._ex_person("GOVTEST", 123456789),
            t._ex("PG-LIC", "ABCDEFGH", "JKMNPQRS"), t._ex("LIC", "PRAL", "OSLU"), t._ex("AG-LIC", "TILU", "UOLI"),
            t._ex("PG", "PRAMU"), t._ex("AG", "ABCD", "EFGH"), t._ex("PG-LIC", "ABCDE"),
            t._ex_person("PRAM", 900000000), t._ex_person("PRAM", 899999000), "TOG-NWRD-000042=", "TOG-SUB-000123"]
    out["parse"] = [dict({"code": c}, **(lambda r: {"parsed": r["result"]} if "result" in r else r)(run(t.parse, c)))
                    for c in dict.fromkeys(pinned + edge + pub)]

    # describe(): what a string claims, for support tools; never shown beside a video.
    out["describe"] = [dict({"code": c}, **run(t.describe, c))
                       for c in dict.fromkeys(pinned + edge + pub + [s for s, *_ in t.must_reject()[:3]])]

    out["must_reject"] = [{"string": s, "error": ERR[e], "why": why} for s, e, why in t.must_reject()]

    # 0.13 clients (the published regex) refuse every TOG code, and every TOG event code with TOG- dropped.
    new = [c for c in pinned + edge if t.parse(c)["shape"] in t.NEW_SHAPES]
    out["refused_by_0_13"] = [c for c in pinned + edge] + [c[4:] for c in new if t.parse(c)["shape"] == "event"]
    assert not any(t.PUBLISHED_RE.fullmatch(c) for c in out["refused_by_0_13"])

    # code_key: the code itself, no folding; a PG string is not a code.
    out["code_key"] = [dict({"code": c}, **run(t.code_key, c)) for c in pub + pinned + edge]

    # A registry's own migration of its own rows (internal, once): persons and release works by the marker, licences
    # from their signed object. Never called on anything from outside.
    licences = {c: old_licence_record(c) for c in pub if re.fullmatch(r"PG-(?:[A-Z]{4}-)?[A-Z]{3}-[0-9]+-\w{7}", c)}
    tp = t._ex_person("PRAM", 900000037)
    mig = [{"old": c, "record": None, **run_record(t.registry_migrate, c)}
           for c in pub + ["PG" + tp[3:], "PG-PRAM-412345691!", "PG-ABC-000123", tp] if c not in licences]
    mig += [{"old": c, "record": r, **run_record(t.registry_migrate, c, r)} for c, r in licences.items()]
    bad = next(iter(licences))
    mig.append({"old": bad, "record": dict(licences[bad], license_id=bad + "X"),
                **run_record(t.registry_migrate, bad, dict(licences[bad], license_id=bad + "X"))})
    out["migrate"] = mig

    # pregen.org's lookup proxy: the path it asks at the first prefix's registry. The PG path is the transition shim
    # for a registry not yet migrated (removed when its .well-known/pg-policy announces TOG).
    out["proxy"] = [{"code": c, "registry_speaks_tog": tog, **run(t.proxy_path, c, tog)}
                    for c in ["TOG-ZYXW-1234567R", "TOG-000042*", "TOG-STD-000123", tp, ex["home only"][1],
                              "PG-ZYXW-1234567R", "PG" + tp[3:]] for tog in (False, True)]

    # Typed input (never inside a message).
    tilu = t._ex_person("TILU", 142000000)
    tilu_h = t._ex("AG", "TILU", "UOLI")
    lic_ex = t._ex("AG-LIC", "NWRD", "PRAM", "typed")
    ones = next(t.spell("PG", "PRAM", None, "1" * 10 + c, k) for c in t.CROCKFORD
                if (k := t.check_char(t.event_body("PG", "PRAM", None, "1" * 10 + c))) in t.CROCKFORD)
    ones2 = "TOG-AG-LIC-NWRD-PRAM-1111-1111-111" + t.check_char(t.event_body("AG-LIC", "NWRD", "PRAM", "1" * t.TAIL))
    amb = t._ex_person("IILA", 412345678)
    typed = ["  tog-zyxw-1234567r \n", "TOG–ZYXW–1234567R", "ＴＯＧ－ＺＹＸＷ－１２３４５６７Ｒ", "T0G-ZYXW-l234567R",
             "https://resolver.example/v2/codes/TOG-ZYXW-1234567R#x", "PG-ZYXW-1234567R.", "ТОG-ZYХW-1234567R",
             "pg-zyxw-1234567r", "https://api2.prampta.com/v1/pg/PG-ZYXW-1234567R", "PG 000 042 *", "tog-000042*",
             "PG-PRAM-412345691!", "PG-PRAM-0123456789", "tog-pram-412345691!",
             "PG-ZYXW-01234567" + t.check_char("ZYXW01234567"), "tog-abcd-prm-1234567-a1b2c3a", "РG-ZYXW-1234567R",
             "pg–zyxw–1234567r", "PG-STD-000001-K7M2QX9", "https://www.pregen.org/lookup/PG-ZYXW-1234567R",
             "tog-std-000001-k7m2qx9", "pg-std-000001-k7m2qx9", tilu.replace("TILU", "T11U").lower(),
             tilu_h.replace("TILU", "T1LU").replace("UOLI", "U01I"), ones.lower(),
             ones2.replace("TOG", "T0G", 1).lower(), amb.replace("IILA", "111A"),
             "TOG-11111111-11111111-11111111-1"]
    typed += ["(PG-ZYXW-1234567R)", '"PG-ZYXW-1234567R"', "-PG-ZYXW-1234567R", "XPG-0000016", "PG0000016",
              "PG:0000016", "PG_0000016", "PG.0000016", "PG/0000016", "P G-0000016", "РГ-0000016", "photo.jpg"]
    typed += [lic_ex.replace("-LIC-", x) for x in ("-L1C-", "-LlC-", "-1IC-", "-lic-")]
    typed += [c.lower() for c in pinned] + [c[4:] for c in new if t.parse(c)["shape"] == "event"][:6]
    out["typed"] = [dict({"input": s}, **run(t.normalize_typed, s)) for s in dict.fromkeys(typed)]

    # Codes from records.
    named, allow, terms, lic, person = acts()
    out["code_for"] = [{"name": n, "act": a, **run_record(t.code_for, a)} for n, a in named.items()]
    g, lic_code, terms_code = t.code_for(allow), t.code_for(lic), t.code_for(terms)
    out["metadata"] = [
        {"name": n, "meta": m, "act": a, "licence": li, "ok": t.metadata_ok(m, a, li)} for n, m, a, li in (
            ("both copies equal the recomputed codes", {"Code": g, "Licence": lic_code}, allow, lic),
            ("no copy: the record is enough", {}, allow, lic),
            ("a code copy that differs", {"Code": terms_code}, allow, lic),
            ("a licence copy that differs", {"Code": g, "Licence": lic_code[:-1] + "0"}, allow, lic),
            ("a licence copy with no grant at hand: cannot be recomputed", {"Code": g, "Licence": lic_code}, allow,
             None),
            ("terms basis, code copy only", {"Code": terms_code}, terms, None),
            ("a licence copy on a terms basis", {"Code": terms_code, "Licence": lic_code}, terms, lic))]

    # Verdicts: what a verifier may say before signatures and V-H.
    real_l = next(t.event_code("LIC", "NWRD", "PRAM", tail=x) for x in (f"{n:011d}" for n in range(99))
                  if t.check_char(t.event_body("LIC", "NWRD", "PRAM", x)) in t.CROCKFORD)
    vcases = [("aa" * 32, allow, g, None), ("aa" * 32, allow, None, None), ("aa" * 32, allow, person, None),
              ("bb" * 32, allow, g, None), ("bb" * 32, allow, g, "aa" * 32), ("bb" * 32, allow, g, "cc" * 32),
              ("aa" * 32, terms, terms_code, None), ("aa" * 32, allow, terms_code, None),
              ("aa" * 32, dict(allow, cosign=dict(allow["cosign"], home="SKAN")), g, None),
              ("aa" * 32, dict(allow, signer="HLWD"), g, None), ("aa" * 32, dict(allow, type="pg.after_gen.v1"), g, None),
              ("aa" * 32, dict(allow, grant=dict(allow["grant"], signer="HLWD")), g, None),
              ("aa" * 32, dict(allow, grant=None), g, None),
              ("aa" * 32, dict(allow, signer="SKAN", cosign=None), None, None),
              ("aa" * 32, dict(allow, subject_ref="PG-ZYXW-1234567R"), "TOG-ZYXW-1234567R", None),
              ("aa" * 32, dict(allow, subject_ref="TOG-ZYXW-1234567R"), "PG-ZYXW-1234567R", None),
              ("aa" * 32, None, person, None), ("aa" * 32, None, real_l, None), ("aa" * 32, None, g, None),
              ("aa" * 32, None, None, None), ("aa" * 32, None, g[:-1] + ("0" if g[-1] != "0" else "1"), None),
              ("aa" * 32, None, "TOG-PG-PRAM-ZZZZ-K6X4-RZJB", None), ("aa" * 32, None, "PG-PRAM-412345691!", None),
              ("aa" * 32, None, "PG-ZYXW-1234567R", None)]
    out["verdict"] = [{"file": f, "act": a, "caption": c, "ingredient": i, "words": t.verdict(f, a, c, i)}
                      for f, a, c, i in vcases]

    # The registry looks a person up by number; answers in TOG.
    tp = t._ex_person("PRAM", 900000037)
    issued = ["TOG-ZYXW-1234567R", "TOG-STD-000123", tp]
    idx = {t.person_key(c): c for c in issued}

    def answer(asked):
        r = run(t.registry_answer, asked, idx)
        if "error" in r:
            return r
        s = r["result"].split()
        return {"status": s[0]} | ({"code": s[1]} if s[0] == "found" else {"hint": s[1][5:]} if len(s) > 1 else {})
    asks = ["PG-ZYXW-1234567R", "TOG-ZYXW-1234567R", "PG-STD-000123", "PG" + tp[3:], tp, "PG-STD-0000123",
            "TOG-STD-0000123", t._ex_person("PRAM", 412345999), "PG-ZYXW-01234567" + t.check_char("ZYXW01234567")]
    out["lookup"] = {"issued": issued, "cases": [{"asked": a, **answer(a)} for a in asks]}

    # Dated party checks against a v3-shaped directory.
    base, later, dirs = parties_directories()
    omni_front = t._ex("PG-LIC", "NWRD", "OMNI")
    pcases = [("base", ex["home + market"][1], None, None), ("base", ex["market + provider"][1], None,
                                                            "https://hybr.example"),
              ("base", omni_front, None, "https://omni.example"), ("base", t._ex("LIC", "LYONMK", "KOBEMK"), None, None),
              ("base", t._ex("LIC", "TGOV"), None, None), ("base", t._ex("PG", "PRAM", "NWRD"), None, None),
              ("base", t._ex("LIC", "XXXX", "PRAM"), None, None), ("later", ex["home + market"][0], None, None),
              ("later", ex["home + market"][0], 2027, None), ("later", ex["home + market"][0], 2030, None),
              ("later", ex["agency registry"][1], 2027, None), ("later", t._ex_person("FAKEGOV", 900000001), None, None)]
    out["parties"] = {"directories": dirs, "cases": [
        {"directory": d, "code": c, "at": at, "provider": pv,
         **dict(zip(("ok", "facts"), t.check_parties(c, base if d == "base" else later, at, pv)))}
        for d, c, at, pv in pcases]}

    # Prefix admission by the steward.
    built, order = {}, []
    for prefix, e in t.DIRECTORY.items():
        order.append({"prefix": prefix, "entity": e["entity"], "government": e.get("government", False),
                      "directory": sorted(built), "refusal": t.admission_refusal(
                          prefix, e["entity"], e.get("government", False), built, reserved=())})
        built[prefix] = e
    refused = ["PRAN", "PRAMS", "PRMA", "BRAM", "PPAM", "NWRO", "HLWO", "USGOV", "CQVES", "FRAME", "PRAM", "PRA",
               "KOBEMQ", "PRAMPTA", "OMNIUM", "NWRDPRAM", "HLVVD", "NVVRD", "OFFICIAL", "VERIFIED", "LICENSED",
               "LEGALCO", "PREGEN", "POLICE", "HOMEX", "SHOPG", "TOGCO", "ADULTCO", "NWRD", "LICX", "LLCA", "IICO",
               "PGLIC", "AGLIC", "PGAB", "AGENTS", "PCLIC", "ACLIC", "TQGAB", "TOCAB", "RGAB", "LJCA", "NLIC", "LGIC",
               "LIZC", "ACMELIC", "NLJC", "LJGA", "ACMELLC"]
    cases = [(p, {"FRAME": "Newroad"}.get(p, "X"), False, None, True) for p in refused]
    cases += [("SPAIN", "Spain", True, None, True), ("TGOVX", "Y", True, None, True),
              ("ESGOV", "Spain", True, None, True), ("PORTO", "Porto", False, None, True),
              ("KPGOV", "B", True, {"KRGOV": "A"}, True), ("BRMKT", "B", False, {"JPMKT": "J"}, True),
              ("VELR", "V", False, {}, True), ("FOTIRTNT", "X", False, {"FOTIRNT": "Y"}, False)]
    adm = []
    for p, ent, gov, d, res in cases:
        directory = built if d is None else {k: {"entity": v} for k, v in d.items()}
        adm.append({"prefix": p, "entity": ent, "government": gov,
                    "directory": None if d is None else d, "fixtures_reserved": res,
                    "refusal": t.admission_refusal(p, ent, gov, directory, t.FIXTURES if res else ())})
    out["admission"] = {
        "description": "refusal '' = admissible. directory null = every fixture of `in_order` (prefix -> entity), "
                       "otherwise the given prefix -> entity map. fixtures_reserved = alphabet.fixture_prefixes "
                       "are reserved. The reason wording is informative; refused or not is normative.",
        "fixtures": {p: {"entity": e["entity"], "government": e.get("government", False)}
                     for p, e in t.DIRECTORY.items()},
        "in_order": order, "cases": adm}

    hiding = next(t.person_code("SHOPG", n) for n in range(900000059, 900009999)
                  if t.check_char("SHOPG" + str(n)) == t.check_char(str(n), t.CROCKFORD)
                  and t.check_char(str(n)) in t.CROCKFORD)
    out["find_codes"] = [{"text": s, "codes": t.find_codes(s)} for s in (
        f"*{pinned[1]}*, see ({pinned[1]}).", f"see {hiding}.", "PG-000042* and TOG-000042*",
        f"under the video: AI-made with permission · {pinned[2]}", "no code here, TOG- alone")]

    json.dump(out, sys.stdout, ensure_ascii=False, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
