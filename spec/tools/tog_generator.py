# copy of PRE-GEN-Drafts/tog-generator/tog_generator.py, do not edit here. Everything below this line is the approved
# reference byte for byte; tog_generator_vectors.py checks its SHA-256 (REFERENCE_SHA256) before it writes a vector.
"""ToG generator, profile likeness/2 — reference for DESIGN.md (merged design). PRIVATE DRAFT, 2026-11-09.

Built on tog_generator_rigor.py (same folder), plus the member `modalities`, split(), the third-person card and the
person-first flow. `python3 -I tog_generator.py` runs an exhaustive self-check (no dependencies) and prints the
example cards of DESIGN.md §4. It checks, by enumeration:
  1. opens() is exactly "the new version permits a use the old one did not" (a template move is its own act and
     always takes a factor, so it is not modelled here);
  2. meet() permits exactly what both versions permit (rule 9; an agency's or moderator's narrowing);
  3. split() publishes a closing half at once without a factor, and the opening half only with one;
  4. the card is a function of the rules: two different rules never render the same card, in EN and RU, first and
     third person; every card has exactly one bold phrase; no purpose label shares a stem with the training line;
  5. rules -> answers -> rules round-trips for every answer of the main flow;
  6. every must-reject vector is refused; only a "No" may be signed below channel-official or for someone else.
Revised 2026-11-09 after the six critiques (CHANGES.md): labels, the mixed headline, the yes/no "binds" line, the
real-recording line, first person except estates, training closed by PRAMPTA policy, may_sign().
"""
import hashlib
from itertools import product

VOCAB = ("adult", "advertising", "alcohol", "cannabis", "drugs", "endorsement", "fashion", "financial", "gambling",
         "health", "political", "religion", "sexual", "tobacco", "violence", "weapons")     # likeness/1, unchanged
FLOOR = ("adult", "sexual")            # in every version; standing terms never open them (rule 4 tier 2)
REGISTRY_LOCK = ("political",)         # PRAMPTA policy, not the profile: in every PRAMPTA version that allows something
PURPOSES = ("commercial", "editorial", "educational", "personal", "research")
MODES = ("approve", "open")            # approve = AFTER-GEN: each output approved before anyone, the requester included, sees it (legal §2(b))
MODALITIES = ("3d", "image", "video", "voice")
MEMBERS = {"uses", "modalities", "excluded_categories", "training"}


def no() -> dict:
    """The one spelling of "no to everything"."""
    return {"uses": {}, "modalities": [], "excluded_categories": list(FLOOR), "training": False}


def _sorted_set(v, vocab) -> bool:
    return type(v) is list and all(type(c) is str and c in vocab for c in v) and v == sorted(set(v))


def validate(r) -> dict:
    """likeness/2 `rules`, or ValueError. Never repaired, never normalised (rule 6)."""
    if type(r) is not dict or set(r) != MEMBERS:
        raise ValueError("members")
    u, m, x, t = r["uses"], r["modalities"], r["excluded_categories"], r["training"]
    if type(u) is not dict or any(type(k) is not str or k not in PURPOSES or type(v) is not str or v not in MODES
                                  for k, v in u.items()):
        raise ValueError("uses")
    if not _sorted_set(m, MODALITIES):
        raise ValueError("modalities")
    if not _sorted_set(x, VOCAB):
        raise ValueError("excluded_categories")
    if type(t) is not bool:
        raise ValueError("training")
    if not set(FLOOR) <= set(x):
        raise ValueError("floor")
    if not u and r != no():
        raise ValueError("no has one spelling")
    if u and not m:
        raise ValueError("uses without modalities")
    return r


def prampta_policy(r: dict) -> bool:
    """What PRAMPTA's generator may sign, on top of the profile: politics stays excluded while anything is allowed,
    and standing terms never allow training (training only by a signed deal with an end date; §11 decision 12)."""
    return not r["uses"] or (set(REGISTRY_LOCK) <= set(r["excluded_categories"]) and not r["training"])


OPEN_LEVELS = ("channel-official", "verified")     # memo 08: `channel` proves an account, not a person


def may_sign(r: dict, level: str, by_person: bool) -> bool:
    """Whether the registry may sign `r` for a subject at lookup level `level`. A version that allows nothing may be
    signed at any level and on a representative's or parent's instruction (it opens nothing). Anything that allows
    a use needs the person's own act at channel-official or verified (rule 1; F3, A1)."""
    return not r["uses"] or (by_person and level in OPEN_LEVELS)


# ---- the semantic model opens(), meet() and split() must match ---------------------------------------------------
# A use = (purpose, one declared category or None, one modality, shared before approval, kept as a model).
# Categories and modalities are conjunctive, so singletons decide every set of them.
def _uses(purposes=PURPOSES, cats=VOCAB, mods=MODALITIES):
    return list(product(purposes, (None,) + tuple(cats), mods, (False, True), (False, True)))


def permitted(r, U) -> frozenset:
    if r is None:
        return frozenset()
    return frozenset((p, c, m, shared, kept) for p, c, m, shared, kept in U
                     if p in r["uses"] and c not in r["excluded_categories"] and m in r["modalities"]
                     and (not shared or r["uses"][p] == "open") and (not kept or r["training"]))


def opens(old, new) -> bool:
    """Whether a version opens (rule 5: the person's press and a second factor). A version that allows nothing
    never opens, whatever it replaces. A template move is a separate act that always takes a factor; a narrowing
    never moves the template (B12, A16)."""
    if not new["uses"]:
        return False
    if old is None or not old["uses"]:
        return True
    ou = old["uses"]
    return (any(p not in ou or (ou[p] == "approve" and m == "open") for p, m in new["uses"].items())
            or bool(set(new["modalities"]) - set(old["modalities"]))
            or bool(set(old["excluded_categories"]) - set(new["excluded_categories"]))
            or (new["training"] and not old["training"]))


def meet(a: dict, b: dict) -> dict:
    """Both at once: purposes both allow, the stricter mode, modalities both allow, every exclusion either names,
    training only if both. Nothing left to allow -> the one "no"."""
    u = {p: "open" if a["uses"][p] == b["uses"][p] == "open" else "approve" for p in a["uses"].keys() & b["uses"].keys()}
    m = sorted(set(a["modalities"]) & set(b["modalities"]))
    if not u or not m:
        return no()
    return {"uses": dict(sorted(u.items())), "modalities": m, "training": a["training"] and b["training"],
            "excluded_categories": sorted(set(a["excluded_categories"]) | set(b["excluded_categories"]))}


def split(old, new) -> list:
    """The versions one save publishes, in log order, as (rules, needs_factor). What closes is live at once; what
    opens waits for the code (rule 5). The opening half is bound to the terms id it amends: any newer version voids
    it (TERMS_CHANGED, A9). Both halves keep the current template."""
    if old is None or old == new:
        return [] if old == new else [(new, opens(None, new))]
    first = meet(old, new)
    out = [(first, False)] if first != old else []
    return out + ([(new, True)] if first != new else [])


def from_likeness1(body: dict) -> dict:
    """A likeness/1 version read as likeness/2, for meet() only, never published. likeness/1 said nothing about
    approval, modality or training, so it restricts none of them; minor: true allows nothing."""
    if body["minor"]:
        return no()
    r = body["rules"]
    return {"uses": {p: "open" for p in r["purposes"]}, "modalities": list(MODALITIES), "training": True,
            "excluded_categories": sorted(set(r["excluded_categories"]) | set(FLOOR))}


# ---- the generator: answers <-> rules (main flow; "More settings" edits the atoms directly) ----------------------
FOR = {"fun": ("personal",), "news": ("editorial", "educational", "research"), "paid": ("commercial",)}
NEVER = {"vice": ("alcohol", "cannabis", "drugs", "tobacco"), "weapons": ("weapons",), "violence": ("violence",),
         "gambling": ("gambling",), "money": ("financial",), "health": ("health",), "religion": ("religion",),
         "ads": ("advertising",), "endorse": ("endorsement",), "fashion": ("fashion",)}


def default_never(for_: tuple) -> tuple:
    """Screen 3's pre-ticked chips: everything but fashion; ads unticked once paid work is chosen."""
    return tuple(k for k in NEVER if k != "fashion" and not (k == "ads" and "paid" in for_))


def rules_from_answers(a: dict) -> dict:
    if a["decision"] == "no" or not a["for"]:          # nothing ticked + Next is a "no" (the app says so)
        return no()
    purposes = [p for k in a["for"] for p in FOR[k]]
    if a["decision"] == "approve_all":
        uses = {p: "approve" for p in purposes}
    else:                                             # "within my rules": approval on paid work only
        uses = {p: "approve" if p == "commercial" else "open" for p in purposes}
    r = {"uses": dict(sorted(uses.items())), "training": False,
         "modalities": sorted({"image", "video"} | ({"voice"} if a["voice"] else set())),
         "excluded_categories": sorted(set(FLOOR) | set(REGISTRY_LOCK) | {c for k in a["never"] for c in NEVER[k]})}
    return validate(r)


def answers_from_rules(r: dict):
    """Main-flow answers that give `r` back exactly, or None (then the editor opens "More settings")."""
    if not r["uses"]:
        return {"decision": "no"}
    for_ = tuple(k for k in FOR if set(FOR[k]) <= r["uses"].keys())
    never = tuple(k for k in NEVER if set(NEVER[k]) <= set(r["excluded_categories"]))
    for decision in ("rules", "approve_all"):
        a = {"decision": decision, "for": for_, "never": never, "voice": "voice" in r["modalities"]}
        if rules_from_answers(a) == r:
            return a
    return None


PRESETS = {   # named answer sets for tests and docs; only NO is ever a link (/no); never written into the record
    "NO": {"decision": "no"},
    "NEWS": {"decision": "rules", "for": ("news",), "never": default_never(("news",)), "voice": False},
    "FANS": {"decision": "rules", "for": ("fun", "news"), "never": default_never(("fun", "news")), "voice": False},
    "ADS": {"decision": "rules", "for": ("fun", "news", "paid"), "never": default_never(("fun", "news", "paid")),
            "voice": False},
}


# ---- the card: a pure function of the rules ----------------------------------------------------------------------
L = {
    "en": {
        "personal": "fun and fan content", "editorial": "news, commentary and satire",
        "educational": "teaching", "research": "research", "rnd": "news, commentary and satire, teaching and research",
        "commercial": "ads and paid work", "and": "and",
        "image": "pictures", "video": "video", "3d": "3D avatars", "voice": {"1": "my voice", "3": "their voice"},
        "adult": "adult content", "sexual": "sexual content", "adult+sexual": "sexual or adult content",
        "political": "politics", "advertising": "ads", "endorsement": "\"I recommend it\" (endorsements)",
        "advertising+endorsement": "ads and \"I recommend it\" (endorsements)",
        "alcohol": "alcohol", "cannabis": "cannabis", "drugs": "drugs", "tobacco": "tobacco",
        "alcohol+cannabis+drugs+tobacco": "alcohol, tobacco, cannabis and drugs", "gambling": "gambling",
        "weapons": "weapons", "violence": "violence", "religion": "religion", "health": "medicine and health",
        "financial": "money and investing", "fashion": "fashion and beauty",
        "no": {"1": "**No AI generation of me.**", "3": "**No AI generation of this person.**"},
        "no2": {"1": "Not for fun, not for news, not for ads, and no training of AI models on me.",
                "3": "Not for fun, not for news, not for ads, and no training of AI models on this person."},
        "all_approve": {"1": "AI may make me **only with my approval of each one**.",
                        "3": "AI may make this person **only with their approval of each one**."},
        "only": {"1": "AI may make me **only for {list}**.", "3": "AI may make this person **only for {list}**."},
        "mixed": {"1": "AI may make me for {open}, and **for {approve} only with my approval of each one**.",
                  "3": "AI may make this person for {open}, and **for {approve} only with their approval of each "
                       "one**."},
        "for": "For: {list}.",
        "paid": {"1": "Ads and paid work: only under a deal I sign.",
                 "3": "Ads and paid work: only under a deal they sign."},
        "as": "As: {list}.", "no_voice": {"1": "Not my voice.", "3": "Not their voice."},
        "never": "Never: {list}.",
        "train_no": {"1": "Training AI models on me: no.", "3": "Training AI models on this person: no."},
        "train_yes": {"1": "Training AI models on me: allowed. Each later use must still ask.",
                      "3": "Training AI models on this person: allowed. Each later use must still ask."},
        "except": {"1": "Exceptions only by a deal I sign myself, and never for sexual or adult content.",
                   "3": "Exceptions only by a deal the person signs, and never for sexual or adult content."},
        "real": {"1": "Never presented as a real recording of me.",
                 "3": "Never presented as a real recording of this person."},
        "binds": {"1": "These rules bind AI companies that accept them. They never limit my rights under the law.",
                  "3": "These rules bind AI companies that accept them. They never limit this person's rights "
                       "under the law."},
        "binds_yes": "This yes is only for AI companies that accept these rules. It gives no one else permission.",
    },
    "ru": {
        "personal": "развлечений и фан-творчества", "editorial": "новостей, комментариев и сатиры",
        "educational": "образования", "research": "исследований",
        "rnd": "новостей, комментариев и сатиры, образования и исследований",
        "commercial": "рекламы и платной работы", "and": "и",
        "image": "фото", "video": "видео", "3d": "3D-аватары", "voice": {"1": "мой голос", "3": "голос этого человека"},
        "adult": "контент для взрослых", "sexual": "сексуальный контент", "adult+sexual": "секс и контент для взрослых",
        "political": "политика", "advertising": "реклама", "endorsement": "«я рекомендую» (рекомендации от имени)",
        "advertising+endorsement": "реклама и «я рекомендую» (рекомендации от имени)",
        "alcohol": "алкоголь", "cannabis": "каннабис", "drugs": "наркотики", "tobacco": "табак",
        "alcohol+cannabis+drugs+tobacco": "алкоголь, табак, каннабис и наркотики", "gambling": "азартные игры",
        "weapons": "оружие", "violence": "насилие", "religion": "религия", "health": "медицина и здоровье",
        "financial": "деньги и инвестиции", "fashion": "мода и красота",
        "no": {"1": "**Я не разрешаю ИИ создавать меня.**", "3": "**Не разрешено ИИ создавать этого человека.**"},
        "no2": {"1": "Ни для развлечения, ни для новостей, ни для рекламы, и никакого обучения ИИ-моделей на мне.",
                "3": "Ни для развлечения, ни для новостей, ни для рекламы, и никакого обучения ИИ-моделей на этом "
                     "человеке."},
        "all_approve": {"1": "ИИ может создавать меня **только с моим одобрением каждой работы**.",
                        "3": "ИИ может создавать этого человека **только если он одобрит каждую работу**."},
        "only": {"1": "ИИ может создавать меня **только для {list}**.",
                 "3": "ИИ может создавать этого человека **только для {list}**."},
        "mixed": {"1": "ИИ может создавать меня для {open}, а **для {approve} — только с моим одобрением каждой "
                       "работы**.",
                  "3": "ИИ может создавать этого человека для {open}, а **для {approve} — только если он одобрит "
                       "каждую работу**."},
        "for": "Для {list}.",
        "paid": {"1": "Реклама и платная работа — только по договору с моей подписью.",
                 "3": "Реклама и платная работа — только по договору с подписью этого человека."},
        "as": "В виде: {list}.", "no_voice": {"1": "Без моего голоса.", "3": "Без голоса этого человека."},
        "never": "Никогда: {list}.",
        "train_no": {"1": "Обучать ИИ-модели на мне: нельзя.", "3": "Обучать ИИ-модели на этом человеке: нельзя."},
        "train_yes": {"1": "Обучать ИИ-модели на мне: можно. Каждое следующее использование всё равно спрашивает.",
                      "3": "Обучать ИИ-модели на этом человеке: можно. Каждое следующее использование всё равно "
                           "спрашивает."},
        "except": {"1": "Исключение — только договор с моей подписью, и никогда для секса и контента для взрослых.",
                   "3": "Исключение — только договор с подписью этого человека, и никогда для секса и контента для "
                        "взрослых."},
        "real": {"1": "Никогда не выдаётся за настоящую запись со мной.",
                 "3": "Никогда не выдаётся за настоящую запись с этим человеком."},
        "binds": {"1": "Эти правила обязывают ИИ-компании, которые их приняли, и никогда не ограничивают мои права "
                       "по закону.",
                  "3": "Эти правила обязывают ИИ-компании, которые их приняли, и никогда не ограничивают права этого "
                       "человека по закону."},
        "binds_yes": "Это «да» — только для ИИ-компаний, которые приняли эти правила. Больше никому оно ничего не "
                     "разрешает.",
    },
}
PURPOSE_ORDER = (("personal",), ("editorial", "educational", "research"), ("commercial",))
MODALITY_ORDER = (("image",), ("video",), ("3d",), ("voice",))
CATEGORY_ORDER = (("adult", "sexual"), ("political",), ("alcohol", "cannabis", "drugs", "tobacco"), ("weapons",),
                  ("violence",), ("gambling",), ("financial",), ("health",), ("religion",),
                  ("advertising", "endorsement"), ("fashion",))
assert sorted(c for g in CATEGORY_ORDER for c in g) == list(VOCAB)


def _items(present: set, order, t: dict, key=lambda g: "+".join(g)) -> list:
    out = []
    for g in order:
        if len(g) > 1 and set(g) <= present:
            out.append(t[key(g)])
        else:
            out += [t[c] for c in g if c in present]
    return out


def _join(items: list, t: dict, sep: str = "; ") -> str:
    """Groups that hold commas or "and" are joined by "; " alone; plain words by ", " and a final "and"."""
    if sep == "; " or len(items) == 1:
        return sep.join(items)
    return ", ".join(items[:-1]) + f" {t['and']} " + items[-1]


def card(r: dict, lang: str, who: str = "1") -> list:
    """The card's body lines from the rules alone. `who` is "1" for every living person, a child's or a
    representative's "No" included (a third-person "No" would reveal a child or a ward, L8/A12); "3" only for an
    estate (later). Header, who-line and meta come from the envelope (frame())."""
    t = {k: (v[who] if isinstance(v, dict) else v) for k, v in L[lang].items()}
    validate(r)
    if not r["uses"]:
        return [t["no"], t["no2"], t["except"], t["binds"]]
    rnd = lambda g: "rnd" if len(g) == 3 else g[0]
    ps = lambda modes: _join(_items({p for p, m in r["uses"].items() if m in modes}, PURPOSE_ORDER, t, rnd), t)
    modes = set(r["uses"].values())
    if modes == {"approve"}:
        lines = [t["all_approve"], t["for"].format(list=ps({"approve"}))]
    elif modes == {"open"}:
        lines = [t["only"].format(list=ps({"open"}))]
    else:
        lines = [t["mixed"].format(open=ps({"open"}), approve=ps({"approve"}))]
    if "commercial" in r["uses"]:
        lines.append(t["paid"])
    as_line = t["as"].format(list=_join(_items(set(r["modalities"]), MODALITY_ORDER, t), t, ", "))
    lines.append(as_line if "voice" in r["modalities"] else f"{as_line} {t['no_voice']}")
    lines.append(t["never"].format(list=_join(_items(set(r["excluded_categories"]), CATEGORY_ORDER, t), t)))
    lines.append(t["train_yes" if r["training"] else "train_no"])
    return lines + [t["real"], t["except"], t["binds_yes"]]


FRAME = {"en": {"head": "TERMS OF GENERATION · {code} · VERSION {v} · SINCE {date}",
                "claimed": "Recorded by the holder of this code. Not yet confirmed: AI apps get this answer from "
                           "the day it is confirmed.",
                "confirmed": "Confirmed by the registry.",
                "meta": "Terms id {tid} · legal text prampta-likeness v2 · A summary: the signed rules govern."},
         "ru": {"head": "УСЛОВИЯ ГЕНЕРАЦИИ · {code} · ВЕРСИЯ {v} · С {date}",
                "claimed": "Записано владельцем этого кода. Ещё не подтверждено: ИИ-приложения получат этот ответ "
                           "с того дня, как его подтвердят.",
                "confirmed": "Подтверждено реестром.",
                "meta": "id условий {tid} · юридический текст prampta-likeness v2 · Это краткое изложение: "
                        "действуют подписанные правила."}}


def frame(r, lang, who, code, v, date, tid, level, display=None) -> list:
    """The card as shown: header and meta from the envelope; the who-line from lookup's level (memo 08): claimed ->
    no name; channel -> @handle; channel-official / verified -> the name, only if the person ticked "Show my name",
    else @handle. A "No" filed by a parent or representative, or confirmed with no handle, shows only "Confirmed by
    the registry", so no card tells a child, a ward or an adult apart (L8, A12)."""
    f = FRAME[lang]
    who_line = f["claimed"] if level == "claimed" else (display or f["confirmed"])
    return [f["head"].format(code=code, v=v, date=date), who_line] + card(r, lang, who) + \
        [f["meta"].format(tid=tid)]


# ---- self-check ---------------------------------------------------------------------------------------------------
def _states(purposes, cats, mods):
    yield no()
    for modes in product((None,) + MODES, repeat=len(purposes)):
        u = {p: m for p, m in zip(purposes, modes) if m}
        if not u:
            continue
        for mb in product((False, True), repeat=len(mods)):
            m = sorted(x for x, b in zip(mods, mb) if b)
            if not m:
                continue
            for cb in product((False, True), repeat=len(cats)):
                x = sorted(set(FLOOR) | {c for c, b in zip(cats, cb) if b})
                for training in (False, True):
                    yield validate({"uses": dict(sorted(u.items())), "modalities": m, "excluded_categories": x,
                                    "training": training})


def _check():
    P3, C2, M2 = ("commercial", "editorial", "personal"), ("alcohol", "gambling"), ("image", "voice")
    U = _uses(P3, C2, M2)
    S = list(_states(P3, C2, M2))
    P = [permitted(s, U) for s in S]
    for i, a in enumerate(S):                                                       # 1, 2, 3
        assert opens(None, a) == bool(P[i])
        for j, b in enumerate(S):
            assert opens(a, b) == (not P[j] <= P[i]), (a, b)
            mt = meet(a, b)
            assert validate(mt) and permitted(mt, U) == P[i] & P[j], (a, b)
            cur, cur_p = a, P[i]
            for version, factor in split(a, b):
                vp = permitted(version, U)
                assert factor == opens(cur, version) == (not vp <= cur_p), (a, b, version)
                cur, cur_p = version, vp
            assert cur == b, (a, b)
            steps = split(a, b)
            if steps and not steps[0][1]:
                assert permitted(steps[0][0], U) <= P[i] & P[j]                     # the closing half closes only
    for lang, stem, keys in (("en", "train", ("personal", "editorial", "educational", "research", "rnd",
                                              "commercial")),
                              ("ru", "обуч", ("personal", "editorial", "educational", "research", "rnd",
                                              "commercial"))):
        assert not any(stem in L[lang][k] for k in keys), lang                      # W2: no "обучение" as a purpose
    assert may_sign(no(), "claimed", False) and not may_sign(_ok, "channel", True)
    assert may_sign(_ok, "verified", True) and not may_sign(_ok, "verified", False)
    n_cards = 0                                                                     # 4
    for lang, who in product(L, ("1", "3")):
        seen = {}
        for s in _states(PURPOSES, ("alcohol", "advertising", "endorsement"), MODALITIES):
            c = tuple(card(s, lang, who))
            assert sum(line.count("**") for line in c) == 2, c
            k = repr(s)
            assert seen.setdefault(c, k) == k, (c, k, seen[c])
            n_cards += 1
        lines = {}
        for bits in product((False, True), repeat=len(VOCAB)):
            x = sorted({c for c, b in zip(VOCAB, bits) if b} | set(FLOOR))
            r = {"uses": {"personal": "open"}, "modalities": ["image"], "excluded_categories": x, "training": False}
            line = card(r, lang, who)[2]
            assert lines.setdefault(line, x) == x, (line, x)
    n = 0                                                                           # 5
    for decision, voice in product(("rules", "approve_all"), (False, True)):
        for fb in product((False, True), repeat=len(FOR)):
            for nb in product((False, True), repeat=len(NEVER)):
                a = {"decision": decision, "for": tuple(k for k, b in zip(FOR, fb) if b),
                     "never": tuple(k for k, b in zip(NEVER, nb) if b), "voice": voice}
                r = rules_from_answers(a)
                assert prampta_policy(r) and not r["training"]
                b = answers_from_rules(r)
                assert b is not None and rules_from_answers(b) == r, a
                n += 1
    for bad in REJECT:                                                              # 6
        try:
            validate(bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted: {bad!r}")
    assert not prampta_policy({**_ok, "excluded_categories": ["adult", "sexual"]})
    assert not prampta_policy({**_ok, "training": True})
    return len(S), n_cards, n


_ok = {"uses": {"editorial": "open"}, "modalities": ["image", "video"],
       "excluded_categories": ["adult", "political", "sexual"], "training": False}
REJECT = [
    {**_ok, "uses": ["editorial"]},                                              # likeness/1's list, not a map
    {**_ok, "uses": {"Editorial": "open"}},                                      # case
    {**_ok, "uses": {"editorial": "Open"}},
    {**_ok, "uses": {"editorial": "allow"}},                                     # a synonym of a mode
    {**_ok, "uses": {"editorial": "open "}},                                     # trailing space
    {**_ok, "uses": {"news": "open"}},                                           # a generator answer, not a purpose
    {**_ok, "uses": {"training": "open"}},                                       # training is not a purpose
    {**_ok, "uses": {"editorial": "licence"}},                                   # no third mode
    {**_ok, "modalities": ["audio", "image"]},                                   # the word is voice
    {**_ok, "modalities": ["video", "image"]},                                   # unsorted
    {**_ok, "modalities": ["Image", "video"]},
    {**_ok, "modalities": []},                                                   # allows a purpose in no form
    {**_ok, "excluded_categories": ["adult", "political"]},                      # floor missing
    {**_ok, "excluded_categories": ["political", "adult", "sexual"]},            # unsorted
    {**_ok, "excluded_categories": ["adult", "adult", "political", "sexual"]},    # duplicate
    {**_ok, "excluded_categories": ["аdult", "political", "sexual"]},       # Cyrillic a
    {**_ok, "excluded_categories": ["adult", "political", "sex‍ual"]},      # zero-width joiner
    {**_ok, "excluded_categories": ["adult", "beer", "political", "sexual"]},    # outside the vocabulary
    {**_ok, "training": 0},                                                      # a number, not a boolean
    {**_ok, "training": "false"},
    {**_ok, "minor": False},                                                     # likeness/1 member
    {**_ok, "territories": ["*"]},                                               # left to deals on purpose
    {**_ok, "approval": ["editorial"]},                                          # approval lives in `uses`
    {"uses": {}, "modalities": [], "excluded_categories": ["adult", "alcohol", "sexual"], "training": False},
    {"uses": {}, "modalities": [], "excluded_categories": ["adult", "sexual"], "training": True},
    {"uses": {}, "modalities": ["image"], "excluded_categories": ["adult", "sexual"], "training": False},
    {"uses": {}, "modalities": [], "excluded_categories": ["adult", "political", "sexual"], "training": False},
    {"purposes": [], "excluded_categories": ["adult", "sexual"]},                # likeness/1 shape
]

if __name__ == "__main__":
    states, cards, answers = _check()
    print(f"ok: {states} rule states checked pairwise (opens, meet, split); {cards} cards injective with one bold "
          f"phrase (en/ru, 1st/3rd person); {answers} main-flow answers round-trip; {len(REJECT)} must-reject refused")
    examples = (
        ("NO, unconfirmed", "NO", "1", "PG-PRAM-000123E", 1, "claimed", None),
        ("NO, filed for someone else (a parent, a representative) and confirmed", "NO", "1", "PG-PRAM-000130Y", 1,
         "verified", None),
        ("NEWS", "NEWS", "1", "PG-PRAM-000456N", 1, "verified", "Anna Karpova"),
        ("ADS", "ADS", "1", "PG-PRAM-000789W", 2, "channel-official", "@mila.models"),
    )
    for title, preset, who, code, v, level, display in examples:
        r = rules_from_answers(PRESETS[preset])
        print(f"\n### {title}\n{r}")
        for lang, date in (("en", "9 NOV 2026"), ("ru", "9 НОЯБРЯ 2026")):
            print()
            print("\n".join(line for line in frame(r, lang, who, code, v, date, hashlib.sha256(code.encode()).hexdigest()[:12], level, display)
                            if line))
