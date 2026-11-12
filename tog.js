// /tog: make your ToG (spec/drafts/tog-funnel.md). One question per screen; the letter key picks an answer, Enter
// answers or confirms the one already chosen. The result is a short card that links the one common legal text
// (/tog/1.0), never a personal copy of it. Nothing leaves the browser until the person picks their home registry: then
// only the closed answers travel, in the URL fragment (#tog=v1.…), which browsers never send to a server.
// The year of birth stays in this page's memory: never in a URL, never in storage. A person's yes may add conditions in
// their own words (ToG 1.0 §6(f)), shown first on the card as plain text.
import { rulesFromAnswers, card, companyRules, cardCompany, encodeAnswers, offeredRegistries, defaultNever,
  conditionsOk, loadDirectory, proofLine, NEVER, LEGAL, CONDITIONS_MAX, COMPANY_NOTE } from "/packages/verify-js/tog.js";

const LETTERS = "ABCDEFGHIJ";
const LOCAL = ["localhost", "127.0.0.1"].includes(location.hostname);
const CHIPS = { vice: "alcohol, tobacco, cannabis and drugs", weapons: "weapons", violence: "violence",
  gambling: "gambling", money: "money and investing", health: "medicine and health", religion: "religion", ads: "ads",
  endorse: "\"I recommend it\"", fashion: "fashion and beauty" };
const FOR_LABELS = [
  ["fun", "For fun and fan content", "memes, fan art, personal posts, no money"],
  ["news", "News, commentary and satire, teaching and research", "unpaid; a paid film or course counts as paid work"],
  ["paid", "Ads and paid work", "brands, film, games, paid courses"]];

const $ = (id) => document.getElementById(id);
let S, trail;
function reset(who = null) {
  S = { who, year: "", age: null, decision: null, for: [], never: null, neverFor: null, voice: false, floor: "each",
    conditions: "" };
  trail = [who === "me" ? "year" : "who"];
  if (who) trail.unshift("who");
}

// ---- rendering helpers --------------------------------------------------------------------------------------------
function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "on") e.addEventListener("click", v);
    else if (v !== false && v != null) e.setAttribute(k, v === true ? "" : v);
  }
  e.append(...kids.flat().filter((k) => k != null && k !== false));
  return e;
}
/** Text with one **bold phrase** -> nodes (textContent only, never HTML). */
function rich(text) {
  return text.split(/\*\*(.+?)\*\*/).map((part, i) => (i % 2 ? el("strong", {}, part) : part));
}
const yes = () => S.decision && S.decision !== "no" && S.for.length > 0;
const company = () => S.who === "company";
/** What the person typed, as the fragment carries it (spec/drafts/tog-funnel.md): one line break, NFC, trimmed. */
const words = () => S.conditions.replace(/\r\n?/g, "\n").replace(/\t/g, " ").trim().normalize("NFC");

/** The answers a registry gets (spec/drafts/tog-funnel.md); "nothing ticked" is the no. Never a name or a domain. */
function answers() {
  if (S.who === "child") return { who: "child", decision: "no" };
  if (company()) return yes() ? { who: "company", decision: S.decision, for: S.for, never: S.never } : { who: "company", decision: "no" };
  if (!yes()) return { age: S.age, decision: "no" };
  return { age: S.age, decision: S.decision, for: S.for, never: S.never, voice: S.voice,
    ...(S.for.includes("paid") && { floor: S.floor }), ...(words() && { conditions: words() }) };
}
const personRules = () => rulesFromAnswers(answers());

function planned() {
  if (S.who === "other") return ["who", "other"];
  if (S.who === "child") return ["who", "child", "card"];
  if (company()) return ["who", "decision", ...(S.decision && S.decision !== "no" ? ["for", "never"] : []), "card"];
  return ["who", "year", "decision", ...(S.decision && S.decision !== "no" ? ["for", "never", "voice",
    ...(S.for.includes("paid") ? ["floor"] : []), "words"] : []), "card"];
}

const go = (screen) => { trail.push(screen); render(); };
const back = () => { if (trail.length > 1) { trail.pop(); render(); } };

// ---- screens: each returns {title, hint?, body, options?, ok?} ------------------------------------------------------
function choice(options, selected) {
  return el("ul", { class: "tf-choices" }, options.map((o, i) => el("li", {},
    el("button", { type: "button", class: "tf-choice", "data-on": selected === o.value, "aria-pressed": selected === o.value ? "true" : false, on: o.pick },
      el("kbd", {}, LETTERS[i]), el("span", {}, el("b", {}, o.label), o.sub ? el("small", {}, o.sub) : null)))));
}
function ok(label, onOk, disabled = false) {
  return el("p", { class: "tf-ok" }, el("button", { type: "button", class: "btn primary", disabled, on: onOk }, label),
    el("span", { class: "meta" }, "press ", el("b", {}, "Enter ↵")));
}
function field(value, onInput, attrs, onOk) {
  const input = el("input", { class: "tf-input", value, autocomplete: "off", spellcheck: "false", ...attrs });
  input.addEventListener("input", () => onInput(input.value.trim()));
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); onOk(); } });
  return input;
}

const SCREENS = {
  who() {
    const opts = [
      { value: "me", label: "Me", pick: () => { S.who = "me"; go("year"); } },
      { value: "company", label: "My company", sub: "its marks, products and characters", pick: () => { S.who = "company"; go("decision"); } },
      { value: "child", label: "My child", sub: "as their parent, guardian or other legal representative", pick: () => { S.who = "child"; go("child"); } },
      { value: "other", label: "Another adult", sub: "a relative, a client", pick: () => { S.who = "other"; go("other"); } }];
    return { title: "Who is this for?", hint: "Each person answers for themself. **A company answers only for what it owns.**",
      options: opts, body: choice(opts, S.who) };
  },
  year() {
    const done = () => {
      const y = Number(S.year), now = new Date().getFullYear();
      if (!/^\d{4}$/.test(S.year) || y < 1900 || y > now) return;
      const age = now - y - 1;   // ponytail: a year only, so the youngest age the person can be
      if (age < 18) return go("minor");
      S.age = "18+";
      go("decision");
    };
    return { title: "Your year of birth", hint: "**It stays in this browser.** It is never sent anywhere.",
      body: [field(S.year, (v) => (S.year = v), { inputmode: "numeric", maxlength: "4", placeholder: "1990", "aria-label": "Year of birth" }, done),
        ok("OK", done)], ok: done };
  },
  decision() {
    const co = company();
    const pick = (d) => () => { S.decision = d; d === "no" ? go("card") : go("for"); };
    const opts = [{ value: "no", label: "No.", sub: "Not for fun, not for news, not for ads.", pick: pick("no") },
      { value: "approve_all", label: co ? "Yes, but only what we approve." : "Yes, but only what I approve.",
        sub: co ? "AI apps that ask hold back anything made of them, from everyone, until you say yes."
          : "AI apps that ask hold back anything made of you, from everyone, until you say yes.", pick: pick("approve_all") },
      { value: "rules", label: co ? "Yes, within our rules." : "Yes, within my rules.", sub: "You choose what for, and what never.", pick: pick("rules") }];
    const note = "A yes is recorded as your wish. **It opens only after identity verification, which is coming soon.** Saying no needs no document and no photo.";
    return { title: co ? "May AI make your marks, products or characters?" : "May AI make photos or videos of you, or copy your voice?",
      hint: "**Free, whatever you choose.** You can change your answer any time.", options: opts,
      body: [choice(opts, S.decision), el("p", { class: "meta tf-note" }, ...rich(note))] };
  },
  for() {
    const next = () => {
      if (!S.for.length) return go("nothing");
      const key = S.for.join();
      if (S.neverFor !== key) { S.never = defaultNever(S.for); S.neverFor = key; }
      go("never");
    };
    const toggle = (k) => () => { S.for = FOR_LABELS.map(([x]) => x).filter((x) => (x === k) !== S.for.includes(x)); render(); };
    const opts = FOR_LABELS.map(([k, label, sub]) => ({ value: k, label, sub, pick: toggle(k), on: S.for.includes(k) }));
    return { title: company() ? "What may AI make them for?" : "What may AI make you for?",
      hint: company() ? "Tick what you are happy with. **Ads always need a deal you sign.**"
        : "Tick what you are happy with. **Ads always need a deal you sign yourself.**",
      options: opts, ok: next,
      body: [el("ul", { class: "tf-choices" }, opts.map((o, i) => el("li", {},
        el("button", { type: "button", class: "tf-choice", role: "checkbox", "aria-checked": o.on ? "true" : "false", "data-on": o.on, on: o.pick },
          el("kbd", {}, LETTERS[i]), el("span", {}, el("b", {}, o.label), el("small", {}, o.sub)), el("i", { class: "tf-box", "aria-hidden": "true" }, o.on ? "✓" : ""))))),
        ok("Next", next)] };
  },
  nothing() {
    const opts = [{ value: "no", label: "Yes, no.", pick: () => { S.decision = "no"; S.for = []; go("card"); } },
      { value: "back", label: "Go back and tick", pick: back }];
    return { title: "Nothing ticked means no. Is that right?", hint: "**A no is the narrowest answer.** You can change it any time.",
      options: opts, body: choice(opts) };
  },
  never() {
    const co = company();
    const toggle = (k) => () => { S.never = Object.keys(NEVER).filter((x) => (x === k) !== S.never.includes(x)); render(); };
    const keys = Object.keys(NEVER);
    const opts = keys.map((k) => ({ value: k, pick: toggle(k), on: S.never.includes(k) }));
    const next = () => go(co ? "card" : "voice");
    const lines = co ? cardCompany(companyRules(answers())) : card(personRules());
    return { title: co ? "Never with our marks:" : "Never with me:",
      hint: "We marked the usual ones Never. **Switch to Allowed only what you are fine with.**", options: opts, ok: next,
      body: [
        el("p", { class: "tf-locked" }, "Always closed: sexual or adult content, politics."),
        el("ul", { class: "tf-chips" }, opts.map((o, i) => el("li", {},
          el("button", { type: "button", class: "tf-chip", role: "switch", "aria-checked": o.on ? "true" : "false", "data-on": o.on, on: o.pick },
            el("kbd", {}, LETTERS[i]), el("span", {}, co && o.value === "endorse" ? "\"we recommend it\"" : CHIPS[o.value]),
            el("em", {}, o.on ? "✕ Never" : "Allowed"))))),
        !co && el("p", { class: "meta" }, ...rich("**Fake \"I recommend it\" ads are a common scam.** A deal you sign can still include one.")),
        el("p", { class: "tf-live", "aria-live": "polite" }, lines.find((l) => l.startsWith("Never: "))),
        ok("Next", next)] };
  },
  voice() {
    const pick = (v) => () => { S.voice = v; go(S.for.includes("paid") ? "floor" : "words"); };
    const opts = [{ value: false, label: "No, not my voice", sub: "another actor's voice is still fine", pick: pick(false) },
      { value: true, label: "Yes, my voice too", pick: pick(true) }];
    return { title: "Your voice too?", hint: "**Voice copies are a favourite tool of phone scams.** Turn this on only if you need it.",
      options: opts, body: choice(opts, S.voice) };
  },
  floor() {
    const pick = (f) => () => { S.floor = f; go("words"); };
    const opts = [{ value: "each", label: "We agree on each deal", pick: pick("each") },
      { value: "project", label: "Lowest price per project", sub: "one brand's campaign, as its deal describes it", pick: pick("project") },
      { value: "video", label: "Lowest price per video", sub: "e.g. one 15-second video for one brand's social media", pick: pick("video") }];
    return { title: "What is the lowest price you accept?",
      hint: "**You sign every deal yourself.** Offers below your price are declined for you, and the price is never on your card.",
      options: opts, body: [choice(opts, S.floor),
        el("p", { class: "meta tf-note" }, "You type the amount at the registry. Each deal is a contract you sign, with its own description.")] };
  },
  words() {
    const count = el("span", { class: "meta" });
    const error = el("p", { class: "meta tf-note", role: "alert" });
    const show = () => count.replaceChildren(`${[...words()].length} / ${CONDITIONS_MAX}`);
    const next = () => {
      const w = words();
      if (w && !conditionsOk(w)) {
        return error.replaceChildren([...w].length > CONDITIONS_MAX ? `At most ${CONDITIONS_MAX} characters.`
          : "Remove the invisible control characters from the text.");
      }
      go("card");
    };
    const box = el("textarea", { class: "tf-input tf-words", rows: "5", spellcheck: "true", "aria-label": "Your conditions, in your own words",
      placeholder: "For example: never in a horror film; no changes to my face." });
    box.value = S.conditions;
    box.addEventListener("input", () => { S.conditions = box.value; error.replaceChildren(); show(); });
    show();
    return { title: "In your own words", ok: next,
      hint: "Optional, in any language, up to 1,000 characters. **They can only narrow what you allow.**",
      body: [box, count, error, ok("Next", next)] };
  },
  card() {
    const co = company(), child = S.who === "child";
    const lines = co ? cardCompany(companyRules(answers())) : card(personRules());
    const list = el("div", { class: "tf-registries", "aria-live": "polite" }, el("p", { class: "meta" }, "Loading the signed list of registries…"));
    registries().then((offered) => {
      list.replaceChildren(...(offered.length ? offered.map((r) => el("a", { class: "btn primary tf-go", href: r.start + "#" + encodeAnswers(answers()) },
        `Get a ToG code at ${r.name}`)) : [el("p", {}, "No registry takes ToG codes yet.")]));
    }, () => list.replaceChildren(el("p", {}, "The signed list of registries could not be loaded. Try again later.")));
    const whose = co ? "YOUR COMPANY'S TOG" : child ? "YOUR CHILD'S TOG" : "YOUR TOG";
    return { title: child ? "Your child's answer, as AI apps will read it" : "Your answer, as AI apps will read it", wide: true, body: [
      cardBox(`${whose} · CODE FROM YOUR REGISTRY`, lines, !co && !child && yes() && words(), co   // ToG 1.0 covers a natural person's likeness only
        ? COMPANY_NOTE
        : `${LEGAL.label} · SHA-256 ${LEGAL.sha256} · the same text for everyone`),
      !co && el("p", { class: "tf-legal" }, el("a", { href: "/tog/1.0" }, "Read the legal code"), el("a", { href: "/tog/1.0/deed" }, "Read it in plain words")),
      !co && !child && el("p", { class: "meta" }, ...rich(`Under ${LEGAL.label}: **training AI models on you happens only under a paid deal you sign**; sexual or adult content only under a deal you sign yourself after an identity document check, which is not offered yet; rights you granted before ToG keep their own terms.`)),
      yes() && el("p", { class: "meta" }, ...rich("Your yes is recorded as your wish. **It opens only after identity verification, which is coming soon;** until then it opens nothing.")),
      !child && el("p", { class: "actions" }, el("button", { type: "button", class: "btn", on: () => { trail = trail.slice(0, trail.indexOf("decision") + 1); render(); } }, "Change")),
      !yes() && !co && !child && el("p", {}, ...rich("Saying no right now: write **tog:no** in the bio of your own public profile. Under ToG 1.0 §2(h) it counts at once.")),
      el("h2", {}, "Get your ToG code at your home registry"),
      el("p", {}, ...rich("Your home registry records your answer and gives you your ToG code at once. **You need one home only:** every other registry and AI app uses that code.")),
      el("p", {}, ...rich(`**The code is pending for 7 days.** It permits nothing and forbids nothing until you confirm it is you: ${co ? "publish the file /.well-known/tog.json on your company's domain" : `put the line “${proofLine("<your code>")}” on a public account or website you control`}, or verify your identity. An email alone does not. Your registry reminds you on day 3; on day 7 an unconfirmed code is deleted and never issued again.`)),
      el("p", {}, ...rich("**Once verified, your YES or NO is global** for every registry on ToG Protocol.")),
      child && el("p", {}, "Your registry asks you to confirm that you are the child's parent, guardian or other legal representative."),
      list,
      el("p", { class: "meta" }, `${co || child ? "" : "Your year of birth stays here. "}Only your answers travel, after the # of the link, which browsers never send to a server. Your email is typed at the registry.`)] };
  },
  child() {
    const next = () => { S.decision = "no"; go("card"); };
    return { title: "For a child, the answer is no.", ok: next,
      hint: "**A child is registered only by a parent, guardian or other legal representative,** and for now the only answer is no.",
      body: [ok("Next", next)] };
  },
  minor() {
    return { title: "A parent or guardian does this.", end: true,
      hint: "**Under 18, you are registered only by a parent, guardian or other legal representative.** They can start here with \"My child\".", body: [] };
  },
  other() {
    return { title: "Not yet.", hint: "**Each adult answers for themself.** A helper's form is coming.", end: true, body: [] };
  },
};

/** The card; the person's own conditions come first, as plain text (never parsed for markup). */
function cardBox(head, lines, conditions, meta) {
  return el("figure", { class: "tf-card" }, el("figcaption", {}, head),
    conditions && el("p", { class: "tf-cond" }, conditions),
    lines.map((l) => el("p", {}, ...rich(l))), el("p", { class: "tf-card-meta" }, meta));
}

// ---- the registries (PLAN §2.2): the signed directory, read once ----------------------------------------------------
let dir;
function registries() {
  return (dir ??= (async () => {
    if (LOCAL) {
      try {   // the e2e stand: an ephemeral steward key (test/tog-local.mjs), localhost only
        const key = (await (await fetch("/test/tog-local/steward.json")).json()).public_key_hex;
        return offeredRegistries(await loadDirectory({ url: "/test/tog-local/registries.json", stewardPublicKeyHex: key }), { local: true });
      } catch { /* no local stand: the real directory */ }
    }
    return offeredRegistries(await loadDirectory({ url: "/registries.json" }));
  })());
}

// ---- the frame ------------------------------------------------------------------------------------------------------
let current;
function render() {
  const name = trail.at(-1);
  current = SCREENS[name]();
  const plan = planned();
  const at = plan.indexOf(name);
  $("tf-bar").max = plan.length;
  $("tf-bar").value = at < 0 ? plan.length : at + 1;
  $("tf-back").hidden = trail.length < 2;
  const h = el("h1", { class: "tf-title", tabindex: "-1" }, current.title);
  $("tf-stage").replaceChildren(el("div", { class: current.wide ? "tf-q tf-q--wide" : "tf-q", "data-screen": name },
    el("p", { class: "tf-n", "aria-hidden": "true" }, `${String(Math.min(at < 0 ? plan.length : at + 1, plan.length)).padStart(2, "0")} / ${String(plan.length).padStart(2, "0")}`),
    h, current.hint && el("p", { class: "tf-hint" }, ...rich(current.hint)),
    el("div", { class: "tf-body" }, current.body),
    current.end && el("p", { class: "actions" }, el("button", { type: "button", class: "btn primary", on: () => { reset(); render(); } }, "Start over"))));
  const input = $("tf-stage").querySelector("input") || $("tf-stage").querySelector("textarea");
  (input || h).focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

document.addEventListener("keydown", (e) => {
  if (e.metaKey || e.ctrlKey || e.altKey || !current) return;
  const t = e.target;
  if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA")) return;
  if (e.key === "Enter") {
    if (t && t.closest && t.closest("button, a")) return;   // Enter on a focused control presses it
    // A screen with OK/Next runs it; a one-answer screen confirms the answer already chosen (after Back, say).
    const chosen = current.ok || current.options && $("tf-stage").querySelector(".tf-choice[data-on]");
    if (chosen) { e.preventDefault(); current.ok ? current.ok() : chosen.click(); }
    return;
  }
  // The physical key where there is one (a Russian layout types ф on A); a soft keyboard may send no code.
  const i = LETTERS.indexOf(e.code?.startsWith("Key") ? e.code.slice(3) : e.key.toUpperCase());
  const o = i >= 0 && current.options ? current.options[i] : undefined;
  if (o) { e.preventDefault(); o.pick(); }
});
$("tf-back").addEventListener("click", back);
$("tf-restart").addEventListener("click", () => { reset(); render(); });
reset();
render();
