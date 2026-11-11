// /tog: the ToG generator (UNRELEASED draft; PRE-GEN-Drafts/tog-funnel/PLAN.md). One question per screen; the
// letter key picks an answer, Enter answers. Nothing leaves the browser until the person picks a registry: then
// only the closed answers travel, in the URL fragment (#tog=v1.…), which browsers never send to a server.
// The year of birth stays in this page's memory: never in a URL, never in storage.
import { rulesFromAnswers, card, companyRules, cardCompany, encodeAnswers, companyFiles, offeredRegistries,
  defaultNever, loadDirectory, NEVER } from "/packages/verify-js/tog.js";

const LETTERS = "ABCDEFGHIJ";
const LOCAL = ["localhost", "127.0.0.1"].includes(location.hostname);
const LEGAL_L = "ToG-L-1.0 (draft, not final)";
const LEGAL_B = "ToG-B-1.0 (draft, not final)";
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
    domain: "", name: "" };
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

/** The answers a registry gets (PLAN §2.1); "nothing ticked" is the no. */
function answers() {
  if (!yes()) return { age: S.age, decision: "no" };
  return { age: S.age, decision: S.decision, for: S.for, never: S.never, voice: S.voice,
    ...(S.for.includes("paid") && { floor: S.floor }) };
}
const personRules = () => rulesFromAnswers(answers());
const coAnswers = () => (yes() ? { decision: S.decision, for: S.for, never: S.never } : { decision: "no" });

function planned() {
  if (S.who === "other") return ["who", "other"];
  if (company()) return ["who", "domain", "name", "decision", ...(S.decision && S.decision !== "no" ? ["for", "never"] : []), "files"];
  return ["who", "year", "decision", ...(S.decision && S.decision !== "no" ? ["for", "never", "voice",
    ...(S.for.includes("paid") ? ["floor"] : [])] : []), "card"];
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
      { value: "company", label: "My company", sub: "its marks, products and characters", pick: () => { S.who = "company"; go("domain"); } },
      { value: "other", label: "Someone else", sub: "a child, a relative, a client", pick: () => { S.who = "other"; go("other"); } }];
    return { title: "Who is this for?", hint: "Each person answers for themself. **A company answers only for what it owns.**",
      options: opts, body: choice(opts, S.who) };
  },
  year() {
    const done = () => {
      const y = Number(S.year), now = new Date().getFullYear();
      if (!/^\d{4}$/.test(S.year) || y < 1900 || y > now) return;
      const age = now - y - 1;   // ponytail: a year only, so the youngest age the person can be
      if (age < 13) return go("child");
      S.age = age < 18 ? "13-17" : "18+";
      if (S.age === "13-17" && S.decision !== "no") S.decision = null;   // a minor's answer can only be no
      go("decision");
    };
    return { title: "Your year of birth", hint: "**It stays in this browser.** It is never sent anywhere.",
      body: [field(S.year, (v) => (S.year = v), { inputmode: "numeric", maxlength: "4", placeholder: "1990", "aria-label": "Year of birth" }, done),
        ok("OK", done)], ok: done };
  },
  decision() {
    const co = company();
    const pick = (d) => () => { S.decision = d; d === "no" ? go(co ? "files" : "card") : go("for"); };
    const opts = [{ value: "no", label: "No.", sub: "Not for fun, not for news, not for ads.", pick: pick("no") }];
    if (S.age !== "13-17") {
      opts.push({ value: "approve_all", label: co ? "Yes, but only what we approve." : "Yes, but only what I approve.",
        sub: co ? "AI apps that ask hold back anything made of them, from everyone, until you say yes."
          : "AI apps that ask hold back anything made of you, from everyone, until you say yes.", pick: pick("approve_all") },
      { value: "rules", label: co ? "Yes, within our rules." : "Yes, within my rules.", sub: "You choose what for, and what never.", pick: pick("rules") });
    }
    const note = S.age === "13-17" ? "Under 18, only no is possible here."
      : co ? null : "To allow anything, you will confirm it is you with a document or an official account, and use a code from an authenticator app. Saying no needs neither.";
    return { title: co ? "May AI make your marks, products or characters?" : "May AI make photos or videos of you, or copy your voice?",
      hint: "**Free, whatever you choose.** You can change your answer any time.", options: opts,
      body: [choice(opts, S.decision), note && el("p", { class: "meta tf-note" }, note)] };
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
    const opts = [{ value: "no", label: "Yes, no.", pick: () => { S.decision = "no"; S.for = []; go(company() ? "files" : "card"); } },
      { value: "back", label: "Go back and tick", pick: back }];
    return { title: "Nothing ticked means no. Is that right?", hint: "**A no is the narrowest answer.** You can change it any time.",
      options: opts, body: choice(opts) };
  },
  never() {
    const co = company();
    const toggle = (k) => () => { S.never = Object.keys(NEVER).filter((x) => (x === k) !== S.never.includes(x)); render(); };
    const keys = Object.keys(NEVER);
    const opts = keys.map((k) => ({ value: k, pick: toggle(k), on: S.never.includes(k) }));
    const next = () => go(co ? "files" : "voice");
    const lines = co ? cardCompany(companyRules(coAnswers())) : card(personRules());
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
    const pick = (v) => () => { S.voice = v; go(S.for.includes("paid") ? "floor" : "card"); };
    const opts = [{ value: false, label: "No, not my voice", sub: "another actor's voice is still fine", pick: pick(false) },
      { value: true, label: "Yes, my voice too", pick: pick(true) }];
    return { title: "Your voice too?", hint: "**Voice copies are a favourite tool of phone scams.** Turn this on only if you need it.",
      options: opts, body: choice(opts, S.voice) };
  },
  floor() {
    const pick = (f) => () => { S.floor = f; go("card"); };
    const opts = [{ value: "each", label: "We agree on each deal", pick: pick("each") },
      { value: "project", label: "Lowest price per project", sub: "one brand's campaign, as its deal describes it", pick: pick("project") },
      { value: "video", label: "Lowest price per video", sub: "e.g. one 15-second video for one brand's social media", pick: pick("video") }];
    return { title: "What is the lowest price you accept?",
      hint: "**You sign every deal yourself.** Offers below your price are declined for you, and the price is never on your card.",
      options: opts, body: [choice(opts, S.floor),
        el("p", { class: "meta tf-note" }, "You type the amount at the registry. Each deal is a contract you sign, with its own description.")] };
  },
  card() {
    const lines = card(personRules());
    const list = el("div", { class: "tf-registries", "aria-live": "polite" }, el("p", { class: "meta" }, "Loading the signed list of registries…"));
    registries().then((offered) => {
      list.replaceChildren(...(offered.length ? offered.map((r) => el("a", { class: "btn primary tf-go", href: r.start + "#" + encodeAnswers(answers()) },
        `Get a ToG code at ${r.name}`)) : [el("p", {}, "No registry takes ToG codes yet.")]));
    }, () => list.replaceChildren(el("p", {}, "The signed list of registries could not be loaded. Try again later.")));
    return { title: "Your answer, as AI apps will read it", wide: true, body: [
      cardBox("YOUR TOG · NOT YET RECORDED", lines, `Legal text ${LEGAL_L} · A summary: the signed rules govern.`),
      yes() && el("p", { class: "meta" }, "People may show your yes as if it were permission for them; your card says it is not."),
      el("p", { class: "actions" }, el("button", { type: "button", class: "btn", on: () => { trail = trail.slice(0, trail.indexOf("decision") + 1); render(); } }, "Change")),
      el("h2", {}, "Get a ToG code"),
      el("p", {}, ...rich("A registry records your answers, signs them and gives you a code. **You see every answer again there, before anything is signed.**")),
      list,
      el("p", { class: "meta" }, "Your year of birth stays here. Only your answers travel, after the # of the link, which browsers never send to a server. Your email is typed at the registry.")] };
  },
  files() {
    const f = companyFiles(S.domain, S.name, coAnswers());
    const dl = (name, text, type) => el("a", { class: "btn", download: name, href: URL.createObjectURL(new Blob([text], { type })) }, `Download ${name}`);
    return { title: `Terms of Generation for ${S.name}`, wide: true, body: [
      cardBox(`TERMS OF GENERATION · ${f.handle} · UNSIGNED DRAFT`, cardCompany(companyRules(coAnswers())), `Licence ${LEGAL_B} · A summary: the signed rules govern.`),
      el("p", {}, "Your handle is ", el("code", {}, f.handle), ". ", ...rich("**A company has no ToG code:** AI apps read the files on your own site.")),
      el("h2", {}, "Your site files"),
      el("ol", { class: "tf-files" },
        el("li", {}, el("b", {}, `https://${S.domain}/terms-of-generation`), el("span", { class: "meta" }, "The page people read."), dl("terms-of-generation.html", f.page_html, "text/html")),
        el("li", {}, el("b", {}, `https://${S.domain}/.well-known/tog.json`), el("span", { class: "meta" }, "The file AI apps read."), dl("tog.json", f.tog_json, "application/json")),
        el("li", {}, el("b", {}, "In the <head> of every page"), el("pre", {}, f.link_tag)),
        el("li", {}, el("b", {}, "In the footer, beside Terms of Service and Privacy Policy"), el("pre", {}, f.footer))),
      el("h2", {}, `People at ${S.name}`),
      el("p", {}, ...rich("These files cover only what the company owns. **Each person answers for themself** and can get their own ToG code.")),
      el("p", { class: "actions" }, el("button", { type: "button", class: "btn primary", on: () => { reset("me"); render(); } }, "Start as a person"))] };
  },
  domain() {
    const done = () => { S.domain = S.domain.toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, ""); if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(S.domain)) go("name"); };
    return { title: "Your company's website", hint: "Its domain, like northwind.example. **AI apps will look for your answer there.**",
      body: [field(S.domain, (v) => (S.domain = v), { inputmode: "url", placeholder: "northwind.example", "aria-label": "Domain" }, done), ok("OK", done)], ok: done };
  },
  name() {
    const done = () => { if (S.name) go("decision"); };
    return { title: "And the company's name?", hint: "**It goes only into the files you download.** Nothing is sent.",
      body: [field(S.name, (v) => (S.name = v), { maxlength: "120", placeholder: "Northwind Coffee", "aria-label": "Company name" }, done), ok("OK", done)], ok: done };
  },
  child() {
    return { title: "A parent must do this.", hint: "**Under 13, a parent answers for the child.** That form is coming.", end: true, body: [] };
  },
  other() {
    return { title: "Not yet.", hint: "**For now, each person answers for themself.** A parent's and a helper's form are coming.", end: true, body: [] };
  },
};

function cardBox(head, lines, meta) {
  return el("figure", { class: "tf-card" }, el("figcaption", {}, head),
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
  const input = $("tf-stage").querySelector("input");
  (input || h).focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

document.addEventListener("keydown", (e) => {
  if (e.metaKey || e.ctrlKey || e.altKey || !current) return;
  const t = e.target;
  if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA")) return;
  if (e.key === "Enter") {
    if (t && t.closest && t.closest("button, a")) return;   // Enter on a focused control presses it
    if (current.ok) { e.preventDefault(); current.ok(); }
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
