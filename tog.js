// /tog and /tog/document: the reference registration process (spec/drafts/tog-funnel.md). One question per screen, in
// the site's own form controls. The person says what they need ToG for; an AI service or a registry is sent to its own
// page, a person or a company answers and picks one home registry, which issues the code. The result is one ToG
// statement (HTML for a website, plain text for a profile, or only the code), which cites the one common legal text and
// carries the line "ToG: <code>", so publishing it is the proof that confirms the code.
// Nothing leaves the browser until the person picks their registry: then only the closed answers travel, in the URL
// fragment (#tog=v1.…), which browsers never send to a server. The date of birth stays in this page's memory: never in
// a URL, never in storage. /tog/document reads the registry's return (#code=…&tog=v1.…) the same way.
import { rulesFromAnswers, card, companyRules, cardCompany, encodeAnswers, offeredRegistries, defaultNever,
  conditionsOk, loadDirectory, proofLine, normalizeTyped, CodeError, kindOf, issuerOf, checkChar, parseCode, encodeReturn, decodeReturn,
  NEVER, LEGAL, CONDITIONS_MAX, RETURN_URL } from "/packages/verify-js/tog.js";

const LOCAL = ["localhost", "127.0.0.1"].includes(location.hostname);
const DOCUMENT = /\/tog\/document\/?$/.test(location.pathname);
const BARE = "PRAM";   // the bare namespace (TOG-0000016) belongs to PRAMPTA (TOG-CODE.md §5)
const stage = document.getElementById("tg-stage");

const NEED = [
  ["likeness", "My likeness", "I am a person. I want to state whether AI may generate my face, body and voice."],
  ["brand", "My company's brand or products", "The marks, products and characters a company owns."],
  ["provider", "My AI service", "I build or run an AI product and need to respect the statements of people and brands."],
  ["registry", "A registry", "I want to register people or companies and issue ToG codes."]];
const USE = {
  site: ["On my website", "A ToG statement for a page of your site, for example /tog. Publishing it confirms your code."],
  profile: ["On a public profile or account", "The same statement as plain text, for your profile or a post. Publishing it confirms your code."],
  code: ["Only the code", "Your ToG code alone, to cite in contracts, credits, packaging or metadata."]};
const PURPOSES = [
  ["fun", "Personal and fan content", "Non-commercial: memes, fan art, personal posts."],
  ["news", "News, commentary, satire, education and research", "Non-commercial. A paid film or course is commercial."],
  ["paid", "Advertising and other commercial work", "Only under an agreement signed for each use."]];
const EXCLUDED = { vice: "Alcohol, tobacco, cannabis and drugs", weapons: "Weapons", violence: "Violence",
  gambling: "Gambling", money: "Finance and investment", health: "Medicine and health", religion: "Religion",
  ads: "Advertising", endorse: "Endorsements (“I recommend it”)", fashion: "Fashion and beauty" };
const FEES = [["each", "Agreed for each agreement", ""],
  ["project", "A minimum fee per project", "For example, one brand's campaign."],
  ["video", "A minimum fee per video", "For example, one 15-second video for one brand."]];
const ALWAYS = "Always excluded: political content, and sexual or adult content.";

// ---- state ---------------------------------------------------------------------------------------------------------
let S, trail, error = null;
function reset() {
  S = { need: null, use: null, rep: false, d: "", m: "", y: "", decision: null, for: [], never: null, neverFor: "",
    voice: false, floor: "each", conditions: "", registry: null, typed: "", done: null, view: null };
  trail = ["intro"];
}
const company = () => S.need === "brand";
const yes = () => S.decision === "approve_all" || S.decision === "rules";
/** What the person typed, as the fragment carries it (tog-funnel.md): one line break, NFC, trimmed. */
const words = () => S.conditions.replace(/\r\n?/g, "\n").replace(/\t/g, " ").trim().normalize("NFC");

/** The answers a registry gets (tog-funnel.md): closed codes only, never a date, a name or a domain. */
function answers() {
  if (S.rep) return { who: "child", decision: "no" };
  if (company()) return yes() ? { who: "company", decision: S.decision, for: S.for, never: S.never } : { who: "company", decision: "no" };
  if (!yes()) return { age: "18+", decision: "no" };
  return { age: "18+", decision: S.decision, for: S.for, never: S.never, voice: S.voice,
    ...(S.for.includes("paid") && { floor: S.floor }), ...(words() && { conditions: words() }) };
}

function plan() {
  if (S.need === "provider" || S.need === "registry") return ["need", "end"];
  const more = yes() ? ["for", "never"] : [];
  if (company()) return ["need", "use", "decision", ...more, "review"];
  if (S.rep) return ["need", "use", "dob", "minor", "review"];
  return ["need", "use", "dob", "decision", ...more, ...(yes() ? ["voice", ...(S.for.includes("paid") ? ["floor"] : []), "words"] : []), "review"];
}
const go = (screen) => { error = null; trail.push(screen); render(); };
const back = () => { error = null; if (trail.length > 1) trail.pop(); render(); };
const fail = (msg) => { error = msg; render(); };
const change = (screen) => { error = null; trail = trail.slice(0, trail.lastIndexOf(screen) + 1); render(); };

// ---- building blocks -----------------------------------------------------------------------------------------------
function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith("on") && typeof v === "function") e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e.setAttribute(k, v === true ? "" : v);
  }
  e.append(...kids.flat(Infinity).filter((k) => k != null && k !== false && k !== ""));
  return e;
}
/** Radio buttons (one value) or checkboxes (several), as labelled rows. */
function choices(name, opts, isOn, onPick, multi = false) {
  return el("div", { class: "tg-choices", role: multi ? "group" : "radiogroup", "aria-labelledby": "tg-h" }, opts.map(([value, label, sub]) =>
    el("label", { class: "tg-choice" },
      el("input", { type: multi ? "checkbox" : "radio", name, value, checked: isOn(value), onchange: (e) => onPick(value, e.target.checked) }),
      el("span", { class: "tg-box", "aria-hidden": "true" }),
      el("span", { class: "tg-text" }, el("b", {}, label), sub && el("small", {}, sub)))));
}
function field(label, value, onInput, attrs = {}) {
  const id = "tg-" + label.toLowerCase().replace(/\W+/g, "-");
  const input = el("input", { id, class: "tg-input", value, autocomplete: "off", spellcheck: "false", ...attrs });
  input.addEventListener("input", () => onInput(input.value));
  return el("p", { class: "tg-field" }, el("label", { for: id }, label), input);
}
function copyBlock(title, text, note) {
  const pre = el("pre", {}, el("code", {}, text));
  const b = el("button", { type: "button", class: "copy", "aria-label": `Copy: ${title}` }, "Copy");
  b.addEventListener("click", () => {
    const done = (ok) => { b.replaceChildren(ok ? "Copied" : "Select and copy"); setTimeout(() => b.replaceChildren("Copy"), 1600); };
    navigator.clipboard?.writeText(text).then(() => done(true), () => done(false)) ?? done(false);
  });
  return el("div", { class: "tg-copy" }, el("p", { class: "label" }, title), note && el("p", { class: "meta" }, note),
    el("div", { class: "code" }, pre, b));
}
const rich = (line) => line.split(/\*\*(.+?)\*\*/).map((part, i) => (i % 2 ? el("strong", {}, part) : part));
const plain = (line) => line.replace(/\*\*/g, "");
const listOf = (keys, table) => keys.map((k) => table[k]).join("; ");
/** pregen.org keeps the protocol and this form; registries register people and companies (founder, 2026-11-12). */
const notRegistry = () => el("div", { class: "tg-notice" }, el("b", {}, "pregen.org is not a registry."),
  el("p", {}, "It does not register people or companies and holds no codes. Registries do: you choose one, it confirms your identity and your rights, and after that your ToG code takes effect."));
/** An example code of a registry's form: the first example serial (900000000 and up, never issued) with a check. */
function example(prefix) {
  for (let s = 900000001; s < 900000100; s++) {
    const c = `TOG-${prefix}-${s}${checkChar(prefix + s)}`;
    try { parseCode(c); return c; } catch { /* no check character from the code's alphabet: the next serial */ }
  }
}
const legalLinks = () => el("p", { class: "tg-legal" }, el("a", { href: "/tog/1.0" }, "Read the legal code"),
  el("a", { href: "/tog/1.0/deed" }, "Read it in plain words"));

// ---- the statement: one text, three forms --------------------------------------------------------------------------
const escHtml = (s) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);   // text only, never in an attribute

/** {code, answers, registry} -> the statement's parts. It cites the common legal text, never copies it. */
function statement({ code, answers: a, registry }) {
  const co = a.who === "company", rep = a.who === "child";
  return {
    code, co, rep, registry,
    title: co ? "Terms of Generation of this company" : "Terms of Generation",
    by: rep ? "Made for a person under 18 by their parent or legal guardian." : null,
    conditions: a.conditions || null,
    lines: co ? cardCompany(companyRules(a)) : card(rulesFromAnswers(a)),
    licence: co ? null : LEGAL,   // ToG 1.0 covers a natural person's likeness only
    record: `https://www.pregen.org/lookup?code=${code}`,
  };
}
const CONDITIONS_INTRO = "My own conditions, which only narrow the terms below:";

function asText(st) {
  return [proofLine(st.code), "", st.title, st.by, ...(st.conditions ? ["", CONDITIONS_INTRO, st.conditions] : []), "",
    ...st.lines.map(plain), "",
    ...(st.licence ? [`Licence: ${st.licence.label}, ${st.licence.url}`, `SHA-256 ${st.licence.sha256}`] : []),
    `Record: ${st.record}, home registry ${st.registry}`].filter((l) => l != null).join("\n");
}
/** The section for a page of the person's website. The line "ToG: <code>" stands alone on its own source line and on
 *  its own rendered line, so a registry reading either finds it (extensions/identity.md, Confirmation). */
function asHtml(st) {
  const li = (l) => "<li>" + escHtml(l).replace(/\*\*(.+?)\*\*/, "<strong>$1</strong>") + "</li>";
  return [`<section id="tog" lang="en">`, `<h2>${escHtml(st.title)}</h2>`, "<p>", proofLine(st.code), "</p>",
    st.by && `<p>${escHtml(st.by)}</p>`,
    ...(st.conditions ? [`<p>${CONDITIONS_INTRO}</p>`, `<blockquote><p>${escHtml(st.conditions).replace(/\n/g, "<br>\n")}</p></blockquote>`] : []),
    "<ul>", ...st.lines.map(li), "</ul>",
    st.licence && `<p>Licence: <a href="${st.licence.url}">${st.licence.label}</a>, SHA-256 <code>${st.licence.sha256}</code></p>`,
    `<p>Record: <a href="${st.record}">${st.code}</a>, home registry ${escHtml(st.registry)}</p>`, "</section>"]
    .filter(Boolean).join("\n");
}
/** How the statement looks, built from nodes (the person's conditions are text, never markup). */
function sheet(st) {
  return el("article", { class: "tg-sheet", "aria-label": "Your ToG statement" },
    el("p", { class: "tg-sheet-code" }, st.code ? proofLine(st.code) : "ToG: the code your registry issues"),
    el("h3", {}, st.title), st.by && el("p", {}, st.by),
    st.conditions && [el("p", { class: "tg-sheet-small" }, CONDITIONS_INTRO), el("blockquote", { class: "tg-said" }, st.conditions)],
    el("ul", {}, st.lines.map((l) => el("li", {}, rich(l)))),
    el("p", { class: "tg-sheet-small" }, st.licence && [`Licence: ${st.licence.label}`, el("br")],   // the hash stays in the published text only
      st.code ? `Record: ${st.record}, home registry ${st.registry}` : "Record: on pregen.org, under the code, once it is issued"));
}
/** A company's /.well-known/tog.json, in the form its home registry checks (tog-funnel.md, The return). */
const togJson = (prefix, record, claim) => JSON.stringify({ tog: 1, registered: [{ notary: prefix, record, claim }] }, null, 2);

// ---- screens: each returns {title, hint?, body, next?, cta?, label?} -----------------------------------------------
const SCREENS = {
  intro() {
    return { big: true, label: "ToG Protocol", title: "Create your ToG",
      hint: "State whether AI may generate your likeness, your brand or your products, and on what terms. You prepare your statement here and register it with a registry you choose.",
      body: [
        notRegistry(),
        el("ol", { class: "gsteps" }, [
          ["Answer", "A few questions on this page. Nothing you enter leaves this browser until you choose a registry."],
          ["Choose a registry", "Pick one from the list of available registries. It records your statement and issues your ToG code."],
          ["Confirm", "The registry confirms your identity and your rights. Publishing your ToG statement on a website or profile you control confirms the code is yours."],
          ["In force", "Once confirmed, your ToG code takes effect for every registry and AI service on ToG Protocol."],
        ].map(([h, p], i) => el("li", {}, el("span", { class: "n" }, String(i + 1)), el("div", {}, el("h2", {}, h), el("p", {}, p))))),
        el("p", { class: "tg-actions" }, el("button", { type: "button", class: "btn primary tg-go", onclick: () => go("need") }, "Start"),
          el("span", { class: "meta" }, "About three minutes. Free.")),
        el("p", { class: "meta tg-fine" }, `Under ${LEGAL.label}, one common text for everyone. `, el("a", { href: "/tog/1.0" }, "Read the legal code"), "."),
      ] };
  },
  need() {
    return { title: "What do you need ToG for?", hint: "The result depends on your answer. Each adult makes their own statement.",
      body: choices("need", NEED, (v) => S.need === v, (v) => { S.need = v; }),
      next: () => {
        if (!S.need) return fail("Choose what you need ToG for.");
        S.rep = false;
        go(S.need === "provider" || S.need === "registry" ? "end" : "use");
      } };
  },
  end() {
    const provider = S.need === "provider";
    return provider
      ? { title: "Your AI service needs no ToG code", hint: "An AI service does not register. It reads the ToG codes of the people and brands it is asked to generate, asks their registry before it generates, and generates only on a signed yes.",
        body: el("p", { class: "tg-actions" }, el("a", { class: "btn primary", href: "/connect" }, "Connect your AI"), el("a", { class: "btn", href: "/docs" }, "How it works")) }
      : { title: "A registry is listed, not registered", hint: "A registry implements ToG Protocol on its own site and asks the steward to list it in the signed list of registries. Once listed, it can take statements through this same process.",
        body: el("p", { class: "tg-actions" }, el("a", { class: "btn primary", href: "/create-registry" }, "Create a registry"), el("a", { class: "btn", href: "/registries" }, "Registries")) };
  },
  use() {
    const opts = Object.entries(USE).map(([v, [l, sub]]) => [v, l,
      company() && v === "code" ? "Your ToG code alone, for products, packaging, contracts or metadata. Your domain confirms it." : sub]);
    return { title: "Where will you use your ToG?", hint: "This sets what you receive at the end. You can switch between the forms there.",
      body: choices("use", opts, (v) => S.use === v, (v) => { S.use = v; }),
      next: () => (S.use ? go(company() ? "decision" : "dob") : fail("Choose where you will use your ToG.")) };
  },
  dob() {
    const done = () => {
      const [d, m, y] = [S.d, S.m, S.y].map((x) => Number(String(x).trim()));
      const date = new Date(Date.UTC(y, m - 1, d)), now = new Date();
      if (![d, m, y].every(Number.isInteger) || y < 1900 || date.getUTCMonth() !== m - 1 || date.getUTCDate() !== d)
        return fail("Enter a real date of birth, for example 27 3 1990.");
      if (date > now) return fail("The date of birth must be in the past.");
      const age = now.getUTCFullYear() - y - (now.getUTCMonth() < m - 1 || (now.getUTCMonth() === m - 1 && now.getUTCDate() < d) ? 1 : 0);
      if (age < 18) return go("minor");
      S.rep = false;
      go("decision");
    };
    return { title: "What is your date of birth?", hint: "It confirms that you are 18 or over. It stays in this browser and is never sent.",
      body: el("div", { class: "tg-date" },
        field("Day", S.d, (v) => (S.d = v), { inputmode: "numeric", maxlength: "2", class: "tg-input tg-n2" }),
        field("Month", S.m, (v) => (S.m = v), { inputmode: "numeric", maxlength: "2", class: "tg-input tg-n2" }),
        field("Year", S.y, (v) => (S.y = v), { inputmode: "numeric", maxlength: "4", class: "tg-input tg-n4" })),
      next: done };
  },
  minor() {
    return { label: "Under 18", title: "Under 18, a parent or legal guardian makes this statement",
      hint: "A person under 18 cannot make a ToG statement alone. Their parent or legal guardian can make it for them, and for a person under 18 the only statement is No: no AI generation of their likeness.",
      body: el("p", { class: "meta tg-fine" }, "Sexual or adult content showing a person under 18 is never permitted, under any statement. The registry will ask you to confirm that you are the parent or legal guardian."),
      cta: "I am their parent or legal guardian",
      next: () => { S.rep = true; S.decision = "no"; S.for = []; go("review"); } };
  },
  decision() {
    const co = company();
    const opts = [["no", "No", co ? "AI may not generate the company's marks, products or characters for any purpose." : "AI may not generate your likeness for any purpose."],
      ["approve_all", co ? "Yes, with the company's approval of each output" : "Yes, with my approval of each output",
        co ? "Nothing generated is shown to anyone until the company approves it." : "Nothing generated of you is shown to anyone until you approve it."],
      ["rules", co ? "Yes, within terms the company sets" : "Yes, within terms I set", "You choose the permitted purposes and the excluded categories."]];
    return { title: co ? "May AI generate the company's marks, products or characters?" : "May AI generate your likeness?",
      hint: co ? "This covers only what the company owns." : "Your likeness is your face, body and voice, in images, video and audio.",
      body: [choices("decision", opts, (v) => S.decision === v, (v) => { S.decision = v; }),
        el("p", { class: "tg-inset" }, co ? "A No takes effect once the company's domain confirms the code. A Yes is recorded now and takes effect only after the company is verified, which is not yet available."
          : "A No takes effect once you confirm your code. A Yes is recorded now and takes effect only after identity verification, which is not yet available.")],
      next: () => {
        if (!S.decision) return fail("Choose No or one of the two forms of Yes.");
        if (!yes()) { S.for = []; return go("review"); }
        go("for");
      } };
  },
  for() {
    return { title: "For which purposes?", hint: "Select all that apply. Anything not selected stays closed.",
      body: choices("for", PURPOSES, (v) => S.for.includes(v), (v, on) => {
        S.for = PURPOSES.map(([k]) => k).filter((k) => (k === v ? on : S.for.includes(k)));
      }, true),
      next: () => {
        if (!S.for.length) return fail("Select at least one purpose, or go back and choose No.");
        if (S.neverFor !== S.for.join()) { S.never = defaultNever(S.for); S.neverFor = S.for.join(); }
        go("never");
      } };
  },
  never() {
    const opts = Object.keys(NEVER).map((k) => [k, company() && k === "endorse" ? "Endorsements (“we recommend it”)" : EXCLUDED[k]]);
    return { title: "Which categories are excluded?", hint: "Selected categories are excluded. The usual exclusions are already selected.",
      body: [choices("never", opts, (v) => S.never.includes(v), (v, on) => {
        S.never = Object.keys(NEVER).filter((k) => (k === v ? on : S.never.includes(k)));
      }, true), el("p", { class: "tg-inset" }, ALWAYS)],
      next: () => go(company() ? "review" : "voice") };
  },
  voice() {
    return { title: "May AI reproduce your voice?", hint: "Copies of voices are often used in telephone fraud. Allow it only if you need it.",
      body: choices("voice", [["no", "No", "Another voice may still be used."], ["yes", "Yes", "Your voice, within the terms above."]],
        (v) => S.voice === (v === "yes"), (v) => { S.voice = v === "yes"; }),
      next: () => go(S.for.includes("paid") ? "floor" : "words") };
  },
  floor() {
    return { title: "How are fees for commercial work set?", hint: "You sign each commercial agreement yourself. The amount is entered at your registry and is never published.",
      body: choices("floor", FEES, (v) => S.floor === v, (v) => { S.floor = v; }), next: () => go("words") };
  },
  words() {
    const count = el("span", { class: "meta" }, `${[...words()].length} / ${CONDITIONS_MAX}`);
    const box = el("textarea", { id: "tg-words", class: "tg-input tg-words", rows: "5", spellcheck: "true",
      placeholder: "For example: never in a horror film; no changes to my face." });
    box.value = S.conditions;
    box.addEventListener("input", () => { S.conditions = box.value; count.replaceChildren(`${[...words()].length} / ${CONDITIONS_MAX}`); });
    return { title: "Additional conditions", hint: "Optional. In your own words, in any language, up to 1,000 characters. They can only narrow the terms above, never extend them, and appear first in your statement, exactly as written.",
      body: [el("p", { class: "tg-field" }, el("label", { for: "tg-words" }, "Your conditions (optional)"), box), count],
      next: () => {
        const w = words();
        if (w && !conditionsOk(w)) return fail([...w].length > CONDITIONS_MAX ? `At most ${CONDITIONS_MAX} characters.` : "Remove the invisible control characters from the text.");
        go("review");
      } };
  },
  review() {
    const co = company(), a = answers();
    const decision = { no: "No", approve_all: "Yes, with approval of each output", rules: "Yes, within the terms set" }[a.decision];
    const rows = [
      ["Statement for", S.rep ? "A person under 18, made by their parent or legal guardian" : co ? "A company: the marks, products and characters it owns" : "Yourself", "need"],
      ["Used", USE[S.use][0], "use"],
      !co && ["Age", S.rep ? "Under 18" : "18 or over. The date stays in this browser.", "dob"],
      ["Decision", decision, S.rep ? "dob" : "decision"],
      yes() && ["Purposes", listOf(S.for, Object.fromEntries(PURPOSES.map(([k, l]) => [k, l]))), "for"],
      yes() && ["Excluded", [listOf(S.never, EXCLUDED) || "None selected", el("span", { class: "tg-also" }, ALWAYS)], "never"],
      yes() && !co && ["Voice", S.voice ? "May be reproduced" : "May not be reproduced", "voice"],
      yes() && !co && S.for.includes("paid") && ["Commercial fees", FEES.find(([k]) => k === S.floor)[1], "floor"],
      yes() && !co && ["Your conditions", words() || "None", "words"]].filter(Boolean);
    const st = statement({ code: null, answers: a, registry: "" });
    const list = el("div", { class: "tg-registries", "aria-live": "polite" }, el("p", { class: "meta" }, "Loading the signed list of registries…"));
    registries().then((offered) => {
      list.replaceChildren(el("h3", { class: "label" }, `Available registries (${offered.length})`),
        ...(offered.length ? offered.map((r) => el("div", { class: "tg-reg" },
          el("dl", {}, el("dt", {}, r.name), el("dd", {}, new URL(r.start).host),
            el("dd", {}, "Prefix ", el("span", { class: "mono" }, r.prefix), " · codes look like ", el("span", { class: "mono tg-nowrap" }, example(r.prefix)))),
          el("a", { class: "btn primary tg-to", href: r.start + "#" + encodeAnswers(a), target: "_blank", rel: "noopener noreferrer",
            onclick: () => { S.registry = r; go("code"); } }, `Register with ${r.name}`)))
          : [el("p", {}, "No registry takes ToG statements yet.")]));
    }, () => list.replaceChildren(el("p", {}, "The signed list of registries could not be loaded. Try again later.")));
    return { title: "Check your statement", hint: "Change anything before you register it.",
      body: [
        el("dl", { class: "tg-sum" }, rows.map(([k, v, screen]) => el("div", {}, el("dt", {}, k), el("dd", { class: k === "Your conditions" ? "pg-said" : false }, v),
          el("dd", { class: "tg-change" }, el("button", { type: "button", onclick: () => change(screen) }, "Change", el("span", { class: "tg-sr" }, " " + k.toLowerCase())))))),
        el("h2", {}, "How it will read"),
        el("p", { class: "meta" }, "Your registry adds your code. The statement cites the common legal text; it is not a copy of it."),
        sheet(st),
        !co && [el("p", { class: "meta" }, `Under ${LEGAL.label}: training AI models on you happens only under a paid agreement you sign; sexual or adult content only under an agreement you sign yourself after an identity document check, which is not yet offered; rights you granted before ToG keep their own terms.`), legalLinks()],
        el("h2", {}, "Choose your registry"),
        notRegistry(),
        el("p", {}, `Choose one registry from the list. It records your statement, issues your ToG code and confirms ${co ? "that the company controls its domain and holds the rights" : "your identity and your rights"}. You need only one: every other registry and AI service reads your code.`),
        el("p", {}, `The code is pending for 7 days. It permits and forbids nothing until it is confirmed ${co ? "on the company's domain" : "by publishing your statement or verifying your identity"}. Your registry reminds you on day 3. On day 7 an unconfirmed code is deleted, and its number is never issued again.`),
        el("p", {}, "Once confirmed, your ToG code takes effect for every registry and AI service on ToG Protocol."),
        S.rep && el("p", {}, "Your registry will ask you to confirm that you are the parent or legal guardian."),
        !yes() && !co && !S.rep && el("p", { class: "tg-inset" }, `Until your code is confirmed, you may also write tog:no in the bio of your own public profile. Under ${LEGAL.label} §2(h) it takes effect at once.`),
        list,
        el("p", { class: "meta tg-fine" }, `The registry opens in a new tab. Only your answers are passed on, in the part of the link after #, which browsers do not send to servers.${co || S.rep ? "" : " Your date of birth stays here."} You enter your email at the registry.`)] };
  },
  code() {
    const name = S.registry.name;
    return { label: "Registration", title: "Enter your ToG code", hint: `${name} opened in a new tab. When it has issued your code, enter it here to receive your ToG statement.`,
      body: [field("ToG code", S.typed, (v) => (S.typed = v), { class: "tg-input tg-mono", placeholder: `TOG-${S.registry.prefix}-000000000`, autocapitalize: "characters" }),
        el("p", { class: "meta tg-fine" }, `If ${name} brought you back to pregen.org in the other tab, your statement is already there and you can close this one.`)],
      cta: "Get my statement",
      next: () => {
        let code;
        try { code = normalizeTyped(S.typed); } catch (e) {
          if (!(e instanceof CodeError)) throw e;
          return fail(e.reason === "mistyped" ? "The check character does not fit. Compare the code with the one your registry shows." : `Enter the code exactly as ${name} shows it.`);
        }
        if (kindOf(code) !== "subject") return fail("That is not a person's or a company's ToG code.");
        if ((issuerOf(code) || BARE) !== S.registry.prefix) return fail(`That code was not issued by ${name}.`);
        S.done = { code, answers: answers(), registry: S.registry.name, prefix: S.registry.prefix };
        S.view = S.use;
        go("result");
      } };
  },
  result() { return result(S.done); },
  broken() {
    return { label: "ToG statement", title: "This link holds no ToG statement",
      hint: "It may have been cut short when it was copied. Open the link your registry gave you again, or start here.",
      body: el("p", { class: "tg-actions" }, el("a", { class: "btn primary", href: "/tog" }, "Create your ToG")) };
  },
};

/** The result: the code's live status, the statement in the form the person needs, and how to publish it. */
function result(done) {
  const st = statement(done), name = done.registry, co = st.co;
  const view = S.view || "site";
  const line = () => el("span", { class: "tg-nowrap" }, proofLine(done.code));   // never broken at a dash; a new node per use
  const status = el("p", { class: "tg-status-line" }, "Reading the code's status at its registry…");
  lookup(done.code).then((d) => status.replaceChildren(...{
    pending: [el("b", {}, "Pending. "), `It permits and forbids nothing until you confirm it, within 7 days of registration.`],
    active: [el("b", {}, "Active. "), "Your statement is in force for every registry and AI service on ToG Protocol."],
    expired: [el("b", {}, "Expired. "), "The code was not confirmed within 7 days and was deleted. Register again for a new code."],
  }[d.status] || [el("b", {}, "Not found. "), `${name} does not show this code yet. Check that it is the code it issued.`]),
  () => status.replaceChildren(el("b", {}, "Status not available now. "), "Check it later on ", el("a", { href: `/lookup?code=${done.code}` }, "Look up a code"), "."));
  const tabs = el("div", { class: "tg-tabs", role: "group", "aria-label": "Form of your ToG" }, Object.entries({ site: "Website", profile: "Profile or post", code: "Code only" }).map(([v, label]) =>
    el("button", { type: "button", "aria-pressed": view === v ? "true" : "false", onclick: () => { S.view = v; render(); } }, label)));
  const where = co ? "the company's website" : "your website";
  const confirmCo = done.record
    ? copyBlock("/.well-known/tog.json", togJson(done.prefix, done.record, done.claim), `Place this file at https://<the company's domain>/.well-known/tog.json, then ask ${name} to check the domain.`)
    : el("p", {}, `${name} gives you the file /.well-known/tog.json on your code's page. Place it at https://<the company's domain>/.well-known/tog.json, then ask ${name} to check the domain. That confirms the code.`);
  const steps = {
    site: [copyBlock("HTML for a page of " + where, asHtml(st), ["Paste it into a page such as /tog. Keep the line ", line(), " on a line of its own."]),
      co ? confirmCo : el("p", {}, `Then give ${name} the page's address on your code's page. Once it finds the line `, line(), `, your code is active. On your own domain, ${name} can instead read the plain text at https://<your domain>/.well-known/pregen.`)],
    profile: [copyBlock("Plain text for a profile or a post", asText(st), "Post it on a public profile or account in your own name. The first line must stay on a line of its own."),
      co ? confirmCo : el("p", {}, `Then give ${name} the address of the profile or post on your code's page. Once it finds the first line, your code is active.`)],
    code: [el("p", { class: "tg-bigcode" }, done.code),
      el("p", {}, `Cite it wherever ${co ? "the company's marks or products" : "your likeness"} may be used: contracts, credits, packaging, metadata. Anyone can look it up.`),
      co ? confirmCo : copyBlock("The confirmation line", proofLine(done.code), `Put this line, on a line of its own, on a public profile or website you control, and give ${name} its address. Or verify your identity at ${name}.`)],
  }[view];
  let keep = null;
  try {   // the permanent link: the registry's own return, or one built from what was typed here
    keep = (LOCAL ? location.origin + "/tog/document" : RETURN_URL) + "#" + encodeReturn({ code: done.code, answers: done.answers,
      ...(done.record && { record: done.record, claim: done.claim }) });
  } catch { /* nothing to keep */ }
  return { label: "Your ToG", title: view === "code" ? "Your ToG code" : "Your ToG statement",
    hint: ["Code ", el("span", { class: "tg-nowrap" }, done.code), `, registered with ${name}.`],
    body: [
      el("div", { class: "tg-status" }, el("span", { class: "tg-mono" }, done.code), status),
      tabs,
      view !== "code" && sheet(st),
      el("h2", {}, view === "code" ? "Use it and confirm it" : "Publish it and confirm it"),
      steps,
      keep && copyBlock("Link to this statement", keep, "Bookmark it to come back. The statement is in the part after #, which is read in your browser and never sent to a server."),
      !co && [el("h2", {}, "The legal text"), el("p", {}, `Your statement is made under ${LEGAL.label}, one common text for everyone.`), legalLinks()],
      el("p", { class: "tg-actions" }, el("a", { class: "btn", href: "/tog" }, "Start a new statement"))] };
}

// ---- the network: the signed list of registries, and a code's status ----------------------------------------------
let dir;
function directory() {
  return (dir ??= (async () => {
    if (LOCAL) {
      try {   // the e2e stand: an ephemeral steward key (test/tog-local.mjs), localhost only
        const key = (await (await fetch("/test/tog-local/steward.json")).json()).public_key_hex;
        return { list: await loadDirectory({ url: "/test/tog-local/registries.json", stewardPublicKeyHex: key }), local: true };
      } catch { /* no local stand: the real directory */ }
    }
    return { list: await loadDirectory({ url: "/registries.json" }), local: false };
  })());
}
const registries = () => directory().then((d) => offeredRegistries(d.list, { local: d.local }));
/** The registry's public answer for the code (/api/lookup, extensions/lookup.md): the code alone is sent. */
const lookup = (code) => fetch("/api/lookup?code=" + encodeURIComponent(code)).then((r) => (r.ok ? r.json() : Promise.reject(r.status)));

/** /tog/document#code=…&tog=v1.…: the registry's return (tog-funnel.md, The return). The record, when there is one,
 *  must be on the registry's own website, from the signed list. */
async function fromReturn() {
  const ret = decodeReturn(location.hash.slice(1));
  if (ret.result !== "ok") return null;
  const prefix = issuerOf(ret.code) || BARE;
  const reg = await registries().then((list) => list.find((r) => r.prefix === prefix), () => null);
  if (ret.record && (!reg || new URL(ret.record).origin !== new URL(reg.start).origin)) return null;
  return { code: ret.code, answers: ret.answers, registry: reg ? reg.name : prefix, prefix,
    ...(ret.record && { record: ret.record, claim: ret.claim }) };
}

// ---- the frame -----------------------------------------------------------------------------------------------------
function render() {
  const name = trail.at(-1), s = SCREENS[name](), p = plan(), at = p.indexOf(name);
  const step = s.label || (at >= 0 && name !== "end" ? `Step ${at + 1} of ${p.filter((x) => x !== "end").length}` : "Create your ToG");
  const h = el("h1", { id: "tg-h", class: s.big ? "tg-h tg-h--big" : "tg-h", tabindex: "-1" }, s.title);
  const head = [trail.length > 1 && !["result", "broken"].includes(name) && el("button", { type: "button", class: "tg-back", onclick: back }, "Back"),
    el("p", { class: "label tg-step" }, step), h, s.hint && el("p", { class: "tg-hint" }, s.hint),
    error && el("div", { class: "tg-error", role: "alert" }, el("b", {}, "There is a problem"), el("p", {}, error))];
  const body = s.next
    ? el("form", { class: "tg-form", novalidate: true, "aria-labelledby": "tg-h", onsubmit: (e) => { e.preventDefault(); s.next(); } },
      s.body, el("p", { class: "tg-actions" }, el("button", { type: "submit", class: "btn primary tg-go" }, s.cta || "Continue")))
    : el("div", { class: "tg-body" }, s.body);
  stage.replaceChildren(el("div", { class: "tg-screen", "data-screen": name }, head, body));
  (error ? stage.querySelector("input, textarea") || h : h).focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

reset();
const show = () => fromReturn().then((done) => {
  reset();
  if (done) { S.done = done; S.view = "site"; trail = ["result"]; } else trail = ["broken"];
  render();
});
if (DOCUMENT) { show(); window.addEventListener("hashchange", show); } else render();
