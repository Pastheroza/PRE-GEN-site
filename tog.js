// /tog/create and /tog/document. /tog/create is a chooser: the questions are asked at the registry the person picks
// (today prampta.com/start), which issues the code (spec/drafts/tog-funnel.md). /tog/document reads the registry's
// return (#code=…&tog=v1.…) and shows the one ToG statement (HTML for a website, plain text for a profile, or only the
// code), which cites the one common legal text and carries the line "ToG: <code>", so publishing it is the proof.
// Nothing is sent from here: the answers travel from the registry to this page in the URL fragment, which browsers never
// send to a server.
import { card, companyRules, cardCompany, offeredRegistries, loadDirectory, proofLine, issuerOf, checkChar, parseCode,
  rulesFromAnswers, encodeReturn, decodeReturn, LEGAL, RETURN_URL } from "/packages/verify-js/tog.js";
import { holderCopy } from "/tog-copy.js";

const LOCAL = ["localhost", "127.0.0.1"].includes(location.hostname);
const DOCUMENT = /\/tog\/document\/?$/.test(location.pathname);
const BARE = "PRAM";   // the bare namespace (TOG-0000016) belongs to PRAMPTA (TOG-CODE.md §5)
const stage = document.getElementById("tg-stage");

let S, trail;
function reset() {
  S = { holder: "", done: null, view: null };
  trail = ["intro"];
}

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
const legalLinks = () => el("p", { class: "tg-legal" }, el("a", { href: "/tog/1.1" }, "Read the legal code"),
  el("a", { href: "/tog/1.1/deed" }, "Read it in plain words"), el("a", { href: "/downloads" }, "PDF and examples"));

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
    licence: LEGAL,   // ToG-L 1.1 covers persons and companies alike
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
    const list = el("div", { class: "tg-registries", "aria-live": "polite" }, el("p", { class: "meta" }, "Loading the signed list of registries…"));
    registries().then((offered) => {
      list.replaceChildren(el("h2", { class: "label" }, `Available registries (${offered.length})`),
        ...(offered.length ? offered.map((r) => {
          const to = new URL(r.start); to.searchParams.set("path", "tog");
          return el("div", { class: "tg-reg" },
            el("dl", {}, el("dt", {}, r.name), el("dd", {}, new URL(r.start).host),
              el("dd", {}, "Prefix ", el("span", { class: "mono" }, r.prefix), " · codes look like ", el("span", { class: "mono tg-nowrap" }, example(r.prefix)))),
            el("a", { class: "btn primary tg-to", href: to.href, target: "_blank", rel: "noopener noreferrer" }, `Register with ${r.name}`));
        }) : [el("p", {}, "No registry takes ToG statements yet.")]));
    }, () => list.replaceChildren(el("p", {}, "The signed list of registries could not be loaded. Try again later.")));
    return { big: true, label: "PRE-GEN Protocol", title: "Create your ToG",
      hint: "A ToG is your signed yes or no on whether AI may generate your likeness, your brand or your products. The questions are asked at the registry you choose. Your registry issues your ToG code.",
      body: [
        notRegistry(),
        el("ol", { class: "gsteps" }, [
          ["Choose a registry", "Pick one from the list below. It opens in a new tab."],
          ["Answer the questions there", "The registry asks what AI may and may not do, and records your statement."],
          ["Confirm", "The registry confirms your identity and your rights. Publishing your ToG statement on a website or profile you control confirms the code is yours."],
          ["In force", "Once confirmed, your ToG code takes effect for every registry and AI service on PRE-GEN Protocol."],
        ].map(([h, p], i) => el("li", {}, el("span", { class: "n" }, String(i + 1)), el("div", {}, el("h2", {}, h), el("p", {}, p))))),
        list,
        el("p", { class: "meta tg-fine" }, "Your AI service needs no ToG code. ", el("a", { href: "/connect" }, "Connect your AI"), "."),
        el("p", { class: "meta tg-fine" }, "To register people or companies yourself, ", el("a", { href: "/create-registry" }, "create a registry"), "."),
        el("p", { class: "meta tg-fine" }, `Under ${LEGAL.label}, one common text for everyone. `, el("a", { href: "/tog/1.1" }, "Read the legal code"), "."),
      ] };
  },
  result() { return result(S.done); },
  broken() {
    return { label: "ToG statement", title: "This link holds no ToG statement",
      hint: "It may have been cut short when it was copied. Open the link your registry gave you again, or start here.",
      body: el("p", { class: "tg-actions" }, el("a", { class: "btn primary", href: "/tog/create" }, "Create your ToG")) };
  },
};

/** Print the Holder's copy (ToG-L 1.1 §16(g)): built here, printed from a hidden frame; the person saves it as a PDF.
 *  The name stays in S.holder: never in a URL, never in storage. */
function copyPart(done, looked) {
  const note = el("p", { class: "meta tg-fine", "aria-live": "polite" });
  const go = async () => {
    note.replaceChildren("Preparing your copy…");
    try {
      const [text, d] = await Promise.all([fetch("/tog/1.1/legal-code.txt").then((r) => (r.ok ? r.text() : Promise.reject(r.status))), looked.catch(() => null)]);
      const sx = d && d.status === "active" && (d.statement || d);
      const co = done.answers.who === "company";
      const { title, html, pageCss } = holderCopy({ code: done.code, holder: S.holder, company: co, conditions: done.answers.conditions || null,
        lines: statement(done).lines, rules: co ? companyRules(done.answers) : rulesFromAnswers(done.answers), licenceText: text, licence: LEGAL,
        statement: sx && sx.version != null ? { version: sx.version, sha256: sx.sha256 ?? sx.statement_sha256 } : sx ? { held: true } : null, registry: { name: done.registry, prefix: done.prefix } });
      const f = el("iframe", { title: "Your copy", class: "tg-print" });
      const old = document.title;
      f.addEventListener("load", () => {
        document.title = title;   // the name the browser suggests for the PDF
        const w = f.contentWindow, d = f.contentDocument;
        if ("CSSMarginRule" in w) {   // the foot in the page margin; the constructable sheet passes the site's CSP
          const sheet = new w.CSSStyleSheet(); sheet.replaceSync(pageCss); d.adoptedStyleSheets = [sheet];
        } else d.querySelector(".foot").classList.add("fallback");
        w.addEventListener("afterprint", () => { document.title = old; f.remove(); });
        w.focus(); w.print();
      });
      f.srcdoc = html;
      document.body.append(f);
      note.replaceChildren("Choose Save as PDF in the print window.");
    } catch { note.replaceChildren("The copy could not be prepared. Check your connection and try again."); }
  };
  return [el("h2", {}, "Your copy of the licence"),
    el("p", {}, `A PDF of ${LEGAL.label} with your code, your statement and your conditions after it. The text is the same for everyone.`),
    field("Name on your copy (optional)", S.holder, (v) => (S.holder = v), { autocomplete: "name" }),
    el("p", { class: "meta tg-fine" }, "It stays on this page and goes only onto your copy. It is not sent or saved."),
    el("p", { class: "tg-actions" }, el("button", { type: "button", class: "btn primary", onclick: go }, "Download your ToG-L")), note];
}

/** The result: the code's live status, the statement in the form the person needs, and how to publish it. */
function result(done) {
  const st = statement(done), name = done.registry, co = st.co;
  const view = S.view || "site";
  const line = () => el("span", { class: "tg-nowrap" }, proofLine(done.code));   // never broken at a dash; a new node per use
  const status = el("p", { class: "tg-status-line" }, "Reading the code's status at its registry…");
  const looked = lookup(done.code);
  looked.then((d) => status.replaceChildren(...{
    pending: [el("b", {}, "Pending. "), `It permits and forbids nothing until you confirm it, within 7 days of registration.`],
    active: [el("b", {}, "Active. "), "Your statement is in force for every registry and AI service on PRE-GEN Protocol."],
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
      copyPart(done, looked),
      keep && copyBlock("Link to this statement", keep, "Bookmark it to come back. The statement is in the part after #, which is read in your browser and never sent to a server."),
      el("h2", {}, "The legal text"), el("p", {}, `Your statement is made under ${LEGAL.label}, one common text for everyone.`), legalLinks(),
      el("p", { class: "tg-actions" }, el("a", { class: "btn", href: "/tog/create" }, "Start a new statement"))] };
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
  const name = trail.at(-1), s = SCREENS[name]();
  const h = el("h1", { id: "tg-h", class: s.big ? "tg-h tg-h--big" : "tg-h", tabindex: "-1" }, s.title);
  const head = [el("p", { class: "label tg-step" }, s.label || "Create your ToG"), h, s.hint && el("p", { class: "tg-hint" }, s.hint)];
  stage.replaceChildren(el("div", { class: "tg-screen", "data-screen": name }, head, el("div", { class: "tg-body" }, s.body)));
  h.focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

reset();
const show = () => fromReturn().then((done) => {
  reset();
  if (done) { S.done = done; S.view = "site"; trail = ["result"]; } else trail = ["broken"];
  render();
});
if (DOCUMENT) { show(); window.addEventListener("hashchange", show); } else render();
