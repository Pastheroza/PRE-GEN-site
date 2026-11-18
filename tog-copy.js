// The Holder's copy of ToG-L 1.0 (Section 16(g)): the licence text unchanged, then Appendix A (Notice) and Appendix B
// (The Holder's Rules), with a running foot outside the licence text. A pure function: it returns one HTML document,
// which /tog/document prints with window.print() (the person saves it as a PDF). Nothing here reads or writes a URL.
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
/** The licence set as the official PDF is set (Times, justified, "Section N" references linked, definitions indented):
 * a port of the builder's render (apache-style build.py), and prampta.com's server (app/core/tog_copy.py) sets it the
 * same way; change the three together. Presentation only: the hashed text is never altered. */
const escText = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
const inline = (s) => {
  const codes = [];
  s = escText(s).replace(/`([^`]+)`/g, (_, c) => `\0${codes.push(c) - 1}\0`)
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/(?<![\w*])\*(.+?)\*(?![\w*])/g, "<em>$1</em>")
    .replace(/https:\/\/[\w./-]+[\w/]/g, (u) => `<a href="${u}">${u}</a>`)
    .replace(/\b([Ss]ections? |SECTIONS? )(\d{1,2})\b((?:\([a-z0-9]\))*)/g,
      (_, w, n, sub) => `<a class="ref" href="#section-${n}${sub ? "-" + sub[1] : ""}">${w}${n}${sub}</a>`);
  return s.replace(/\0(\d+)\0/g, (_, i) => `<code>${codes[+i]}</code>`);
};
const blocks = (md) => {
  const out = [];
  for (const b of md.replace(/^\n+|\n+$/g, "").split(/\n[ \t]*\n/).filter((x) => x.trim())) {
    if (b.startsWith("    ") && out.length && out[out.length - 1].startsWith("    ")) out[out.length - 1] += "\n    \n" + b;
    else out.push(b);
  }
  return out;
};
const render = (md) => {
  const out = []; let section = 0;
  for (const b of blocks(md)) {
    const first = b.split("\n")[0], keep = b.length < 700 ? " keep" : "";
    let m;
    if ((m = /^## (\d+)\. (.+)\.$/.exec(first))) {
      section = +m[1];
      out.push(`<h2 class="section" id="section-${section}"><a href="#section-${section}">${section}. ${inline(m[2])}</a>.</h2>`);
    } else if (/^\d+\. /.test(first)) {
      const lis = b.split(/\n(?=\d+\. )/).map((i) => `<li value="${i.split(".")[0]}">${inline(i.slice(i.indexOf(". ") + 2))}</li>`).join("");
      out.push(`<ol class="${section === 1 ? "def" : "items"}">${lis}</ol>`);
    } else if (b.startsWith("    ")) {
      out.push("<pre>" + escText(b.split("\n").map((l) => l.slice(4)).join("\n")) + "</pre>");
    } else if ((m = /^\(([a-z])\) /.exec(first))) {
      out.push(`<p class="para${keep}" id="section-${section}-${m[1]}">${inline(b)}</p>`);
    } else {
      let cls = section === 1 ? "def" : "";
      if (first === first.toUpperCase() && /[A-Z]/.test(first) || first.startsWith("TERMS AND CONDITIONS")) cls = "caps";
      const t = inline(b.split("\n").join(" "));
      out.push(cls || keep ? `<p class="${(cls + keep).trim()}">${t}</p>` : `<p>${t}</p>`);
    }
  }
  return out.join("\n");
};
export function renderLicence(text) {
  const bl = blocks(text);
  const titled = bl.length > 4 && bl[0].startsWith("# ");
  const head = titled ? `<h1 class="title">${inline(bl[0].slice(2))}</h1>\n<p class="sub">${inline(bl[1])}</p>\n<p class="sub">${inline(bl[2])}</p>\n<p class="copy">${inline(bl[3])}</p>\n` : "";
  const body = render((titled ? bl.slice(4) : bl).join("\n\n"))
    .replace(/<p class="caps( keep)?">END OF TERMS AND CONDITIONS<\/p>/, '<p class="caps$1 end">END OF TERMS AND CONDITIONS</p>');
  const ids = new Set([...body.matchAll(/id="([^"]+)"/g)].map((x) => x[1]));
  return (head + body).replace(/href="#(section-\d+)-([a-z])"/g, (all, sec, l) => (ids.has(`${sec}-${l}`) ? all : `href="#${sec}"`));
}
const HEX64 = /^[0-9a-f]{64}$/;

/** The running foot, outside the licence text: "ToG: <code> · v<version> · <8 hex> · Check: pregen.org/lookup?code=<code>". */
export function foot({ code, statement }) {
  const ok = statement && statement.version != null && HEX64.test(statement.sha256 || "");
  return `ToG: ${code} · ${ok ? "v" + statement.version : statement?.held ? "in force" : "pending"} · ${ok ? statement.sha256.slice(0, 8) : statement?.held ? "see Registry" : "pending"}`
    + ` · Check: pregen.org/lookup?code=${encodeURIComponent(code)}`;
}

/** The @page rule with the foot in the bottom margin of every page, "Page k of N" after it. */
export const pageCss = (f) => `@page { @bottom-center { content: ${JSON.stringify(f + " · Page ")} counter(page) " of " counter(pages); font: 8.5pt "Times New Roman", Times, serif; } }`;

const PURPOSES = ["personal", "editorial", "educational", "research", "commercial"];
const FORMS = ["image", "video", "voice", "3d"];
const CATEGORIES = ["sexual", "adult", "advertising", "endorsement", "alcohol", "tobacco", "cannabis", "drugs", "gambling",
  "weapons", "violence", "political", "religion", "health", "financial", "fashion"];
const PENDING = "Pending at the home Registry. The Registry&#39;s record decides.";

/** Appendix B as the official copies show it: the Conditions in a frame, a Stop box when nothing is permitted, then
 * Purposes, Forms, Training, Matter and the excluded categories. The rules are the Statement's (verify-js). */
function rulesPage({ code, company, name, conditions, rules, st, registry }) {
  const r = rules || { uses: {}, modalities: [], excluded_categories: [], training: false };
  const uses = r.uses || {}, yes = '<span class="yes">Yes</span>';
  const purpose = (p) => p === "commercial" ? (p in uses ? `<span class="yes">Only by a Deal</span>; the Holder will consider one` : "No")
    : ({ open: yes, approve: `${yes}, each Output only with the Holder&#39;s Approval` }[uses[p]] || "No");
  const cat = (c) => (c === "sexual" || c === "adult") && company ? "never (5(a))" : (r.excluded_categories || []).includes(c) ? "excluded"
    : c === "sexual" || c === "adult" ? "only by a Deal (5(a))" : "not excluded";
  const cond = (conditions || "").trim();
  const matter = company ? "The marks, products and characters the Holder owns" + (name ? ` (${esc(name)})` : "") : "The Person&#39;s Likeness: face, body and voice";
  const head = st ? `Statement version ${esc(st.version)} for ${esc(code)}${registry ? ", at " + esc(registry.name) : ""}` : `Statement for ${esc(code)}: ${PENDING}`;
  return `<h2>APPENDIX B — THE HOLDER&#39;S RULES</h2>
<p class="lead">${head}</p>
<div class="cond"><p class="k">Conditions, in the Holder&#39;s own words (${cond.length.toLocaleString("en-US")} of 1,000 characters)</p><p>${cond ? esc(cond) : "None"}</p></div>
${Object.keys(uses).length ? "" : '<p class="stop">This Statement is a Stop: no AI generation. It permits nothing.</p>'}<table>
<tr><th>Purposes</th><td><div class="kv">${PURPOSES.map((p) => `<div><code>${p}</code> ${purpose(p)}</div>`).join("")}</div></td></tr>
<tr><th>Forms</th><td>${FORMS.map((f) => `<code>${f}</code> ${(r.modalities || []).includes(f) ? yes : "No"}`).join(" &nbsp; ")}</td></tr>
<tr><th>Training</th><td>${r.training ? "No; the Holder will consider a paid Deal with an end date" : "No"} (Section 6(e))</td></tr>
<tr><th>Matter</th><td>${matter}</td></tr>
</table>
<p class="small"><i>Excluded categories</i> (Section 6(d))</p>
<div class="cats">${CATEGORIES.map((c) => `<div><code>${c}</code><span>${cat(c)}</span></div>`).join("")}</div>
<p class="small" style="margin-top:.8em">${company ? "Sexual and adult content: never, not even by a Deal (Section 5(a))." : "Sexual and adult content: Section 5(a) applies."} This Appendix copies the Statement and permits nothing by itself. Where it differs from the Statement as held at the home Registry, the Registry&#39;s record governs (Section 16(g)).</p>`;
}

/** {code, holder, company, conditions, rules, licenceText, licence, statement, registry} -> {title, html, pageCss}.
 *  statement: {version, sha256} when the home Registry shows it, else null (pending). registry: {name, prefix} or null.
 *  The set of the official PDF (pregen.org/tog/files): the licence unchanged to "END OF TERMS AND CONDITIONS", then
 *  Appendix A and Appendix B, each on a page of its own, and the foot outside the text. */
export function holderCopy({ code, holder = "", company = false, conditions = null, rules = null, licenceText, licence,
  statement = null, registry = null }) {
  const title = `ToG-L 1.0 - ${code}`;
  const name = holder.trim();
  const sure = statement && statement.version != null && HEX64.test(statement.sha256 || "");
  const st = sure
    ? `version ${esc(statement.version)}, SHA-256<br><span class="hash">${esc(statement.sha256)}</span>${registry ? ",<br>at " + esc(registry.name) : ""}`
    : statement?.held ? "In force at the home Registry, which shows its version and hash. The Registry&#39;s record decides." : PENDING;
  const matter = company ? "the marks, products and characters that the Holder&#39;s Statement lists" : "the Holder&#39;s Likeness";
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>${esc(title)}</title><link rel="stylesheet" href="/tog-copy.css"></head><body>
<div class="foot">${esc(foot({ code, statement }))}</div>
<div class="licence">${renderLicence(licenceText)}</div>
<section class="addl"><h2>APPENDIX A — NOTICE</h2>
<p class="lead">This Appendix follows the Licence above and is not part of it (Section 16(g)).</p>
<p class="code"><span>ToG:</span> ${esc(code)}</p>
<p>${name ? esc(name) : "The Holder"} has applied the Terms of Generation Licence, Version 1.0 (ToG-L-1.0), to ${matter}.</p>
<table>
<tr><th>Licence</th><td><a href="https://pregen.org/tog">https://pregen.org/tog</a></td></tr>
<tr><th>SHA-256</th><td><span class="hash">${esc(licence.sha256)}</span></td></tr>
<tr><th>Statement</th><td>${st}</td></tr>
</table>
<p>This notice is not a Statement and contains no Rules. The Statement at the Registry decides what is permitted, not this notice. Every use the Statement does not permit is reserved.</p></section>
<section class="addl">${rulesPage({ code, company, name, conditions, rules, st: sure ? statement : null, registry })}</section>
</body></html>`;
  return { title, html, pageCss: pageCss(foot({ code, statement })) };
}
