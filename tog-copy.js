// The Holder's copy of ToG-L 1.1 (Section 16(g)): the licence text unchanged, then Appendix A (Notice) and Appendix B
// (The Holder's Rules), with a running foot outside the licence text. A pure function: it returns one HTML document,
// which /tog/document prints with window.print() (the person saves it as a PDF). Nothing here reads or writes a URL.
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const plain = (s) => s.replace(/\*\*/g, "");
const HEX64 = /^[0-9a-f]{64}$/;

/** The running foot, outside the licence text: "ToG: <code> · v<version> · <8 hex> · Check: pregen.org/lookup?code=<code>". */
export function foot({ code, statement }) {
  const ok = statement && statement.version != null && HEX64.test(statement.sha256 || "");
  return `ToG: ${code} · ${ok ? "v" + statement.version : statement?.held ? "in force" : "pending"} · ${ok ? statement.sha256.slice(0, 8) : statement?.held ? "see Registry" : "pending"}`
    + ` · Check: pregen.org/lookup?code=${encodeURIComponent(code)}`;
}

/** The @page rule with the foot in the bottom margin of every page, "Page k of N" after it. */
export const pageCss = (f) => `@page { @bottom-center { content: ${JSON.stringify(f + " \u00b7 Page ")} counter(page) " of " counter(pages); font: 8.5pt Georgia, serif; } }`;

/** {code, holder, company, conditions, lines, rules, licenceText, licence, statement, registry} -> {title, html, pageCss}.
 *  statement: {version, sha256} when the home Registry shows it, else null (pending). registry: {name, prefix} or null. */
export function holderCopy({ code, holder = "", company = false, conditions = null, lines = [], rules = null, licenceText,
  licence, statement = null, registry = null }) {
  const title = `ToG-L 1.1 - ${code}`;
  const name = holder.trim();
  const matter = company ? "The marks, products and characters the Holder owns" + (name ? ` (${name})` : "")
    : "The likeness and voice of the Holder";
  const st = statement && statement.version != null && HEX64.test(statement.sha256 || "")
    ? `Version ${statement.version}, SHA-256 <span class="hash">${esc(statement.sha256)}</span>${registry ? ", at " + esc(registry.name) : ""}`
    : statement?.held ? "In force at the home Registry, which shows its version and hash. The Registry&#39;s record decides."
    : "Pending at the home Registry. The Registry&#39;s record decides.";
  const reg = registry ? `${esc(registry.name)} (prefix ${esc(registry.prefix)})` : "Not known";
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>${esc(title)}</title><link rel="stylesheet" href="/tog-copy.css"></head><body>
<div class="foot">${esc(foot({ code, statement }))}</div>
<pre class="licence">${esc(licenceText)}</pre>
<section class="app"><h2>Appendix A (Notice)</h2>
<table>
<tr><th>Code</th><td>${esc(code)}</td></tr>
<tr><th>Holder</th><td>${name ? esc(name) : "Not given"}</td></tr>
<tr><th>Matter</th><td>${esc(matter)}</td></tr>
<tr><th>Licence</th><td>${esc(licence.id)}, SHA-256 <span class="hash">${esc(licence.sha256)}</span></td></tr>
<tr><th>Statement</th><td>${st}</td></tr>
<tr><th>Registry</th><td>${reg}</td></tr>
</table>
<p>This notice permits nothing by itself. The Statement at the Registry decides what is permitted.</p></section>
<section class="app"><h2>Appendix B (The Holder&#39;s Rules)</h2>
<h3>Conditions</h3>
<div class="cond">${conditions ? esc(conditions) : "None"}</div>
<h3>The Statement</h3>
<ul>${lines.map(plain).map((l) => `<li>${esc(l)}</li>`).join("")}</ul>
${rules ? `<h3>Machine rules</h3><pre class="rules">${esc(JSON.stringify(rules, null, 2))}</pre>` : ""}
<p>Where this Appendix differs from the Statement as held at the home Registry, the Registry&#39;s record governs.</p></section>
</body></html>`;
  return { title, html, pageCss: pageCss(foot({ code, statement })) };
}
