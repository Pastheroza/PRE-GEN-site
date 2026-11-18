// The Holder's copy of ToG-L 1.0 (tog-copy.js): title, order of the parts, conditions first, the foot, pending wording.
// Run: node --test test/tog-copy.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { holderCopy, foot, pageCss, renderLicence } from "../tog-copy.js";
import { LEGAL, companyRules, rulesFromAnswers, card } from "../packages/verify-js/tog.js";

const CODE = "TOG-PRAM-0000123X";
const answers = { age: "18+", decision: "rules", for: ["fun"], never: ["vice"], voice: false, conditions: "Never in <b>horror</b>." };
const base = { code: CODE, lines: card(rulesFromAnswers(answers)), rules: rulesFromAnswers(answers), conditions: answers.conditions,
  licenceText: "LICENCE TEXT <unchanged>\nSection 1.", licence: LEGAL, registry: { name: "PRAMPTA", prefix: "PRAM" } };
const SHA = "ab".repeat(32);

test("title is the file name; the licence comes first, then Appendix A, then B", () => {
  const { title, html } = holderCopy(base);
  assert.equal(title, "ToG-L 1.0 - TOG-PRAM-0000123X");
  assert.match(html, /<title>ToG-L 1\.0 - TOG-PRAM-0000123X<\/title>/);
  const at = ["LICENCE TEXT &lt;unchanged&gt;", "APPENDIX A \u2014 NOTICE", "APPENDIX B \u2014 THE HOLDER&#39;S RULES"].map((x) => html.indexOf(x));
  assert.ok(at[0] > 0 && at[0] < at[1] && at[1] < at[2], at.join());
  assert.ok(html.includes(LEGAL.sha256));
});

test("appendix B: the conditions in a frame first, escaped; then the purposes, forms, training and matter", () => {
  const { html } = holderCopy(base);
  const b = html.slice(html.indexOf("APPENDIX B"));
  assert.ok(b.indexOf("Conditions, in the Holder&#39;s own words") < b.indexOf("Never in &lt;b&gt;horror&lt;/b&gt;.") && b.indexOf("Never in") < b.indexOf("Purposes"));
  assert.ok(b.indexOf("Purposes") < b.indexOf("Forms") && b.indexOf("Forms") < b.indexOf("Training") && b.indexOf("Training") < b.indexOf("Matter"));
  assert.match(b, /<code>personal<\/code> <span class="yes">Yes<\/span>/);
  assert.match(b, /<code>political<\/code><span>excluded<\/span>/);
  assert.doesNotMatch(b, /Stop/);
  assert.doesNotMatch(b, /\*\*/);
  assert.match(holderCopy({ ...base, rules: { uses: {}, modalities: [], excluded_categories: [], training: false } }).html, /This Statement is a Stop: no AI generation/);
});

test("appendix A: the code, the holder, the matter and pending wording, for a person and for a company", () => {
  let { html } = holderCopy(base);
  assert.match(html, /<p class="code"><span>ToG:<\/span> TOG-PRAM-0000123X<\/p>/);
  assert.match(html, /<p>The Holder has applied the Terms of Generation Licence, Version 1\.0 \(ToG-L-1\.0\), to the Holder&#39;s Likeness\.<\/p>/);
  assert.match(html, /Pending at the home Registry\. The Registry&#39;s record decides\./);
  ({ html } = holderCopy({ ...base, holder: "Northwind & Co", company: true, rules: companyRules({ who: "company", decision: "no" }) }));
  assert.match(html, /<p>Northwind &amp; Co has applied/);
  assert.match(html, /the marks, products and characters that the Holder&#39;s Statement lists/);
  assert.match(html, /The marks, products and characters the Holder owns \(Northwind &amp; Co\)/);
  ({ html } = holderCopy({ ...base, statement: { version: 3, sha256: SHA } }));
  assert.match(html, /version 3, SHA-256<br><span class="hash">abab/);
  assert.doesNotMatch(html, /Pending at the home Registry/);
});

test("everything particular to the Holder comes after the licence's last line (founder 2026-11-17)", () => {
  const { html } = holderCopy({ ...base, licenceText: "Text.\n\nEND OF TERMS AND CONDITIONS\n", holder: "Ada" });
  const body = html.slice(html.indexOf("<body>")), end = body.indexOf("END OF TERMS AND CONDITIONS");
  for (const mine of ["TOG-PRAM-0000123X", "Ada has applied", "Never in"]) assert.ok(body.indexOf(mine, end) > end, mine);
  assert.ok(!body.slice(body.indexOf('<div class="licence">'), end).includes("Ada"));
});

test("the foot: code, version, first 8 hex, where to check; pending when the Registry shows no version", () => {
  assert.equal(foot({ code: CODE, statement: { version: 3, sha256: SHA } }), `ToG: ${CODE} · v3 · abababab · Check: pregen.org/lookup?code=${CODE}`);
  assert.equal(foot({ code: CODE, statement: null }), `ToG: ${CODE} · pending · pending · Check: pregen.org/lookup?code=${CODE}`);
  assert.equal(foot({ code: CODE, statement: { version: 2, sha256: "short" } }), foot({ code: CODE, statement: null }));
  const { html } = holderCopy(base);
  assert.match(html, /<div class="foot">ToG: TOG-PRAM-0000123X · pending/);
  assert.ok(html.indexOf('class="foot"') < html.indexOf('class="licence"'));   // outside the licence text
});

test("no conditions: the frame says None", () => {
  assert.match(holderCopy({ ...base, conditions: null }).html, /<p>None<\/p><\/div>/);
});

test("the page rule puts the foot in the bottom margin with the page count", () => {
  const { pageCss: css } = holderCopy(base);
  assert.equal(css, pageCss(foot({ code: CODE, statement: null })));
  assert.match(css, /^@page \{ @bottom-center \{ content: "ToG: TOG-PRAM-0000123X · pending · pending · Check: pregen\.org\/lookup\?code=TOG-PRAM-0000123X · Page " counter\(page\) " of " counter\(pages\);/);
});

test("the licence is set as the official PDF is: linked Section references, indented definitions, one 'end' paragraph", () => {
  const h = renderLicence("# T\n\nv\n\nu\n\nTERMS AND CONDITIONS FOR X\n\n## 1. Definitions.\n\n1. \"A\" means **b** (see Section 9(a)).\n2. two\n\nEND OF TERMS AND CONDITIONS");
  assert.match(h, /^<h1 class="title">T<\/h1>\n<p class="sub">v<\/p>\n<p class="sub">u<\/p>\n<p class="copy">TERMS AND CONDITIONS FOR X<\/p>/);
  assert.match(h, /<h2 class="section" id="section-1"><a href="#section-1">1\. Definitions<\/a>\.<\/h2>/);
  assert.match(h, /<ol class="def"><li value="1">"A" means <strong>b<\/strong> \(see <a class="ref" href="#section-9">Section 9\(a\)<\/a>\)\.<\/li>/);
  assert.match(h, /<p class="caps keep end">END OF TERMS AND CONDITIONS<\/p>$/);
});

test("the published licence text is the one that is set, and sets as prampta.com's server sets it", () => {
  const text = readFileSync(new URL("../tog/1.0/legal-code.txt", import.meta.url), "utf8");
  assert.equal(createHash("sha256").update(text).digest("hex"), LEGAL.sha256);
  const h = renderLicence(text);
  assert.equal((h.match(/<h2 class="section"/g) || []).length, 16);
  assert.doesNotMatch(h, /\*\*|\n#{1,3} /);                  // no markdown marks left
  assert.match(h, /<p class="caps keep end">END OF TERMS AND CONDITIONS<\/p>/);
});
