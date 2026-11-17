// The Holder's copy of ToG-L 1.1 (tog-copy.js): title, order of the parts, conditions first, the foot, pending wording.
// Run: node --test test/tog-copy.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { holderCopy, foot, pageCss } from "../tog-copy.js";
import { LEGAL, companyRules, rulesFromAnswers, card } from "../packages/verify-js/tog.js";

const CODE = "TOG-PRAM-0000123X";
const answers = { age: "18+", decision: "rules", for: ["fun"], never: ["vice"], voice: false, conditions: "Never in <b>horror</b>." };
const base = { code: CODE, lines: card(rulesFromAnswers(answers)), rules: rulesFromAnswers(answers), conditions: answers.conditions,
  licenceText: "LICENCE TEXT <unchanged>\nSection 1.", licence: LEGAL, registry: { name: "PRAMPTA", prefix: "PRAM" } };
const SHA = "ab".repeat(32);

test("title is the file name; the licence comes first, then Appendix A, then B", () => {
  const { title, html } = holderCopy(base);
  assert.equal(title, "ToG-L 1.1 - TOG-PRAM-0000123X");
  assert.match(html, /<title>ToG-L 1\.1 - TOG-PRAM-0000123X<\/title>/);
  const at = ["LICENCE TEXT &lt;unchanged&gt;", "Appendix A (Notice)", "Appendix B (The Holder&#39;s Rules)"].map((x) => html.indexOf(x));
  assert.ok(at[0] > 0 && at[0] < at[1] && at[1] < at[2], at.join());
  assert.ok(html.includes(LEGAL.sha256));
});

test("appendix B: the conditions come first, escaped; then the yes and no lines; then the machine rules", () => {
  const { html } = holderCopy(base);
  const b = html.slice(html.indexOf("Appendix B"));
  assert.ok(b.indexOf("Conditions") < b.indexOf("Never in &lt;b&gt;horror&lt;/b&gt;.") && b.indexOf("Never in") < b.indexOf("The Statement"));
  assert.ok(b.indexOf("The Statement") < b.indexOf("Machine rules"));
  assert.match(b, /<li>AI may make me only for/);
  assert.doesNotMatch(b, /\*\*/);
});

test("appendix A: pending wording, holder and matter for a person and for a company", () => {
  let { html } = holderCopy(base);
  assert.match(html, /Holder<\/th><td>Not given/);
  assert.match(html, /The likeness and voice of the Holder/);
  assert.match(html, /Pending at the home Registry\. The Registry&#39;s record decides\./);
  ({ html } = holderCopy({ ...base, holder: "Northwind & Co", company: true, rules: companyRules({ who: "company", decision: "no" }) }));
  assert.match(html, /Holder<\/th><td>Northwind &amp; Co/);
  assert.match(html, /The marks, products and characters the Holder owns \(Northwind &amp; Co\)/);
  ({ html } = holderCopy({ ...base, statement: { version: 3, sha256: SHA } }));
  assert.match(html, /Version 3, SHA-256 <span class="hash">abab/);
  assert.doesNotMatch(html, /Pending at the home Registry/);
});

test("the foot: code, version, first 8 hex, where to check; pending when the Registry shows no version", () => {
  assert.equal(foot({ code: CODE, statement: { version: 3, sha256: SHA } }), `ToG: ${CODE} · v3 · abababab · Check: pregen.org/lookup?code=${CODE}`);
  assert.equal(foot({ code: CODE, statement: null }), `ToG: ${CODE} · pending · pending · Check: pregen.org/lookup?code=${CODE}`);
  assert.equal(foot({ code: CODE, statement: { version: 2, sha256: "short" } }), foot({ code: CODE, statement: null }));
  const { html } = holderCopy(base);
  assert.match(html, /<div class="foot">ToG: TOG-PRAM-0000123X · pending/);
  assert.ok(html.indexOf('class="foot"') < html.indexOf('class="licence"'));   // outside the licence text
});

test("no conditions: the box says None", () => {
  assert.match(holderCopy({ ...base, conditions: null }).html, /<div class="cond">None<\/div>/);
});

test("the page rule puts the foot in the bottom margin with the page count", () => {
  const { pageCss: css } = holderCopy(base);
  assert.equal(css, pageCss(foot({ code: CODE, statement: null })));
  assert.match(css, /^@page \{ @bottom-center \{ content: "ToG: TOG-PRAM-0000123X · pending · pending · Check: pregen\.org\/lookup\?code=TOG-PRAM-0000123X · Page " counter\(page\) " of " counter\(pages\);/);
});
