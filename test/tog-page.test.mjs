// /tog (UNRELEASED draft, PRE-GEN-Drafts/tog-funnel/PLAN.md §4.1): the page loads only the ToG module, keeps the CSP,
// never puts the year of birth or the answers anywhere but the fragment, says "draft" beside every legal name, and a
// company's files carry tog:<domain> and no TOG- code. The cards themselves: packages/verify-js/test/tog.test.js.
// Run: node --test test/tog-page.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { companyFiles } from "../packages/verify-js/tog.js";

const read = (f) => readFileSync(new URL("../" + f, import.meta.url), "utf8");
const html = read("tog.html"), js = read("tog.js");

test("the page loads only its own module, which imports only the ToG library; no inline script or style", () => {
  assert.deepEqual(html.match(/<script[^>]*>/g), ['<script src="/theme.js">', '<script src="/site.js" defer>', '<script type="module" src="/tog.js">']);
  assert.deepEqual([...js.matchAll(/^import[^;]*from "([^"]+)"/gms)].map((m) => m[1]), ["/packages/verify-js/tog.js"]);
  assert.doesNotMatch(html, /\sstyle=|<style/);
  assert.doesNotMatch(js, /innerHTML|insertAdjacentHTML|\.style\b|"style"|eval\(|new Function/);
  assert.match(html, /<meta name="robots" content="noindex">/);
  assert.match(read("vercel.json"), /style-src 'self';/);
  assert.doesNotMatch(read("sitemap.xml"), /pregen\.org\/tog</);
});

test("nothing is stored, and only the fragment carries answers", () => {
  assert.doesNotMatch(js, /localStorage|sessionStorage|indexedDB|document\.cookie|history\.|location\.(search|href\s*=)|URLSearchParams|\?tog=/);
  // The one link out: the registry's start URL, '#', the encoded answers (never the year, a name or a domain).
  assert.deepEqual([...js.matchAll(/href: r\.start \+ "#" \+ ([^)]+\))/g)].map((m) => m[1]), ["encodeAnswers(answers()"]);
  assert.doesNotMatch(js.slice(js.indexOf("function answers()"), js.indexOf("const personRules")), /year|name|domain/);
  for (const [, url] of js.matchAll(/fetch\("([^"]+)"/g)) assert.equal(url, "/test/tog-local/steward.json");
});

test('"draft" beside every legal name the page shows', () => {
  for (const text of [html, js]) {
    for (const m of text.matchAll(/ToG-[LB]-1\.0|prampta-likeness/g)) {
      assert.match(text.slice(m.index, m.index + 40), /draft/i, text.slice(m.index - 20, m.index + 40));
    }
  }
  assert.match(js, /ToG-L-1\.0 \(draft, not final\)/);
  assert.match(js, /ToG-B-1\.0 \(draft, not final\)/);
});

test("a company's files: tog:<domain>, the link line, no TOG- code, unsigned", () => {
  for (const a of [{ decision: "no" }, { decision: "rules", for: ["fun", "news", "paid"], never: ["vice"] }]) {
    const f = companyFiles("northwind.example", "Northwind Coffee", a);
    const all = Object.values(f).join("\n");
    assert.match(all, /tog:northwind\.example/);
    assert.doesNotMatch(all, /TOG-/);
    assert.equal(f.link_tag, '<link rel="tog" href="https://northwind.example/.well-known/tog.json">');
    assert.match(f.page_html, /Unsigned draft: until signed with your passkey, AI apps read this as a no\./);
    const doc = JSON.parse(f.tog_json);
    assert.equal(doc.keys, null);
    assert.deepEqual(doc.statements[0].body.signers, []);
  }
});

test("the local stand is never deployed nor committed", () => {
  for (const f of [".vercelignore", ".gitignore"]) assert.match(read(f), /^test\/tog-local\/$/m, f);
  assert.doesNotMatch(read(".vercelignore"), /^!/m);
});
