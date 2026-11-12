// /tog (spec/drafts/tog-funnel.md): the page loads only the ToG module, keeps the CSP, never puts the year of birth
// or the answers anywhere but the fragment, names only the one common legal text (ToG 1.0, with its hash and link) and
// no draft text, and is public. The cards: packages/verify-js/test/tog.test.js; the screens: test/tog-flow.test.mjs.
// Run: node --test test/tog-page.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

const read = (f) => readFileSync(new URL("../" + f, import.meta.url), "utf8");
const exists = (f) => existsSync(new URL("../" + f, import.meta.url));
const html = read("tog.html"), js = read("tog.js");

test("the page loads only its own module, which imports only the ToG library; no inline script or style; public", () => {
  assert.deepEqual(html.match(/<script[^>]*>/g), ['<script src="/theme.js">', '<script src="/site.js" defer>', '<script type="module" src="/tog.js">']);
  assert.deepEqual([...js.matchAll(/^import[^;]*from "([^"]+)"/gms)].map((m) => m[1]), ["/packages/verify-js/tog.js"]);
  assert.doesNotMatch(html, /\sstyle=|<style/);
  assert.doesNotMatch(js, /innerHTML|insertAdjacentHTML|\.style\b|"style"|eval\(|new Function/);
  assert.doesNotMatch(html, /noindex|DRAFT|[Nn]ot public/);
  assert.match(read("vercel.json"), /style-src 'self';/);
  for (const url of ["/tog", "/tog/1.0", "/tog/1.0/deed"]) assert.match(read("sitemap.xml"), new RegExp(`pregen\\.org${url}<`));
});

test("nothing is stored, and only the fragment carries answers", () => {
  assert.doesNotMatch(js, /localStorage|sessionStorage|indexedDB|document\.cookie|history\.|location\.(search|href\s*=)|URLSearchParams|\?tog=/);
  // The one link out: the registry's start URL, '#', the encoded answers (never the year, a name or a domain).
  assert.deepEqual([...js.matchAll(/href: r\.start \+ "#" \+ ([^)]+\))/g)].map((m) => m[1]), ["encodeAnswers(answers()"]);
  assert.doesNotMatch(js.slice(js.indexOf("function answers()"), js.indexOf("const personRules")), /year|name|domain/);
  for (const [, url] of js.matchAll(/fetch\("([^"]+)"/g)) assert.equal(url, "/test/tog-local/steward.json");
});

test("one common legal text: the page names only ToG 1.0, links its pages, and never builds a personal copy", () => {
  for (const text of [html, js]) assert.doesNotMatch(text, /ToG-[LB]-1\.0|prampta-likeness|(?<!public )\bdraft\b(?! 1\b)|UNRELEASED|Blob|download/i);
  assert.match(js, /href: "\/tog\/1\.0" \}, "Read the legal code"/);
  assert.doesNotMatch(html, /ToG 1\.0(?! public draft 1)/);   // the meta description too names which text it is
  assert.match(js, /href: "\/tog\/1\.0\/deed" \}, "Read it in plain words"/);
  for (const f of ["tog/1.0/index.html", "tog/1.0/deed.html", "tog/1.0/legal-code.txt"]) assert.ok(exists(f), f);
  // Every site link the ToG pages hold points at a file served here.
  for (const f of ["tog.html", "tog/1.0/index.html", "tog/1.0/deed.html"]) {
    for (const [, href] of read(f).matchAll(/href="(\/[^"#]*)"/g)) {
      const p = href.slice(1);
      assert.ok([p, p + ".html", p + "/index.html"].some(exists), `${f}: ${href}`);
    }
  }
});

test("the local stand is never deployed nor committed", () => {
  for (const f of [".vercelignore", ".gitignore"]) assert.match(read(f), /^test\/tog-local\/$/m, f);
  assert.doesNotMatch(read(".vercelignore"), /^!/m);
});
