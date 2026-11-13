// /tog and /tog/document (spec/drafts/tog-funnel.md): one module that imports only the ToG library, the CSP kept, the
// date of birth and the answers never anywhere but the fragment, only the one common legal text named (ToG-L 1.0 public
// draft 3, with its hash and link), /tog public and /tog/document never indexed, and "Create your ToG" in every
// page's menu. The cards: packages/verify-js/test/tog.test.js; the screens: test/tog-flow.test.mjs.
// Run: node --test test/tog-page.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";

const read = (f) => readFileSync(new URL("../" + f, import.meta.url), "utf8");
const exists = (f) => existsSync(new URL("../" + f, import.meta.url));
const html = read("tog.html"), doc = read("tog/document.html"), js = read("tog.js");

test("both pages load only their module, which imports only the ToG library; no inline script or style", () => {
  for (const page of [html, doc]) {
    assert.deepEqual(page.match(/<script[^>]*>/g), ['<script src="/theme.js">', '<script src="/site.js" defer>', '<script type="module" src="/tog.js">']);
    assert.doesNotMatch(page, /\sstyle=|<style|tog\.css/);   // the site's own styles.css, not the legal pages' paper
  }
  assert.deepEqual([...js.matchAll(/^import[^;]*from "([^"]+)"/gms)].map((m) => m[1]), ["/packages/verify-js/tog.js"]);
  assert.doesNotMatch(js, /innerHTML|insertAdjacentHTML|\.style\b|"style"|eval\(|new Function/);
  assert.match(read("vercel.json"), /style-src 'self';/);
});

test("/tog is public, /tog/document is never indexed and sends no referrer", () => {
  assert.doesNotMatch(html, /noindex|DRAFT|[Nn]ot public/);
  assert.match(doc, /<meta name="robots" content="noindex">/);
  assert.match(doc, /<meta name="referrer" content="no-referrer">/);
  for (const url of ["/tog", "/tog/1.0", "/tog/1.0/deed"]) assert.match(read("sitemap.xml"), new RegExp(`pregen\\.org${url}<`));
  assert.doesNotMatch(read("sitemap.xml"), /tog\/document/);
});

test("nothing is stored, and only the fragment carries answers", () => {
  assert.doesNotMatch(js, /localStorage|sessionStorage|indexedDB|document\.cookie|history\.|location\.(search|href\s*=)|URLSearchParams|\?tog=/);
  // The one link out: the registry's start URL, '#', the encoded answers (never the date, a name or a domain).
  assert.deepEqual([...js.matchAll(/href: r\.start \+ "#" \+ ([^,]+),/g)].map((m) => m[1]), ["encodeAnswers(a)"]);
  assert.doesNotMatch(js.slice(js.indexOf("function answers()"), js.indexOf("function plan()")), /S\.[dmy]\b|name|domain/);
  // What is fetched: the signed list (or the local stand's), and a code's public status by the code alone.
  assert.deepEqual([...js.matchAll(/fetch\(("[^"]+")/g)].map((m) => m[1]), ['"/test/tog-local/steward.json"', '"/api/lookup?code="']);
});

test("one common legal text: the pages name only ToG-L 1.0 public draft 3, link it, and never build a copy", () => {
  // A link to /downloads (the published PDFs) is not a copy; a download attribute or a Blob would be.
  for (const text of [html, doc, js]) assert.doesNotMatch(text, /ToG-[LB]-1\.0|prampta-likeness|(?<!public )\bdraft\b(?! 3\b)|UNRELEASED|Blob|download(?!s)/i);
  assert.doesNotMatch(html, /ToG(-L)? 1\.0(?! public draft 3)/);
  assert.match(js, /el\("a", \{ href: "\/downloads" \}, "PDF and examples"\)/);
  assert.match(js, /el\("a", \{ href: "\/tog\/1\.0" \}, "Read the legal code"\)/);
  assert.match(js, /el\("a", \{ href: "\/tog\/1\.0\/deed" \}, "Read it in plain words"\)/);
  for (const f of ["tog/1.0/index.html", "tog/1.0/deed.html", "tog/1.0/legal-code.txt"]) assert.ok(exists(f), f);
  for (const f of ["tog.html", "tog/document.html", "tog/1.0/index.html", "tog/1.0/deed.html"]) {
    for (const [, href] of read(f).matchAll(/href="(\/[^"#]*)"/g)) {
      const p = href.slice(1);
      assert.ok([p, p + ".html", p + "/index.html"].some(exists), `${f}: ${href}`);
    }
  }
});

test("every page's menu opens with Create your ToG", () => {
  const pages = [];
  const walk = (d) => readdirSync(new URL("../" + d, import.meta.url)).forEach((f) => {
    const p = d + f;
    if (["node_modules", "test", ".git", ".claude", "packages", "spec"].includes(f)) return;
    if (statSync(new URL("../" + p, import.meta.url)).isDirectory()) walk(p + "/");
    else if (p.endsWith(".html")) pages.push(p);
  });
  walk("");
  const menus = pages.filter((p) => read(p).includes('<nav aria-label="Main">'));
  assert.ok(menus.length >= 25, String(menus.length));
  for (const p of menus) assert.match(read(p), /<nav aria-label="Main"><a href="\/tog"( aria-current="page")?>Create your ToG<\/a>/, p);
});

test("the local stand is never deployed nor committed", () => {
  for (const f of [".vercelignore", ".gitignore"]) assert.match(read(f), /^test\/tog-local\/$/m, f);
  assert.doesNotMatch(read(".vercelignore"), /^!/m);
});
