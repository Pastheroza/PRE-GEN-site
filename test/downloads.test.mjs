// /downloads: every file it lists is served from tog/files, and the size, SHA-256 and text fingerprint shown are the
// file's own; every page with the site menu links it in the menu and the footer.
// Run: node --test test/downloads.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";

const ROOT = new URL("..", import.meta.url);
const read = (f) => readFileSync(new URL(f, ROOT));
const sha = (b) => createHash("sha256").update(b).digest("hex");
const html = read("downloads.html").toString();

test("each listed file is there, with its own size, SHA-256 and text fingerprint", () => {
  const cards = html.split('<div class="pg-card">').slice(1);
  assert.deepEqual(cards.map((c) => c.match(/href="\/tog\/files\/([^"]+)" download>/)[1]), ["ToG-L-1.0.pdf",
    "ToG-L-1.0-plain-words.pdf", "ToG-RS-1.0.pdf", ...["person", "company", "provider", "platform", "security"]
      .map((x) => `ToG-L-1.0-example-${x}.pdf`)]);
  for (const c of cards) {
    const name = c.match(/href="\/tog\/files\/([^"]+)"/)[1], b = read("tog/files/" + name);
    assert.ok(c.includes(`<dd>${name} · ${Math.round(b.length / 1024)} KB</dd>`), name);
    assert.ok(c.includes(`<dd class="mono">${sha(b)}</dd>`), name);
  }
  // The text fingerprints: the hashed legal text of each, the same hash the PDF prints.
  assert.equal(sha(read("tog/1.0/legal-code.txt")), "567cc9e2070f1b1a57d6f1c2fed41bb9887489699e7dd49f16e8ab25ac73c3f2");
  assert.equal(sha(read("tog/files/ToG-RS-1.0.txt")), "ba764bc88ec530f27523785db30925c74a68304d278f2d9883c340ae145c248d");
  for (const f of ["tog/1.0/legal-code.txt", "tog/files/ToG-RS-1.0.txt"]) assert.ok(html.includes(`<span class="mono">${sha(read(f))}</span> <a href="#how-to-check">`), f);
  assert.match(html, /<h2 id="how-to-check">/);
  assert.match(html, /Examples only\. Every name, code, registry and hash in them is fictional/);
});

test("every page with the menu links /downloads in the menu and the footer", () => {
  const pages = readdirSync(ROOT, { recursive: true }).map((f) => f.split("\\").join("/"))
    .filter((f) => f.endsWith(".html") && !/^(\.git|\.claude|node_modules|packages|test|spec)\//.test(f));
  const menus = pages.filter((f) => read(f).toString().includes('<nav aria-label="Main">'));
  assert.ok(menus.length >= 27, String(menus.length));
  for (const f of menus) {
    const t = read(f).toString();
    assert.match(t, /<a href="\/lookup"( aria-current="page")?>Look up a code<\/a><a href="\/downloads"( aria-current="page")?>Downloads<\/a>/, f);
    assert.match(t, /Specification<\/a><a href="\/downloads">Downloads<\/a>/, f);
  }
});
