// No page shows a PG code (TOG-CODE.md §6, design rev. 7 §8.3 "tests"): every served page of the site is read as
// served, and none holds a PG code string, nor a PG to TOG table. The word "PG-" alone (the retired marker), the
// protocol names PG-Access and PG-CODE.md, and the kind PG-LIC (as in TOG-PG-LIC-…) are not codes. The two historical
// documents are kept as published and must carry the retired banner instead.
// Run: node --test test/pages.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const HISTORICAL = { "docs/pg-code.html": /Retired, not supported/, "spec/paper/pre-gen-v5.html": /Retired, not supported/ };
const PG_CODE = /(?<![A-Za-z0-9-])PG-(?!Access\b|CODE\b|LIC\b)[A-Z0-9][A-Z0-9*~$=!-]*/g;

// A walk, not git ls-files: the suite also runs from an archive or tarball.
const pages = readdirSync(ROOT, { recursive: true }).map((f) => f.split("\\").join("/"))
  .filter((f) => /\.(html|md|txt)$/.test(f) && !/(^|\/)(\.git|\.venv|\.claude|node_modules)\//.test(f))
  .filter((f) => !/^(packages|test|spec)\//.test(f) || f.endsWith(".html") && f.startsWith("spec/"));

test("no page shows a PG code; the historical documents carry the retired banner", () => {
  assert.ok(pages.includes("docs/tog-code.html") && pages.includes("lookup.html") && pages.length > 20, pages.join());
  for (const f of pages) {
    const text = readFileSync(ROOT + f, "utf8");
    if (HISTORICAL[f]) assert.match(text, HISTORICAL[f], f);
    else assert.deepEqual(text.match(PG_CODE) ?? [], [], f);
  }
});

test("the sitemap does not list the retired PG code page", () => {
  assert.doesNotMatch(readFileSync(ROOT + "sitemap.xml", "utf8"), /pg-code/);
});

// The protocol's name (founder, 2026-11-12): the protocol is PRE-GEN Protocol again; ToG names the licence, the codes
// and the statement, never the protocol. Every footer carries the site's line, and no page, front page, llms.txt or
// tog.js calls the protocol ToG Protocol or keeps the sentence about its earlier names.
const FOOT = "Pre-Generative Authorization Protocol. AI asks before it generates a real person.";
const NOT_THE_NAME = /ToG Protocol|Terms of Generation Protocol|Earlier versions of this protocol/;
test("the name: PRE-GEN Protocol; ToG never names the protocol", () => {
  const served = pages.filter((f) => f.endsWith(".html") && !HISTORICAL[f]);
  for (const f of served) {
    const text = readFileSync(ROOT + f, "utf8");
    if (text.includes('class="foot-brand"')) assert.ok(text.includes(`<p>${FOOT}</p>`), f);
    assert.doesNotMatch(text, /integrated PRE-GEN|PRE-GEN: &lt;|“PRE-GEN: /, f);
  }
  assert.ok(served.filter((f) => readFileSync(ROOT + f, "utf8").includes('class="foot-brand"')).length > 20);
  for (const f of [...pages, "spec/README.md", "spec/PRE-GEN-SPEC.md", "packages/verify-py/README.md",
    "packages/verify-js/README.md", "packages/registry/README.md", "tog.js"]) assert.doesNotMatch(readFileSync(ROOT + f, "utf8"), NOT_THE_NAME, f);
  // llms.txt, linked from every footer: H1 and its one-line summary first (llmstxt.org).
  const llms = readFileSync(ROOT + "llms.txt", "utf8").split("\n");
  assert.deepEqual([llms[0], llms[2].slice(0, 36)], ["# PRE-GEN", "> PRE-GEN is an open standard by Val"]);
});
