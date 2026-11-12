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

// The protocol's name (founder, exact wording): every footer and the spec and package front pages carry it; a page title
// never names the whole protocol PRE-GEN. The historical v5 paper keeps its own title.
const NAME = "ToG Protocol (Terms of Generation Protocol). Earlier versions of this protocol were published as Prompt "
  + "Protocol and as PRE-GEN Protocol. It is the same protocol under its current name.";
test("the name: ToG Protocol in every footer, title and front page; PRE-GEN only as an earlier name", () => {
  const served = pages.filter((f) => f.endsWith(".html") && !HISTORICAL[f]);
  for (const f of served) {
    const text = readFileSync(ROOT + f, "utf8");
    if (text.includes('class="foot-brand"')) assert.ok(text.includes(`<p>${NAME}</p>`), f);
    assert.doesNotMatch(text, /Pre-Generative Authorization Protocol\. AI asks/, f);
    for (const [, a, b] of text.matchAll(/<title>([^<]*)<\/title>|property="og:title" content="([^"]*)"/g)) assert.doesNotMatch(a ?? b, /PRE-GEN/, f);
    assert.doesNotMatch(text, /integrated PRE-GEN|PRE-GEN: &lt;|“PRE-GEN: /, f);
  }
  assert.ok(served.filter((f) => readFileSync(ROOT + f, "utf8").includes('class="foot-brand"')).length > 20);
  for (const f of ["spec/README.md", "spec/PRE-GEN-SPEC.md", "packages/verify-py/README.md", "packages/verify-js/README.md",
    "packages/registry/README.md", "README.md"]) assert.ok(readFileSync(ROOT + f, "utf8").split("\n").slice(0, 4).includes(NAME), f);
  // llms.txt, linked from every footer: H1 and its one-line summary first (llmstxt.org), then the name.
  const llms = readFileSync(ROOT + "llms.txt", "utf8").split("\n");
  assert.deepEqual([llms[0], llms[2].slice(0, 41), llms[4]], ["# ToG Protocol", "> ToG Protocol is an open standard by Val", NAME]);
});
