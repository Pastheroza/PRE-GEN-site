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
