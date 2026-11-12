// /lookup's card (lookup.js): a person's own words (lookup.md, Conditions) come first, as plain text, their line
// breaks kept, and never again as a catch-all row. Run: node --test test/lookup-page.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("an active person's conditions are the first row, plain text with its line breaks, shown once", async () => {
  const answer = { code: "TOG-ZYXW-0000014", status: "active", holder: "person", level: "channel",
    conditions: "never in horror\nno <b>face</b> edits" };
  const ids = { pgForm: { addEventListener() {} }, pgInput: { value: "", focus() {} }, pgResult: { innerHTML: "" } };
  globalThis.document = { getElementById: (id) => ids[id] };
  globalThis.window = { location: { search: "?code=" + answer.code }, history: { replaceState() {} } };
  globalThis.fetch = async () => ({ status: 200, json: async () => answer });
  const lib = new URL("../packages/verify-js/index.js", import.meta.url).href;
  const src = (await readFile(new URL("../lookup.js", import.meta.url), "utf8")).replace('"/packages/verify-js/index.js"', JSON.stringify(lib));
  await import("data:text/javascript," + encodeURIComponent(src));
  for (let i = 0; i < 50 && !ids.pgResult.innerHTML.includes("pg-rows"); i++) await new Promise((r) => setTimeout(r, 5));
  const rows = [...ids.pgResult.innerHTML.matchAll(/<dt>([^<]*)<\/dt><dd>(.*?)<\/dd><\/div>/gs)];
  assert.equal(rows[0][1], "Conditions");
  assert.equal(rows[0][2], '<span class="pg-said">never in horror\nno &lt;b&gt;face&lt;/b&gt; edits</span>');
  assert.equal(rows.filter((r) => /conditions/i.test(r[1])).length, 1);
  assert.doesNotMatch(src, /style=/);                                       // the CSP (style-src 'self') refuses it
  assert.match(await readFile(new URL("../styles.css", import.meta.url), "utf8"), /\.pg-said \{ white-space: pre-line; \}/);
});
