// Self-check: runs a provider's own integration through the sandbox codes 1-12 and the rows of
// spec/extensions/sandbox.md, and compares every answer with the expected one.
//   node selfcheck.mjs [./adapter.mjs] [flags for the adapter, e.g. --sandbox]
// An adapter exports open(argv) → {sandbox: true, prefix, api, licenseeId?, ask(q), buy?(code), giveBack?(result)}, where
// ask({code, purpose, categories?, licenseeId?, terms?}) returns {status, reason} from the answer it verified, or
// {error, httpStatus} for an HTTP error. Each ask is a new job. Every allow is given back, so nothing stays reserved.
// Row 9 "before buying" needs a provider id that never bought at this sandbox.
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { mintCode } from "./pregen.mjs";

const args = process.argv.slice(2);
const adapter = await import(pathToFileURL(resolve(args[0] && !args[0].startsWith("-") ? args.shift() : "./adapter.mjs")));
const a = await adapter.open(args);
// It buys, asks about codes 1-12 of the adapter's prefix and signs with a creator's licensee_id: never in production.
if (a.sandbox !== true) throw new Error("the adapter must say sandbox: true; the self-check never runs against a production registry");
const code = (n) => mintCode(a.prefix, n);
const counts = { PASS: 0, FAIL: 0, SKIP: 0 };
const show = (r) => (r.error ? `HTTP ${r.httpStatus} ${r.error}` : `${r.status}${r.reason ? ` ${r.reason}` : ""}`);
const line = (verdict, label, got, expected) => {
  counts[verdict]++;
  console.log(`${verdict}  ${label}: ${got}${verdict === "FAIL" ? `   (expected ${expected})` : ""}`);
};

async function ask(q) {
  try { return await a.ask({ purpose: "research", ...q }); } catch (e) { return { error: e.message, httpStatus: "-" }; }
}
async function giveBack(r) { if (r.status === "allow" && a.giveBack) await a.giveBack(r); }
async function row(label, q, expected, keep = false) {
  const r = await ask(q);
  line(show(r) === expected ? "PASS" : "FAIL", label, show(r), expected);
  if (!keep) await giveBack(r);
  return r;
}

const deny = (reason) => `deny ${reason}`;
await row("1 research", { code: code(1) }, "allow");
await row("2", { code: code(2) }, deny("PG_NO_LICENSE"));
await row("3", { code: code(3) }, deny("PG_SUBJECT_OPTED_OUT"));
await row("4", { code: code(4) }, deny("PG_USAGE_LIMIT"));
await row("5", { code: code(5) }, deny("PG_PROHIBITED_USE"));
await row("6", { code: code(6) }, "review PG_REVIEW_REQUIRED");
await row("7", { code: code(7) }, "not_blocked PG_NO_LICENSE");
await row("8 (not registered)", { code: code(8) }, deny("PG_UNKNOWN_SUBJECT"));

// 9: buy first (sandbox.md, Test purchase; limits.md: reserve, give back, race)
const nine = { code: code(9) };
await row("9 before buying", nine, deny("PG_NO_LICENSE"));
if (a.buy && a.giveBack) {
  await a.buy(code(9));
  const first = await row("9 after one purchase", nine, "allow", true);
  await row("9 again while that use is reserved", nine, deny("PG_USAGE_LIMIT"));
  await giveBack(first);
  await giveBack(await row("9 after a not_generated report", nine, "allow", true));
  const race = await Promise.all([ask(nine), ask(nine)]);
  const got = race.map(show).sort().join(" + "), expected = `allow + ${deny("PG_USAGE_LIMIT")}`;
  line(got === expected ? "PASS" : "FAIL", "9 two jobs at once for the last use", got, expected);
  for (const r of race) await giveBack(r);
} else line("SKIP", "9 purchase rows", "the adapter has no buy() or giveBack()", "");

// 10: the person's terms (terms.md). The current id comes from the lookup.
const look = await fetch(`${a.api}/v2/codes/${encodeURIComponent(code(10))}`).then((r) => r.json()).catch(() => ({}));
const terms = look.terms?.id;
await row("10 no terms", { code: code(10) }, deny("PG_NO_LICENSE"));
if (terms) await row("10 the current terms", { code: code(10), terms }, deny("PG_NO_LICENSE"));
else line("SKIP", "10 the current terms", "the lookup names no terms", "");
await row("10 any other terms id", { code: code(10), terms: "0".repeat(64) }, deny("PG_TERMS_NOT_ACCEPTED"));
await row("10 commercial", { code: code(10), purpose: "commercial" }, deny("PG_TERMS_EXCLUDED"));
if (terms) await row("10 commercial, with terms", { code: code(10), purpose: "commercial", terms }, deny("PG_TERMS_EXCLUDED"));
await row("10 advertising", { code: code(10), categories: ["advertising"] }, deny("PG_TERMS_EXCLUDED"));
if (terms) await row("10 advertising, with terms", { code: code(10), categories: ["advertising"], terms }, deny("PG_TERMS_EXCLUDED"));

// 11: a minor, licensed for everything: the floor comes first (likeness/1)
await row("11 no categories", { code: code(11) }, "allow");
await row("11 fashion", { code: code(11), categories: ["fashion"] }, "allow");
for (const c of ["violence", "nsfw-art", "sexual", "adult"]) {
  await row(`11 ${c}`, { code: code(11), categories: [c] }, deny("PG_PROHIBITED_USE"));
}

// 12: a creator's licence through bind: research only, reachable only through the binding
if (a.licenseeId) {
  await row("12 research, connected licence", { code: code(12), licenseeId: a.licenseeId }, "allow");
  await row("12 commercial, connected licence", { code: code(12), licenseeId: a.licenseeId, purpose: "commercial" }, deny("PG_SCOPE_VIOLATION"));
  await row("12 without licensee_id", { code: code(12) }, deny("PG_NO_LICENSE"));
  await row("12 a licensee_id not bound to you", { code: code(12), licenseeId: `unbound-${Date.now()}-0000` }, "HTTP 403 PG_NOT_BOUND");
} else line("SKIP", "12", "no connected licence: connect one in the app first", "");

console.log(`\n${counts.PASS} passed, ${counts.FAIL} failed, ${counts.SKIP} skipped`);
console.log("Not checked here: recognising people in prompts or outputs, classifying the use, your own product-to-purpose "
  + "mapping, the other-provider rows of code 9 and 10, production keys and your domain.");
process.exitCode = counts.FAIL ? 1 : 0;
