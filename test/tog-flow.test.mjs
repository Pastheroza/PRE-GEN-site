// /tog driven screen by screen in a tiny fake DOM: what the person needs ToG for, then a person's no and yes, an AI
// service, a minor through a parent or legal guardian, a company; the registry step (pending 7 days, the global yes or
// no), the code typed back and the ToG statement in its three forms; and /tog/document reading a registry's return.
// Run: node --test test/tog-flow.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { canonicalJson, fingerprint } from "../packages/verify-js/index.js";
import { decodeFragment, LEGAL } from "../packages/verify-js/tog.js";

const V = JSON.parse(await readFile(new URL("../spec/test-vectors/tog-generator.json", import.meta.url), "utf8"));

class Node {
  constructor(tag) { this.tag = tag; this.attrs = {}; this.kids = []; this.on = {}; this.value = ""; this.checked = false; }
  setAttribute(k, v) { this.attrs[k] = v; if (k === "value") this.value = v; if (k === "checked") this.checked = true; }
  addEventListener(t, f) { (this.on[t] ||= []).push(f); }
  fire(t, e = {}) { for (const f of this.on[t] || []) f({ target: this, preventDefault() {}, ...e }); }
  append(...k) { this.kids.push(...k); }
  replaceChildren(...k) { this.kids = k; }
  focus() {}
  click() { this.fire("click"); }
  all() { return this.kids.flatMap((k) => (k instanceof Node ? [k, ...k.all()] : [])); }
  querySelector() { return this.all().find((n) => n.tag === "input" || n.tag === "textarea") ?? null; }
  get text() { return this.kids.map((k) => (k instanceof Node ? k.text : String(k))).join(""); }
}

const START = "https://prampta.example/start";
async function stand() {   // test/tog-local.mjs in memory: an ephemeral steward key lists PRAM with tog_start
  const hex = (b) => Buffer.from(b).toString("hex");
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pub = hex(await crypto.subtle.exportKey("raw", keys.publicKey));
  const directory = { schema: "pregen.registries.v2", sequence: 1, issued_at: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
    steward_key_id: await fingerprint(pub), registries: [{ name: "PRAMPTA", prefix: "PRAM", website: "https://prampta.com",
      tog_start: "https://prampta.com/start", api: "https://api.invalid", keys: "https://api.invalid/keys",
      key_fingerprints: ["pg-ed25519:" + "0".repeat(32)] }] };
  directory.signature = hex(await crypto.subtle.sign("Ed25519", keys.privateKey, new TextEncoder().encode(canonicalJson(directory))));
  return { "/test/tog-local/steward.json": { public_key_hex: pub }, "/test/tog-local/registries.json": directory };
}

let n = 0;
const tick = () => new Promise((r) => setTimeout(r, 5));
async function page({ path = "/tog", hash = "" } = {}) {
  const files = await stand(), asked = [];
  const stage = new Node("div");
  globalThis.document = { getElementById: (id) => (id === "tg-stage" ? stage : null), createElement: (t) => new Node(t), addEventListener() {} };
  globalThis.location = { hostname: "localhost", pathname: path, hash, origin: "http://localhost:8773" };
  globalThis.window = { scrollTo() {}, addEventListener() {} };
  globalThis.fetch = async (url) => {
    asked.push(url);
    if (url.startsWith("/api/lookup?code=")) return { ok: true, status: 200, json: async () => ({ status: "pending" }) };
    return { ok: url in files, status: url in files ? 200 : 404, json: async () => structuredClone(files[url]) };
  };
  const lib = new URL("../packages/verify-js/tog.js", import.meta.url).href;
  const src = (await readFile(new URL("../tog.js", import.meta.url), "utf8")).replace('"/packages/verify-js/tog.js"', JSON.stringify(lib));
  await import("data:text/javascript," + encodeURIComponent(src + `\n// page ${n++}`));
  const find = (pred, what) => { const x = stage.all().find(pred); assert.ok(x, `no ${what} on: ${stage.text.slice(0, 300)}`); return x; };
  const p = {
    stage, asked, text: () => stage.text, screen: () => stage.all().find((x) => x.attrs["data-screen"]).attrs["data-screen"],
    press: (label) => find((x) => (x.tag === "button" || x.tag === "a") && x.text.startsWith(label), `"${label}"`).click(),
    pick: (label) => { const l = find((x) => x.tag === "label" && x.text.startsWith(label), `choice "${label}"`);
      const i = l.kids[0]; i.checked = !i.checked || i.attrs.type === "radio"; i.fire("change"); },
    type: (id, v) => { const i = find((x) => x.attrs.id === id, id); i.value = v; i.fire("input"); },
    next: () => find((x) => x.tag === "form", "a form").fire("submit"),
    registry: async () => {   // the registry buttons arrive once the signed directory is read
      for (let i = 0; i < 100 && !stage.all().some((x) => x.attrs.class?.includes("tg-to")); i++) await tick();
      const go = stage.all().filter((x) => x.attrs.class?.includes("tg-to"));
      assert.equal(go.length, 1);
      assert.match(stage.text, /Available registries \(1\)PRAMPTAprampta\.comPrefix PRAM · codes look like TOG-PRAM-9\d{8}[0-9A-Z]Register with PRAMPTA/);
      const href = go[0].attrs.href;
      assert.ok(href.startsWith("https://prampta.com/start#tog=v1.") && !href.includes("?"), href);
      assert.equal(go[0].attrs.target, "_blank");
      assert.equal(go[0].attrs.rel, "noopener noreferrer");
      return { answers: decodeFragment(href.split("#")[1]), open: () => go[0].click() };
    },
  };
  return p;
}
async function person(p, use = "On my website", dob = ["27", "3", "1990"]) {
  p.press("Start"); p.pick("My likeness"); p.next(); p.pick(use); p.next();
  p.type("tg-day", dob[0]); p.type("tg-month", dob[1]); p.type("tg-year", dob[2]); p.next();
}
async function codeBack(p, code = "TOG-PRAM-900000037K") {
  const r = await p.registry();
  r.open();
  assert.equal(p.screen(), "code");
  p.type("tg-tog-code", code); p.next();
  for (let i = 0; i < 50 && !/Pending\./.test(p.text()); i++) await tick();
  return r.answers;
}

function registryStep(t, co = false) {
  assert.match(t, /Choose your registry/);
  assert.match(t, /pregen\.org is not a registry\.It does not register people or companies and holds no codes\. Registries do: you choose one, it confirms your identity and your rights, and after that your ToG code takes effect\./);
  assert.match(t, /You need only one: every other registry and AI service reads your code\./);
  assert.match(t, /The code is pending for 7 days\. It permits and forbids nothing until it is confirmed/);
  assert.match(t, /Your registry reminds you on day 3\. On day 7 an unconfirmed code is deleted, and its number is never issued again\./);
  assert.match(t, /Once confirmed, your ToG code takes effect for every registry and AI service on PRE-GEN Protocol\./);
  assert.doesNotMatch(t, /ToG 1\.0|public draft|Not in force/);   // every line that cites the text says "ToG-L 1.0"
  assert.match(t, /Read the legal code.*Read it in plain words/);   // a company cites ToG-L 1.0 like a person
  if (co) assert.doesNotMatch(t, /training AI models on you/);
}

test("the intake: an AI service needs no code and a registry is listed; nothing is asked of either", async () => {
  const p = await page();
  assert.match(p.text(), /Create your ToG.*pregen\.org is not a registry\..*Answer.*Choose a registry.*Confirm.*In force/);
  p.press("Start");
  assert.match(p.text(), /What do you need ToG for\?/);
  p.next();
  assert.match(p.text(), /There is a problem.*Choose what you need ToG for\./);
  p.pick("My AI service"); p.next();
  assert.match(p.text(), /Your AI service needs no ToG code/);
  assert.ok(p.stage.all().some((x) => x.tag === "a" && x.attrs.href === "/connect"));
  p.press("Back"); p.pick("A registry"); p.next();
  assert.ok(p.stage.all().some((x) => x.tag === "a" && x.attrs.href === "/create-registry"));
  assert.deepEqual(p.asked, []);
});

test("a person's no: checked, registered in a new tab, the code typed back, the statement with the proof line", async () => {
  const p = await page();
  await person(p);
  assert.match(p.text(), /May AI generate your likeness\?/);
  p.pick("No"); p.next();
  const t = p.text();
  assert.match(t, /Check your statement/);
  assert.match(t, /write tog:no in the bio of your own public profile\. Under ToG-L 1\.0 §2\(h\) it takes effect at once\./);
  registryStep(t);
  const answers = await codeBack(p, " tog-pram-900000037k ");   // typed codes fold to their one spelling
  assert.deepEqual(answers, { result: "ok", answers: { age: "18+", decision: "no" } });
  const out = p.text();
  assert.match(out, /Your ToG statement.*Pending\./);
  assert.match(out, /<p>\nToG: TOG-PRAM-900000037K\n<\/p>/);   // the proof line alone on its own source line
  assert.match(out, /No AI generation of me\./);
  assert.match(out, new RegExp(`Licence: <a href="${LEGAL.url}">${LEGAL.label}</a>, SHA-256 <code>${LEGAL.sha256}</code>`));
  assert.match(out, /Record: <a href="https:\/\/www\.pregen\.org\/lookup\?code=TOG-PRAM-900000037K">/);
  assert.ok(p.asked.includes("/api/lookup?code=TOG-PRAM-900000037K"));
  const keep = p.stage.all().find((x) => x.tag === "code" && x.text.startsWith("http://localhost:8773/tog/document#"));
  assert.equal(keep.text, "http://localhost:8773/tog/document#" + V.return.encode.find((e) => e.name === "person, no").fragment);
  p.press("Profile or post");
  assert.match(p.text(), /ToG: TOG-PRAM-900000037K\n\nTerms of Generation\n\nNo AI generation of me\./);   // plain text, first line the proof
  p.press("Code only");
  assert.match(p.text(), /Your ToG code/);
});

test("a code from another registry, or mistyped, is refused", async () => {
  const p = await page();
  await person(p); p.pick("No"); p.next();
  (await p.registry()).open();
  p.type("tg-tog-code", "TOG-PRAM-900000037J"); p.next();
  assert.match(p.text(), /The check character does not fit/);
  p.type("tg-tog-code", "TOG-ABCD-9000000389"); p.next();
  assert.match(p.text(), /That code was not issued by PRAMPTA\./);
});

test("a person's yes: purposes, exclusions, voice, fees and own words; the words come first, as plain text", async () => {
  const p = await page();
  await person(p);
  assert.match(p.text(), /A Yes is recorded now and takes effect only after identity verification, which is not yet available\./);
  p.pick("Yes, within terms I set"); p.next();
  p.next();
  assert.match(p.text(), /Select at least one purpose, or go back and choose No\./);
  p.pick("Personal"); p.pick("Advertising"); p.next();
  assert.match(p.text(), /Always excluded: political content, and sexual or adult content\./);
  p.next(); p.pick("Yes"); p.next(); p.pick("A minimum fee per project"); p.next();
  p.type("tg-words", "😀".repeat(1001)); p.next();
  assert.match(p.text(), /At most 1000 characters\./);                    // 1,001 code points: refused, never cut
  p.type("tg-words", "no ‮ads"); p.next();
  assert.match(p.text(), /Remove the invisible control characters/);
  const said = "Не в рекламе казино 🎰\nNever **bold**, never <b>html</b>.";
  p.type("tg-words", `  ${said}\t `); p.next();
  const t = p.text();
  assert.ok(t.indexOf(said) >= 0 && t.indexOf(said) < t.indexOf("AI may make me"));
  const quoted = p.stage.all().find((x) => x.attrs.class === "tg-said");
  assert.deepEqual(quoted.kids, [said]);                                    // one text node: no <strong>, no markup
  const { answers } = await codeBack(p);
  assert.deepEqual(answers, { age: "18+", decision: "rules", for: ["fun", "paid"], never: ["vice", "weapons", "violence",
    "gambling", "money", "health", "religion", "endorse"], voice: true, floor: "project", conditions: said });
  assert.match(p.text(), /<blockquote><p>Не в рекламе казино 🎰<br>\nNever \*\*bold\*\*, never &lt;b&gt;html&lt;\/b&gt;\.<\/p><\/blockquote>/);
});

test("under 18: only a parent or legal guardian, and only a No; the date never leaves the page", async () => {
  const p = await page();
  await person(p, "On my website", ["1", "6", String(new Date().getFullYear() - 15)]);
  assert.match(p.text(), /Under 18, a parent or legal guardian makes this statement/);
  assert.match(p.text(), /the only statement is No/);
  p.next();                                                                // "I am their parent or legal guardian"
  const t = p.text();
  assert.match(t, /A person under 18, made by their parent or legal guardian/);
  assert.match(t, /Your registry will ask you to confirm that you are the parent or legal guardian\./);
  registryStep(t);
  assert.deepEqual(await codeBack(p), { result: "ok", answers: { who: "child", decision: "no" } });
  assert.match(p.text(), /Made for a person under 18 by their parent or legal guardian\./);
  assert.deepEqual(p.asked, ["/test/tog-local/steward.json", "/test/tog-local/registries.json", "/api/lookup?code=TOG-PRAM-900000037K"]);
});

test("a company: the same form of code, ToG-L 1.0 cited like a person's, its domain confirms it", async () => {
  const p = await page();
  p.press("Start"); p.pick("My company's brand or products"); p.next(); p.pick("Only the code"); p.next();
  assert.match(p.text(), /May AI generate the company's marks, products or characters\?/);
  p.pick("No"); p.next();
  registryStep(p.text(), true);
  assert.deepEqual(await codeBack(p), { result: "ok", answers: { who: "company", decision: "no" } });
  const t = p.text();
  assert.match(t, /Your ToG code/);
  assert.match(t, /PRAMPTA gives you the file \/\.well-known\/tog\.json on your code's page/);
  assert.match(t, /Your statement is made under ToG-L 1\.0/);
});

test("/tog/document: a registry's return shows the statement; a company's tog.json from its record; a broken link", async () => {
  const co = V.return.encode.find((e) => e.name === "company, yes");
  let p = await page({ path: "/tog/document", hash: "#" + co.fragment });
  for (let i = 0; i < 100 && !p.stage.all().some((x) => x.attrs["data-screen"] === "result"); i++) await tick();
  const t = p.text();
  assert.match(t, /Terms of Generation of this company/);
  assert.match(t, /Licence: ToG-L 1\.0/);
  assert.match(t, new RegExp(`"record": "${co.record}",\\s*"claim": "${co.claim}"`));
  p = await page({ path: "/tog/document", hash: "#code=TOG-PRAM-900000037K&tog=v1.broken" });
  for (let i = 0; i < 100 && !/This link holds no ToG statement/.test(p.text()); i++) await tick();
  assert.match(p.text(), /This link holds no ToG statement/);
});
