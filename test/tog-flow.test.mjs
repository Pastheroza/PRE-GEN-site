// /tog driven screen by screen in a tiny fake DOM: a person's no and yes, a company, a minor and a parent. The output
// is a card that links the one common legal text, then the mandatory home registry step (pending 7 days, the global
// yes or no), and the only link out is the registry's start URL with the closed answers in the #fragment.
// Run: node --test test/tog-flow.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { canonicalJson, fingerprint } from "../packages/verify-js/index.js";
import { decodeFragment, LEGAL } from "../packages/verify-js/tog.js";

class Node {
  constructor(tag) { this.tag = tag; this.attrs = {}; this.kids = []; this.on = {}; this.value = ""; }
  setAttribute(k, v) { this.attrs[k] = v; if (k === "value") this.value = v; }
  addEventListener(t, f) { (this.on[t] ||= []).push(f); }
  append(...k) { this.kids.push(...k); }
  replaceChildren(...k) { this.kids = k; }
  focus() {}
  closest() { return null; }
  click() { for (const f of this.on.click || []) f({}); }
  all() { return this.kids.flatMap((k) => (k instanceof Node ? [k, ...k.all()] : [])); }
  querySelector(sel) { return this.all().find((n) => (sel === "input" ? n.tag === "input" : false)) ?? null; }
  get text() { return this.kids.map((k) => (k instanceof Node ? k.text : String(k))).join(""); }
}

const LOCAL = "http://localhost:3100";
async function stand() {   // test/tog-local.mjs in memory: an ephemeral steward key lists PRAM with tog_start
  const hex = (b) => Buffer.from(b).toString("hex");
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pub = hex(await crypto.subtle.exportKey("raw", keys.publicKey));
  const directory = { schema: "pregen.registries.v2", sequence: 1, issued_at: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
    steward_key_id: await fingerprint(pub), registries: [{ name: "PRAMPTA", prefix: "PRAM", website: LOCAL,
      tog_start: `${LOCAL}/start`, api: "https://api.invalid", keys: "https://api.invalid/keys",
      key_fingerprints: ["pg-ed25519:" + "0".repeat(32)] }] };
  directory.signature = hex(await crypto.subtle.sign("Ed25519", keys.privateKey, new TextEncoder().encode(canonicalJson(directory))));
  return { "/test/tog-local/steward.json": { public_key_hex: pub }, "/test/tog-local/registries.json": directory };
}

let n = 0;
async function page() {
  const files = await stand();
  const ids = { "tf-bar": new Node("progress"), "tf-back": new Node("button"), "tf-restart": new Node("button"), "tf-stage": new Node("div") };
  globalThis.document = { getElementById: (id) => ids[id], createElement: (t) => new Node(t), addEventListener() {} };
  globalThis.location = { hostname: "localhost" };
  globalThis.window = { scrollTo() {} };
  globalThis.fetch = async (url) => ({ ok: url in files, status: url in files ? 200 : 404, json: async () => structuredClone(files[url]) });
  const lib = new URL("../packages/verify-js/tog.js", import.meta.url).href;
  const src = (await readFile(new URL("../tog.js", import.meta.url), "utf8")).replace('"/packages/verify-js/tog.js"', JSON.stringify(lib));
  await import("data:text/javascript," + encodeURIComponent(src + `\n// page ${n++}`));
  const stage = ids["tf-stage"];
  const press = (label) => {
    const b = stage.all().find((x) => (x.tag === "button" || x.tag === "a") && x.text.includes(label));
    assert.ok(b, `no "${label}" on: ${stage.text.slice(0, 200)}`);
    b.click();
  };
  const type = (v) => { const i = stage.querySelector("input"); i.value = v; i.on.input.forEach((f) => f()); };
  const out = async () => {   // the registry buttons arrive once the signed directory is read
    for (let i = 0; i < 50 && !stage.all().some((x) => x.tag === "a" && x.attrs.class?.includes("tf-go")); i++) await new Promise((r) => setTimeout(r, 5));
    const go = stage.all().filter((x) => x.tag === "a" && x.attrs.class?.includes("tf-go")).map((x) => x.attrs.href);
    assert.equal(go.length, 1);
    assert.ok(go[0].startsWith(`${LOCAL}/start#tog=v1.`) && !go[0].includes("?"), go[0]);
    return decodeFragment(go[0].split("#")[1]);
  };
  return { stage, press, type, out, text: () => stage.text };
}

function registryStep(t) {
  assert.match(t, /Get your ToG code at your home registry/);
  assert.match(t, /You need one home only:/);
  assert.match(t, /The code is pending for 7 days\. It permits nothing and forbids nothing until you confirm it is you/);
  assert.match(t, /An email alone does not\. Your registry reminds you on day 3; on day 7 an unconfirmed code is deleted and never issued again\./);
  assert.match(t, /After verification, your YES or NO becomes global for every registry that integrated PRE-GEN\./);
  assert.match(t, new RegExp(`Legal code ToG-1\\.0 · SHA-256 ${LEGAL.sha256} · the same text for everyone`));
  assert.match(t, /Read the legal code.*Read it in plain words/);
}

test("a person's no: the card, tog:no first, then the registry; the year never leaves the page", async () => {
  const p = await page();
  p.press("Me"); p.type("1990"); p.press("OK"); p.press("No.");
  const t = p.text();
  assert.match(t, /No AI generation of me\./);
  assert.match(t, /write tog:no in the bio of your own public profile/);
  assert.ok(t.indexOf("tog:no") < t.indexOf("Get your ToG code"));
  registryStep(t);
  assert.deepEqual(await p.out(), { result: "ok", answers: { age: "18+", decision: "no" } });
  assert.ok(p.stage.all().some((x) => x.tag === "a" && x.attrs.href === "/tog/1.0"));
});

test("a person's yes is recorded as a wish that opens only after identity verification", async () => {
  const p = await page();
  p.press("Me"); p.type("1990"); p.press("OK");
  assert.match(p.text(), /It opens only after identity verification, which is coming soon\./);
  p.press("Yes, within my rules."); p.press("For fun"); p.press("Next"); p.press("Next"); p.press("No, not my voice");
  const t = p.text();
  assert.match(t, /Your yes is recorded as your wish\. It opens only after identity verification, which is coming soon;/);
  assert.doesNotMatch(t, /tog:no/);
  registryStep(t);
  assert.equal((await p.out()).answers.decision, "rules");
});

test("under 18: only a parent, guardian or other legal representative registers you; nothing is handed off", async () => {
  const p = await page();
  p.press("Me"); p.type(String(new Date().getFullYear() - 15)); p.press("OK");
  assert.match(p.text(), /Under 18, you are registered only by a parent, guardian or other legal representative\./);
  assert.ok(!p.stage.all().some((x) => x.tag === "a"));
});

test("a parent, guardian or representative registers a child's no, and only a no", async () => {
  const p = await page();
  p.press("My child");
  assert.match(p.text(), /registered only by a parent, guardian or other legal representative, and for now the only answer is no/);
  p.press("Next");
  const t = p.text();
  assert.match(t, /YOUR CHILD'S TOG · CODE FROM YOUR REGISTRY/);
  assert.match(t, /confirm that you are the child's parent, guardian or other legal representative/);
  registryStep(t);
  assert.deepEqual(await p.out(), { result: "ok", answers: { who: "child", decision: "no" } });
});

test("a company gets a code of the same form at its registry, proved by its tog.json", async () => {
  const p = await page();
  p.press("My company"); p.press("No.");
  const t = p.text();
  assert.match(t, /YOUR COMPANY'S TOG · CODE FROM YOUR REGISTRY/);
  assert.match(t, /No AI generation of our marks, products or characters\./);
  assert.match(t, /\(a company: the file \/\.well-known\/tog\.json on its domain\)/);
  registryStep(t);
  assert.deepEqual(await p.out(), { result: "ok", answers: { who: "company", decision: "no" } });
});
