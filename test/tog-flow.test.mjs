// /tog/create (one screen: a chooser that sends the person to a registry) and /tog/document reading a registry's return.
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
async function page({ path = "/tog/create", hash = "" } = {}) {
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
  const src = (await readFile(new URL("../tog.js", import.meta.url), "utf8")).replace('"/packages/verify-js/tog.js"', JSON.stringify(lib))
    .replace('"/tog-copy.js"', JSON.stringify(new URL("../tog-copy.js", import.meta.url).href));
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

test("/tog/create is one screen: a chooser that sends the person to a registry and asks nothing itself", async () => {
  const p = await page();
  for (let i = 0; i < 100 && !p.stage.all().some((x) => x.attrs.class?.includes("tg-to")); i++) await tick();
  const t = p.text();
  assert.match(t, /Create your ToG.*signed yes or no.*The questions are asked at the registry you choose/);
  assert.match(t, /pregen\.org is not a registry\.It does not register people or companies and holds no codes\./);
  assert.match(t, /Choose a registry.*Answer the questions there.*Confirm.*In force/);
  assert.match(t, /Available registries \(1\)PRAMPTAprampta\.comPrefix PRAM · codes look like TOG-PRAM-9\d{8}[0-9A-Z]Register with PRAMPTA/);
  const go = p.stage.all().filter((x) => x.attrs.class?.includes("tg-to"));
  assert.equal(go.length, 1);
  assert.equal(go[0].attrs.href, "https://prampta.com/start?path=tog");
  assert.equal(go[0].attrs.target, "_blank");
  assert.equal(go[0].attrs.rel, "noopener noreferrer");
  const links = p.stage.all().filter((x) => x.tag === "a").map((x) => x.attrs.href);
  for (const h of ["/connect", "/create-registry", "/tog/1.1"]) assert.ok(links.includes(h), h);
  assert.equal(p.stage.all().filter((x) => x.tag === "form" || x.tag === "input").length, 0);   // no question is asked here
  assert.deepEqual(p.asked, ["/test/tog-local/steward.json", "/test/tog-local/registries.json"]);
});

test("/tog/document: a registry's return shows the statement; a company's tog.json from its record; a broken link", async () => {
  const co = V.return.encode.find((e) => e.name === "company, yes");
  let p = await page({ path: "/tog/document", hash: "#" + co.fragment });
  for (let i = 0; i < 100 && !p.stage.all().some((x) => x.attrs["data-screen"] === "result"); i++) await tick();
  const t = p.text();
  assert.match(t, /Terms of Generation of this company/);
  assert.match(t, /Licence: ToG-L 1\.1/);
  assert.match(t, new RegExp(`"record": "${co.record}",\\s*"claim": "${co.claim}"`));
  p = await page({ path: "/tog/document", hash: "#code=TOG-PRAM-900000037K&tog=v1.broken" });
  for (let i = 0; i < 100 && !/This link holds no ToG statement/.test(p.text()); i++) await tick();
  assert.match(p.text(), /This link holds no ToG statement/);
});

test("/tog/document: a person's yes with face: false prints the voice-only card line", async () => {
  const { encodeReturn } = await import("../packages/verify-js/tog.js");
  const answers = { age: "18+", decision: "rules", for: ["news"], never: [], voice: true, face: false };
  const p = await page({ path: "/tog/document", hash: "#" + encodeReturn({ code: "TOG-PRAM-900000037K", answers }) });
  for (let i = 0; i < 100 && !p.stage.all().some((x) => x.attrs["data-screen"] === "result"); i++) await tick();
  assert.match(p.text(), /As: my voice\. No pictures or video of me\./);
});
