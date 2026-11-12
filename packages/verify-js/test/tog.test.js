// ToG funnel (UNRELEASED): spec/test-vectors/tog-generator.json replayed against tog.js. Generated from the approved
// reference spec/tools/tog_generator.py; a disagreement is an erratum in the port, never a local fix.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { validate, rulesFromAnswers, card, cardCompany, companyRules, encodeAnswers, decodeFragment, offeredRegistries,
  defaultNever, conditionsOk, NEVER, FOR, WHO, LEGAL, MAX_FRAGMENT, CONDITIONS_MAX } from "../tog.js";

const V = JSON.parse(readFileSync(new URL("../../../spec/test-vectors/tog-generator.json", import.meta.url)));

test("meta: the chip and purpose tables are the reference's; every card links the one common legal text", () => {
  assert.deepEqual(FOR, V.meta.for);
  assert.deepEqual(NEVER, V.meta.never);
  assert.deepEqual(WHO, V.meta.fragment.who);
  assert.deepEqual(LEGAL, V.meta.legal);
  assert.deepEqual(Object.keys(V.meta.company), ["profile", "modalities"]);   // a company's card cites no licence text and carries no note
  const text = readFileSync(new URL("../../../tog/1.0/legal-code.txt", import.meta.url));
  assert.equal(createHash("sha256").update(text).digest("hex"), LEGAL.sha256);
});

test("answers: rules and the English card, byte for byte", () => {
  assert.ok(V.answers.length > 100);
  for (const { name, answers, rules, card: c } of V.answers) {
    assert.deepEqual(rulesFromAnswers(answers), rules, name);
    assert.equal(JSON.stringify(card(rules)), JSON.stringify(c.en), name);
  }
});

test("never_lines: every chip set", () => {
  assert.equal(V.never_lines.length, 1024);
  for (const { never, en } of V.never_lines) {
    assert.equal(card(rulesFromAnswers({ decision: "rules", for: ["fun"], never, voice: false }))[2], en, never.join());
  }
});

test("defaultNever: everything but fashion; ads allowed once paid work is ticked", () => {
  for (const { name, answers } of V.answers.filter((a) => a.name.startsWith("default ") && !a.name.includes(" flip "))) {
    assert.deepEqual(defaultNever(answers.for), answers.never, name);
  }
});

test("reject_rules: all 28 refused", () => {
  assert.equal(V.reject_rules.length, 28);
  for (const r of V.reject_rules) assert.throws(() => validate(r), JSON.stringify(r));
});

test("fragment.encode and decode", () => {
  for (const { name, answers, fragment } of V.fragment.encode) {
    assert.equal(encodeAnswers(answers), fragment, name);
    assert.deepEqual(decodeFragment(fragment), { result: "ok", answers }, name);
  }
  for (const { name, fragment, result, answers } of V.fragment.decode) {
    assert.deepEqual(decodeFragment(fragment), answers ? { result, answers } : { result }, name);
  }
  assert.throws(() => encodeAnswers({ age: "13-17", decision: "rules", for: ["fun"], never: [], voice: false }));
  // A minor registers only through a parent, guardian or representative, who may only say no.
  assert.throws(() => encodeAnswers({ age: "13-17", decision: "no" }));
  assert.throws(() => encodeAnswers({ who: "child", decision: "rules", for: ["fun"], never: [] }));
  assert.throws(() => encodeAnswers({ who: "company", decision: "no", domain: "northwind.example" }));
  assert.equal(V.fragment.encode.filter((e) => e.answers.who).length, 4);
});

test("conditions: the person's own words ride a person's yes only, code points counted, never repaired", () => {
  assert.equal(MAX_FRAGMENT, V.meta.fragment.max_length);
  assert.equal(CONDITIONS_MAX, V.meta.fragment.conditions_max);
  const withC = V.fragment.encode.filter((e) => "conditions" in e.answers);
  assert.equal(withC.length, 3);
  const longest = withC.find((e) => e.name.includes("longest"));
  assert.equal([...longest.answers.conditions].length, 1000);   // 2,000 UTF-16 units: a code point is a character
  assert.equal(longest.fragment.length, V.meta.fragment.longest_encoded);
  assert.equal(V.fragment.decode.filter((d) => /^conditions/.test(d.name)).every((d) => d.result === "malformed"), true);
  assert.ok(conditionsOk("ü\nok") && !conditionsOk("u\u0308") && !conditionsOk("\ud800") && !conditionsOk("x".repeat(1001)));
  const ads = V.fragment.encode.find((e) => e.name === "ADS").answers;
  for (const bad of [{ ...ads, conditions: "" }, { age: "18+", decision: "no", conditions: "x" },
    { who: "company", decision: "no", conditions: "x" }]) assert.throws(() => encodeAnswers(bad), JSON.stringify(bad));
});

test("conditions are checked without String.prototype.isWellFormed (ES2024: Safari < 16.4, Firefox < 119)", () => {
  const own = String.prototype.isWellFormed;
  delete String.prototype.isWellFormed;
  try {
    assert.ok(conditionsOk("ok 🎰\nне в рекламе"));                                        // a surrogate pair is one character
    for (const lone of ["\ud800", "a\udfffb", "\ude00\ud83c"]) assert.equal(conditionsOk(lone), false, escape(lone));
  } finally {
    String.prototype.isWellFormed = own;
  }
});

test("company: rules and card; a company gets its ToG code at a registry, like a person", () => {
  for (const { name, answers, rules, card: c } of V.company) {
    assert.deepEqual(companyRules(answers), rules, name);
    assert.equal(JSON.stringify(cardCompany(rules)), JSON.stringify(c.en), name);
    assert.doesNotMatch(c.en.join("\n"), /passkey|[Uu]nsigned/, name);
  }
});

test("chooser: offered registries", () => {
  for (const { name, local, registries, offered } of V.chooser) {
    assert.deepEqual(offeredRegistries(registries, { local }), offered, name);
  }
  assert.deepEqual(offeredRegistries([{ name: "X", prefix: "PRAM", website: "https://a.example",
    tog_start: "https://a.example/start\t" }]), []);
});
