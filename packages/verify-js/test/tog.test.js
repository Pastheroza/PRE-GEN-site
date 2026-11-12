// ToG funnel (UNRELEASED): spec/test-vectors/tog-generator.json replayed against tog.js. Generated from the approved
// reference spec/tools/tog_generator.py; a disagreement is an erratum in the port, never a local fix.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { validate, rulesFromAnswers, card, cardCompany, companyRules, encodeAnswers, decodeFragment, offeredRegistries,
  defaultNever, NEVER, FOR, WHO, LEGAL } from "../tog.js";

const V = JSON.parse(readFileSync(new URL("../../../spec/test-vectors/tog-generator.json", import.meta.url)));

test("meta: the chip and purpose tables are the reference's; every card links the one common legal text", () => {
  assert.deepEqual(FOR, V.meta.for);
  assert.deepEqual(NEVER, V.meta.never);
  assert.deepEqual(WHO, V.meta.fragment.who);
  assert.deepEqual(LEGAL, V.meta.legal);
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
