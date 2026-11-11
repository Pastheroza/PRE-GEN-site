// ToG funnel (UNRELEASED): spec/test-vectors/tog-generator.json replayed against tog.js. Generated from the approved
// reference spec/tools/tog_generator.py; a disagreement is an erratum in the port, never a local fix.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { validate, rulesFromAnswers, card, cardCompany, companyRules, encodeAnswers, decodeFragment, companyFiles,
  offeredRegistries, defaultNever, NEVER, FOR } from "../tog.js";

const V = JSON.parse(readFileSync(new URL("../../../spec/test-vectors/tog-generator.json", import.meta.url)));

test("meta: the chip and purpose tables are the reference's", () => {
  assert.deepEqual(FOR, V.meta.for);
  assert.deepEqual(NEVER, V.meta.never);
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
});

test("company: card and statement body", () => {
  for (const { name, answers, rules, card: c, statement_body } of V.company) {
    assert.deepEqual(companyRules(answers), rules, name);
    assert.equal(JSON.stringify(cardCompany(rules)), JSON.stringify(c.en), name);
    const f = companyFiles(V.meta.company.domain, "Northwind Coffee", answers);
    const body = JSON.parse(f.tog_json).statements[0].body;
    assert.deepEqual(Object.fromEntries(Object.keys(statement_body).map((k) => [k, body[k]])), statement_body, name);
    assert.equal(f.handle, "tog:northwind.example");
    assert.doesNotMatch(f.page_html + f.tog_json, /TOG-/, name);   // a company has no registry code
    assert.match(f.page_html, /ToG-B-1\.0 \(draft, not final\)/);
    assert.match(f.page_html, /<link rel="tog" href="https:\/\/northwind\.example\/\.well-known\/tog\.json">/);
  }
  assert.throws(() => companyFiles("https://northwind.example", "N", { decision: "no" }));
  assert.match(companyFiles("a.example", "<b>&", { decision: "no" }).page_html, /&#60;b&#62;&#38;/);
});

test("chooser: offered registries", () => {
  for (const { name, local, registries, offered } of V.chooser) {
    assert.deepEqual(offeredRegistries(registries, { local }), offered, name);
  }
  assert.deepEqual(offeredRegistries([{ name: "X", prefix: "PRAM", website: "https://a.example",
    tog_start: "https://a.example/start\t" }]), []);
});
