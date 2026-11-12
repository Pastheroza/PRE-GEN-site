// ToG generator, profile likeness/2 (UNRELEASED library 0.14.0): the rules, the English card, the company card, the
// `tog=v1` fragment (a person, a company, a minor's representative; a person's yes may carry their own-words
// `conditions`, ToG 1.0 §6(f)) and the registry chooser (spec/drafts/tog-funnel.md).
// A port of spec/tools/tog_generator.py (+ tog_generator_vectors.py); spec/test-vectors/tog-generator.json is the
// judge (test/tog.test.js). A disagreement is an erratum in the port, never a local fix of the vectors.
// ponytail: English card only (pregen.org is English); the Russian card lives in PRAMPTA's port.
import { canonicalJson, parseCode } from "./index.js";
export { loadDirectory, proofLine, normalizeTyped, CodeError, kindOf, issuerOf, checkChar, parseCode } from "./index.js";

export const VOCAB = ["adult", "advertising", "alcohol", "cannabis", "drugs", "endorsement", "fashion", "financial",
  "gambling", "health", "political", "religion", "sexual", "tobacco", "violence", "weapons"];
const FLOOR = ["adult", "sexual"];
const REGISTRY_LOCK = ["political"];
const PURPOSES = ["commercial", "editorial", "educational", "personal", "research"];
const MODES = ["approve", "open"];
const MODALITIES = ["3d", "image", "video", "voice"];
const MEMBERS = ["excluded_categories", "modalities", "training", "uses"];

export const FOR = { fun: ["personal"], news: ["editorial", "educational", "research"], paid: ["commercial"] };
export const NEVER = { vice: ["alcohol", "cannabis", "drugs", "tobacco"], weapons: ["weapons"], violence: ["violence"],
  gambling: ["gambling"], money: ["financial"], health: ["health"], religion: ["religion"], ads: ["advertising"],
  endorse: ["endorsement"], fashion: ["fashion"] };
export const AGES = ["18+", "13-17"];   // 13-17 only ever decodes as "minor": a representative registers a minor
export const WHO = ["company", "child"];  // a person answering for themself has no `who` (byte-identical to before)
export const DECISIONS = ["no", "approve_all", "rules"];
export const FLOORS = ["each", "project", "video"];
export const MAX_FRAGMENT = 6144;   // the longest answers with 1,000 four-byte characters of conditions: 5,629
export const CONDITIONS_MAX = 1000;  // ToG 1.0 §6(f): at most 1,000 characters (Unicode code points), any language
// Never in conditions: C0 and C1 controls but LF, the line and paragraph separators, bidi controls
// (U+202A-U+202E, U+2066-U+2069; the card would show other text than the bytes), lone surrogates (with the `u` flag a
// surrogate pair is one character, so only a lone half matches; no isWellFormed(), which older browsers lack).
const COND_BAD = /[\x00-\x09\x0b-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069\uD800-\uDFFF]/u;

/** The person's own words: a non-empty NFC string of at most 1,000 code points, LF the only control. */
export function conditionsOk(c) {
  return typeof c === "string" && c.length > 0 && [...c].length <= CONDITIONS_MAX
    && c.normalize("NFC") === c && !COND_BAD.test(c);
}
/** The one common licence text every card links to, the same for everyone (tog/1.0/legal-code.txt), and the label
 *  every card that cites it shows: public draft 1, whose brackets are not yet completed (its §16(a)). */
export const LEGAL = { id: "ToG-1.0", label: "ToG 1.0 public draft 1",
  sha256: "b5ca28ccaeeecf3be03e7532b3460ff2d0d696c2f72cc7af1cff5ef5cdd178e4", url: "https://www.pregen.org/tog/1.0" };

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const sortedSet = (xs) => [...new Set(xs)].sort();

export function no() {
  return { uses: {}, modalities: [], excluded_categories: [...FLOOR], training: false };
}

function sortedSetOf(v, vocab) {
  return Array.isArray(v) && v.every((c) => typeof c === "string" && vocab.includes(c)) && same(v, sortedSet(v));
}

/** likeness/2 `rules`, or throws. Never repaired, never normalised (rule 6). */
export function validate(r) {
  const bad = (why) => { throw new Error(why); };
  if (!isObj(r) || !same(Object.keys(r).sort(), MEMBERS)) bad("members");
  const { uses: u, modalities: m, excluded_categories: x, training: t } = r;
  if (!isObj(u) || Object.entries(u).some(([k, v]) => !PURPOSES.includes(k) || typeof v !== "string" || !MODES.includes(v))) bad("uses");
  if (!sortedSetOf(m, MODALITIES)) bad("modalities");
  if (!sortedSetOf(x, VOCAB)) bad("excluded_categories");
  if (typeof t !== "boolean") bad("training");
  if (!FLOOR.every((c) => x.includes(c))) bad("floor");
  const empty = Object.keys(u).length === 0;
  if (empty && (m.length || !same(x, FLOOR) || t)) bad("no has one spelling");
  if (!empty && !m.length) bad("uses without modalities");
  return r;
}

export function defaultNever(for_) {
  return Object.keys(NEVER).filter((k) => k !== "fashion" && !(k === "ads" && for_.includes("paid")));
}

/** Answers {decision, for, never, voice} (age and floor ignored) -> rules. Nothing ticked is the "no". */
export function rulesFromAnswers(a) {
  if (a.decision === "no" || !a.for.length) return no();
  const uses = {};
  for (const p of a.for.flatMap((k) => FOR[k]).sort()) {
    uses[p] = a.decision === "approve_all" || p === "commercial" ? "approve" : "open";
  }
  return validate({ uses, training: false, modalities: a.voice ? ["image", "video", "voice"] : ["image", "video"],
    excluded_categories: sortedSet([...FLOOR, ...REGISTRY_LOCK, ...a.never.flatMap((k) => NEVER[k])]) });
}

// ---- the card (English, first person) -----------------------------------------------------------------------------
const EN = {
  personal: "fun and fan content", editorial: "news, commentary and satire", educational: "teaching",
  research: "research", rnd: "news, commentary and satire, teaching and research", commercial: "ads and paid work",
  and: "and", image: "pictures", video: "video", "3d": "3D avatars", voice: "my voice",
  adult: "adult content", sexual: "sexual content", "adult+sexual": "sexual or adult content", political: "politics",
  advertising: "ads", endorsement: "\"I recommend it\" (endorsements)",
  "advertising+endorsement": "ads and \"I recommend it\" (endorsements)", alcohol: "alcohol", cannabis: "cannabis",
  drugs: "drugs", tobacco: "tobacco", "alcohol+cannabis+drugs+tobacco": "alcohol, tobacco, cannabis and drugs",
  gambling: "gambling", weapons: "weapons", violence: "violence", religion: "religion", health: "medicine and health",
  financial: "money and investing", fashion: "fashion and beauty",
  no: "**No AI generation of me.**",
  no2: "Not for fun, not for news, not for ads, and no training of AI models on me.",
  all_approve: "AI may make me **only with my approval of each one**.",
  only: "AI may make me **only for {list}**.",
  mixed: "AI may make me for {open}, and **for {approve} only with my approval of each one**.",
  for: "For: {list}.", paid: "Ads and paid work: only under a deal I sign.", as: "As: {list}.",
  no_voice: "Not my voice.", never: "Never: {list}.", train_no: "Training AI models on me: no.",
  train_yes: "Training AI models on me: allowed. Each later use must still ask.",
  except: "Exceptions only by a deal I sign myself. Sexual or adult content only by such a deal after an identity "
    + "document check, and never showing me as under 18.",
  real: "Never presented as a real recording of me.",
  binds: "These rules bind AI companies that accept them. They never limit my rights under the law.",
  binds_yes: "This yes is only for AI companies that accept these rules. It gives no one else permission.",
};
const CO = "our marks, products and characters";
const COMPANY = { ...EN,
  no: "**No AI generation of our marks, products or characters.**",
  no2: "Not for fun, not for news, not for ads, and no training of AI models on our marks.",
  all_approve: `AI may make ${CO} **only with our approval of each one**.`,
  only: `AI may make ${CO} **only for {list}**.`,
  mixed: `AI may make ${CO} for {open}, and **for {approve} only with our approval of each one**.`,
  paid: "Ads and paid work: only under a deal we sign.",
  endorsement: "\"we recommend it\" (endorsements)",
  "advertising+endorsement": "ads and \"we recommend it\" (endorsements)", "3d": "3D",
  train_no: "Training AI models on our marks: no.",
  real: "Never presented as our own advertising or statement.",
  except: "Exceptions only by a deal we sign, and never for sexual or adult content.",
  binds: "This covers only what we own. It never licenses any real person shown with it. It does not stop uses the "
    + "law allows without a licence." };
const PURPOSE_ORDER = [["personal"], ["editorial", "educational", "research"], ["commercial"]];
const MODALITY_ORDER = [["image"], ["video"], ["3d"], ["voice"]];
const CATEGORY_ORDER = [["adult", "sexual"], ["political"], ["alcohol", "cannabis", "drugs", "tobacco"], ["weapons"],
  ["violence"], ["gambling"], ["financial"], ["health"], ["religion"], ["advertising", "endorsement"], ["fashion"]];

function items(present, order, t, key = (g) => g.join("+")) {
  return order.flatMap((g) => (g.length > 1 && g.every((c) => present.has(c)) ? [t[key(g)]]
    : g.filter((c) => present.has(c)).map((c) => t[c])));
}
function join(xs, t, sep = "; ") {
  return sep === "; " || xs.length === 1 ? xs.join(sep) : xs.slice(0, -1).join(", ") + ` ${t.and} ` + xs.at(-1);
}
const fill = (s, v) => s.replace(/\{(\w+)\}/g, (_, k) => v[k]);

// The lines both cards share, up to and including the Never line.
function head(r, t, voiceLine) {
  const ps = (mode) => join(items(new Set(Object.keys(r.uses).filter((p) => r.uses[p] === mode)), PURPOSE_ORDER, t,
    (g) => (g.length === 3 ? "rnd" : g[0])), t);
  const modes = new Set(Object.values(r.uses));
  const lines = modes.size === 2 ? [fill(t.mixed, { open: ps("open"), approve: ps("approve") })]
    : modes.has("approve") ? [t.all_approve, fill(t.for, { list: ps("approve") })]
    : [fill(t.only, { list: ps("open") })];
  if ("commercial" in r.uses) lines.push(t.paid);
  const as = fill(t.as, { list: join(items(new Set(r.modalities), MODALITY_ORDER, t), t, ", ") });
  lines.push(voiceLine && !r.modalities.includes("voice") ? `${as} ${t.no_voice}` : as);
  lines.push(fill(t.never, { list: join(items(new Set(r.excluded_categories), CATEGORY_ORDER, t), t) }));
  return lines;
}

/** The card's body lines from the rules alone (English, first person); `**` marks the one bold phrase. */
export function card(r) {
  validate(r);
  const t = EN;
  if (!Object.keys(r.uses).length) return [t.no, t.no2, t.except, t.binds];
  return [...head(r, t, true), r.training ? t.train_yes : t.train_no, t.real, t.except, t.binds_yes];
}

/** Company answers {decision, for, never} -> rules: forms are always pictures, video and 3D, never voice. */
export function companyRules(a) {
  const r = rulesFromAnswers({ ...a, voice: false });
  return Object.keys(r.uses).length ? validate({ ...r, modalities: ["3d", "image", "video"] }) : r;
}

/** The company card (profile marks/1, draft wording of PLAN §3.1). */
export function cardCompany(r) {
  validate(r);
  const t = COMPANY;
  if (r.training || r.modalities.includes("voice")) throw new Error("marks/1 has no training and no voice");
  if (!Object.keys(r.uses).length) return [t.no, t.no2, t.except, t.binds];
  return [...head(r, t, false), t.train_no, t.real, t.except, t.binds];
}

// ---- the fragment `tog=v1` (PLAN §2.1) ----------------------------------------------------------------------------
function ordered(v, keys) {
  return Array.isArray(v) && v.every((x) => typeof x === "string" && keys.includes(x)) && same(v, keys.filter((k) => v.includes(k)));
}

/** A company's or a representative's answers: `who` names which; never an age, a domain or a name. A minor's
 *  representative may only say no (founder, 2026-11-11). */
function whoOk(a) {
  const keys = Object.keys(a).sort();
  if (a.who === "child") return same(keys, ["decision", "who"]) && a.decision === "no";
  if (a.who !== "company" || typeof a.decision !== "string" || !DECISIONS.includes(a.decision)) return false;
  if (a.decision === "no") return same(keys, ["decision", "who"]);
  return same(keys, ["decision", "for", "never", "who"]) && ordered(a.for, Object.keys(FOR)) && a.for.length > 0
    && ordered(a.never, Object.keys(NEVER));
}

/** The exact member set for the decision and every value in its closed set (the age rule is decodeFragment's). */
export function answersOk(a) {
  if (isObj(a) && "who" in a) return whoOk(a);
  if (!isObj(a) || typeof a.age !== "string" || !AGES.includes(a.age)
      || typeof a.decision !== "string" || !DECISIONS.includes(a.decision)) return false;
  const keys = Object.keys(a).sort();
  if (a.decision === "no") return same(keys, ["age", "decision"]);
  const f = a.for;
  if (!ordered(f, Object.keys(FOR)) || !f.length || !ordered(a.never, Object.keys(NEVER)) || typeof a.voice !== "boolean") return false;
  const paid = f.includes("paid");
  if (!same(keys.filter((k) => k !== "conditions"), ["age", "decision", ...(paid ? ["floor"] : []), "for", "never", "voice"])) return false;
  if ("conditions" in a && !conditionsOk(a.conditions)) return false;
  return !paid || (typeof a.floor === "string" && FLOORS.includes(a.floor));
}

const b64url = (s) => btoa(String.fromCharCode(...new TextEncoder().encode(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const minor = (a) => a.age === "13-17";   // a minor registers only through a parent, guardian or representative

/** Answers -> the fragment without its leading '#'. Never a minor's own answers. */
export function encodeAnswers(a) {
  if (!answersOk(a) || minor(a)) throw new Error("these answers cannot be handed off");
  return "tog=v1." + b64url(canonicalJson(a));   // UTF-8 of canonical JSON: conditions as raw UTF-8, never \u escapes
}

/** location.hash without the '#' -> {result: "ok", answers} | {result: "unknown_version" | "malformed" | "minor"}.
 *  Strict, never repairs (rule 6): the answers must re-encode to exactly the input. */
export function decodeFragment(f) {
  const bad = { result: "malformed" };
  if (typeof f !== "string" || f.length > MAX_FRAGMENT || !f.startsWith("tog=")) return bad;
  if (!f.startsWith("tog=v1.")) return { result: "unknown_version" };
  const p = f.slice("tog=v1.".length);
  if (!/^[A-Za-z0-9_-]*$/.test(p)) return bad;
  let a;
  try {
    const bin = atob(p.replace(/-/g, "+").replace(/_/g, "/"));
    a = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bin, (c) => c.charCodeAt(0))));
  } catch {
    return bad;
  }
  if (!answersOk(a) || "tog=v1." + b64url(canonicalJson(a)) !== f) return bad;
  if (minor(a)) return { result: "minor" };
  return { result: "ok", answers: a };
}

// ---- the registry chooser (PLAN §2.2) -----------------------------------------------------------------------------
const LOCAL_HOSTS = ["localhost", "127.0.0.1"];

function origin(u, local) {
  // Printable ASCII only: the WHATWG parser would otherwise drop tabs and spaces that urlsplit keeps.
  if (typeof u !== "string" || !/^[\x21-\x7e]+$/.test(u) || u.includes("\\")) return null;
  let s;
  try { s = new URL(u); } catch { return null; }
  if (!s.hostname || s.username || s.password) return null;
  if (!(s.protocol === "https:" || (local && s.protocol === "http:" && LOCAL_HOSTS.includes(s.hostname)))) return null;
  return s.origin;   // the default port is dropped and the host lowercased, as urlsplit's (scheme, host, port)
}

/** The registries a person may be handed to, in directory order: {name, prefix, start}. `directory` is a Directory
 *  from loadDirectory() or its list of entries; `local` allows http://localhost (the e2e stand only). */
export function offeredRegistries(directory, { local = false } = {}) {
  const list = Array.isArray(directory) ? directory : directory.registries;
  return list.filter((e) => {
    const o = origin(e.tog_start, local);
    return e.prefix && e.revoked == null && o && o === origin(e.website, local)
      && !new URL(e.tog_start).search && !e.tog_start.includes("#");
  }).map((e) => ({ name: e.name, prefix: e.prefix, start: e.tog_start }));
}

// ---- the return (spec/drafts/tog-funnel.md, The return) ------------------------------------------------------------
/** Where a home registry sends the person once it has issued the code: the page shows their ToG statement. */
export const RETURN_URL = "https://www.pregen.org/tog/document";
export const MAX_RETURN = 8192;
export const RECORD_MAX = 512;
const CLAIM = /^[0-9a-f]{16,64}$/;

function personCode(code) {
  try { const p = parseCode(code); return p.kind === "subject" && p.shape !== "old_no_check"; } catch { return false; }
}
/** A company's record page: https, printable ASCII, no credentials or fragment, at most 512 characters. That its origin
 *  is the registry's website is the page's check (it needs the signed directory). */
function recordOk(r) {
  if (typeof r !== "string" || !r.length || r.length > RECORD_MAX || !/^[\x21-\x7e]+$/.test(r) || r.includes("\\")
      || r.includes("#")) return false;
  let u;
  try { u = new URL(r); } catch { return false; }
  return u.protocol === "https:" && Boolean(u.hostname) && !u.username && !u.password;
}

/** {code, answers, record?, claim?} -> the fragment of RETURN_URL without '#'. record and claim: both or neither, and
 *  only a company's (the two members of its /.well-known/tog.json entry). */
export function encodeReturn({ code, answers, record, claim }) {
  const has = record !== undefined;
  if (!personCode(code) || has !== (claim !== undefined)
      || (has && !(answers && answers.who === "company" && recordOk(record) && CLAIM.test(claim)))) throw new Error("not a return");
  const f = `code=${code}&${encodeAnswers(answers)}` + (has ? `&record=${encodeURIComponent(record)}&claim=${claim}` : "");
  if (f.length > MAX_RETURN) throw new Error("not a return");
  return f;
}

/** location.hash of RETURN_URL without '#' -> {result: "ok", code, answers, record?, claim?} | {result:
 *  "unknown_version" | "minor" | "malformed"}. Strict, never repairs: the whole re-encodes to exactly the input. */
export function decodeReturn(f) {
  const bad = { result: "malformed" };
  if (typeof f !== "string" || f.length > MAX_RETURN || !f.startsWith("code=")) return bad;
  const parts = f.split("&");
  if (![2, 4].includes(parts.length) || !parts[1].startsWith("tog=")) return bad;
  const inner = decodeFragment(parts[1]);
  if (inner.result !== "ok") return inner;
  const out = { result: "ok", code: parts[0].slice("code=".length), answers: inner.answers };
  if (parts.length === 4) {
    if (!parts[2].startsWith("record=") || !parts[3].startsWith("claim=")) return bad;
    try { out.record = decodeURIComponent(parts[2].slice("record=".length)); } catch { return bad; }
    out.claim = parts[3].slice("claim=".length);
  }
  try { if (encodeReturn(out) !== f) return bad; } catch { return bad; }
  return out;
}
