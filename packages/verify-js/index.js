// @pregen/verify — check PRE-GEN signatures against the signed registry
// directory (PG-CODE.md §9.1, PRE-GEN-SPEC.md §2, V-9 to V-12).
// No dependencies: Ed25519 and SHA-256 come from Web Crypto (Node >= 20, browsers).

export const STEWARD_PUBLIC_KEY_HEX = "5cb949aab04186e3e216ec541b847c912fc3f78138c0ec3cb2560b2dad0d1f1b";
/** The successor steward key, created in advance and kept apart (PG-CODE.md §9.1). A directory
 * it signs replaces every directory signed by the current steward key, whatever their sequence. */
export const STEWARD_SUCCESSOR_PUBLIC_KEY_HEX = "658544163d6abd5fef046407980d249817875d87d8cf4b67879a2e265fa5612f"; // pg-ed25519:3e5e20729ce8485eea274c4cb33721d6, created 2026-10-03
/** The directory (PRE-GEN-CORE.md rule 2, TOG-CODE.md §9.2). The v2 file stays frozen at DIRECTORY_V2_URL for
 * clients before 0.14; this library reads both. */
export const DIRECTORY_URL = "https://www.pregen.org/registries.v3.json";
export const DIRECTORY_V2_URL = "https://www.pregen.org/registries.json";
const SCHEMA = "pregen.registries.v2", SCHEMA_V3 = "pregen.registries.v3";
const ROLES = ["home", "market", "wallet", "log_operator", "witness"];
const MAX_INT = 2 ** 53 - 1;
const PREFIX = /^[ABCDEFGHJKMNPQRSTVWXYZ]{4}$/;
const FINGERPRINT = /^pg-ed25519:[0-9a-f]{32}$/;

export class PregenError extends Error {
  constructor(message) { super(message); this.name = "PregenError"; }
}
const fail = (message) => { throw new PregenError(message); };
const utf8 = new TextEncoder();

function bytesCompare(a, b) {
  for (let i = 0; i < a.length && i < b.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

function hexBytes(hex, length) {
  if (typeof hex !== "string" || hex.length !== length * 2 || !/^[0-9a-fA-F]*$/.test(hex)) {
    fail(`expected ${length} bytes of hex`);
  }
  return Uint8Array.from(hex.match(/../g), (h) => parseInt(h, 16));
}

const toHex = (bytes) => Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");

/** Canonical JSON (PRE-GEN-SPEC.md §2) as a string; encode with UTF-8 to sign. */
export function canonicalJson(value) {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail("signed JSON numbers must be safe integers");
    return String(value);
  }
  if (typeof value === "string") {
    if (!value.isWellFormed()) fail("invalid Unicode in signed JSON");
    return JSON.stringify(value); // escapes exactly as §2 requires
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) if (!(i in value)) fail("sparse arrays are not JSON");
    return "[" + value.map(canonicalJson).join(",") + "]";
  }
  if (typeof value === "object" && [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    // UTF-8 byte order is Unicode code point order.
    const keys = Object.keys(value).sort((a, b) => bytesCompare(utf8.encode(a), utf8.encode(b)));
    return "{" + keys.map((k) => canonicalJson(k) + ":" + canonicalJson(value[k])).join(",") + "}";
  }
  fail("signed JSON must contain only JSON values");
}

export async function sha256Hex(data) {
  return toHex(await crypto.subtle.digest("SHA-256", typeof data === "string" ? utf8.encode(data) : data));
}

/** "pg-ed25519:" + first 32 hex of SHA-256(raw public key) (§2.1). */
export async function fingerprint(publicKeyHex) {
  return "pg-ed25519:" + (await sha256Hex(hexBytes(publicKeyHex, 32))).slice(0, 32);
}

// The curve's 8 small-order points, sign bit cleared; y = p and p + 1 are 0 and 1 again (as libsodium lists them).
// Under such a key a signature checks out for any message with no private key behind it, and OpenSSL takes it
// (stress test C1, 2026-10-28). The same list as PRAMPTA's verify_ed25519 and pregen.check_public_key.
const SMALL_ORDER = new Set([
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]);
const P = 2n ** 255n - 19n;

/** The raw key, or PregenError for a key no one can be held to: a small-order point in any encoding, or a
 *  non-canonical encoding (y >= p). Call it wherever a key is first recorded; verifyBytes calls it too. */
export function checkPublicKey(publicKeyHex) {
  const raw = hexBytes(publicKeyHex, 32);
  const y = Uint8Array.from(raw);
  y[31] &= 0x7f;
  let n = 0n;
  for (let i = 31; i >= 0; i--) n = (n << 8n) | BigInt(y[i]);
  if (SMALL_ORDER.has(toHex(y)) || n >= P) fail("public key is a small-order or non-canonical point: anyone could sign under it");
  return raw;
}

/** Ed25519 over raw bytes. False on any bad signature or key encoding, and under a key checkPublicKey refuses. */
export async function verifyBytes(publicKeyHex, signatureHex, message) {
  try {
    const key = await crypto.subtle.importKey("raw", checkPublicKey(publicKeyHex), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, hexBytes(signatureHex, 64), message);
  } catch {
    return false;
  }
}

/** Verify `obj[signatureField]` over the canonical JSON of `obj` without the excluded fields. */
export async function verifySigned(obj, publicKeyHex, signatureField, exclude = [signatureField]) {
  if (!obj || typeof obj !== "object") return false;
  const body = Object.fromEntries(Object.entries(obj).filter(([k]) => !exclude.includes(k)));
  return verifyBytes(publicKeyHex, obj[signatureField], utf8.encode(canonicalJson(body)));
}

/** A license (§1.2): subject signature over the body, operator countersignature over
 * canonical body || subject signature (64 raw bytes) || license id (ASCII). */
export async function verifyLicense({ body, licenseId, subjectPublicKeyHex, subjectSignatureHex,
  operatorPublicKeyHex, operatorSignatureHex }) {
  const bodyBytes = utf8.encode(canonicalJson(body));
  const subjectValid = await verifyBytes(subjectPublicKeyHex, subjectSignatureHex, bodyBytes);
  let operatorValid = false;
  try {
    const sig = hexBytes(subjectSignatureHex, 64);
    const id = utf8.encode(String(licenseId));
    const message = new Uint8Array(bodyBytes.length + 64 + id.length);
    message.set(bodyBytes); message.set(sig, bodyBytes.length); message.set(id, bodyBytes.length + 64);
    operatorValid = await verifyBytes(operatorPublicKeyHex, operatorSignatureHex, message);
  } catch { /* bad encoding: invalid */ }
  return { subjectValid, operatorValid };
}

/** The registry to ask for a code: its first prefix, or "" for the bare legacy namespace (TOG-CODE.md §8). Reads the
 *  shape only, never says a code is real. Anything else — lower case, spaces, invisible or non-ASCII characters — is
 *  refused, never repaired: one code, one string. Pass what a person typed through normalizeTyped first. */
export function issuerOf(code) {
  if (typeof code !== "string") fail("a code must be a string");
  return parseCode(code, { check: false }).issuer;
}

/** @deprecated Use normalizeTyped, which folds look-alikes and gives the TOG spelling. Surrounding ASCII spaces
 *  trimmed and lower case raised, nothing else; the spelling is kept as typed (PG-CODE.md §7). */
export function normalizeCode(typed) {
  if (typeof typed !== "string") fail("a code must be a string");
  const s = typed.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, "");
  if (!/^[\x00-\x7f]*$/.test(s)) fail("a code is ASCII: retype it");
  issuerOf(s.toUpperCase());
  return s.toUpperCase();
}

// ── ToG code (spec/TOG-CODE.md): the one code family, written TOG-; PG- is legacy input only ──

export const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";   // serials, tails (PG-CODE §3, frozen)
export const TOG_VALUES = CROCKFORD + "ILOU";                  // TOG bodies only: I L O U take 32-35 (§3)
const CHECK = CROCKFORD + "*~$=!";
const MAX_BODY = 36, TAIL = 11, RESERVED_SERIAL = 900_000_000n, RESERVED_TAIL = "ZZZZ", BARE_ISSUER = "PRAM";
const FIVE = ["PG", "PG-LIC", "AG", "AG-LIC", "LIC"];
const KINDS = { LIC: "license", PG: "generated", AG: "approved_after" };
const KIND_OF_TYPE = { "pg.grant.v1": "LIC", "pg.license.v2": "LIC", "pg.answer.v1": "PG", "pg.after_gen.v1": "AG" };

/** A string that is not a code, or a record that gives none. `reason`: "malformed" (not a code), "mistyped" (the check
 * fails), "ask_registry" (an old licence id with no record at hand) or "no_code" (a record that gives no code).
 * `hints`: both readings when typed input is ambiguous. */
export class CodeError extends PregenError {
  constructor(reason, message = reason, hints) {
    super(message);
    this.name = "CodeError";
    this.reason = reason;
    if (hints) this.hints = hints;
  }
}
const codeFail = (reason, message, hints) => { throw new CodeError(reason, message, hints); };

const C = "0-9A-HJKMNP-TV-Z", K = `[${C}*~$=!]`;
const TP = "(?!LIC|L[A-Z]IC(?![A-Z])|LI[A-Z]C(?![A-Z]))[A-Z]{4,8}(?<!LIC)", OLDP = "[A-HJKMNP-TV-Z]{4}";
const SHAPES = [   // [shape, marker, kind, regex]: exactly one matches any valid code (§7.1)
  ["person", "TOG", "subject", `TOG-(${TP})-([1-9][0-9]{8})([${C}])`],
  ["event", "TOG", null, `TOG-(LIC|(?:PG|AG)(?:-LIC)?)-(${TP})(?:-(${TP}))?-([${C}]{4}-[${C}]{4}-[${C}]{3})([${C}])`],
  ["old_person", "TOG", "subject", `TOG-(${OLDP})-([0-9]{6,7})(${K})`],
  ["old_bare_person", "TOG", "subject", `TOG-()([0-9]{6,})(${K})`],
  ["old_no_check", "TOG", "subject", "TOG-(STD|SUB)-([0-9]{6,})"],
  ["pg_person", "PG", "subject", `PG-(${OLDP})-([0-9]{6,})(${K})`],
  ["pg_licence", "PG", "license", `PG-(${OLDP})-([A-Z]{3})-([0-9]{6,})-([${C}]{6})(${K})`],
  ["bare_person", "PG", "subject", `PG-()([0-9]{6,})(${K})`],
  ["bare_licence", "PG", "license", `PG-()([A-Z]{3})-([0-9]{6,})-([${C}]{6})(${K})`],
  ["no_check", "PG", "subject", "PG-([A-Z]{3})-([0-9]{6,})"],
].map(([s, m, k, rx]) => [s, m, k, new RegExp(`^${rx}$`)]);
const PREFIX_TOG = new RegExp(`^${TP}$`);

/** The check character of a body (PG-CODE §4.1): value × 1-based position, mod 37. Values from the TOG table by
 * default; pass CROCKFORD for a PG body. Throws CodeError "malformed" for a body over 36 or outside the table. */
export function checkChar(body, values = TOG_VALUES) {
  if (typeof body !== "string" || body.length > MAX_BODY || [...body].some((c) => !values.includes(c))) {
    codeFail("malformed", "body too long or outside the alphabet");
  }
  let sum = 0;
  for (let i = 0; i < body.length; i++) sum += values.indexOf(body[i]) * (i + 1);
  return CHECK[sum % 37];
}
const verifies = (body, chk, values) => { try { return checkChar(body, values) === chk; } catch { return false; } };
const eventBody = (kind, issuer, home, tail) =>
  `${issuer.length}${(home || "").length}${FIVE.indexOf(kind) + 1}${issuer}${home || ""}${tail}`;

/** The one reading of a code exactly as it stands in a message (§7): no trimming, case change or folding. Returns
 * {shape, marker, kind, home, key, issuer, example, ...}: `kind` is "subject", "license", "generated" or
 * "approved_after"; `key` the TOG spelling (null for an old PG licence id: ask its registry). Throws CodeError
 * "malformed" or "mistyped". `check: false` reads the shape only (routing); it never says a code is real. */
export function parseCode(code, { check = true } = {}) {
  if (typeof code !== "string" || !/^[\x00-\x7f]*$/.test(code)) codeFail("malformed", "not an ASCII string");
  const hits = SHAPES.map(([s, mk, k, rx]) => [s, mk, k, rx.exec(code)]).filter((h) => h[3]);
  if (hits.length !== 1) codeFail("malformed", `not a code: ${JSON.stringify(code)}`);
  const [shape, marker, kind, m] = hits[0], g = m.slice(1).map((x) => x ?? null);
  const out = { shape, marker, kind, home: null, key: marker === "TOG" ? code : null };
  if (marker === "PG" && kind === "subject") {
    // Legacy input: its one spelling is TOG- + the rest. With no valid TOG spelling it was never issued (§7.3).
    if (check && shape !== "no_check" && !verifies(g[0] + g[1], g[2], CROCKFORD)) codeFail("mistyped", code);
    if (check && !isCode("TOG" + code.slice(2))) codeFail("malformed", "never issued in any spelling");
    out.key = "TOG" + code.slice(2);
  }
  if (shape === "no_check" || shape === "old_no_check") return { ...out, issuer: "", cls: g[0], serial: g[1], example: false };
  if (shape === "event") {
    const [k, issuer, home, groups, chk] = g, tail = groups.replaceAll("-", "");
    if (home === issuer) codeFail("malformed", "a registry is written once");
    if (check && !verifies(eventBody(k, issuer, home, tail), chk, TOG_VALUES)) codeFail("mistyped", code);
    return { ...out, kind: KINDS[k.slice(0, 3).replace(/-$/, "")], basis: k === "LIC" ? null : k.endsWith("-LIC") ? "licence" : "terms",
      issuer, home, example: tail.startsWith(RESERVED_TAIL) };
  }
  const prefix = g[0], rest = g.slice(1, -1), chk = g.at(-1);
  if (check && !verifies(prefix + rest.join(""), chk, marker === "TOG" ? TOG_VALUES : CROCKFORD)) codeFail("mistyped", code);
  const serial = kind === "subject" ? rest.at(-1) : rest[1];
  return { ...out, issuer: prefix, cls: "", serial, example: BigInt(serial) >= RESERVED_SERIAL };
}
const isCode = (s) => { try { parseCode(s); return true; } catch { return false; } };

/** "subject", "license", "generated" or "approved_after", from the string alone (no network). */
export function kindOf(code) { return parseCode(code).kind; }

/** What the string claims, for support tools (§15): never shown beside a video, where party names come only from a
 * record that fits the file. Throws CodeError "malformed" or "mistyped". */
export function describe(code) {
  const p = parseCode(code);
  const home = p.home ? ` · home ${p.home}` : "";
  const basis = { licence: " under a licence", terms: " under the person's terms" }[p.basis] ?? "";
  let ex = p.example ? " · EXAMPLE, never issued" : "";
  if (p.marker === "PG") ex += p.key ? ` · old spelling of ${p.key}` : " · old licence number: its registry gives its TOG code";
  return `claims ${p.kind}${basis} · issued by ${p.issuer || "the bare legacy namespace"}${home} · not checked${ex}`;
}

/** The one TOG spelling of a code (§7.3). Every comparison, hash key and refusal check uses it. A TOG code is its own
 * key; a PG person folds by its marker; an old PG licence id folds through its signed pg.license.v2 record, from
 * `licences` ({old id: record}), else CodeError "ask_registry". Never returns a PG- string. */
export function codeKey(code, licences = {}) {
  const p = parseCode(code);
  if (p.key) return p.key;
  const rec = Object.hasOwn(licences ?? {}, code) ? licences[code] : null;
  if (rec == null || rec.license_id !== code) codeFail("ask_registry", `${code}: only its registry gives its TOG code`);
  return codeFor(rec);
}
const truthy = (o) => Boolean(o) && (typeof o !== "object" || Object.keys(o).length > 0);   // as the reference model reads a record
/** codeKey where there is one, else the string as it stands: a comparison never splits one code in two (§7.3). */
const keyOf = (c) => { try { return codeKey(c); } catch { return c; } };
/** One code under two spellings (§7.3): equal TOG spellings. A string that is not a code equals nothing. */
function sameCode(a, b) {
  try { return codeKey(a) === codeKey(b); } catch { return false; }
}

function tailOf(messageId) {
  if (typeof messageId !== "string" || !/^[0-9a-f]{64}$/.test(messageId)) codeFail("no_code", "a message id is 64 lowercase hex");
  const n = BigInt("0x" + messageId) >> BigInt(256 - 5 * TAIL);
  return Array.from({ length: TAIL }, (_, i) => CROCKFORD[Number((n >> BigInt(5 * (TAIL - 1 - i))) & 31n)]).join("");
}

function eventCode(kind, issuer, home, messageId) {
  if (home === issuer) home = null;
  const tail = tailOf(messageId);
  if (tail.startsWith(RESERVED_TAIL)) codeFail("no_code", "reserved tail: the issuer signs again");
  const chk = checkChar(eventBody(kind, issuer, home, tail));
  if (!CROCKFORD.includes(chk)) codeFail("no_code", "symbol check: the issuer signs again");
  const t = tail + chk, code = `TOG-${kind}-${issuer}${home ? "-" + home : ""}-${t.slice(0, 4)}-${t.slice(4, 8)}-${t.slice(8)}`;
  parseCode(code);
  return code;
}

/** The code of an act, computed from its record, never read off a code (§6.1). act = {type, id, signer, subject_ref,
 * grant?: {id, signer}, cosign?: {id, home, home_in_code}}: `type` pg.grant.v1 / pg.license.v2 (LIC), pg.answer.v1
 * (PG), pg.after_gen.v1 (AG); `grant` the licence the act names (adds -LIC); `signer` the signer's prefix. Throws
 * CodeError ("no_code" when the record gives none). */
export function codeFor(act) {
  let kind = Object.hasOwn(KIND_OF_TYPE, act?.type) ? KIND_OF_TYPE[act.type] : null;
  if (!kind) codeFail("no_code", "not an act type");
  const grant = act.grant;
  if (truthy(grant)) {
    if (kind === "LIC" || grant.signer !== act.signer) {
      codeFail("no_code", "a licence has no basis; the grant behind an act is signed by the act's own signer");
    }
    kind += "-LIC";
  }
  const cs = act.cosign;
  if (cs == null) {
    if ((issuerOf(act.subject_ref) || BARE_ISSUER) !== act.signer) {
      codeFail("no_code", "no home countersignature: only the person's own registry may sign alone");
    }
    return eventCode(kind, act.signer, null, act.id);
  }
  return eventCode(kind, act.signer, cs.home_in_code ? cs.home : null, cs.id);
}

/** Readable copies beside the signed record (§14): meta = {Code?, Licence?} (pgag:Code, pgag:Licence, or a proof
 * entry's code and licence). Both are recomputed: the act's code, and the code of `licence`, the record its grant
 * names. True when every copy present equals its recomputed code; a missing copy is not an error. */
export function metadataOk(meta, act, licence = null) {
  const want = { Code: null, Licence: null };
  try {
    want.Code = codeFor(act);
    if (truthy(act.grant) && licence != null && licence.id === act.grant.id) want.Licence = codeFor(licence);
  } catch (e) {
    if (e instanceof CodeError) return false;
    throw e;
  }
  return Object.entries(meta).every(([k, v]) => !Object.hasOwn(want, k) || (want[k] !== null && want[k] === v));
}

const COVERS = " It covers the named person only, and says nothing about anyone else in the file.";
const WORDS = {
  noRecord: "No record. This says nothing either way.",
  otherFile: "This code belongs to a different file. It does not show that this video is allowed.",
  differs: "The code does not match its record.",
  example: "Example code from the specification. Never issued.",
  mistyped: "Mistyped code.",
  notACode: "Not a code.",
  editClaim: "An editor states this was made from an approved file. Only the editor says so.",
};
const safeCode = (act) => { try { return codeFor(act); } catch { return null; } };   // a record that gives no code

/** What a verifier may say before signatures and the chain (§15). `fileHash` and act.media_hash name the file;
 * `caption` is a code found beside it, checked against the act, never the other way round; `ingredient` is the hash
 * an edited file's C2PA manifest cites. "fits: …" means: now verify the signatures and the chain, then show the
 * outcome with its parties. No party is ever named from a string. */
export function codeVerdict(fileHash, act = null, caption = null, ingredient = null) {
  let p = null;
  if (caption != null) {
    try { p = parseCode(caption); } catch (e) {
      if (!(e instanceof CodeError)) throw e;
      return e.reason === "mistyped" ? WORDS.mistyped : WORDS.notACode;
    }
    if (p.example) return WORDS.example;
  }
  if (act == null) {
    if (p === null) return WORDS.noRecord;
    if (p.shape !== "event" || p.kind === "license") return `This code names a ${p.kind}. It says nothing about this file.`;
    return "Unchecked: no record at hand. This says nothing either way.";
  }
  let edit = false;
  if (act.media_hash !== fileHash) {
    if (ingredient == null || ingredient !== act.media_hash) return WORDS.otherFile;
    edit = true;
  }
  if (p !== null && !(p.shape === "event" ? safeCode(act) === caption : sameCode(caption, act.subject_ref))) return WORDS.differs;
  if (safeCode(act) === null) return WORDS.differs;
  const kind = KINDS[KIND_OF_TYPE[act.type]];
  if (edit) return WORDS.editClaim;
  return `fits: ${kind}; now verify signatures and the chain (V-H).` + COVERS;
}

const held = (span, at) => span != null && (at == null || (span.from <= at && (span.until == null || at < span.until)));

/** Offline party check of a code against a dated directory (§9.2), for support tools, never beside a video.
 * `entries`: prefix → {entity, group, government, roles: {home|market|…: {from, until}}, provider_domains: [domain],
 * void_from?, closed?} (Directory#partyEntries gives it). `at`: the act's witnessed time, or null: then a revoked,
 * closed or re-roled party is a fact, never a failure. Returns {ok, facts}; ok is false only when a slot names an
 * unlisted party, a party without the slot's role at `at`, or one whose listing was void at `at`. */
export function checkParties(code, entries, { at = null, provider = null } = {}) {
  const p = parseCode(code);
  const slots = p.shape !== "event" ? [["issuer", p.issuer || BARE_ISSUER, []]]
    : p.home ? [["issuer", p.issuer, ["market"]], ["home", p.home, ["home"]]]
      : [["issuer", p.issuer, p.kind === "license" ? ["market"] : ["home", "market"]]];
  const get = (x) => (Object.hasOwn(entries, x) ? entries[x] : undefined);
  let ok = true;
  const facts = [];
  for (const [slot, prefix, roles] of slots) {
    const e = get(prefix);
    if (e === undefined || prefix.includes("GOV") !== Boolean(e.government)) {
      ok = false;
      facts.push(`! ${prefix} is not a listed registry`);
      continue;
    }
    if (roles.length && !roles.some((r) => held(e.roles?.[r], at))) {
      ok = false;
      facts.push(`! ${prefix} did not hold the role ${roles.join(" or ")}` + (at ? " at the act" : ""));
    }
    const v = e.void_from;
    if (v != null) {
      if (at != null && at >= v) {
        ok = false;
        facts.push(`! ${prefix} listing void from ${v}; the act is after it`);
      } else facts.push(`${prefix} listing void from ${v}` + (at != null ? "; the act predates it" : ""));
    }
    if (e.closed != null) facts.push(`${prefix} closed at ${e.closed}; ask the home`);
    facts.push(`${slot} ${prefix} (${e.entity})`);
  }
  const listed = slots.map((s) => get(s[1])).filter((e) => e !== undefined);
  if (listed.length === 2 && listed[0].group === listed[1].group) facts.push("issuer and home are one group");
  for (const [, x] of slots) {
    if (provider && get(x)?.provider_domains?.includes(provider)) facts.push(`${x} also generated it (${provider})`);
  }
  return { ok, facts };
}

const SKELETON = Object.fromEntries([..."CGQDJLVNRF"].map((c, i) => [c, "OOOOIIUMPE"[i]]));
const skeleton = (s) => s.replaceAll("VV", "W").replaceAll("RN", "M").replaceAll("CL", "D").replace(/[CGQDJLVNRF]/g, (c) => SKELETON[c]);
const RESERVED_WORDS = ["PREGEN", "AFTERGEN", "TOGCODE", "STEWARD", "HOME", "MARKET", "BRANCH", "PROVIDER", "WALLET",
  "ALLOW", "APPROV", "AUTHORI", "VERIF", "VALID", "LEGAL", "LAWFUL", "LICENS", "OFFICIAL", "CERTIF", "GENUIN",
  "NOTFAKE", "TRUST", "DENIED", "DENY", "REFUS", "REVOK", "BLOCK", "BANNED", "POLICE", "COURT", "STATE",
  "ADULT", "PORN", "NSFW", "XXX", "EROTIC", "NUDE"];
/** Prefixes of the specification's examples and vectors: reserved forever (§11). */
export const FIXTURE_PREFIXES = Object.freeze(["NWRD", "HLWD", "USAD", "VELR", "SKAN", "KAST", "TGOV", "HYBR", "OMNI",
  "KINO", "KOBEMK", "LYONMK", "RIOMKT", "PUNEMK", "OSLOMK", "ZYXW", "ABCD", "TEST"]);

function osa(a, b) {   // optimal string alignment: substitution, insertion, deletion, adjacent swap
  const d = Array.from({ length: a.length + 1 }, (_, i) => Array.from({ length: b.length + 1 }, (_, j) => (i * j === 0 ? i + j : 0)));
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0));
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

/** The steward's admission check of a new prefix (§9.1): "" when `prefix` may be listed for this legal entity, else
 * the reason (its wording is informative). `directory`: prefix → {entity} already listed. Human judgement (another
 * party's mark, offensive or sensitive words) comes on top. */
export function admissionRefusal(prefix, entity, government, directory, reserved = FIXTURE_PREFIXES) {
  const n = prefix;
  if (typeof n !== "string" || !PREFIX_TOG.test(n)) return "4 to 8 letters A-Z, never LIC at either end, never LIC with one letter added";
  if (Object.hasOwn(directory, n) || reserved.includes(n)) return "taken or reserved: a prefix is never reassigned";
  if (government !== n.includes("GOV")) return "GOV is for governments, and governments hold only prefixes with GOV";
  const sk = skeleton(n);
  if (!government && sk.includes("OOU")) return "looks like GOV";
  if (/^(?:T[OQCGD][CGQ]|[PRA][CGQ]|[IJL]{2}[CGQ])/.test(n) || /[IJL]{2}[CGQ]$/.test(n)
      || (n.length === 4 && /[IJL].?[IJL].?[CGQ]/.test(n)) || n.endsWith("PG") || n.endsWith("TOG")) {
    return "reads as a marker or a kind";
  }
  if (RESERVED_WORDS.some((w) => sk.includes(skeleton(w)))) return "contains a reserved word";
  if (Object.values(directory).some((e) => e.entity === entity)) return "one prefix per legal entity";
  for (const old of Object.keys(directory)) {
    const so = skeleton(old);
    if (osa(n, old) <= 1 || osa(sk, so) <= 1 || sk.includes(so) || so.includes(sk)) return `too close to ${old}`;
  }
  return "";
}

const FIND = /(?<![A-Za-z0-9-])(?:TOG|PG)-[A-Z0-9]+(?:-[A-Z0-9]+)*[*~$=!]?(?![A-Za-z0-9])/g;
/** Every code in free text (captions, pages, transcripts), as it stands there (§13). A PG- string found is legacy
 * input: pass it through codeKey before comparing or showing it. */
export function findCodes(text) {
  return (text.match(FIND) || []).map((c) => (isCode(c) ? c : c.slice(0, -1))).filter(isCode);
}

const DASHES = /[‐‑‒–—―−﹣]/g;
const DROP = /[­​‌‍⁠﻿\\]/g;
const LOOKALIKE = Object.fromEntries([..."АВСЕНІКМОРТХаеорсхіктмΑΒΕΗΙΚΜΝΟΡΤΧΥΖ"].map((c, i) => [c, "ABCEHIKMOPTXAEOPCXIKTMABEHIKMNOPTXYZ"[i]]));
const SPACE = "[\\s\\x1c-\\x1f\\x85]";   // Python's str.isspace: the reference model strips and splits on these
const MAX_READINGS = 4096;
const asDigits = (g) => g.replace(/[OIL]/g, (c) => (c === "O" ? "0" : "1"));

function groupVariants(g, letters = true) {
  const out = new Set([g, asDigits(g)]);
  if (letters && g.length <= 8 && /^[A-Z01]*$/.test(g)) {
    let all = [""];
    for (const c of g) {
      const opts = c === "1" ? ["I", "L"] : c === "0" ? ["O"] : [c];
      all = all.flatMap((x) => opts.map((o) => x + o));
    }
    for (const x of all) out.add(x);
  }
  if (letters && /^[1IL]{2}C$/.test(g)) out.add("LIC");
  return [...out];
}

/** Where a person types, pastes or scans a code (never inside a message, §7.4): the one code meant, in its TOG
 * spelling, for a "Did you mean …?" prompt. Folds width, dashes, invisibles, look-alikes, a resolver URL, trailing
 * punctuation, case and display spaces, then O/0 and I/L/1 by slot, then the PG spelling (codeKey). Throws CodeError:
 * "malformed" for none or (with `hints`) more than one valid reading, or over 4096 readings; "mistyped"; or
 * "ask_registry" for an old licence id whose record is not in `licences`, with the folded old id as `folded`. */
export function normalizeTyped(typed, licences = {}) {
  if (typeof typed !== "string") codeFail("malformed", "a code is a string");
  let s = typed.normalize("NFKC").replace(DASHES, "-").replace(DROP, "").replace(/./gsu, (c) => LOOKALIKE[c] ?? c)
    .replace(new RegExp(`^${SPACE}+|${SPACE}+$`, "gu"), "");
  if (s.includes("/")) s = s.split("#")[0].replace(/\/+$/, "").split("/").at(-1);
  s = s.replace(/[.,;:)\]"']+$/, "").toUpperCase();
  const words = s.split(new RegExp(`${SPACE}+`, "u")).filter(Boolean);
  let groups;
  if (s.includes("-")) groups = s.split("-").map((x) => x.replace(new RegExp(`${SPACE}+`, "gu"), ""));
  else if (words.length && ["PG", "TOG"].includes(words[0])) {   // the display form "PG 000 042 *" (§18)
    groups = words.length > 2 && !/^\p{L}+$/u.test(words[1]) ? [words[0], words.slice(1).join("")] : words;
  } else groups = [s];
  const tailFrom = groupVariants(groups[0]).includes("TOG") && groups.length >= 6 ? groups.length - 3 : groups.length;
  const readings = groups.map((g, i) => groupVariants(g, i < tailFrom));
  if (readings.reduce((n, r) => n * r.length, 1) > MAX_READINGS) codeFail("malformed", "too many readings: type the code again");
  const found = new Set();
  let combos = [""];
  readings.forEach((r, i) => { combos = combos.flatMap((x) => r.map((v) => (i ? `${x}-${v}` : v))); });
  for (const c of combos) {
    if (!isCode(c)) continue;
    try { found.add(codeKey(c, licences)); } catch (e) {
      if (!(e instanceof CodeError) || e.reason !== "ask_registry") throw e;
      found.add(c);   // an old licence id: only its registry knows its code
    }
  }
  if (found.size > 1) { const hints = [...found].sort(); codeFail("malformed", `ambiguous: ${hints.join(", ")}`, hints); }
  if (!found.size) {
    parseCode(groups.join("-"));   // the honest error for the string as typed
    codeFail("malformed", `not a code: ${JSON.stringify(typed)}`);
  }
  const [c] = found;
  if (c.startsWith("PG-")) {   // `folded`: the old id as folded here, for asking its registry (never for showing)
    const e = new CodeError("ask_registry", `${c}: only its registry gives its TOG code`);
    e.folded = c;
    throw e;
  }
  return c;
}

function httpsUrl(value, field) {
  let url;
  try { url = new URL(value); } catch { fail(`registry ${field} must be a URL`); }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    fail(`registry ${field} must use HTTPS without credentials, query or fragment`);
  }
}

function checkInvariants(d) {
  if (!d || typeof d !== "object" || Array.isArray(d)) fail("directory must be an object");
  if (d.schema !== SCHEMA && d.schema !== SCHEMA_V3) fail(`schema must be ${SCHEMA} or ${SCHEMA_V3}`);
  const v3 = d.schema === SCHEMA_V3;
  if (!Number.isSafeInteger(d.sequence) || d.sequence < 1) fail("sequence must be a positive integer");
  if (!FINGERPRINT.test(String(d.steward_key_id))) fail("steward_key_id must be a pg-ed25519 fingerprint");
  if (!Array.isArray(d.registries) || d.registries.length === 0) fail("registries must be a non-empty list");
  const seen = new Set();
  for (const r of d.registries) {
    if (!r || typeof r !== "object") fail("registry entry must be an object");
    if (typeof r.name !== "string" || !r.name.trim()) fail("registry name must be nonempty");
    httpsUrl(r.api, "api");
    httpsUrl(r.keys, "keys");
    if (r.prefix !== "" && !(typeof r.prefix === "string" && (v3 ? PREFIX_TOG : PREFIX).test(r.prefix))) fail(`bad prefix ${r.prefix}`);
    if (seen.has(r.prefix)) fail(r.prefix === "" ? "the bare namespace is listed twice" : `prefix ${r.prefix} is listed twice`);
    seen.add(r.prefix);
    if (!Array.isArray(r.key_fingerprints) || !r.key_fingerprints.length
        || !r.key_fingerprints.every((f) => FINGERPRINT.test(String(f)))) {
      fail(`registry ${r.name}: key_fingerprints must list pg-ed25519 fingerprints`);
    }
  }
  // Revocation (PG-CODE.md §9.1): a revoked registry keeps its entry; a revoked key keeps its listing.
  for (const r of d.registries) {
    if (r.revoked !== undefined && !(r.revoked && typeof r.revoked === "object" && typeof r.revoked.at === "string")) {
      fail(`registry ${r.name}: revoked must be an object with "at"`);
    }
  }
  if (v3) checkV3(d);
  if (d.revoked_keys !== undefined && !(Array.isArray(d.revoked_keys)
      && d.revoked_keys.every((k) => k && FINGERPRINT.test(String(k.key_id)) && typeof k.at === "string"))) {
    fail("revoked_keys must list {key_id, at}");
  }
  // identity.md: steward findings on one person, every member required, times in RFC 3339.
  for (const [field, members] of [["false_claims", ["anchor", "code", "at", "reason"]],
    ["false_claim_reversals", ["anchor", "code", "at", "reason"]], ["freezes", ["anchor", "at", "until", "reason"]]]) {
    const v = d[field];
    if (v !== undefined && !(Array.isArray(v) && v.every((f) => f && typeof f === "object"
        && members.every((m) => typeof f[m] === "string" && f[m])))) fail(`${field} must list {${members.join(", ")}}`);
    for (const f of v || []) {
      for (const m of ["at", "until"].filter((x) => members.includes(x))) {
        if (!RFC3339.test(f[m])) fail(`${field}: not an RFC 3339 time`);
        when(f[m]);
      }
    }
  }
  for (const f of d.freezes || []) {
    const span = when(f.until) - when(f.at);
    if (!(span > 0 && span <= SETTLED_AFTER)) fail("a freeze lasts more than nothing and at most 7 days");
  }
}

// Directory v3 members (TOG-CODE.md §9.2), every time in RFC 3339 like v2's revoked.at.
function checkV3(d) {
  const time = (v, nullable) => (nullable && v === null) || (typeof v === "string" && Number.isFinite(when(v)));
  const span = (x) => isObject(x) && time(x.from) && time(x.until, true) && Object.keys(x).every((k) => ["from", "until"].includes(k));
  for (const r of d.registries) {
    const bad = (m) => fail(`registry ${r.name}: ${m}`);
    for (const m of ["entity", "group"]) if (r[m] !== undefined && !(typeof r[m] === "string" && r[m])) bad(`${m} must be a nonempty string`);
    if (r.government !== undefined && typeof r.government !== "boolean") bad("government must be true or false");
    if (r.roles !== undefined && !(isObject(r.roles) && Object.entries(r.roles).every(([k, v]) => ROLES.includes(k) && span(v)))) {
      bad(`roles maps ${ROLES.join(", ")} to {from, until}`);
    }
    if (r.provider_domains !== undefined && !(Array.isArray(r.provider_domains) && r.provider_domains.every((x) => span({ from: x?.from, until: x?.until })
        && typeof x.domain === "string" && x.domain && Object.keys(x).every((k) => ["domain", "from", "until"].includes(k))))) {
      bad("provider_domains lists {domain, from, until}");
    }
    for (const m of ["void_from", "closed"]) if (r[m] !== undefined && !time(r[m])) bad(`${m} must be an RFC 3339 time`);
  }
  if (d.resolver !== undefined) httpsUrl(d.resolver, "resolver");
  if (d.min_library !== undefined && !(typeof d.min_library === "string" && /^[0-9]+\.[0-9]+\.[0-9]+$/.test(d.min_library))) {
    fail("min_library must be a version");
  }
}

const RFC3339 = /^(?!0000)[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{3})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$/;
// Unix seconds of a real instant, read as Python's datetime reads it: Date.parse rolls February 30 into March and
// 24:00 into the next day, so the written date and time must come back unchanged.
function when(s) {
  const ms = RFC3339.test(s) ? Date.parse(s) : NaN;
  const off = s.endsWith("Z") ? 0 : (s.at(-6) === "-" ? -1 : 1) * (Number(s.slice(-5, -3)) * 60 + Number(s.slice(-2)));
  if (Number.isNaN(ms) || new Date(ms + off * 60_000).toISOString().slice(0, 19) !== s.slice(0, 19)) {
    fail(`not an RFC 3339 time: ${s}`);
  }
  return ms / 1000;
}
/** identity.md: a new channel permits after 7 days; a steward freeze lasts at most 7 days. */
export const SETTLED_AFTER = 7 * 86_400;

/** A directory accepted under V-12. Build one with verifyDirectory() or loadDirectory(). */
export class Directory {
  #d;
  #pins;
  constructor(token, directory, pins, loadedAt) {
    if (token !== Directory.#token) fail("use verifyDirectory() or loadDirectory()");
    this.#d = structuredClone(directory);
    this.#pins = pins; // the caller's own pins, prefix -> fingerprints; no registry is pinned by default
    this.loadedAt = loadedAt; // Unix seconds when it was accepted; checkAnswer wants it under a day old
  }
  static #token = Symbol();
  static _make(directory, pins, loadedAt) { return new Directory(Directory.#token, directory, pins, loadedAt); }

  /** Store this and pass it as minSequence next time, so an older copy is refused. */
  get sequence() { return this.#d.sequence; }
  get registries() { return structuredClone(this.#d.registries); }
  /** The signed directory itself: persist it and pass it back as `previous`. */
  toJSON() { return structuredClone(this.#d); }

  /** The registry that owns a code's namespace (resolve codes only there, V-11), or null. */
  registryFor(code) {
    let issuer;
    try { issuer = issuerOf(code); } catch { return null; }
    const r = this.#d.registries.find((x) => x.prefix === issuer);
    return r ? structuredClone(r) : null;
  }

  /** Offline party check of `code` (TOG-CODE.md §9.2) against this v3 directory, read at `at` (Unix seconds: the
   * act's witnessed time, or null). Returns {ok, facts}; for support tools, never beside a video. */
  parties(code, { at = null, provider = null } = {}) {
    if (this.#d.schema !== SCHEMA_V3) fail("party checks need directory v3");
    const t = (v) => (v == null ? null : when(v));
    const entries = Object.fromEntries(this.#d.registries.map((r) => [r.prefix, { entity: r.entity ?? r.name, group: r.group,
      government: r.government ?? false, provider_domains: (r.provider_domains || []).map((x) => x.domain),
      roles: Object.fromEntries(Object.entries(r.roles || {}).map(([k, v]) => [k, { from: t(v.from), until: t(v.until) }])),
      ...(r.void_from !== undefined && { void_from: t(r.void_from) }), ...(r.closed !== undefined && { closed: t(r.closed) }) }]));
    return checkParties(code, entries, { at, provider });
  }

  /** The steward found `code` a false claim under `anchor` and has not reversed it (identity.md): drop that claim. For
   * one anchor and code the latest entry of false_claims and false_claim_reversals by `at` decides; a tie stays false.
   * Without `anchor`, under any anchor: a code asked as a private person is then never generated. */
  isFalseClaim(code, anchor = null) {
    const latest = new Map();
    for (const [isFalse, field] of [[true, "false_claims"], [false, "false_claim_reversals"]]) {
      for (const f of this.#d[field] || []) {
        if (keyOf(f.code) !== keyOf(code) || (anchor !== null && anchor !== undefined && f.anchor !== anchor)) continue;
        const at = when(f.at), was = latest.get(f.anchor);
        if (!was || at > was[0] || (at === was[0] && isFalse)) latest.set(f.anchor, [at, isFalse]);
      }
    }
    return [...latest.values()].some(([, isFalse]) => isFalse);
  }

  /** The steward's freeze of `anchor` in effect at `now` (at <= now < until), or null (identity.md rule 0).
   * Pass it to decideIdentity(claims, { frozen }). */
  frozen(anchor, now = Math.floor(Date.now() / 1000)) {
    const f = (this.#d.freezes || []).find((x) => x.anchor === anchor
      && when(x.at) <= now && now < when(x.until));
    return f ? structuredClone(f) : null;
  }

  /** V-10, V-14: "valid", "unknown_issuer", "issuer_mismatch" or "revoked". */
  checkSigner(code, signerKeyId) {
    const r = this.registryFor(code);
    if (!r) return "unknown_issuer";
    if (r.revoked || (this.#d.revoked_keys || []).some((k) => k.key_id === signerKeyId)) return "revoked";
    if (!r.key_fingerprints.includes(signerKeyId)) return "issuer_mismatch";
    const pin = this.#pins[r.prefix];
    if (pin && !pin.includes(signerKeyId)) return "issuer_mismatch";
    return "valid";
  }

  /** The public key behind `keyId`, which must belong to the owner of `code`'s namespace.
   * The key comes from the owner's key set and must hash to the listed fingerprint. */
  /** Given `at` (the message's signed time), a key its key set retired (`deactivated_at`) before then is refused. */
  async publicKey(code, keyId, { fetch: fetchFn = globalThis.fetch, at } = {}) {
    const verdict = this.checkSigner(code, keyId);
    if (verdict !== "valid") fail(`${keyId} may not sign ${code}: ${verdict}`);
    const res = await fetchFn(this.registryFor(code).keys, { redirect: "error" });
    if (!res.ok) fail(`key set: HTTP ${res.status}`);
    const entry = ((await res.json()).keys || []).find((k) => k && k.key_id === keyId);
    if (!entry || (await fingerprint(entry.public_key_hex)) !== keyId) fail(`no key ${keyId} in the key set`);
    if (Number.isInteger(at) && Number.isInteger(entry.deactivated_at) && at >= entry.deactivated_at) {
      fail(`${keyId} was retired before this was signed`);
    }
    return entry.public_key_hex;
  }
}

/** A newer directory may add registries and keys, never remove or move them (PG-CODE.md §9.1). */
function checkContinuity(next, previous) {
  if (crossSchema(next, previous)) return;
  if (next.sequence < previous.sequence) fail(`sequence ${next.sequence} is older than ${previous.sequence} already seen`);
  if (next.sequence === previous.sequence) {
    if (canonicalJson(next) !== canonicalJson(previous)) fail("a different directory with the same sequence");
    return;
  }
  keepsHistory(next, previous);
}

/** v2 and v3 are two lines, each with its own sequence: none is compared across them, and a v2 directory after a v3 one
 * is refused (it would hide registries listed only in v3). */
function crossSchema(next, previous) {
  if (next.schema === previous.schema) return false;
  if (previous.schema === SCHEMA_V3) fail("a v3 directory was already accepted: load registries.v3.json");
  return true;
}

/** Revocations a successor's first directory may drop (PG-CODE.md §9.1). */
function annulments(d) {
  if (d.annulled === undefined) return [];
  const since = Date.parse(d.steward_compromised_since);
  if (!Array.isArray(d.annulled) || Number.isNaN(since)) fail("annulled needs a list and steward_compromised_since");
  return d.annulled.map((a) => ({ ...a, since }));
}
const annulledAt = (list, field, value, at) =>
  list.some((a) => a[field] === value && Date.parse(at) >= a.since);

function keepsHistory(next, previous, annulled = []) {
  for (const a of previous.annulled || []) {
    if (!(next.annulled || []).some((x) => same(x, a))) fail("an annulment was removed");
  }
  for (const old of previous.registries) {
    const now = next.registries.find((r) => r.prefix === old.prefix);
    if (!now) fail(`namespace ${old.prefix || "(bare)"} was removed`);
    for (const f of old.key_fingerprints) if (!now.key_fingerprints.includes(f)) fail(`key ${f} was removed from ${now.name}`);
    if (old.revoked && !(now.revoked && same(now.revoked, old.revoked))
        && !annulledAt(annulled, "prefix", old.prefix, old.revoked.at)) fail(`the revocation of ${old.name} was undone`);
  }
  for (const f of previous.false_claims || []) {
    if (!(next.false_claims || []).some((x) => same(x, f))) fail(`the false claim ${f.code} was removed`);
  }
  for (const f of previous.false_claim_reversals || []) {
    if (!(next.false_claim_reversals || []).some((x) => same(x, f))) fail(`the reversal of the false claim ${f.code} was removed`);
  }
  for (const f of previous.freezes || []) {
    if (!(next.freezes || []).some((x) => same(x, f))) fail(`the freeze of ${f.anchor} was removed`);
  }
  for (const k of previous.revoked_keys || []) {
    if (!(next.revoked_keys || []).some((x) => same(x, k))
        && !annulledAt(annulled, "key_id", k.key_id, k.at)) fail(`the revocation of key ${k.key_id} was undone`);
  }
}

/** V-12: accept the directory only with the pinned steward's signature, its invariants,
 * a sequence no lower than one already seen and, given the last accepted directory,
 * nothing removed from it. No registry is pinned unless you pass pinnedKeys. */
export async function verifyDirectory(directory, { stewardPublicKeyHex = STEWARD_PUBLIC_KEY_HEX, successorPublicKeyHex,
  minSequence = 0, previous, pinnedKeys, originKeyFingerprints, now = Math.floor(Date.now() / 1000) } = {}) {
  if (!Number.isSafeInteger(minSequence) || minSequence < 0) fail("minSequence must be a nonnegative integer");
  checkInvariants(directory);
  const successor = successorPublicKeyHex !== undefined ? successorPublicKeyHex
    : stewardPublicKeyHex === STEWARD_PUBLIC_KEY_HEX ? STEWARD_SUCCESSOR_PUBLIC_KEY_HEX : null;
  const currentId = await fingerprint(stewardPublicKeyHex);
  const successorId = successor ? await fingerprint(successor) : null;
  const bySuccessor = successorId !== null && directory.steward_key_id === successorId;
  if (directory.steward_key_id !== currentId && !bySuccessor) fail("signed by a different steward key");
  if (!(await verifySigned(directory, bySuccessor ? successor : stewardPublicKeyHex, "signature"))) fail("bad steward signature");
  const prev = previous instanceof Directory ? previous.toJSON() : previous;
  if (prev && successorId !== null && prev.steward_key_id === successorId && !bySuccessor) {
    fail("the steward key was handed over; directories signed by the old key are refused");
  }
  // Handover: the successor's first directory replaces the old key's line, whatever its sequence
  // (a thief holding the old key may have raised it). Within one key's line the usual rules hold.
  const handover = bySuccessor && (!prev || prev.steward_key_id !== successorId);
  if (!handover) {
    if (directory.sequence < minSequence) fail(`sequence ${directory.sequence} is older than ${minSequence} already seen`);
    if (prev) checkContinuity(directory, prev);
  } else if (prev && !crossSchema(directory, prev)) {
    // A handover may restart the sequence, never drop a listing or a revocation, except
    // revocations the old key signed after it was compromised, named in `annulled`.
    keepsHistory(directory, prev, annulments(directory));
  }
  const pins = Object.fromEntries(Object.entries(pinnedKeys || {}).map(([k, v]) => [k, [...v]]));
  if (originKeyFingerprints && !("" in pins)) pins[""] = [...originKeyFingerprints]; // deprecated alias: a pin for the bare namespace
  return Directory._make(directory, pins, now);
}

/** Download and verify the directory from pregen.org. Pass the last accepted one as `previous`. */
export async function loadDirectory({ url = DIRECTORY_URL, minSequence = 0, previous, fetch: fetchFn = globalThis.fetch,
  stewardPublicKeyHex = STEWARD_PUBLIC_KEY_HEX } = {}) {
  // stewardPublicKeyHex is for testing only: a test directory signed by a test steward key (extensions/sandbox.md).
  const res = await fetchFn(url, { redirect: "error" });
  if (!res.ok) fail(`directory: HTTP ${res.status}`);
  return verifyDirectory(await res.json(), { minSequence, previous, stewardPublicKeyHex });
}

/** Is this registry decision genuine, and signed by a key of the registry that owns `code`?
 * Signatures only: use checkDecision() before generating. */
export async function verifyDecision(decision, code, { directory, fetch: fetchFn = globalThis.fetch } = {}) {
  const dir = directory || (await loadDirectory({ fetch: fetchFn }));
  const key = await dir.publicKey(code, decision && decision.operator_key_id, { fetch: fetchFn });
  return verifySigned(decision, key, "operator_signature");
}

// Members this library knows how to handle: the core (PRE-GEN-SPEC.md §1.1) and the origin
// registry's (PRE-GEN-EXTENSIONS.md X.2). A `critical` member outside this set makes an allow unusable.
const UNDERSTOOD = new Set(["schema_version", "decision_id", "nonce", "disposition", "allowed", "reason",
  "policy_version", "subject_id", "licensee_id", "provider_id", "license_id", "prompt_hash", "model", "modality",
  "intended_use", "obligations", "generation_id", "issued_at", "expires_at", "critical", "operator_key_id",
  "operator_signature", "subject_authority", "rules_text", "rules_text_hash", "watermark_payload", "is_hard_refusal",
  "revocation_epoch", "max_cache_age_seconds", "cache_scope", "provider_user_binding", "provider_identity_link_id",
  "detection_id", "remediation"]);
const MAX_DECISION_LIFETIME = 900;
/** PRE-GEN-CORE.md rule 2: reload the directory at least daily. This bounds how long a copy is kept, not how
 * old its content is: a stale copy can still hide a newer revocation. */
export const DIRECTORY_MAX_AGE = 86_400;
/** A proof's occurred_at is the provider's word; the registry-signed received_at bounds it (stress test H1). */
export const REPORT_GRACE = 86_400;
const ECHOED = ["subject_id", "provider_id", "licensee_id", "prompt_hash", "model", "modality"];
const isEmpty = (v) => v === undefined || v === null || v === "" || (Array.isArray(v) && v.length === 0);
const same = (a, b) => canonicalJson(a) === canonicalJson(b);

/** Everything a provider must check before generating on a decision (PRE-GEN-SPEC.md §5.4):
 * a genuine signature by the owner of the license's namespace (V-1, V-2, V-10), the decision
 * answers exactly this request (V-4), it is within its validity window (V-3), it carries a
 * verified user binding when a user was named (V-13), it is a license-backed allow (P-5), its
 * registry and key are not revoked (V-14) and it lists no `critical` member this library does not
 * understand (E-3). `requireVerifiedAuthority` also refuses a subject whose authority is not "verified".
 * `request` is what you sent: the /v1/verify body plus provider_id and licensee_id.
 * Throws PregenError with the reason; returns the decision when you may generate. */
export async function checkDecision(decision, request, { directory, fetch: fetchFn = globalThis.fetch,
  now = Math.floor(Date.now() / 1000), requireVerifiedAuthority = false } = {}) {
  if (!decision || typeof decision !== "object") fail("decision must be an object");
  if (!request || typeof request !== "object") fail("request must be an object");
  if (decision.allowed !== true || decision.disposition !== "allow") fail(`not an allow: ${decision.disposition}`);
  if (typeof decision.license_id !== "string" || !decision.license_id) fail("an allow must name its license");
  if (decision.critical !== undefined) {
    if (!Array.isArray(decision.critical)) fail("critical must be a list");
    const unknown = decision.critical.filter((m) => !UNDERSTOOD.has(m));
    if (unknown.length) fail(`critical members this library does not understand: ${unknown.join(", ")}`); // E-3
  }
  if (requireVerifiedAuthority && decision.subject_authority !== "verified") {
    fail(`the subject's authority is ${decision.subject_authority ?? "not stated"}, not verified`);
  }

  if (decision.schema_version !== "pg.decision.v1") fail(`unsupported schema_version: ${decision.schema_version}`);
  const exp = decision.expires_at, iat = decision.issued_at;
  if (!Number.isSafeInteger(exp) || exp <= 0) fail("expires_at must be a positive integer");
  if (!Number.isSafeInteger(iat) || iat <= 0 || iat >= exp || iat > now + 60) {
    fail("issued_at must be a positive integer before expires_at and not in the future");
  }
  if (exp - iat > MAX_DECISION_LIFETIME) fail(`a decision lives at most ${MAX_DECISION_LIFETIME} seconds`); // PRE-GEN §1.1
  if (exp <= now) fail("decision expired");

  for (const f of ECHOED) {
    if ((decision[f] ?? "") !== (request[f] ?? "")) fail(`${f} does not match the request`);
  }
  const got = decision.intended_use ?? {}, sent = request.intended_use ?? {};
  if (typeof got !== "object" || typeof sent !== "object") fail("intended_use must be an object");
  for (const k of new Set([...Object.keys(got), ...Object.keys(sent)])) {
    const ok = isEmpty(sent[k]) ? isEmpty(got[k]) : same(got[k] ?? null, sent[k]); // empty and absent are the same
    if (!ok) fail(`intended_use.${k} does not match the request`);
  }
  for (const f of ["generation_id", "provider_identity_link_id"]) {
    if (!isEmpty(request[f]) && decision[f] !== request[f]) fail(`${f} does not match the request`);
  }
  if (!isEmpty(request.provider_user_id) || !isEmpty(request.provider_identity_link_id)) {
    if (decision.provider_user_binding !== "verified" || isEmpty(decision.provider_identity_link_id)) {
      fail("no verified binding to the user you named");
    }
  }

  if (!(await verifyDecision(decision, decision.license_id, { directory, fetch: fetchFn }))) fail("bad signature");
  return decision;
}

/** A PRE-GEN v5 message id (PRE-GEN-CORE.md, Messages). Signatures are not part of it. */
export async function messageId(type, body) {
  return sha256Hex("PREGEN-V5-ID\0" + type + "\0" + canonicalJson(body));
}

/** The bytes a v5 signature covers: "PREGEN-V5" 0x00 type 0x00 canonical(body) (PRE-GEN-CORE.md, Messages). */
export function signingInput(type, body) {
  return utf8.encode(`PREGEN-V5\0${type}\0` + canonicalJson(body));
}

const PKCS8_ED25519 = "302e020100300506032b657004220420";   // the DER prefix of a raw 32-byte Ed25519 seed
const privateKey = (hex) => crypto.subtle.importKey("pkcs8", hexBytes(PKCS8_ED25519 + hex, 48), { name: "Ed25519" }, true,
  ["sign"]);

/** A new Ed25519 private key: 32 random bytes (the RFC 8032 seed), as hex. Keep it secret, server-side. */
export function newPrivateKeyHex() {
  return toHex(crypto.getRandomValues(new Uint8Array(32)));
}

/** The raw 32-byte public key of an Ed25519 private key (seed), as hex. Its key id is fingerprint() of it. */
export async function publicKeyHex(privateKeyHex) {
  const jwk = await crypto.subtle.exportKey("jwk", await privateKey(privateKeyHex));
  return toHex(Uint8Array.from(atob(jwk.x.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)));
}

/** A v5 envelope {type, body, signatures}: one signature per private key, in the order of body.signers. With no key,
 * `signatures` is empty (a request a registry authenticates by its credential). */
export async function signEnvelope(type, body, ...privateKeyHexes) {
  const data = signingInput(type, body);
  const signatures = [];
  for (const k of privateKeyHexes) signatures.push(toHex(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, await privateKey(k), data))));
  return { type, body, signatures };
}

// ── extension provider-identity: a provider known by its domain, with no account anywhere ──────────────

const HOST = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;

/** A provider URL (extensions/provider-identity.md): `https://` + the app's own domain, lower case, ASCII (an IDN in
 * its xn-- form), with no path, query, fragment, credentials, port or trailing dot. One app, one id. A sandbox
 * (allowPort) also takes a port and `localhost`, to test from a laptop. Returns it; throws PregenError otherwise. */
export function checkProviderUrl(url, { allowPort = false } = {}) {
  let u;
  try { u = new URL(url); } catch { fail("a provider URL is https://<your domain>"); }
  const host = u.hostname;
  // A sandbox (allowPort) also takes a port, and on your own machine only <32 hex of the key id>.localhost.
  if (u.protocol !== "https:" || u.origin !== url || u.username || (u.port && !allowPort) || host === "localhost"
      || u.port === "0" || !(HOST.test(host) || (allowPort && /^[0-9a-f]{32}\.localhost$/.test(host)))) {
    fail(`not a provider URL: ${JSON.stringify(url)} (https://<domain>, lower case, no path, port, query or fragment)`);
  }
  return url;
}

/** A test id for a sandbox, on your own machine (provider-identity, Sandboxes): bound to your key, so two people's
 * tests never collide. `https://<32 hex of the key id>.localhost[:port]`. */
export async function sandboxProviderUrl(privateKeyHex, port) {
  if (port !== undefined && port !== null && !(Number.isInteger(port) && port > 0 && port < 65536)) {
    fail("port is an integer from 1 to 65535");
  }
  const host = (await fingerprint(await publicKeyHex(privateKeyHex))).split(":")[1] + ".localhost";
  return checkProviderUrl(`https://${host}` + (port == null || port === 443 ? "" : `:${port}`), { allowPort: true });
}

/** The document a provider serves at `{providerUrl}/.well-known/pregen-party.json` (provider-identity): who it is and
 * its signing key, as a `first` keyset signed by that key. The same key gives the same document every time, so build
 * it at deploy time or on each start. To change the key later, append a `rotation` keyset (provider-keys). */
export async function partyDocument(providerUrl, name, privateKeyHex,
  { redirectUris = [], bindInitiateUri = "", policy = "", contact = "" } = {}) {
  checkProviderUrl(providerUrl, { allowPort: true });
  const pub = await publicKeyHex(privateKeyHex);
  const kid = await fingerprint(pub);
  const keyset = await signEnvelope("pg.keyset.v1", { signers: [{ role: "provider", key_id: kid }], kind: "first",
    provider_id: providerUrl, previous: null, recovery_registry: "",
    keys: [{ key_id: kid, public_key_hex: pub, status: "current" }] }, privateKeyHex);
  const doc = { party_id: providerUrl, name, roles: ["provider"], keysets: [keyset] };
  if (redirectUris.length) doc.redirect_uris = [...redirectUris];
  if (bindInitiateUri) doc.bind_initiate_uri = bindInitiateUri;
  if (policy) doc.policy = policy;
  if (contact) doc.contact = contact;
  return doc;
}

/** The `PG-Access` header value for a GET by a provider known by its domain (provider-identity): a `pg.access.v1`
 * envelope over {provider_id, aud (the registry's api, from the directory), method, path (with its query string),
 * issued_at}, signed with the current key, as base64url. A registry accepts it within 60 seconds of `issued_at`, for
 * itself only: a header signed for another registry is refused. */
export async function pgAccess(providerUrl, privateKeyHex, aud, method, path, { now } = {}) {
  const kid = await fingerprint(await publicKeyHex(privateKeyHex));
  const env = await signEnvelope("pg.access.v1", { signers: [{ role: "provider", key_id: kid }], provider_id: providerUrl,
    aud: aud.replace(/\/+$/, ""), method: method.toUpperCase(), path, issued_at: Math.floor(now ?? Date.now() / 1000) }, privateKeyHex);
  const bytes = utf8.encode(canonicalJson(env));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** PRE-GEN-CORE.md rule 5: may I generate on this answer? `request` is the pg.request.v1 envelope you
 * sent. Checks that a key the directory lists for the subject's prefix signed it (and is not revoked),
 * that it answers exactly this request under the same profile, that it is within its lifetime, that it
 * is not a sandbox answer outside testing, and that it is an `allow`. Throws PregenError with the
 * reason; returns the answer body when you may generate. Keep the answer with the output. */
/** A message signed by exactly one registry key the directory lists for `code`'s prefix (core rules 1-2). Returns its body. */
export async function registrySigned(env, type, code, directory, fetchFn) {
  if (!env || env.type !== type || !same(Object.keys(env).sort(), ["body", "signatures", "type"])
      || !env.body || typeof env.body !== "object") fail(`not a ${type} envelope`);
  const body = env.body, signers = body.signers, sigs = env.signatures;
  if (!Array.isArray(signers) || signers.length !== 1 || signers[0]?.role !== "registry"
      || !Array.isArray(sigs) || sigs.length !== 1) fail(`a ${type} is signed by exactly one registry key`);
  const key = await directory.publicKey(code, signers[0].key_id, { fetch: fetchFn, at: body.issued_at ?? body.received_at });
  if (!(await verifyBytes(key, sigs[0], signingInput(type, body)))) fail("bad signature");
  return body;
}

/** PRE-GEN-CORE.md rule 4: an allow names its basis — a policy rule or a grant — and no reason; every
 * other status gives a reason and no basis (schemas/answer.json). */
function checkStatusShape(body) {
  const { status, basis } = body;
  if (!["allow", "deny", "review", "not_blocked"].includes(status)) fail(`unknown status: ${status}`);
  const keys = (o) => (o && typeof o === "object" && !Array.isArray(o) ? Object.keys(o).sort() : null);
  if (status === "allow") {
    const policy = same(keys(basis), ["kind", "rule"]) && basis.kind === "policy" && typeof basis.rule === "string" && basis.rule !== "";
    const g = basis?.grant, gk = keys(g);
    const grant = same(keys(basis), ["grant", "kind"]) && basis.kind === "grant" && gk !== null
      && gk.includes("format") && gk.includes("id") && gk.every((k) => ["format", "id", "license_id"].includes(k))
      && typeof g.format === "string" && typeof g.id === "string" && /^[0-9a-f]{64}$/.test(g.id);
    if (!policy && !grant) fail("an allow must name its basis: a policy rule or a grant");
    if ("reason" in body) fail("an allow carries no reason");
  } else {
    if (typeof body.reason !== "string" || body.reason === "") fail(`a ${status} answer must give a reason`);
    if ("basis" in body) fail(`a ${status} answer carries no basis`);
  }
}

/** Is this a genuine, current answer to this request, whatever its status? Everything checkAnswer checks
 * except that it is an allow: use it to weigh refusals from several registries (decideIdentity). Like
 * checkAnswer, it compares `profile` only as a name, and nothing about a version of a registry's rules. */
// The members an answer body may carry (spec/schemas/answer.json; PRE-GEN-CORE.md: unknown members are rejected).
// A registry's own members go in `ext`.
const ANSWER_MEMBERS = new Set(["signers", "request_id", "profile", "status", "reason", "basis", "issued_at", "expires_at",
  "level", "obligations", "ext", "critical"]);

export async function verifyAnswer(answer, request, { directory, fetch: fetchFn = globalThis.fetch,
  now = Math.floor(Date.now() / 1000), testing = false } = {}) {
  if (!request || request.type !== "pg.request.v1" || !request.body || typeof request.body !== "object") {
    fail("request must be the pg.request.v1 envelope you sent");
  }
  const asked = request.body;
  directory ??= await loadDirectory({ fetch: fetchFn });
  if (now - directory.loadedAt > DIRECTORY_MAX_AGE) fail("the directory was loaded more than 24 hours ago: load it again");
  if (testing && [await fingerprint(STEWARD_PUBLIC_KEY_HEX), await fingerprint(STEWARD_SUCCESSOR_PUBLIC_KEY_HEX)]
    .includes(directory.toJSON().steward_key_id)) {
    fail("testing is for a test directory only: the PRE-GEN steward's directory never accepts a sandbox answer");
  }
  const body = await registrySigned(answer, "pg.answer.v1", asked.subject_ref, directory, fetchFn);
  const unknown = Object.keys(body).filter((k) => !ANSWER_MEMBERS.has(k)).sort();
  if (unknown.length) fail(`the answer carries members the core does not define: ${unknown.join(", ")}`);
  checkStatusShape(body);
  if (body.request_id !== (await messageId("pg.request.v1", asked))) fail("the answer is for another request");
  if (body.profile !== asked.profile) fail("the answer is under another profile");
  const iat = body.issued_at, exp = body.expires_at;
  if (!Number.isSafeInteger(iat) || !Number.isSafeInteger(exp) || exp - iat < 1 || exp - iat > MAX_DECISION_LIFETIME) {
    fail(`an answer lives 1 to ${MAX_DECISION_LIFETIME} seconds`);
  }
  if (iat > now + 60) fail("issued in the future");
  if (exp <= now) fail("answer expired");
  if (body.ext?.sandbox && !testing) fail("a sandbox answer is accepted only when testing");
  if (body.critical?.length) fail(`critical extensions this library does not understand: ${body.critical}`);
  return body;
}

/** PRE-GEN-CORE.md rule 5: may I generate on this answer? `request` is the pg.request.v1 envelope you
 * sent. Checks that a key the directory lists for the subject's prefix signed it (and is not revoked),
 * that it answers exactly this request under the same profile, that it is within its lifetime, that it
 * is not a sandbox answer outside testing, that the steward recorded no unreversed false claim on the code under any
 * anchor, and that it is an `allow`. `profile` is compared as a name: the
 * fixed name of a vocabulary of uses (`likeness/1`), never a version of anyone's policy; nothing that names
 * a version, hash or counter of a registry's rules is carried or compared. Throws PregenError with the reason; returns the answer body when you
 * may generate. Keep the answer with the output. */
export async function checkAnswer(answer, request, options = {}) {
  const directory = options.directory ?? await loadDirectory({ fetch: options.fetch ?? globalThis.fetch });
  const code = request?.body?.subject_ref;
  if (typeof code === "string" && directory.isFalseClaim(code)) {           // identity.md: the steward ruled it false
    fail(`${code} is a false claim the steward recorded: never generated`);
  }
  const body = await verifyAnswer(answer, request, { ...options, directory });
  if (body.status !== "allow") fail(`not an allow: ${body.status} ${body.reason ?? ""}`.trim());
  return body;
}

// ── extension identity (spec/extensions/identity.md) ──

/** likeness/1 refusals that come from the person, not from a missing licence: across one person's
 * registries, any of them refuses for all. */
export const FLOOR_REASONS = Object.freeze(["PG_SUBJECT_OPTED_OUT", "PG_SUBJECT_UNAVAILABLE", "PG_PROHIBITED_USE",
  "PG_IMMUTABLE_DENIAL", "PG_PERSONAL_SIGNATURE_REQUIRED"]);

/** A registry's signed anchor list (pg.anchors.v1), checked through the directory and at most a day old, so an
 * old copy cannot hide a new opt-out. Returns its entries, each code in its TOG spelling (a PG- line of an older list
 * folds by codeKey), without those the steward found false under their own anchor (a false claim under another anchor
 * silences no one). An entry naming another registry's code is dropped, not the whole list: one foreign line must not
 * make the list fail. An entry that is not a person code (unknown shape, mistyped, a licence or an event) fails the
 * whole list: dropping it could lose a refusal. A list naming one of its codes twice, in either spelling, is refused:
 * its anchor would depend on which line a client read last. */
export async function verifyAnchors(envelope, prefix, { directory, fetch: fetchFn = globalThis.fetch,
  now = Math.floor(Date.now() / 1000) } = {}) {
  // The code only names the prefix, so the directory finds the registry's keys (any prefix length).
  const body = await registrySigned(envelope, "pg.anchors.v1", `TOG-${prefix}-1000000000`, directory, fetchFn);
  if (body.registry !== prefix || !Array.isArray(body.anchors) || !Number.isSafeInteger(body.issued_at)) {
    fail("not an anchor list of this registry");
  }
  if (now - body.issued_at < -60 || now - body.issued_at > DIRECTORY_MAX_AGE) fail("the anchor list is more than 24 hours old");
  if (!body.anchors.every((e) => e && typeof e === "object" && !Array.isArray(e) && typeof e.code === "string")) {
    fail("an anchor list entry is {anchor, code, level, proof_url, status}");
  }
  let parsed;
  try { parsed = body.anchors.map((e) => parseCode(e.code)); } catch { parsed = null; }
  if (!parsed || parsed.some((p) => p.kind !== "subject")) {
    fail("an anchor list entry of unknown shape fails the whole list: not a person code");
  }
  const own = body.anchors.flatMap((e, i) => (parsed[i].issuer === prefix ? [{ ...e, code: parsed[i].key }] : []));
  if (new Set(own.map((e) => e.code)).size !== own.length) fail("an anchor list names each code once");
  return own.filter((e) => !directory.isFalseClaim(e.code, e.anchor));
}

/** One public person, held by several registries (spec/extensions/identity.md). `claims` lists, for every code
 * the anchor lists name, {code, confirmed, answer, settled, refusal_only}: `confirmed` is whether the person confirmed
 * this code on a current official channel; `settled` whether that channel was also official SETTLED_AFTER (7 days)
 * earlier: only a settled claim's allow permits, so a fresh Wikidata edit can refuse at once and permit only after a
 * week (missing: not settled); `refusal_only` that it still counts, for a refusal of the person only, because its line
 * stands at a channel official 7 days earlier and no longer, or you saw it confirmed in the last 7 days and its line is
 * gone (a recent refusal survives a channel change); `answer` is the body verifyAnswer returned, or null when there is none to weigh: the code's
 * registry gave no valid answer, or its anchor list failed (pass the entries of its last verified list with answer
 * null, so a broken list blocks only the people it held). Rule: not who came first, but who proved it.
 * `frozen` is directory.frozen(anchor): while the steward freezes the person, the result is deny, PG_SUBJECT_UNAVAILABLE.
 * Returns {status: "allow" | "deny" | "review" | "not_blocked", reason, code}: generate only on "allow". Throws
 * PregenError (no decision: do not generate) when a confirmed or refusal-only claim has no answer and no other such
 * claim refuses the person. */
export function decideIdentity(claims, { allowUnconfirmed = false, frozen = null } = {}) {
  // Before the person confirmed, PRE-GEN says nothing either way; an unconfirmed claim
  // neither permits nor refuses (allowUnconfirmed no longer permits anything). Rule 9: never the claims' order.
  if (frozen != null && frozen !== false) return { status: "deny", reason: "PG_SUBJECT_UNAVAILABLE", code: null }; // rule 0
  const counted = claims.filter((c) => c.confirmed || c.refusal_only)
    .sort((a, b) => (a.code < b.code ? -1 : a.code > b.code ? 1 : 0));
  for (const c of counted) {
    if (c.answer != null && c.answer.status !== "allow" && FLOOR_REASONS.includes(c.answer.reason)) {
      return { status: "deny", reason: c.answer.reason, code: c.code };
    }
  }
  // It may hold the person's refusal: unknown is not unconfirmed.
  if (counted.some((c) => c.answer == null)) fail("no decision: a claim the person confirmed has no answer");
  const group = counted.filter((c) => !c.refusal_only);
  const allowed = group.find((c) => c.answer.status === "allow" && c.settled);
  if (allowed) return { status: "allow", reason: null, code: allowed.code };
  const refusals = group.filter((c) => c.answer.status !== "allow");
  if (!refusals.length) { // nobody confirmed, or only on channels younger than a week
    return { status: "not_blocked", reason: claims.length ? "PG_IDENTITY_UNCONFIRMED" : "PG_UNKNOWN_SUBJECT", code: null };
  }
  const severity = (c) => ({ deny: 0, review: 1 })[c.answer.status] ?? 2; // the strongest refusal, ties by code
  const worst = refusals.reduce((w, c) => (severity(c) < severity(w) ? c : w));
  return { status: worst.answer.status, reason: worst.answer.reason ?? null, code: worst.code };
}

// A proof URL or official channel, exactly as written: https, a lower-case ASCII host, no credentials, port, query,
// fragment, percent-escape or dot segment, at most 512 characters, so every client reads the same page (stress B-9, D-1).
const CHANNEL_URL = /^https:\/\/([a-z0-9.-]{1,253})((?:\/(?!\.\.?(?:\/|$))[A-Za-z0-9._~@-]+)*\/?)$/;
const WELL_KNOWN = "/.well-known/pregen";

function channelUrl(url) {
  const m = typeof url === "string" && url.length <= 512 ? CHANNEL_URL.exec(url) : null;
  return m && HOST.test(m[1]) ? [m[1], m[2]] : null;
}

/** Did the person confirm `code` on an official channel (`officialUrls`, for example from wikidataOfficialUrls)?
 * Only two places count, never any other page on the host:
 * - an official website ("https://<host>", no path): exactly https://<host>/.well-known/pregen, whose text `getText`
 *   returns as a string;
 * - an official account ("https://x.com/<handle>" and the like): a post or profile at or below that path, for which
 *   `getText` returns {author: <handle or channel id>, text: <what the account itself wrote there>} from the
 *   platform's own record of who wrote it. The author must be the account (letter case aside); a string, a comment or
 *   another account's post confirms nothing.
 * The text must have a line "PRE-GEN: <code>", the whole code in either spelling (codeKey), alone or followed by a space and more words; a line
 * "PRE-GEN: <code> withdraw <party>" confirms nothing. `proofUrl` is taken exactly as written: https, a lower-case
 * host, no credentials, port, query, fragment, percent-escape or dot segment, at most 512 characters; `getText` must
 * not follow redirects (treat a 3xx like a 404: return ""). If `getText` throws (the page cannot be read), the claim
 * is unconfirmed, unless `seenConfirmed` (you saw it confirmed at the last check): then the error is thrown, and you
 * have no decision for this person. */
export async function checkChannelProof(code, proofUrl, officialUrls, getText, { seenConfirmed = false } = {}) {
  const p = channelUrl(proofUrl);
  let account = null;
  const on = p && officialUrls.map(channelUrl).some((o) => {
    if (!o || o[0] !== p[0]) return false;
    const base = o[1].replace(/\/+$/, ""), path = p[1].replace(/\/+$/, "");
    if (!base) return p[1] === WELL_KNOWN;
    if (path !== base && !path.startsWith(base + "/")) return false;
    account = base.slice(base.lastIndexOf("/") + 1).replace(/^@+/, "").toLowerCase();
    return true;
  });
  if (!on) return false;
  let got;
  try { got = await getText(proofUrl); } catch (e) {
    if (seenConfirmed) throw e;
    return false;
  }
  if (account !== null) {
    const author = got && typeof got === "object" ? got.author : null;
    if (!(typeof author === "string" && /^[A-Za-z0-9._-]+$/.test(author) && author.toLowerCase() === account)) return false;
    got = got.text;
  }
  return (typeof got === "string" ? got : "").split("\n").some((line) => {
    const words = line.replace(/^[ \t\r]+|[ \t\r]+$/g, "").split(/[ \t]+/);
    return words[0] === "PRE-GEN:" && words.length > 1 && keyOf(words[1]) === keyOf(code) && words[2] !== "withdraw";
  });
}

// Wikidata properties naming a person's own channels (official website, X, Instagram, YouTube channel, TikTok), each
// with the value it must have: anything else is dropped, never repaired (stress B-11).
const OFFICIAL = {
  P2002: [/^[A-Za-z0-9_]{1,15}$/, (v) => `https://x.com/${v}`],
  P2003: [/^[A-Za-z0-9_][A-Za-z0-9._]{0,29}$/, (v) => `https://www.instagram.com/${v}`],
  P2397: [/^UC[0-9A-Za-z_-]{22}$/, (v) => `https://www.youtube.com/channel/${v}`],
  P7085: [/^[A-Za-z0-9_][A-Za-z0-9._]{0,23}$/, (v) => `https://www.tiktok.com/@${v}`],
};

// A Wikidata time qualifier as [year, month, day], month and day 0 below that precision; null if it has none.
function wdDay(snak) {
  const t = snak?.snaktype === "value" ? snak.datavalue?.value?.time : undefined;
  const m = typeof t === "string" ? /^([+-])0*([0-9]{1,16})-([0-9]{2})-([0-9]{2})T[0-9:]{8}Z$/.exec(t) : null;
  return m ? [Number(m[2]) * (m[1] === "-" ? -1 : 1), Number(m[3]), Number(m[4])] : null;
}
const dayLE = (a, b) => a[0] !== b[0] ? a[0] < b[0] : a[1] !== b[1] ? a[1] < b[1] : a[2] <= b[2];

// Not deprecated, not ended (an end time today or before, or an unknown one), not yet to start (stress B-1).
function current(statement, today) {
  const q = statement.qualifiers || {};
  const ended = (q.P582 || []).some((s) => s?.snaktype !== "novalue" && dayLE(wdDay(s) ?? today, today));
  const started = (q.P580 || []).every((s) => s?.snaktype !== "value" || dayLE(wdDay(s) ?? [1e17, 0, 0], today));
  return statement.rank !== "deprecated" && !ended && started;
}

/** The official channels Wikidata currently lists for an anchor "wikidata:Q…": statements that are not deprecated,
 * have not ended and have started, with a value of the property's own form. A website counts by its host alone
 * ("https://<host>"): only its /.well-known/pregen can confirm (checkChannelProof).
 * Given `at` (Unix seconds, normally now - SETTLED_AFTER), the channels of the item as it stood then, from its last
 * revision at or before `at` ([] if the item did not exist yet), current as of that day: a claim is settled when its
 * channel is in both lists, and its refusal survives when its line stands at a channel only in this one. */
export async function wikidataOfficialUrls(anchor, { fetch: fetchFn = globalThis.fetch, now = Math.floor(Date.now() / 1000),
  at } = {}) {
  const qid = anchor.replace(/^wikidata:/, "");
  if (!/^Q[0-9]+$/.test(qid)) fail("not a wikidata anchor");
  let url = `https://www.wikidata.org/wiki/Special:EntityData/${qid}.json`;
  if (at !== undefined && at !== null) {
    now = Math.floor(at);
    const stamp = new Date(now * 1000).toISOString().replace(/\.[0-9]{3}Z$/, "Z");
    const r = await fetchFn("https://www.wikidata.org/w/api.php?action=query&format=json&formatversion=2&prop=revisions"
      + `&rvprop=ids&rvdir=older&rvlimit=1&titles=${qid}&rvstart=${stamp}`, { redirect: "error" });
    if (!r.ok) fail(`wikidata: HTTP ${r.status}`);
    const pages = (await r.json())?.query?.pages;
    const page = Array.isArray(pages) && pages[0] && typeof pages[0] === "object" ? pages[0] : null;
    if (!page || page.missing) fail(`wikidata: no entity ${qid} (merged or redirected)`);
    const revs = page.revisions;
    if (!revs || !revs.length) return []; // no revision at or before `at`: the item had no channels then
    const revid = Array.isArray(revs) ? revs[0]?.revid : undefined;
    if (!Number.isSafeInteger(revid)) fail(`wikidata: no revision of ${qid} to read`);
    url += `?revision=${revid}`;
  }
  const res = await fetchFn(url, { redirect: "error" });
  if (!res.ok) fail(`wikidata: HTTP ${res.status}`);
  const entity = (await res.json())?.entities?.[qid];
  if (!entity || typeof entity !== "object" || Array.isArray(entity)) fail(`wikidata: no entity ${qid} (merged or redirected)`);
  const d = new Date(now * 1000), today = [d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate()];
  const claims = entity.claims || {}, urls = [];
  for (const prop of ["P856", ...Object.keys(OFFICIAL)]) {
    for (const c of claims[prop] || []) {
      if (!c || typeof c !== "object") continue;
      const v = c.mainsnak?.datavalue?.value;
      if (typeof v !== "string" || !current(c, today)) continue;
      if (prop === "P856") {
        const m = /^https?:\/\/([A-Za-z0-9.-]+)(?:[/?#][!-~]*)?$/.exec(v);
        if (m && HOST.test(m[1].toLowerCase())) urls.push("https://" + m[1].toLowerCase());
      } else if (OFFICIAL[prop][0].test(v)) urls.push(OFFICIAL[prop][1](v));
    }
  }
  return urls;
}

// ── extension terms (spec/extensions/terms.md) ──

/** likeness/1's closed vocabulary of content categories (spec/profiles/likeness-1.md). A request that accepts a
 * person's terms names only these; any other word or spelling is refused, never normalised or passed (stress test TC1, TH1). */
export const CATEGORIES = Object.freeze(["adult", "advertising", "alcohol", "cannabis", "drugs", "endorsement", "fashion",
  "financial", "gambling", "health", "political", "religion", "sexual", "tobacco", "violence", "weapons"]);
export const PROHIBITED_FOR_MINORS = Object.freeze(["adult", "sexual", "violence"]); // never a minor's likeness, whatever the licence
export const INTIMATE = Object.freeze(["adult", "sexual"]);     // only on a grant the person signs with their own key, never on terms
const PURPOSES = ["personal", "educational", "research", "editorial", "commercial"];

function categoriesOf(use) {
  const cats = use && typeof use === "object" && !Array.isArray(use) ? (Object.hasOwn(use, "categories") ? use.categories : []) : null;
  if (!Array.isArray(cats) || !cats.every((c) => typeof c === "string")) fail("use.categories is a list of words");
  return new Set(cats);
}

/** likeness/1's fixed protections, which no terms and no licence lift: a minor's likeness in a prohibited category
 * gives "PG_PROHIBITED_USE", then any intimate category "PG_PERSONAL_SIGNATURE_REQUIRED". null when neither applies.
 * A word outside CATEGORIES matches nothing here: refuse it before. */
export function floor(use, minor) {
  const cats = categoriesOf(use);
  if (minor === true && PROHIBITED_FOR_MINORS.some((c) => cats.has(c))) return "PG_PROHIBITED_USE";
  return INTIMATE.some((c) => cats.has(c)) ? "PG_PERSONAL_SIGNATURE_REQUIRED" : null;
}

/** The first part of a declared use that a person's rules rule out, or null: a purpose they do not allow, then the
 * categories they exclude. An absent `excluded_categories` excludes nothing. */
export function forbids(rules, use) {
  if (!rules.purposes.includes(use.purpose)) return "purpose " + canonicalJson(use.purpose ?? null);
  const cats = categoriesOf(use), excluded = [...new Set(rules.excluded_categories ?? [])].filter((c) => cats.has(c)).sort();
  return excluded.length ? "categories " + canonicalJson(excluded) : null;
}

/** Whether a version of a person's terms opens anything (rule 5): a first version (`old` is null), a purpose added,
 * an exclusion removed, another template, or `minor` going from true to false. A version that opens takes the
 * person's own press with a second factor; all else only narrows. `old` and `next` are pg.terms.v1 bodies, or just
 * {rules, minor}. */
export function termsOpens(old, next) {
  if (old == null) return true;
  const r = old.rules, s = next.rules;
  return s.purposes.some((p) => !r.purposes.includes(p))
    || (r.excluded_categories ?? []).some((c) => !(s.excluded_categories ?? []).includes(c))
    || !same(old.template ?? null, next.template ?? null)
    || (old.minor === true && next.minor !== true);
}

const TERMS_MEMBERS = ["signers", "subject_ref", "profile", "version", "amends", "template", "legal", "rules", "minor",
  "assent", "instruction", "factor", "issued_at"];
// No control or format character in any member name or string: a zero-width joiner hides inside a word (TC1), and a
// trailing newline slips past a pattern that ends in `$` (TL2). As Python's str.isprintable: Other or Separator, but " ".
const UNPRINTABLE = /(?! )[\p{C}\p{Z}]/u;
const printable = (v) => (Array.isArray(v) ? v.every(printable)
  : v && typeof v === "object" ? Object.entries(v).every(([k, x]) => printable(k) && printable(x))
  : typeof v !== "string" || !UNPRINTABLE.test(v));
const hex64 = (v) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
const count = (v, low = 1) => Number.isSafeInteger(v) && v >= low;
/** A sorted list of distinct words from `vocabulary`. */
const words = (v, vocabulary, atLeast = 0) => Array.isArray(v) && v.length >= atLeast
  && v.every((x) => typeof x === "string" && vocabulary.includes(x)) && same(v, [...new Set(v)].sort());
const isObject = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);

/** A person's terms (pg.terms.v1, spec/extensions/terms.md) as their registry published them: signed by exactly one
 * key the directory lists for the code's prefix (PM10), for `code` itself (PM1), every member in shape and every
 * string printable, `amends` present exactly when it is not the first version, and a first version naming its second
 * factor. `assent` is always "registry": the registry's word on the person's authenticated instruction, never the
 * person's own key. It shows what was signed, not that this version still stands. Throws PregenError; returns the
 * body. Its message id, messageId("pg.terms.v1", body), is what a request accepts in `terms`. */
export async function checkTerms(env, code, { directory, fetch: fetchFn = globalThis.fetch } = {}) {
  directory ??= await loadDirectory({ fetch: fetchFn });
  const b = await registrySigned(env, "pg.terms.v1", code, directory, fetchFn);
  if (keyOf(b.subject_ref) !== keyOf(code)) fail("these terms are another person's");
  const has = (k) => Object.hasOwn(b, k);
  if (!TERMS_MEMBERS.every((k) => has(k) || k === "amends" || k === "factor") || !Object.keys(b).every((k) => TERMS_MEMBERS.includes(k))
      || !printable(b) || !same(Object.keys(b.signers[0]).sort(), ["key_id", "role"])) {
    fail("not a pg.terms.v1 body: a member missing or unknown, or a control or format character");
  }
  if (b.assent !== "registry" || b.profile !== "likeness/1") fail('terms are the registry\'s word under likeness/1 (assent "registry")');
  if (!count(b.version) || has("amends") !== b.version > 1 || (has("amends") && !hex64(b.amends))) {
    fail("a later version names the message id of the one it amends, and a first version names none");
  }
  if (!["authenticator", "email"].includes(has("factor") ? b.factor : "email") || (b.version === 1 && !has("factor"))) {
    fail("a first version, and any that opens, names the second factor the registry checked");
  }
  const t = b.template, legal = b.legal, rules = b.rules;
  if (!(hex64(b.instruction) && typeof b.minor === "boolean" && count(b.issued_at, 0)
      && isObject(t) && same(Object.keys(t).sort(), ["id", "jurisdiction", "version"])
      && typeof t.id === "string" && /^[a-z0-9-]{1,40}$/.test(t.id) && count(t.version)
      && typeof t.jurisdiction === "string" && /^[A-Z]{2}$/.test(t.jurisdiction)
      && isObject(legal) && same(Object.keys(legal).sort(), ["sha256", "url"])
      && hex64(legal.sha256) && typeof legal.url === "string" && /^https:\/\/[!-~]{1,2040}$/.test(legal.url) // printable ASCII, no space
      && isObject(rules) && same(Object.keys(rules).sort(), ["excluded_categories", "purposes"])
      && words(rules.purposes, PURPOSES, 1) && words(rules.excluded_categories, CATEGORIES))) {
    fail("not a pg.terms.v1 body: instruction, minor, issued_at, template, legal or rules");
  }
  return b;
}

/** What a proof shows about the terms the provider's signed request accepted: "absent" when it accepted none;
 * "unverified" when the record is not carried, not the one accepted, or not validly signed; "outside" when the use
 * reaches the floor, names a word outside CATEGORIES, or, on a policy basis, is outside the person's rules (a grant
 * decides its own scope); else "ok". */
async function termsFinding(item, asked, basis, code, directory, fetchFn) {
  if (!("terms" in asked)) return { terms: "absent", termsAssent: null };
  const pregenOnly = (e) => { if (!(e instanceof PregenError)) throw e; };
  let terms;
  try {
    terms = await checkTerms(item.terms, code, { directory, fetch: fetchFn });
    if ((await messageId("pg.terms.v1", terms)) !== asked.terms) fail("not the terms the request accepted");
  } catch (e) {
    pregenOnly(e);
    return { terms: "unverified", termsAssent: null };
  }
  const use = asked.use, policy = isObject(basis) && basis.kind === "policy";
  let out;
  try {
    out = Boolean(floor(use, terms.minor) || [...categoriesOf(use)].some((c) => !CATEGORIES.includes(c))
      || (policy && forbids(terms.rules, use)));
  } catch (e) {
    pregenOnly(e);
    out = true;
  }
  return { terms: out ? "outside" : "ok", termsAssent: terms.assent };
}

// ── extension proof (spec/extensions/proof.md) ──

/** proof.md acceptance step 3: an entry's readable copies `code` and `licence` equal the codes recomputed from its
 * signed answer (flat model: the answer's signer is the code's own registry) and from `grant`, the pg.grant.v1 envelope
 * whose message id the answer's basis names. A missing copy is not an error. */
async function checkCopies(it, answer, code) {
  const meta = Object.fromEntries([["Code", it.code], ["Licence", it.licence]].filter(([, v]) => v !== undefined));
  if (!Object.keys(meta).length) return;
  const signer = issuerOf(code) || BARE_ISSUER, g = answer.basis?.kind === "grant" ? answer.basis.grant : null;
  const act = { type: "pg.answer.v1", id: await messageId("pg.answer.v1", answer), signer, subject_ref: code,
    grant: g && { id: g.id, signer } };
  const env = it.grant, licence = g?.format === "pg.grant.v1" && env?.type === "pg.grant.v1" && isObject(env.body)
    && (await messageId("pg.grant.v1", env.body)) === g.id ? { type: "pg.grant.v1", id: g.id, signer, subject_ref: env.body.subject_ref } : null;
  if (!metadataOk(meta, act, licence)) fail(`${code}: a readable copy does not match the code its record gives`);
}

/** A pg.proof.v1 bundle carried with an output: was every subject of the job allowed at the moment it was
 * generated, did each registry acknowledge the provider's report of this output, and (given its SHA-256) is it
 * this file? Throws PregenError with the reason; returns {outputHash, jobId, subjects}. Each subject also says what the
 * proof shows about the terms its request accepted (`terms`: "absent", "ok", "outside" or "unverified", and
 * `termsAssent`, "registry" for a record that checked out): what was signed, not that those terms still stand. */
export async function checkProof(bundle, { directory, fetch: fetchFn = globalThis.fetch, outputSha256,
  now = Math.floor(Date.now() / 1000), testing = false } = {}) {
  directory ??= await loadDirectory({ fetch: fetchFn });
  if (now - directory.loadedAt > DIRECTORY_MAX_AGE) fail("the directory was loaded more than 24 hours ago: load it again");
  const items = bundle?.format === "pg.proof.v1" ? bundle.subjects : null;
  if (!Array.isArray(items) || !items.length) fail("not a pg.proof.v1 bundle");
  const outputs = new Set(), jobs = new Set(), subjects = [];
  for (const it of items) {
    const code = it.request?.body?.subject_ref, rbody = it.report?.body;
    if (!rbody || typeof rbody !== "object" || it.report.type !== "pg.report.v1") fail("each subject needs its report");
    if (typeof code === "string" && directory.isFalseClaim(code)) {           // identity.md: the steward ruled it false
      fail(`${code} is a false claim the steward recorded: never generated`);
    }
    // The answer had to be valid when the output was made, not today.
    const answer = await verifyAnswer(it.answer, it.request, { directory, fetch: fetchFn, now: rbody.occurred_at, testing });
    if (answer.status !== "allow") fail(`${code}: not an allow: ${answer.status} ${answer.reason ?? ""}`.trim());
    const ack = await registrySigned(it.ack, "pg.report_ack.v1", code, directory, fetchFn);
    if (ack.report !== (await messageId("pg.report.v1", rbody)) || ack.answer !== (await messageId("pg.answer.v1", answer))
        || rbody.answer !== ack.answer || rbody.outcome !== "generated") {
      fail(`${code}: the registry's acknowledgement does not match this report and answer (one was changed) or names no generation`);
    }
    if (!Number.isInteger(ack.received_at) || ack.received_at > (answer.expires_at ?? 0) + REPORT_GRACE) {
      fail(`${code}: reported more than 24 hours after the allow expired, so when the output was made is only the provider's word`);
    }
    await checkCopies(it, answer, code);
    outputs.add(rbody.output_hash);
    jobs.add(rbody.job_id);
    subjects.push({ code, level: answer.level, basis: answer.basis,
      ...(await termsFinding(it, it.request.body, answer.basis, code, directory, fetchFn)) });
  }
  if (outputs.size !== 1 || jobs.size !== 1) fail("the reports are about different outputs");
  const [outputHash] = outputs, [jobId] = jobs;
  if (outputSha256 !== undefined && outputSha256 !== outputHash) fail("the proof belongs to another file");
  return { outputHash, jobId, subjects };
}

/** An offline sandbox registry for tests and CI: no network, no secret, its own throwaway keys.
 * Its directory is signed by a throwaway steward key, so nothing it signs is ever accepted by
 * the real directory. Answers the documented sandbox subjects:
 *   sbx-allowed → allow · sbx-revoked, sbx-expired → PG_NO_LICENSE · sbx-exhausted → PG_USAGE_LIMIT
 *   sbx-optedout → PG_SUBJECT_OPTED_OUT · anything else → PG_NO_SUBJECT
 * Use `sim.fetch` in place of fetch and `sim.directory` in checkDecision. */
export async function createSimulator({ baseUrl = "https://simulator.pregen.invalid" } = {}) {
  const keygen = async () => {
    const k = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const pub = toHex(await crypto.subtle.exportKey("raw", k.publicKey));
    const sign = async (body) => toHex(await crypto.subtle.sign({ name: "Ed25519" }, k.privateKey, utf8.encode(canonicalJson(body))));
    return { pub, id: await fingerprint(pub), sign };
  };
  const steward = await keygen(), operator = await keygen();
  const dirBody = { schema: SCHEMA, sequence: 1, steward_key_id: steward.id, simulator: true,
    registries: [{ name: "PRE-GEN simulator (not a registry)", prefix: "TEST", api: baseUrl, keys: baseUrl + "/keys",
      key_fingerprints: [operator.id] }] };
  const directory = await verifyDirectory({ ...dirBody, signature: await steward.sign(dirBody) },
    { stewardPublicKeyHex: steward.pub, successorPublicKeyHex: null, pinnedKeys: { TEST: [operator.id] } });
  const answers = { "sbx-allowed": ["allow", null], "sbx-revoked": ["deny", "PG_NO_LICENSE"], "sbx-expired": ["deny", "PG_NO_LICENSE"],
    "sbx-exhausted": ["deny", "PG_USAGE_LIMIT"], "sbx-optedout": ["deny", "PG_SUBJECT_OPTED_OUT"] };
  // What PRAMPTA's /v1 does with receipts (R-10), so a provider's tests meet the same rules: a receipt
  // needs an allow issued to this pair for the same prompt_hash; the identical receipt again gets the
  // first answer, a different one is a conflict; release is refused once a receipt exists, and the
  // sandbox licences have no usage limit, so there is nothing to release.
  const decisions = new Map(), receipts = new Map();
  let n = 0;
  // A real Response, as fetch returns: json(), text(), headers — clients read error bodies with text().
  const reply = (status, body) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  const refuse = (status, detail) => reply(status, { detail });
  const header = (init, name) => {
    const h = init && init.headers; if (!h) return "";
    return (typeof h.get === "function" ? h.get(name) : h[name] ?? h[name.toLowerCase()]) || "";
  };
  async function simFetch(url, init = {}) {
    const path = new URL(String(url)).pathname;
    if (path === "/keys") return reply(200, { current_key_id: operator.id, keys: [{ key_id: operator.id, public_key_hex: operator.pub, status: "active" }] });
    const req = init.body ? JSON.parse(init.body) : {};
    if (path.replace(/\/$/, "") === "/v1/verify") {
      const [disposition, reason] = answers[req.subject_id] || ["deny", "PG_NO_SUBJECT"];
      const now = Math.floor(Date.now() / 1000);
      const named = !isEmpty(req.provider_user_id) || !isEmpty(req.provider_identity_link_id);
      const body = { schema_version: "pg.decision.v1", decision_id: `sim-${++n}`, simulator: true,
        allowed: disposition === "allow", disposition, reason, is_hard_refusal: reason === "PG_SUBJECT_OPTED_OUT",
        subject_id: req.subject_id ?? "", provider_id: header(init, "X-Provider-ID"), licensee_id: header(init, "X-Licensee-ID"),
        license_id: disposition === "allow" ? "TOG-LIC-TEST-ZZZZ-0000-001K" : null,
        prompt_hash: req.prompt_hash ?? "", model: req.model ?? "", modality: req.modality ?? "",
        intended_use: req.intended_use ?? {}, generation_id: req.generation_id ?? "",
        provider_user_binding: named ? "verified" : "unbound",
        provider_identity_link_id: req.provider_identity_link_id || (named ? "sim-link" : ""),
        issued_at: now, expires_at: now + 300, cache_scope: "not_cacheable", max_cache_age_seconds: 0,
        operator_key_id: operator.id };
      decisions.set(body.decision_id, body);
      return reply(200, { ...body, operator_signature: await operator.sign(body) });
    }
    const pair = (d) => d.provider_id === header(init, "X-Provider-ID") && d.licensee_id === header(init, "X-Licensee-ID");
    const release = path.match(/^\/v1\/receipts\/([^/]+)\/release$/);
    if (release) {
      const d = decisions.get(decodeURIComponent(release[1]));
      if (!d || d.disposition !== "allow") return refuse(404, "No authorized decision found for this decision_id");
      if (!pair(d)) return refuse(403, "This decision was not issued to your provider/licensee pair");
      if (receipts.has(d.decision_id)) return refuse(409, { error: "already_receipted", error_description: "A receipt says this decision was used." });
      return refuse(409, { error: "nothing_to_release", error_description: "This licence has no usage limit; nothing was reserved." });
    }
    if (path.replace(/\/$/, "") === "/v1/receipts") {
      const d = decisions.get(req.decision_id);
      if (!d || d.disposition !== "allow") return refuse(400, "No authorized decision found for this decision_id");
      if (d.prompt_hash !== req.prompt_hash) return refuse(400, "prompt_hash does not match the authorized decision");
      if (!pair(d)) return refuse(403, "This decision was not issued to your provider/licensee pair");
      if (!String(req.output_hash ?? "").trim()) return refuse(400, "output_hash is required to identify the reported output");
      if (req.schema_version && req.v && req.schema_version !== req.v) return refuse(400, "Conflicting receipt schema versions");
      const v = req.schema_version || req.v || "pg.receipt.v2";
      if (v !== "pg.receipt.v2" && v !== "pg.receipt.v3") return refuse(400, "Unsupported receipt schema version");
      const eventType = req.event_type ?? "output_accepted";
      // The body PRAMPTA hashes (app/core/receipt_body.py), so receipt_hash binds the answer to these bytes.
      const body = { v, decision_id: d.decision_id, subject_id: d.subject_id, licensee_id: d.licensee_id, provider_id: d.provider_id,
        prompt_hash: req.prompt_hash, output_hash: req.output_hash, model: req.model ?? "",
        obligations_applied: req.obligations_applied ?? {}, watermark_embedded: req.watermark_embedded ?? false,
        generated_at: req.generated_at ?? 0, ...(v === "pg.receipt.v3" ? { event_type: eventType } : {}) };
      const receiptHash = await sha256Hex(canonicalJson(body));
      const stored = receipts.get(d.decision_id);
      if (stored) {
        if (stored !== receiptHash) return refuse(409, { error: "receipt_conflict", error_description: "A different receipt for this decision already exists." });
        return reply(200, { status: "already_recorded", decision_id: d.decision_id, receipt_hash: receiptHash, compliant: true,
          provider_signature_verified: false });
      }
      receipts.set(d.decision_id, receiptHash);
      return reply(200, { schema_version: v, status: "recorded", decision_id: d.decision_id, receipt_hash: receiptHash,
        compliant: true, obligation_violations: [], provider_signature_verified: false, provider_signed_event_type: false });
    }
    return reply(404, { error: "not simulated" });
  }
  return { baseUrl, directory, fetch: simFetch, operatorPublicKeyHex: operator.pub };
}

// ── draft after-gen (spec/drafts/after-gen.md): a record that the rights holder approved one existing file ──
export * from "./after-gen.js";
