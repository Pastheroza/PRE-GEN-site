// @pregen/verify — check PRE-GEN signatures against the signed registry
// directory (PG-CODE.md §9.1, PRE-GEN-SPEC.md §2, V-9 to V-12).
// No dependencies: Ed25519 and SHA-256 come from Web Crypto (Node >= 20, browsers).

export const STEWARD_PUBLIC_KEY_HEX = "5cb949aab04186e3e216ec541b847c912fc3f78138c0ec3cb2560b2dad0d1f1b";
export const DIRECTORY_URL = "https://www.pregen.org/registries.json";
const SCHEMA = "pregen.registries.v2";
const MAX_INT = 2 ** 53 - 1;
const PREFIX = /^[ABCDEFGHJKMNPQRSTVWXYZ]{4}$/;
const FINGERPRINT = /^pg-ed25519:[0-9a-f]{32}$/;
const ISSUER_IN_CODE = /^PG-([ABCDEFGHJKMNPQRSTVWXYZ]{4})-/;
const BARE_CODE = /^PG-(?:(?:STD|SUB|PRM|RND)-)?[0-9]/;

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

/** Ed25519 over raw bytes. False on any bad signature or key encoding. */
export async function verifyBytes(publicKeyHex, signatureHex, message) {
  try {
    const key = await crypto.subtle.importKey("raw", hexBytes(publicKeyHex, 32), { name: "Ed25519" }, false, ["verify"]);
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

/** The namespace of a PG code: its four-letter prefix, or "" for the bare namespace. */
export function issuerOf(code) {
  if (typeof code !== "string") fail("PG code must be a string");
  const c = code.trim().toUpperCase();
  const m = ISSUER_IN_CODE.exec(c);
  if (m) return m[1];
  if (!BARE_CODE.test(c)) fail("unrecognized PG namespace");
  return "";
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
  if (d.schema !== SCHEMA) fail(`schema must be ${SCHEMA}`);
  if (!Number.isSafeInteger(d.sequence) || d.sequence < 1) fail("sequence must be a positive integer");
  if (!FINGERPRINT.test(String(d.steward_key_id))) fail("steward_key_id must be a pg-ed25519 fingerprint");
  if (!Array.isArray(d.registries) || d.registries.length === 0) fail("registries must be a non-empty list");
  const seen = new Set();
  for (const r of d.registries) {
    if (!r || typeof r !== "object") fail("registry entry must be an object");
    if (typeof r.name !== "string" || !r.name.trim()) fail("registry name must be nonempty");
    httpsUrl(r.api, "api");
    httpsUrl(r.keys, "keys");
    if (r.prefix !== "" && !(typeof r.prefix === "string" && PREFIX.test(r.prefix))) fail(`bad prefix ${r.prefix}`);
    if (seen.has(r.prefix)) fail(r.prefix === "" ? "the bare namespace is listed twice" : `prefix ${r.prefix} is listed twice`);
    seen.add(r.prefix);
    if (!Array.isArray(r.key_fingerprints) || !r.key_fingerprints.length
        || !r.key_fingerprints.every((f) => FINGERPRINT.test(String(f)))) {
      fail(`registry ${r.name}: key_fingerprints must list pg-ed25519 fingerprints`);
    }
  }
  if (!seen.has("")) fail("no registry holds the bare namespace");
}

/** A directory accepted under V-12. Build one with verifyDirectory() or loadDirectory(). */
export class Directory {
  #d;
  constructor(token, directory) {
    if (token !== Directory.#token) fail("use verifyDirectory() or loadDirectory()");
    this.#d = structuredClone(directory);
  }
  static #token = Symbol();
  static _make(directory) { return new Directory(Directory.#token, directory); }

  /** Store this and pass it as minSequence next time, so an older copy is refused. */
  get sequence() { return this.#d.sequence; }
  get registries() { return structuredClone(this.#d.registries); }

  /** The registry that owns a code's namespace (resolve codes only there, V-11), or null. */
  registryFor(code) {
    let issuer;
    try { issuer = issuerOf(code); } catch { return null; }
    const r = this.#d.registries.find((x) => x.prefix === issuer);
    return r ? structuredClone(r) : null;
  }

  /** V-10: "valid", "unknown_issuer" or "issuer_mismatch". */
  checkSigner(code, signerKeyId) {
    const r = this.registryFor(code);
    if (!r) return "unknown_issuer";
    return r.key_fingerprints.includes(signerKeyId) ? "valid" : "issuer_mismatch";
  }

  /** The public key behind `keyId`, which must belong to the owner of `code`'s namespace.
   * The key comes from the owner's key set and must hash to the listed fingerprint. */
  async publicKey(code, keyId, { fetch: fetchFn = globalThis.fetch } = {}) {
    const verdict = this.checkSigner(code, keyId);
    if (verdict !== "valid") fail(`${keyId} may not sign ${code}: ${verdict}`);
    const res = await fetchFn(this.registryFor(code).keys, { redirect: "error" });
    if (!res.ok) fail(`key set: HTTP ${res.status}`);
    const entry = ((await res.json()).keys || []).find((k) => k && k.key_id === keyId);
    if (!entry || (await fingerprint(entry.public_key_hex)) !== keyId) fail(`no key ${keyId} in the key set`);
    return entry.public_key_hex;
  }
}

/** V-12: accept the directory only with the pinned steward's signature, its
 * invariants, and a sequence no lower than one already seen. */
export async function verifyDirectory(directory, { stewardPublicKeyHex = STEWARD_PUBLIC_KEY_HEX, minSequence = 0 } = {}) {
  if (!Number.isSafeInteger(minSequence) || minSequence < 0) fail("minSequence must be a nonnegative integer");
  checkInvariants(directory);
  if (directory.steward_key_id !== (await fingerprint(stewardPublicKeyHex))) fail("signed by a different steward key");
  if (!(await verifySigned(directory, stewardPublicKeyHex, "signature"))) fail("bad steward signature");
  if (directory.sequence < minSequence) fail(`sequence ${directory.sequence} is older than ${minSequence} already seen`);
  return Directory._make(directory);
}

/** Download and verify the directory from pregen.org. */
export async function loadDirectory({ url = DIRECTORY_URL, minSequence = 0, fetch: fetchFn = globalThis.fetch } = {}) {
  const res = await fetchFn(url, { redirect: "error" });
  if (!res.ok) fail(`directory: HTTP ${res.status}`);
  return verifyDirectory(await res.json(), { minSequence });
}

/** Step 4 in one call: is this registry decision genuine, and signed by a key of the
 * registry that owns `code`? Request matching and expiry (V-3, V-4, V-13) stay with the caller. */
export async function verifyDecision(decision, code, { directory, fetch: fetchFn = globalThis.fetch } = {}) {
  const dir = directory || (await loadDirectory({ fetch: fetchFn }));
  const key = await dir.publicKey(code, decision && decision.operator_key_id, { fetch: fetchFn });
  return verifySigned(decision, key, "operator_signature");
}
