export const STEWARD_PUBLIC_KEY_HEX: string;
export const DIRECTORY_URL: string;
/** Load the directory again at least this often (seconds): PRE-GEN-CORE.md rule 2. */
export const DIRECTORY_MAX_AGE: number;
export const STEWARD_SUCCESSOR_PUBLIC_KEY_HEX: string | null;

export class PregenError extends Error {}

export interface RegistryEntry {
  name: string;
  prefix: string;
  api: string;
  keys: string;
  key_fingerprints: string[];
  [member: string]: unknown;
}

type Fetch = (url: string, init?: { redirect?: "error" }) => Promise<{ ok: boolean; status: number; json(): Promise<any> }>;

export class Directory {
  private constructor();
  /** Store it and pass it back as `minSequence`, so an older directory is refused. */
  readonly sequence: number;
  /** Unix seconds when it was accepted. checkAnswer refuses a directory older than DIRECTORY_MAX_AGE. */
  readonly loadedAt: number;
  /** The steward found `code` a false claim under `anchor` and has not reversed it (identity.md); without `anchor`,
   * under any anchor (a private person's code is then never generated). The latest entry by `at` decides; a tie stays false. */
  isFalseClaim(code: string, anchor?: string | null): boolean;
  /** The steward's freeze of `anchor` in effect at `now` (at <= now < until), or null: pass it to decideIdentity. */
  frozen(anchor: string, now?: number): { anchor: string; at: string; until: string; reason: string } | null;
  readonly registries: RegistryEntry[];
  /** The signed directory itself: persist it and pass it back as `previous`. */
  toJSON(): Record<string, unknown>;
  /** The registry that owns a code's namespace (resolve codes only there), or null. */
  registryFor(code: string): RegistryEntry | null;
  /** V-10: may this operator key sign objects carrying this code? */
  checkSigner(code: string, signerKeyId: string): "valid" | "unknown_issuer" | "issuer_mismatch" | "revoked";
  /** The owner's public key for `keyId`, fetched from its key set and checked against the listed fingerprint. */
  publicKey(code: string, keyId: string, options?: { fetch?: Fetch }): Promise<string>;
}

export function canonicalJson(value: unknown): string;
export function sha256Hex(data: string | Uint8Array): Promise<string>;
export function fingerprint(publicKeyHex: string): Promise<string>;
/** The raw key, or a PregenError for a small-order or non-canonical key (stress test C1). */
/** Seconds after an allow expires within which its report must reach the registry for a proof (stress test H1). */
export const REPORT_GRACE: number;
export function checkPublicKey(publicKeyHex: string): Uint8Array;
export function verifyBytes(publicKeyHex: string, signatureHex: string, message: Uint8Array): Promise<boolean>;
export function verifySigned(obj: Record<string, unknown>, publicKeyHex: string, signatureField: string, exclude?: string[]): Promise<boolean>;
export function verifyLicense(license: {
  body: Record<string, unknown>; licenseId: string;
  subjectPublicKeyHex: string; subjectSignatureHex: string;
  operatorPublicKeyHex: string; operatorSignatureHex: string;
}): Promise<{ subjectValid: boolean; operatorValid: boolean }>;
export function issuerOf(code: string): string;
/** What a person typed, as the canonical code (trim ASCII spaces, raise lower case, nothing else). Input boundaries only. */
export function normalizeCode(typed: string): string;
export function verifyDirectory(directory: unknown, options?: { stewardPublicKeyHex?: string; successorPublicKeyHex?: string | null; minSequence?: number;
  previous?: Directory | Record<string, unknown>;
  /** Your own pins: prefix → key fingerprints ("" for bare codes). No registry is pinned by default. */
  pinnedKeys?: Record<string, string[]>;
  /** @deprecated use pinnedKeys: {"": [...]} */
  originKeyFingerprints?: string[] | null; now?: number }): Promise<Directory>;
export function loadDirectory(options?: { url?: string; minSequence?: number; previous?: Directory | Record<string, unknown>; fetch?: Fetch;
  /** Testing only: a test directory signed by a test steward key. */ stewardPublicKeyHex?: string }): Promise<Directory>;
/** The bytes a v5 signature covers: "PREGEN-V5" 0x00 type 0x00 canonical(body). */
export function signingInput(type: string, body: Record<string, unknown>): Uint8Array;
/** A new Ed25519 private key (the 32-byte RFC 8032 seed) as hex. Keep it secret, server-side. */
export function newPrivateKeyHex(): string;
/** The raw 32-byte public key of a private key (seed), as hex. */
export function publicKeyHex(privateKeyHex: string): Promise<string>;
/** A v5 envelope {type, body, signatures}: one signature per private key, in the order of body.signers. */
export function signEnvelope(type: string, body: Record<string, unknown>, ...privateKeyHexes: string[]): Promise<{ type: string; body: Record<string, unknown>; signatures: string[] }>;
/** A provider URL (provider-identity): https://<domain>, lower case, no path, port, query or fragment. Throws PregenError. */
export function checkProviderUrl(url: string, options?: { allowPort?: boolean }): string;
/** A sandbox test id bound to your key: https://<32 hex of the key id>.localhost[:port]. */
export function sandboxProviderUrl(privateKeyHex: string, port?: number): Promise<string>;
/** The document to serve at {providerUrl}/.well-known/pregen-party.json: name, roles and a first keyset signed by the key. */
export function partyDocument(providerUrl: string, name: string, privateKeyHex: string,
  options?: { redirectUris?: string[]; bindInitiateUri?: string; policy?: string; contact?: string }): Promise<Record<string, unknown>>;
/** The PG-Access header value for a GET by a provider known by its domain: a signed pg.access.v1 envelope, base64url. */
export function pgAccess(providerUrl: string, privateKeyHex: string, aud: string, method: string, path: string, options?: { now?: number }): Promise<string>;
export function verifyDecision(decision: Record<string, unknown>, code: string, options?: { directory?: Directory; fetch?: Fetch }): Promise<boolean>;
/** Everything to check before generating (V-1 to V-4, V-10, V-13, P-5). Throws PregenError with the
 * reason; returns the decision when you may generate. `request`: the /v1/verify body plus provider_id and licensee_id. */
export function checkDecision<T extends Record<string, unknown>>(decision: T, request: Record<string, unknown>,
  options?: { directory?: Directory; fetch?: Fetch; now?: number; requireVerifiedAuthority?: boolean }): Promise<T>;
export function messageId(type: string, body: Record<string, unknown>): Promise<string>;
/** PRE-GEN-CORE.md rule 5: may I generate on this answer? Checks it through the directory; throws PregenError
 * with the reason; returns the answer body on a valid allow. `request`: the pg.request.v1 envelope you sent. */
export function checkAnswer(answer: Record<string, unknown>, request: Record<string, unknown>,
  options?: { directory?: Directory; fetch?: Fetch; now?: number; testing?: boolean }): Promise<Record<string, unknown>>;
/** Everything checkAnswer checks except that it is an allow: weigh refusals from several registries. */
export function verifyAnswer(answer: Record<string, unknown>, request: Record<string, unknown>,
  options?: { directory?: Directory; fetch?: Fetch; now?: number; testing?: boolean }): Promise<Record<string, unknown>>;
/** Refusals of the person (not a missing licence): one of them in any of a person's registries holds everywhere. */
export const FLOOR_REASONS: readonly string[];
export interface AnchorEntry { anchor: string; code: string; level: string; proof_url: string; status: string }
/** A registry's signed pg.anchors.v1 list, at most a day old, without the steward's false claims and another registry's
 * codes (identity.md). Throws on a list naming one of its codes twice. */
export function verifyAnchors(envelope: Record<string, unknown>, prefix: string,
  options: { directory: Directory; fetch?: Fetch; now?: number }): Promise<AnchorEntry[]>;
/** Not who came first, but who proved it (identity.md). Generate only on status "allow". `answer` null: none to weigh
 * (no valid answer, or its registry's anchor list failed); throws PregenError (no decision) when such a claim is
 * confirmed or refusal-only and no such claim refuses the person. Only a `settled` claim's allow permits (its channel
 * was official SETTLED_AFTER earlier too; missing: not settled); a `refusal_only` claim counts for a refusal of the
 * person only. `frozen` (directory.frozen(anchor)) denies first, PG_SUBJECT_UNAVAILABLE. */
export function decideIdentity(claims: { code: string; confirmed: boolean; answer: Record<string, unknown> | null;
  settled?: boolean; refusal_only?: boolean }[],
  options?: { allowUnconfirmed?: boolean; frozen?: object | null }): { status: "allow" | "deny" | "review" | "not_blocked"; reason: string | null; code: string | null };
/** What `getText` returns for an official account: who wrote it, by the platform's own record, and what they wrote. */
export interface AccountText { author: string; text: string }
/** True when the line "PRE-GEN: <code>" stands at https://<official host>/.well-known/pregen (getText returns a string)
 * or in a post or profile by the official account itself (getText returns {author, text}). If getText throws, false,
 * unless seenConfirmed: then it throws (no decision). */
export function checkChannelProof(code: string, proofUrl: string, officialUrls: string[],
  getText: (url: string) => Promise<string | AccountText> | string | AccountText,
  options?: { seenConfirmed?: boolean }): Promise<boolean>;
/** The official channels Wikidata currently lists for "wikidata:Q…": not deprecated, not ended, started, well-formed.
 * With `at` (Unix seconds, normally now - SETTLED_AFTER), those of the item as it stood then. */
export function wikidataOfficialUrls(anchor: string, options?: { fetch?: Fetch; now?: number; at?: number }): Promise<string[]>;
/** 7 days in seconds: a new official channel permits only after it; a steward freeze lasts at most it. */
export const SETTLED_AFTER: number;
/** likeness/1's closed vocabulary of content categories: a request that accepts a person's terms names only these. */
export const CATEGORIES: readonly string[];
/** Never a minor's likeness, whatever the licence. */
export const PROHIBITED_FOR_MINORS: readonly string[];
/** Only on a grant the person signs with their own key, never on terms. */
export const INTIMATE: readonly string[];
export interface TermsRules { purposes: string[]; excluded_categories?: string[] }
/** likeness/1's fixed protections: "PG_PROHIBITED_USE" (a minor), then "PG_PERSONAL_SIGNATURE_REQUIRED" (intimate), or null. */
export function floor(use: { categories?: string[]; [member: string]: unknown }, minor: boolean): "PG_PROHIBITED_USE" | "PG_PERSONAL_SIGNATURE_REQUIRED" | null;
/** The first part of a declared use the person's rules rule out ("purpose …" or "categories […]"), or null. */
export function forbids(rules: TermsRules, use: { purpose?: string; categories?: string[] }): string | null;
/** Whether a version of a person's terms opens anything (rule 5), so it takes the person's own press with a second factor. */
export function termsOpens(old: { rules: TermsRules; minor?: boolean; template?: unknown } | null,
  next: { rules: TermsRules; minor?: boolean; template?: unknown }): boolean;
/** A person's terms (pg.terms.v1) as their registry published them: signed by one key the directory lists for the code's
 * prefix, for this code, in shape. Returns the body; assent is always "registry". Throws PregenError. */
export function checkTerms(env: Record<string, unknown>, code: string, options?: { directory?: Directory; fetch?: Fetch }): Promise<{
  signers: { role: "registry"; key_id: string }[]; subject_ref: string; profile: "likeness/1"; version: number; amends?: string;
  template: { id: string; version: number; jurisdiction: string }; legal: { sha256: string; url: string }; rules: TermsRules;
  minor: boolean; assent: "registry"; instruction: string; factor?: "authenticator" | "email"; issued_at: number }>;
/** A pg.proof.v1 bundle: every subject allowed when the output was made, each report acknowledged, and (given its
 * SHA-256) this very file (proof.md). Each subject says what the proof shows about the terms its request accepted.
 * Throws PregenError with the reason. */
export function checkProof(bundle: Record<string, unknown>, options?: { directory?: Directory; fetch?: Fetch;
  outputSha256?: string; now?: number; testing?: boolean }): Promise<{ outputHash: string; jobId: string; subjects: {
    code: string; level?: string; basis?: unknown;
    terms: "absent" | "ok" | "outside" | "unverified"; termsAssent: "registry" | null }[] }>;
/** Offline sandbox registry for tests and CI. Never accepted by the real directory. */
export function createSimulator(options?: { baseUrl?: string }): Promise<{ baseUrl: string; directory: Directory; operatorPublicKeyHex: string; fetch: Fetch & ((url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => Promise<Response>) }>;
