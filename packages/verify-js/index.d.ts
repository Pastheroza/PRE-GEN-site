export const STEWARD_PUBLIC_KEY_HEX: string;
/** The directory v3 (TOG-CODE.md §9.2). */
export const DIRECTORY_URL: string;
/** The frozen v2 directory, for clients before 0.14. This library reads both. */
export const DIRECTORY_V2_URL: string;
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
  /** Offline party check of a code against this v3 directory at `at` (Unix seconds, the act's witnessed time, or null). */
  parties(code: string, options?: { at?: number | null; provider?: string | null }): { ok: boolean; facts: string[] };
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
/** The registry to ask: a code's first prefix, "" for the bare namespace. Shape only (TOG-CODE.md §8); a PG- string is not a code. */
export function issuerOf(code: string): string;
/** @deprecated Use normalizeTyped. Trims ASCII spaces and raises lower case, nothing else; keeps the spelling typed. */
export function normalizeCode(typed: string): string;

// ── ToG code (TOG-CODE.md) ──
export const CROCKFORD: string;
/** The TOG value table: Crockford, then I L O U as 32-35. */
export const TOG_VALUES: string;
/** Prefixes of the specification's examples and vectors, reserved forever. */
export const FIXTURE_PREFIXES: readonly string[];
/** Not a code, or a record that gives none. `hints`: both readings of ambiguous typed input. */
export class CodeError extends PregenError {
  reason: "malformed" | "mistyped" | "no_code";
  hints?: string[];
}
/** The one message for a typed PG- string: "PG codes are retired. Use the ToG code your registry shows you." */
export const RETIRED: string;
export interface ParsedCode {
  shape: "person" | "event" | "old_person" | "old_bare_person" | "old_no_check";
  marker: "TOG";
  kind: "subject" | "license" | "generated" | "approved_after";
  /** Events only: "terms", "licence", or null for a licence. */
  basis?: "terms" | "licence" | null;
  issuer: string;
  home: string | null;
  cls?: string;
  serial?: string;
  example: boolean;
}
/** An act record: the fields codeFor reads. */
export interface CodeAct {
  type: "pg.grant.v1" | "pg.answer.v1" | "pg.after_gen.v1";
  id: string;
  signer: string;
  subject_ref: string;
  grant?: { id: string; signer: string } | null;
  cosign?: { id: string; home: string; home_in_code: boolean } | null;
  media_hash?: string;
}
/** The check character of a body, under the TOG table (default) or CROCKFORD (the frozen table). */
export function checkChar(body: string, values?: string): string;
/** The one reading of a code exactly as it stands in a message, never repaired. Throws CodeError. */
export function parseCode(code: string, options?: { check?: boolean }): ParsedCode;
/** The key every comparison uses: the code itself, once it parses. No folding: a PG- string throws. */
export function codeKey(code: string): string;
/** "subject", "license", "generated" or "approved_after", from the string alone (no network). */
export function kindOf(code: string): string;
/** What the string claims, for support tools; never shown beside a video. */
export function describe(code: string): string;
/** Where a person types: the one code meant, for "Did you mean …?". Throws CodeError; a PG- string gets RETIRED. */
export function normalizeTyped(typed: string): string;
/** The code of an act, computed from its record. Throws CodeError ("no_code" when the record gives none). */
export function codeFor(act: CodeAct): string;
/** Readable copies {Code?, Licence?} against the record: true when every copy present equals its recomputed code. */
export function metadataOk(meta: { Code?: string; Licence?: string }, act: CodeAct, licence?: CodeAct | null): boolean;
/** What a verifier may say before signatures and the chain (TOG-CODE.md §15). */
export function codeVerdict(fileHash: string, act?: CodeAct | null, caption?: string | null, ingredient?: string | null): string;
export interface PartyEntry { entity: string; group: string; government?: boolean;
  roles: Record<string, { from: number; until: number | null }>; provider_domains?: string[]; void_from?: number; closed?: number }
/** Offline party check against dated entries (prefix → entry); Directory#parties builds them from a v3 directory. */
export function checkParties(code: string, entries: Record<string, PartyEntry>,
  options?: { at?: number | null; provider?: string | null }): { ok: boolean; facts: string[] };
/** The steward's admission check of a new prefix: "" if admissible, else the reason. */
export function admissionRefusal(prefix: string, entity: string, government: boolean,
  directory: Record<string, { entity: string }>, reserved?: readonly string[]): string;
/** Every well-formed code in free text, as it stands there. Fold a PG- string with codeKey before comparing it. */
export function findCodes(text: string): string[];
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
/** A message signed by exactly one registry key the directory lists for `code`'s prefix (core rules 1-2). Returns its body. */
export function registrySigned(env: unknown, type: string, code: string, directory: Directory, fetch?: Fetch): Promise<Record<string, any>>;

// ── draft after-gen (spec/drafts/after-gen.md): a record that the rights holder approved one existing file ──
/** The three statements every record carries, exactly. */
export const AFTER_GEN_LABEL: "approved after generation";
export const AFTER_GEN_NOTICE: string;
export const AFTER_GEN_NOT: readonly ["pre_generation_permission", "statement_of_origin"];
export interface MediaHash { binding: "media/1"; hash: string; leaves: number }
/** A file read in ranges: `read` resolves to exactly `length` bytes. */
export interface RangeReader { size: number; read(offset: number, length: number): Promise<Uint8Array> }
export interface Envelope { type: string; body: Record<string, any>; signatures: string[] }
/** media/1 of an ISO base media file (MP4, MOV, M4V), read in ranges. Throws PregenError("media/1: <reason>"). */
export function mediaHash(source: Uint8Array | Blob | RangeReader): Promise<MediaHash>;
/** The readable copies beside a record in XMP (pgag:Code, pgag:Licence), each present or not. */
export interface AfterGenCodeCopies { Code?: string; Licence?: string }
/** The records a file carries, unchecked: the C2PA assertion of the active manifest and the XMP pgag:Record, or null;
 * `codes`, the readable copies beside the XMP record. */
export function readAfterGen(source: Uint8Array | Blob | RangeReader): Promise<{ c2pa: Envelope | null; xmp: Envelope | null;
  codes: AfterGenCodeCopies }>;
/** The readable codes computed from a record: the approval's (TOG-AG-… or TOG-AG-LIC-…) and, under a licence basis, the
 * licence's (TOG-LIC-…); null where a code cannot be formed, Licence null under a terms basis. */
export function afterGenCodes(env: unknown): Promise<{ Code: string | null; Licence: string | null }>;
/** The file with the record in a top-level XMP uuid box appended at the end; an existing XMP box becomes `free` of the
 * same size and its properties move into the new packet. Given the directory, pgag:Status is {api}/v2/after-gen/{id}. */
export function embedXmp(bytes: Uint8Array, envelope: Envelope, options?: { directory?: Directory }): Promise<Uint8Array>;
/** The assertion to add with your own C2PA tool and certificate. */
export function c2paAssertion(envelope: Envelope): { label: "org.pregen.after_gen"; data: Envelope };
export interface AfterGenSummary {
  id: string; subject_ref: string; prefix: string; label: string; notice: string; not: string[]; holder: string;
  basis: { kind: "licence"; licence: { format: "pg.grant.v1"; id: string }; use: { n: number; of: number | null } }
    | { kind: "terms"; terms: string };
  scope: { purposes: string[]; categories: string[]; territories: string[]; channels: string[]; project: string; not_after: number };
  approval: Record<string, string>; approvedBy: string; issued_at: number; content: MediaHash;
  /** true when `media` was given and matched; null when no file was given. */
  fileMatch: true | null;
}
/** The record's shape, constants and floor, its signature by one registry key of the subject's prefix, and, given
 * `media`, that it names this file (else PregenError "not for this file"); given `codes`, that each present copy is the
 * code computed from the record. */
export function checkAfterGen(env: unknown, options?: { directory?: Directory; getJson?: (url: string) => Promise<any>; fetch?: Fetch;
  media?: MediaHash | string; codes?: AfterGenCodeCopies }): Promise<AfterGenSummary>;
/** The live status of this record ({api}/v2/after-gen/{id}): signed for the subject's prefix, naming this record,
 * current, at most 300 seconds of life. */
export function checkAfterGenStatus(statusEnv: unknown, recordEnv: unknown, options?: { directory?: Directory;
  getJson?: (url: string) => Promise<any>; fetch?: Fetch; now?: number }): Promise<{ state: "active" | "withdrawn" | "expired";
  approved_at: number; withdrawn_at: number | null; not_after: number }>;
