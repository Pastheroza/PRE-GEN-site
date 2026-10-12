export const STEWARD_PUBLIC_KEY_HEX: string;
export const DIRECTORY_URL: string;
/** Load the directory again at least this often (seconds): PRE-GEN-CORE.md rule 2. */
export const DIRECTORY_MAX_AGE: number;
export const ORIGIN_KEY_FINGERPRINTS: readonly string[];
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
  /** The steward marked this code a false claim (identity.md). */
  isFalseClaim(code: string): boolean;
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
export function verifyBytes(publicKeyHex: string, signatureHex: string, message: Uint8Array): Promise<boolean>;
export function verifySigned(obj: Record<string, unknown>, publicKeyHex: string, signatureField: string, exclude?: string[]): Promise<boolean>;
export function verifyLicense(license: {
  body: Record<string, unknown>; licenseId: string;
  subjectPublicKeyHex: string; subjectSignatureHex: string;
  operatorPublicKeyHex: string; operatorSignatureHex: string;
}): Promise<{ subjectValid: boolean; operatorValid: boolean }>;
export function issuerOf(code: string): string;
export function verifyDirectory(directory: unknown, options?: { stewardPublicKeyHex?: string; successorPublicKeyHex?: string | null; minSequence?: number;
  previous?: Directory | Record<string, unknown>; originKeyFingerprints?: string[] | null; now?: number }): Promise<Directory>;
export function loadDirectory(options?: { url?: string; minSequence?: number; previous?: Directory | Record<string, unknown>; fetch?: Fetch }): Promise<Directory>;
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
/** A registry's signed pg.anchors.v1 list, at most a day old, without the steward's false claims (identity.md). */
export function verifyAnchors(envelope: Record<string, unknown>, prefix: string,
  options: { directory: Directory; fetch?: Fetch; now?: number }): Promise<AnchorEntry[]>;
/** Not who came first, but who proved it (identity.md). Generate only on status "allow". */
export function decideIdentity(claims: { code: string; confirmed: boolean; answer: Record<string, unknown> }[],
  options?: { allowUnconfirmed?: boolean }): { status: "allow" | "deny" | "review"; reason: string | null; code: string | null };
/** True when `proofUrl` lies on one of the person's official channels and shows "PRE-GEN: <code>". */
export function checkChannelProof(code: string, proofUrl: string, officialUrls: string[],
  getText: (url: string) => Promise<string> | string): Promise<boolean>;
/** The official channels Wikidata lists for "wikidata:Q…". */
export function wikidataOfficialUrls(anchor: string, options?: { fetch?: Fetch }): Promise<string[]>;
/** A pg.proof.v1 bundle: every subject allowed when the output was made, each report acknowledged, and (given its
 * SHA-256) this very file (proof.md). Throws PregenError with the reason. */
export function checkProof(bundle: Record<string, unknown>, options?: { directory?: Directory; fetch?: Fetch;
  outputSha256?: string; now?: number }): Promise<{ outputHash: string; jobId: string; subjects: { code: string; level?: string; basis?: unknown }[] }>;
/** Offline sandbox registry for tests and CI. Never accepted by the real directory. */
export function createSimulator(options?: { baseUrl?: string }): Promise<{ baseUrl: string; directory: Directory; operatorPublicKeyHex: string; fetch: Fetch & ((url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => Promise<Response>) }>;
