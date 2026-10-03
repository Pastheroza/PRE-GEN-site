export const STEWARD_PUBLIC_KEY_HEX: string;
export const DIRECTORY_URL: string;
export const ORIGIN_KEY_FINGERPRINTS: readonly string[];

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
  readonly registries: RegistryEntry[];
  /** The signed directory itself: persist it and pass it back as `previous`. */
  toJSON(): Record<string, unknown>;
  /** The registry that owns a code's namespace (resolve codes only there), or null. */
  registryFor(code: string): RegistryEntry | null;
  /** V-10: may this operator key sign objects carrying this code? */
  checkSigner(code: string, signerKeyId: string): "valid" | "unknown_issuer" | "issuer_mismatch";
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
export function verifyDirectory(directory: unknown, options?: { stewardPublicKeyHex?: string; minSequence?: number;
  previous?: Directory | Record<string, unknown>; originKeyFingerprints?: string[] | null }): Promise<Directory>;
export function loadDirectory(options?: { url?: string; minSequence?: number; previous?: Directory | Record<string, unknown>; fetch?: Fetch }): Promise<Directory>;
export function verifyDecision(decision: Record<string, unknown>, code: string, options?: { directory?: Directory; fetch?: Fetch }): Promise<boolean>;
/** Everything to check before generating (V-1 to V-4, V-10, V-13, P-5). Throws PregenError with the
 * reason; returns the decision when you may generate. `request`: the /v1/verify body plus provider_id and licensee_id. */
export function checkDecision<T extends Record<string, unknown>>(decision: T, request: Record<string, unknown>,
  options?: { directory?: Directory; fetch?: Fetch; now?: number }): Promise<T>;
