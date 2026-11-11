// The /tog page's local stand (PLAN §2.2, §4.3): an ephemeral steward key signs a test directory listing PRAM with
// `tog_start` at a local registry. The page reads these two files only on localhost; both are git- and vercel-ignored.
// Run: node test/tog-local.mjs [registry origin, default http://localhost:3100]
import { mkdirSync, writeFileSync } from "node:fs";
import { canonicalJson, fingerprint } from "../packages/verify-js/index.js";

const origin = new URL(process.argv[2] || "http://localhost:3100").origin;
const hex = (b) => Buffer.from(b).toString("hex");
const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const pub = hex(await crypto.subtle.exportKey("raw", keys.publicKey));
const directory = {
  schema: "pregen.registries.v2", sequence: 1, issued_at: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
  note: "LOCAL TEST directory for /tog, signed by an ephemeral key. Never served by pregen.org.",
  steward_key_id: await fingerprint(pub),
  registries: [{ name: "PRAMPTA", prefix: "PRAM", website: origin, tog_start: `${origin}/start`,
    api: "https://api.invalid", keys: "https://api.invalid/keys", key_fingerprints: ["pg-ed25519:" + "0".repeat(32)] }],
};
directory.signature = hex(await crypto.subtle.sign("Ed25519", keys.privateKey, new TextEncoder().encode(canonicalJson(directory))));
const dir = new URL("./tog-local/", import.meta.url);
mkdirSync(dir, { recursive: true });
writeFileSync(new URL("registries.json", dir), JSON.stringify(directory, null, 1) + "\n");
writeFileSync(new URL("steward.json", dir), JSON.stringify({ public_key_hex: pub }) + "\n");
console.log(`test/tog-local/: PRAM -> ${origin}/start, steward ${directory.steward_key_id}`);
