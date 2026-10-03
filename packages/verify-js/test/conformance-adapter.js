// Level 1 conformance adapter (spec/conformance/README.md): one JSON request on stdin, one JSON answer on stdout.
//   python3 spec/conformance/level1/run_conformance.py --adapter "node packages/verify-js/test/conformance-adapter.js" \
//     --require-op canonical_json --require-op verify_signature --require-op verify_license \
//     --require-op verify_directory --require-op check_namespace
import { canonicalJson, sha256Hex, verifySigned, verifyLicense, verifyDirectory } from "../index.js";

let input = "";
for await (const chunk of process.stdin) input += chunk;
const req = JSON.parse(input);

async function handle() {
  switch (req.op) {
    case "canonical_json": {
      const raw = canonicalJson(req.input);
      return { canonical_utf8: raw, sha256_hex: await sha256Hex(raw) };
    }
    case "verify_signature":
      return { valid: await verifySigned({ ...req.message, _sig: req.signature_hex }, req.public_key_hex, "_sig") };
    case "verify_license": {
      const r = await verifyLicense({ body: req.body, licenseId: req.license_id,
        subjectPublicKeyHex: req.subject_public_key_hex, subjectSignatureHex: req.subject_signature_hex,
        operatorPublicKeyHex: req.operator_public_key_hex, operatorSignatureHex: req.operator_signature_hex });
      return { subject_valid: r.subjectValid, operator_valid: r.operatorValid };
    }
    case "verify_directory":
      try {
        await verifyDirectory(req.directory, { stewardPublicKeyHex: req.steward_public_key_hex, minSequence: req.min_sequence });
        return { valid: true };
      } catch { return { valid: false }; }
    case "check_namespace": {
      const dir = await verifyDirectory(req.directory, { stewardPublicKeyHex: req.steward_public_key_hex });
      return { result: dir.checkSigner(req.code, req.signer_key_id) };
    }
    default:
      return { unsupported: true };
  }
}
process.stdout.write(JSON.stringify(await handle()));
