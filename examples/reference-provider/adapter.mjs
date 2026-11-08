// The self-check adapter for this app. It asks through pregen.mjs, the same code the app's workers use.
// Write your own with the same shape: open(argv) → {prefix, api, licenseeId?, ask, buy?, giveBack?, close?}.
import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { openPregen, parseConfig, pg, sha256 } from "./pregen.mjs";

export async function open(argv) {
  const cfg = parseConfig(argv);
  const p = await openPregen(cfg);
  const entry = await p.registry(cfg.authority);
  await p.introduce(entry);
  // Code 12 needs a creator's connected licence: the newest binding a signed-in creator made in this app.
  const file = join(cfg.data, "app.db");
  const row = existsSync(file) ? new DatabaseSync(file, { readOnly: true }).prepare(
    "SELECT licensee_id FROM bindings WHERE authority = ? AND expires_at > unixepoch() ORDER BY rowid DESC LIMIT 1").get(cfg.authority) : null;

  async function request({ code, purpose, categories, licenseeId, terms }) {
    const use = { purpose, ...(categories ? { categories } : {}) }, jobId = `selfcheck-${randomUUID()}`;
    const jobHash = sha256(pg.canonicalJson({ job_id: jobId, provider_id: cfg.providerUrl, asks: [{ subject_ref: code,
      registry: cfg.authority, profile: "likeness/1", use }], selfcheck: true }));
    return p.signRequest({ code, use, jobId, jobHash, licenseeId, terms });
  }

  return {
    prefix: cfg.authority, api: entry.api, licenseeId: row?.licensee_id,
    async ask(q) {
      const req = await request(q);
      const r = await p.ask(req);
      if (r.error) return { error: r.error, httpStatus: r.status };
      return { status: r.body.status, reason: r.body.reason, request: req, answer: r.answer };
    },
    async buy(code) {                                   // sandbox.md, Test purchase: the same signed request envelope
      const r = await p.post(entry.api + "/v2/sandbox/purchases", await request({ code, purpose: "research" }));
      if (r.status !== 200) throw new Error(`purchase: HTTP ${r.status} ${r.body.error ?? ""}`);
    },
    async giveBack({ request: req, answer }) {         // reports.md: not_generated releases the reserved use (limits.md)
      await p.fileReport(req.body.subject_ref, await p.makeReport(req, answer, "not_generated", "", Math.floor(Date.now() / 1000)));
    },
  };
}
