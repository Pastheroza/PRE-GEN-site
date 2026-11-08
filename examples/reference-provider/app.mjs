// PRE-GEN reference provider: creators sign in, connect their licence (bind), and generate on a signed allow.
//   node app.mjs --sandbox                     the public test network
//   node app.mjs --provider-url https://your.domain --authority PRAM --key-file /run/secrets/pregen.key
import { createServer as createHttp } from "node:http";
import { createServer as createHttps } from "node:https";
import { DatabaseSync } from "node:sqlite";
import { randomBytes, randomUUID, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { openPregen, parseConfig, pg, sha256, Unavailable, PROFILE } from "./pregen.mjs";

const cfg = await parseConfig(process.argv.slice(2));
const pregen = await openPregen(cfg);
const OUT = join(cfg.data, "outputs");
mkdirSync(OUT, { recursive: true });
const now = () => Math.floor(Date.now() / 1000);

// The product menu. The SERVER fixes purpose and categories: a request's `use` is the provider's own signed
// statement (docs/provider.md step 4), so it comes from what the product renders, never from what a user claims.
const PRODUCTS = {
  "research-still": { label: "Research still", use: { purpose: "research" } },
  "editorial-illustration": { label: "Editorial illustration", use: { purpose: "editorial" } },
  "ad-banner": { label: "Ad banner", use: { purpose: "commercial", categories: ["advertising"] } },
};
const RENDERER = "stub-text/1";
const UNAVAILABLE = "The registry could not be reached. Nothing was generated; try again in a few minutes.";
const CONNECT_AGAIN = "Connect your licence: the connection between your licence and this app has ended. Connect it again, then retry.";

// ── storage: one node:sqlite file ──
const db = new DatabaseSync(join(cfg.data, "app.db"));
db.exec(`PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;
CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, account_id INTEGER NOT NULL, csrf TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS bind_starts (state TEXT PRIMARY KEY, account_id INTEGER NOT NULL, authority TEXT NOT NULL,
  verifier TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS bindings (account_id INTEGER NOT NULL, authority TEXT NOT NULL, licensee_id TEXT NOT NULL,
  binding TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY (account_id, authority));
CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, account_id INTEGER NOT NULL, created_at INTEGER NOT NULL,
  input TEXT NOT NULL, job_hash TEXT NOT NULL, request TEXT NOT NULL,       -- fixed before anything is sent (jobs.md X-2)
  state TEXT NOT NULL DEFAULT 'queued', worker TEXT, claimed_at INTEGER,   -- queued | claimed | done | unresolved
  sent_at INTEGER, answer TEXT, status TEXT, reason TEXT,                  -- stored before acting on it
  began_at INTEGER, output TEXT, output_hash TEXT, report TEXT, ack TEXT, report_error TEXT, outcome TEXT);`);
const one = (sql, ...a) => db.prepare(sql).get(...a);
const all = (sql, ...a) => db.prepare(sql).all(...a);
const run = (sql, ...a) => db.prepare(sql).run(...a);

// ── jobs ──
async function createJob(account, code, productId, prompt) {
  const product = PRODUCTS[productId];
  const entry = (await pregen.directory()).registryFor(code);
  if (!product) throw new Error("choose a product");
  if (!entry) throw new Error(`no listed registry holds ${code}`);
  const binding = one("SELECT licensee_id, expires_at FROM bindings WHERE account_id = ? AND authority = ?", account.id, entry.prefix);
  let licenseeId;
  if (binding) {
    // bind.md: an ended connection (expired, replaced, revoked) is "connect your licence", never a refusal.
    if (binding.expires_at <= now()) throw new Error(CONNECT_AGAIN);
    let held;
    try { held = await pregen.grants(entry.prefix, binding.licensee_id); }
    catch (e) { throw new Error(e instanceof Unavailable ? UNAVAILABLE : e.message); }
    if (held.error === "PG_NOT_BOUND") throw new Error(CONNECT_AGAIN);
    if (held.error) throw new Error(`the registry would not show your licence: ${held.error}`);
    // The creator's licensee_id goes only into a request that rests on their own licence: a subject among the
    // binding's grants. Anything else is asked for the provider itself and rests on its own grant, which covers
    // generating for users only with the resale right (catalog.md).
    if (held.grants.some((g) => (g.grant?.body ?? g.terms)?.subject_ref === code)) licenseeId = binding.licensee_id;
  }
  const id = `job-${randomUUID()}`;                          // a new job_id for every generation (jobs.md)
  // jobs.md: the job input is fixed once, holds everything we fixed, and hashes to job_hash.
  const input = { job_id: id, provider_id: cfg.providerUrl, asks: [{ subject_ref: code, registry: entry.prefix,
    profile: PROFILE, use: product.use }], product: productId, prompt, renderer: RENDERER,
    customer: licenseeId ? { [entry.prefix]: licenseeId } : null };
  const canonical = pg.canonicalJson(input), jobHash = sha256(canonical);
  const request = await pregen.signRequest({ code, use: product.use, jobId: id, jobHash, licenseeId });
  run("INSERT INTO jobs (id, account_id, created_at, input, job_hash, request) VALUES (?, ?, ?, ?, ?, ?)",
    id, account.id, now(), canonical, jobHash, JSON.stringify(request));
  return id;
}

// jobs.md X-1: claim atomically in storage every worker shares; one statement, so two workers never get one job.
function claim(worker) {
  return one(`UPDATE jobs SET state = 'claimed', worker = ?, claimed_at = ? WHERE id =
    (SELECT id FROM jobs WHERE state = 'queued' ORDER BY created_at LIMIT 1) AND state = 'queued' RETURNING *`, worker, now());
}
const finish = (id, outcome, reason = null) =>
  run("UPDATE jobs SET state = 'done', outcome = ?, reason = coalesce(?, reason) WHERE id = ?", outcome, reason, id);
const job = (id) => one("SELECT * FROM jobs WHERE id = ?", id);

async function runJob(j) {
  const request = JSON.parse(j.request);
  run("UPDATE jobs SET sent_at = coalesce(sent_at, ?) WHERE id = ?", now(), j.id);   // from here an answer may exist
  let r;
  try { r = await pregen.ask(request); } catch (e) {          // no answer, or one that does not verify (never received)
    return releaseLost(j.id, e instanceof Unavailable ? "unavailable" : "failed", e instanceof Unavailable ? null : e.message);
  }
  if (process.env.PREGEN_DROP_ANSWER && cfg.sandbox) return releaseLost(j.id, "unavailable");   // e2e: a lost answer
  if (r.error) return finish(j.id, r.error === "PG_NOT_BOUND" ? "not_connected" : "failed", r.error);   // bind.md B-5
  // limits.md: an allow reserves a use the moment it is issued, so it is stored before anything else happens.
  run("UPDATE jobs SET answer = ?, status = ?, reason = ? WHERE id = ?", JSON.stringify(r.answer), r.body.status,
    r.body.reason ?? null, j.id);
  if (r.body.status !== "allow") return finish(j.id, "refused", r.body.reason);   // only an allow permits (core rule 4)
  if (process.env.PREGEN_CRASH_AFTER_ALLOW && cfg.sandbox) process.exit(70);     // the e2e test's crash, sandbox only
  await generate(j.id);
}

async function generate(id) {
  const j = job(id), request = JSON.parse(j.request), answer = JSON.parse(j.answer);
  try { await pregen.checkAllow(answer, request); }               // jobs.md X-3: re-check its time just before
  catch (e) { return giveBack(id, e.message); }
  // Render exactly what was fixed: the stored input must still hash to the job_hash the registry signed over.
  if (sha256(pg.canonicalJson(JSON.parse(j.input))) !== j.job_hash || request.body.job_hash !== j.job_hash) {
    return giveBack(id, "the stored job input no longer matches its job_hash");
  }
  if (answer.body.obligations?.length) return giveBack(id, "an allow with obligations this product cannot apply");
  const began = now();                                             // reports.md: occurred_at is when generation began
  run("UPDATE jobs SET began_at = ? WHERE id = ?", began, id);
  let file;
  try { file = render(JSON.parse(j.input)); } catch (e) { return giveBack(id, `render failed: ${e.message}`); }
  const hash = sha256(readFileSync(file));
  const report = await pregen.makeReport(request, answer, "generated", hash, began);
  // jobs.md X-5: store the output hash and the signed report before sending it.
  run("UPDATE jobs SET output = ?, output_hash = ?, report = ? WHERE id = ?", file, hash, JSON.stringify(report), id);
  await fileReport(id);
}

// An answer the app never received may still hold a reserved use. The request is never sent again (a resend after
// that answer expired would reserve a second use): the app reports not_generated with answer null and the request
// itself (reports.md), and the registry releases that ask's reserved allows within the give-back window (limits.md).
async function releaseLost(id, outcome, why = null) {
  finish(id, outcome, why);
  const report = await pregen.makeReport(JSON.parse(job(id).request), null, "not_generated", "", now());
  run("UPDATE jobs SET report = ? WHERE id = ?", JSON.stringify(report), id);
  await fileReport(id);
}

// reports.md + limits.md: a use that never happened goes back with a signed not_generated report.
async function giveBack(id, why) {
  const j = job(id);
  const report = await pregen.makeReport(JSON.parse(j.request), JSON.parse(j.answer), "not_generated", "", now());
  run("UPDATE jobs SET report = ?, reason = ? WHERE id = ?", JSON.stringify(report), why, id);
  await fileReport(id);
}

async function fileReport(id) {
  const j = job(id), report = JSON.parse(j.report), code = JSON.parse(j.request).body.subject_ref;
  try {
    const ack = await pregen.fileReport(code, report);
    run("UPDATE jobs SET ack = ? WHERE id = ?", JSON.stringify(ack), id);
  } catch (e) {
    console.error(`${id}: report not filed: ${e.message}`);
    // A registry that cannot be reached gets it again from recover(); a refusal is kept and not retried.
    if (!(e instanceof Unavailable)) run("UPDATE jobs SET report_error = ? WHERE id = ?", e.message, id);
    return finish(id, j.outcome ?? "report_pending");
  }
  if (report.body.outcome !== "generated") return finish(id, j.outcome === "unavailable" ? "unavailable" : "given_back");
  try {   // proof.md: fetched by report id, checked against this file's SHA-256, kept next to the exact file
    const proof = await pregen.fetchProof(code, report, sha256(readFileSync(j.output)));
    writeFileSync(j.output + ".proof.json", JSON.stringify(proof, null, 2));
    finish(id, "generated");
  } catch (e) { finish(id, "generated", `no proof yet: ${e.message}`); }
}

// The renderer is a stub: a deterministic text file made only from the stored job input. Replace it with your model;
// it must read nothing but `input`.
function render(input) {
  const file = join(OUT, `${input.job_id}.txt`);
  writeFileSync(file + ".tmp", `PRE-GEN reference provider: stub output (${input.renderer})\njob: ${input.job_id}\n`
    + `subject: ${input.asks[0].subject_ref}\nproduct: ${input.product}\nuse: ${pg.canonicalJson(input.asks[0].use)}\n`
    + `prompt: ${input.prompt}\n`);
  renameSync(file + ".tmp", file);                                // the delivered file appears whole or not at all
  return file;
}

// After a crash: every stored allow with no report gets not_generated, or its use stays reserved and counted
// (limits.md); an answer lost on the way is released the same way, never asked again. A job that may have begun
// generating is never restarted or given back automatically (jobs.md X-7).
// ponytail: assumes one app process owns the 'claimed' rows; with several, recover only jobs of dead workers.
async function recover(startup) {
  for (const j of startup ? all("SELECT * FROM jobs WHERE state = 'claimed'") : []) {
    if (j.report) await fileReport(j.id);                        // signed and stored: send those same bytes
    else if (!j.answer && !j.sent_at) run("UPDATE jobs SET state = 'queued' WHERE id = ?", j.id);   // never sent: safe to send
    else if (!j.answer) await releaseLost(j.id, "given_back", "the app stopped before the answer was stored");
    else if (j.status !== "allow") finish(j.id, "refused", j.reason);
    else if (!j.began_at) await giveBack(j.id, "the app stopped before generating");
    else run("UPDATE jobs SET state = 'unresolved', outcome = 'unresolved' WHERE id = ?", j.id);
  }
  for (const j of all(`SELECT id FROM jobs WHERE state = 'done' AND report IS NOT NULL AND ack IS NULL
    AND report_error IS NULL`)) await fileReport(j.id);
}

async function worker(name) {
  for (;;) {
    const j = claim(name);
    if (!j) { await new Promise((r) => setTimeout(r, 250)); continue; }
    try { await runJob(j); } catch (e) { console.error(`${j.id}:`, e); }
  }
}

if (cfg.giveBack) {          // an operator resolves an interrupted job whose output was never delivered (jobs.md X-7)
  const j = job(cfg.giveBack);
  if (j?.state !== "unresolved") throw new Error(`${cfg.giveBack} is not an unresolved job`);
  await giveBack(j.id, "resolved by an operator: not delivered");
  console.log(`${j.id}: ${job(j.id).outcome}`);
  process.exit(0);
}

// ── web: accounts, sessions, CSRF ──
const SECURE = Boolean(cfg.tls) || !cfg.sandbox;                  // production sits behind TLS
const COOKIE = SECURE ? "__Host-sid" : "sid";
const h = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

// scrypt at OWASP's N = 2^17, r = 8, p = 1. The parameters live in the hash, so raising them later keeps old hashes valid.
const scryptAsync = promisify(scrypt);
const derive = (pw, salt, N, r, p) => scryptAsync(pw, salt, 64, { N, r, p, maxmem: 256 * N * r });
async function hashPassword(pw, salt = randomBytes(16).toString("hex"), N = 2 ** 17, r = 8, p = 1) {
  return `scrypt$${N}$${r}$${p}$${salt}$${(await derive(pw, salt, N, r, p)).toString("hex")}`;
}
async function passwordOk(pw, stored) {
  const [, N, r, p, salt, hash] = stored.split("$");
  return timingSafeEqual(await derive(pw, salt, Number(N), Number(r), Number(p)), Buffer.from(hash, "hex"));
}
const DUMMY = await hashPassword("not a password");               // same work for an unknown email

function session(req) {
  // Only the exact cookie name, and exactly one of it: a second value (say, planted with a narrower Path) is no session.
  const values = (req.headers.cookie ?? "").split(";").map((c) => c.trim().split("=")).filter(([k]) => k === COOKIE);
  const sid = values.length === 1 && /^[A-Za-z0-9_-]{43}$/.test(values[0][1] ?? "") ? values[0][1] : null;
  return sid ? one(`SELECT s.csrf, a.id, a.email FROM sessions s JOIN accounts a ON a.id = s.account_id
    WHERE s.id = ? AND s.expires_at > ?`, sha256(sid), now()) : undefined;
}
function startSession(res, accountId) {
  const sid = randomBytes(32).toString("base64url");
  run("INSERT INTO sessions VALUES (?, ?, ?, ?)", sha256(sid), accountId, randomBytes(16).toString("hex"), now() + 7 * 86400);
  // SameSite=Lax, not Strict: the bind callback is a top-level navigation from the registry and must carry it.
  res.setHeader("Set-Cookie", `${COOKIE}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800${SECURE ? "; Secure" : ""}`);
}

const page = (res, title, body, status = 200) => {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8", "Content-Security-Policy": "default-src 'none'; form-action 'self' https:; style-src 'unsafe-inline'",
    "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store" });
  res.end(`<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width"><title>${h(title)}</title>
<style>body{font:15px system-ui;max-width:46rem;margin:2rem auto;padding:0 1rem}.msg{padding:.5rem;background:#f4f4f4}</style>
<h1>${h(title)}</h1>${body}`);
};
const redirect = (res, to) => { res.writeHead(303, { Location: to }); res.end(); };
const csrfField = (s) => `<input type=hidden name=csrf value="${h(s.csrf)}">`;
const signInForms = `<form method=post action=/signin><h2>Sign in</h2><input name=email type=email required placeholder=email>
<input name=password type=password required placeholder=password><button>Sign in</button></form>
<form method=post action=/signup><h2>Create an account</h2><input name=email type=email required placeholder=email>
<input name=password type=password required minlength=10 placeholder="password (10+ characters)"><button>Create</button></form>`;

// The three things a creator must tell apart: the registry is down, the licence is not connected, a refusal.
function message(j) {
  switch (j.outcome) {
    case "generated": return `Generated.${j.reason ? ` ${j.reason}` : " The proof is saved next to the file."}`;
    case "refused": return `Refused by the registry: ${j.reason}. Nothing was generated.`;
    case "not_connected": return CONNECT_AGAIN;
    case "unavailable": return UNAVAILABLE;
    case "given_back": return `Not generated; the use went back to the licence (${j.reason}).`;
    case "report_pending": return "Waiting for the registry to acknowledge the report.";
    case "unresolved": return "Interrupted while generating: an operator has to resolve this job.";
    case "failed": return `Failed: ${j.reason}`;
    default: return "Waiting…";
  }
}

async function licencePanel(s) {
  const rows = [];
  for (const b of all("SELECT * FROM bindings WHERE account_id = ?", s.id)) {
    let r;
    try { r = await pregen.grants(b.authority, b.licensee_id); } catch (e) {
      rows.push(`<p class=msg>${h(b.authority)}: the registry could not be reached to show your licence.</p>`); continue;
    }
    if (r.error === "PG_NOT_BOUND") rows.push(`<p class=msg>${h(b.authority)}: ${CONNECT_AGAIN}</p>`);
    else if (r.error) rows.push(`<p class=msg>${b.authority}: ${h(r.error)}</p>`);
    else for (const g of r.grants) {       // status and remaining are unsigned: they inform, only an allow permits
      const body = g.grant?.body ?? {};
      rows.push(`<p>${h(b.authority)} licence on <b>${h(body.subject_ref)}</b>: purposes ${h((body.use?.purposes ?? []).join(", "))};
        ${h(g.status)}, ${h(g.remaining ?? "unlimited")} uses left</p>`);
    }
  }
  return rows.join("") || "<p>No licence connected yet.</p>";
}

async function home(res, s) {
  const jobs = all("SELECT * FROM jobs WHERE account_id = ? ORDER BY created_at DESC LIMIT 50", s.id);
  page(res, cfg.name, `<p>Signed in as ${h(s.email)}. <form method=post action=/signout style=display:inline>${csrfField(s)}<button>Sign out</button></form></p>
<h2>Your licence</h2>${await licencePanel(s)}
<form method=post action=/connect>${csrfField(s)}<button>Connect your licence at ${h(cfg.authority)}</button></form>
<h2>Generate</h2><form method=post action=/jobs>${csrfField(s)}
<p><input name=code required placeholder="PG code, e.g. PG-TEST-0000123"></p>
<p><select name=product>${Object.entries(PRODUCTS).map(([k, p]) => `<option value=${k}>${h(p.label)}</option>`).join("")}</select></p>
<p><textarea name=prompt rows=3 cols=60 maxlength=2000 placeholder=Prompt></textarea></p><button>Generate</button></form>
<h2>Jobs</h2>${jobs.map((j) => `<p><a href="/jobs/${h(j.id)}">${h(j.id)}</a> ${h(JSON.parse(j.input).asks[0].subject_ref)}
  ${h(JSON.parse(j.input).product)}: ${h(message(j))}</p>`).join("")}${cfg.sandbox ? "<p><i>Sandbox: test subjects only. Nothing here is a label.</i></p>" : ""}`);
}

async function readForm(req) {
  let data = "";
  for await (const chunk of req) { data += chunk; if (data.length > 16384) throw new Error("form too large"); }
  return Object.fromEntries(new URLSearchParams(data));
}

const inDirectory = async (prefix) => (await pregen.directory()).registries.some((r) => r.prefix === prefix && !r.revoked);

async function handle(req, res) {
  const url = new URL(req.url, "http://x"), path = url.pathname, s = session(req);
  if (path === "/.well-known/pregen-party.json") {                // provider-identity.md: the party document
    res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "max-age=300" });
    return res.end(JSON.stringify(pregen.party));
  }
  if (req.method === "POST") {
    // CSRF: refuse a cross-site post outright, then require the session's token on every signed-in form.
    const origin = req.headers.origin;
    if ((origin && origin !== "null" && new URL(origin).host !== req.headers.host) || req.headers["sec-fetch-site"] === "cross-site") {
      return page(res, "Refused", "<p>Cross-site form.</p>", 403);
    }
    const f = await readForm(req);
    if (path === "/signup" || path === "/signin") {
      const email = String(f.email ?? "").trim().toLowerCase(), pw = String(f.password ?? "");
      if (!/^[^\s@]{1,64}@[^\s@]{1,190}$/.test(email) || pw.length < 10 || pw.length > 1024) {
        return page(res, "Sign in", `<p class=msg>An email and a password of 10 or more characters.</p>${signInForms}`, 400);
      }
      let acc = one("SELECT * FROM accounts WHERE email = ?", email);
      if (path === "/signup") {
        if (acc) return page(res, "Sign in", `<p class=msg>That account exists: sign in.</p>${signInForms}`, 409);
        acc = { id: Number(run("INSERT INTO accounts (email, password) VALUES (?, ?)", email, await hashPassword(pw)).lastInsertRowid) };
      } else if (!(await passwordOk(pw, acc?.password ?? DUMMY)) || !acc) {   // ponytail: no rate limit; put one in front
        return page(res, "Sign in", `<p class=msg>Wrong email or password.</p>${signInForms}`, 401);
      }
      startSession(res, acc.id);
      return redirect(res, "/");
    }
    if (!s || typeof f.csrf !== "string" || f.csrf.length !== s.csrf.length || !timingSafeEqual(Buffer.from(f.csrf), Buffer.from(s.csrf))) {
      return page(res, "Refused", "<p>Sign in again.</p>", 403);
    }
    if (path === "/signout") {
      run("DELETE FROM sessions WHERE account_id = ? AND csrf = ?", s.id, s.csrf);
      res.setHeader("Set-Cookie", `${COOKIE}=; Path=/; Max-Age=0${SECURE ? "; Secure" : ""}`);
      return redirect(res, "/");
    }
    if (path === "/connect") {
      // bind.md: the app chooses the authority. Its own configured prefix, or, from a registry's "Use at" link, an
      // iss the person just confirmed that is a prefix in the verified directory.
      const authority = f.iss || cfg.authority;
      if (!(await inDirectory(authority))) return page(res, "Connect", "<p class=msg>Not a registry in the directory.</p>", 400);
      try {
        const start = await pregen.bindStart(authority, typeof f.hint === "string" ? f.hint.slice(0, 100) : "");
        run("DELETE FROM bind_starts WHERE created_at < ?", now() - 600);
        run("INSERT INTO bind_starts VALUES (?, ?, ?, ?, ?)", start.state, s.id, authority, start.verifier, now());
        return redirect(res, start.url);
      } catch (e) {
        return page(res, "Connect", `<p class=msg>${e instanceof Unavailable ? "The registry could not be reached." : h(e.message)}</p>`, 502);
      }
    }
    if (path === "/jobs") {
      let id;
      try { id = await createJob(s, pg.normalizeCode(String(f.code ?? "")), f.product, String(f.prompt ?? "").slice(0, 2000)); }
      catch (e) { return page(res, "Generate", `<p class=msg>${h(e.message)}</p><p><a href=/>Back</a></p>`, 400); }
      return redirect(res, `/jobs/${id}`);
    }
    return page(res, "Not found", "", 404);
  }
  if (path === "/") return s ? home(res, s) : page(res, cfg.name, signInForms);
  if (path === "/callback") {                                    // bind.md step 3
    if (!s) return page(res, "Connect", `<p class=msg>Sign in first, then connect again.</p>${signInForms}`, 401);
    const st = one("SELECT * FROM bind_starts WHERE state = ?", url.searchParams.get("state") ?? "");
    if (st) run("DELETE FROM bind_starts WHERE state = ?", st.state);           // single use
    // The state was made for THIS account, recently; iss is the authority we started with (RFC 9207: no mix-up).
    if (!st || st.account_id !== s.id || now() - st.created_at > 600 || url.searchParams.get("iss") !== st.authority) {
      return page(res, "Connect", "<p class=msg>This connection was not started here. Start again.</p><p><a href=/>Back</a></p>", 400);
    }
    if (url.searchParams.get("error")) return page(res, "Connect", "<p class=msg>Not connected: you cancelled at the registry.</p><p><a href=/>Back</a></p>");
    try {
      const binding = await pregen.bindExchange(st.authority, url.searchParams.get("code") ?? "", st.verifier);
      run(`INSERT INTO bindings VALUES (?, ?, ?, ?, ?) ON CONFLICT (account_id, authority) DO UPDATE SET
        licensee_id = excluded.licensee_id, binding = excluded.binding, expires_at = excluded.expires_at`,
        s.id, st.authority, binding.body.licensee_id, JSON.stringify(binding), binding.body.expires_at);
      return redirect(res, "/");
    } catch (e) {
      return page(res, "Connect", `<p class=msg>${e instanceof Unavailable ? "The registry could not be reached." : h(e.message)}</p>`, 502);
    }
  }
  if (path === "/bind/initiate") {      // bind.md: a registry's "Use at <app>" button. Ask the person first.
    const iss = url.searchParams.get("iss") ?? "", hint = url.searchParams.get("hint") ?? "";
    if (!(await inDirectory(iss))) return page(res, "Connect", "<p class=msg>Not a registry in the directory.</p>", 400);
    if (!s) return page(res, "Connect", `<p>Sign in, then open the registry's link again.</p>${signInForms}`);
    const name = (await pregen.registry(iss)).name;
    return page(res, `Connect your licences from ${name}?`, `<form method=post action=/connect>${csrfField(s)}
      <input type=hidden name=iss value="${h(iss)}"><input type=hidden name=hint value="${h(hint)}">
      <button>Connect</button> <a href=/>Not now</a></form>`);
  }
  const m = /^\/jobs\/(job-[0-9a-f-]{36})(\.json|\/output|\/proof)?$/.exec(path);
  const j = m && s && one("SELECT * FROM jobs WHERE id = ? AND account_id = ?", m[1], s.id);
  if (!j) return page(res, "Not found", "", 404);
  const view = { id: j.id, state: j.state, outcome: j.outcome, status: j.status, reason: j.reason, message: message(j),
    output: j.output && existsSync(j.output) ? `/jobs/${j.id}/output` : null,
    proof: j.output && existsSync(j.output + ".proof.json") ? `/jobs/${j.id}/proof` : null };
  if (m[2] === ".json") { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify(view)); }
  if (m[2] && view[m[2].slice(1)]) {
    res.writeHead(200, { "Content-Type": m[2] === "/proof" ? "application/json" : "text/plain; charset=utf-8" });
    return res.end(readFileSync(m[2] === "/proof" ? j.output + ".proof.json" : j.output));
  }
  return page(res, j.id, `<p>${h(view.message)}</p>${view.output ? `<p><a href="${view.output}">Output</a>` : ""}
    ${view.proof ? ` · <a href="${view.proof}">Proof</a></p>` : ""}<p><a href=/>Back</a></p>`);
}

// ── start ──
await recover(true);
setInterval(() => recover(false).catch((e) => console.error("recover:", e.message)), 5 * 60_000).unref();
const pregenRegistry = await pregen.registry(cfg.authority);
await pregen.introduce(pregenRegistry);                             // sandbox only: the party document by post
for (let i = 0; i < cfg.workers; i++) worker(`${process.pid}-${i}`);
const server = cfg.tls ? createHttps(cfg.tls, (q, r) => handle(q, r).catch((e) => { console.error(e); if (!r.headersSent) page(r, "Error", "", 500); }))
  : createHttp((q, r) => handle(q, r).catch((e) => { console.error(e); if (!r.headersSent) page(r, "Error", "", 500); }));
server.listen(cfg.port, () => {
  console.log(`${cfg.name}: provider id ${cfg.providerUrl} (${cfg.sandbox ? "SANDBOX: test directory, test answers only" : "production"}), `
    + `authority ${cfg.authority}, key ${pregen.keyId}\nOpen ${cfg.sandbox ? cfg.appUrl : `${cfg.providerUrl} (listening on port ${cfg.port})`}`);
});
