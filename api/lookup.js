/* PRE-GEN registry lookup proxy — pregen.org/api/lookup?code=TOG-...
   Read-only, hardened:
   - GET only, strict code validation (no proxy abuse)
   - per-IP sliding-window rate limit (per serverless instance)
   - in-memory response cache (absorbs replay floods, cuts upstream load)
   - 5s upstream timeout (no slow-loris cost amplification)
   - no secrets in responses
   Codes are read with @pregen/verify (TOG-CODE.md): a PG- code is legacy input and is asked and answered in its TOG
   spelling; every code in an answer is shown in its TOG spelling. */

const REGISTRIES = require("../registries.json");
const LIB = import("../packages/verify-js/index.js");

/* Returns { code, issuer } or { error, detail, status }. The code exactly as sent: the page folds typed input. */
function classify(raw, { parseCode, codeKey, CodeError }) {
  const code = String(raw || "");
  if (!code) return { error: "missing_code", detail: "Provide ?code=TOG-…", status: 400 };
  if (code.length > 64) return { error: "invalid_code", detail: "Not a code.", status: 422 };
  let p;
  try { p = parseCode(code); } catch (e) {
    if (!(e instanceof CodeError)) throw e;
    return e.reason === "mistyped"
      ? { error: "check_mismatch", detail: "Mistyped code: the check character does not fit.", status: 422 }
      : { error: "invalid_code", detail: "Not a code.", status: 422 };
  }
  try { return { code: codeKey(code), issuer: p.issuer }; } catch (e) {
    if (!(e instanceof CodeError)) throw e;
    return { code, issuer: p.issuer };   // an old licence number: only its registry gives its TOG code
  }
}

/* Every code in an answer in its TOG spelling (TOG-CODE.md §13); an old licence number its registry did not respell
   is not shown. */
function togOnly(v, { findCodes, codeKey }) {
  const key = (c) => { try { return codeKey(c); } catch { return "(an old licence number)"; } };
  if (typeof v === "string") return findCodes(v).reduce((s, c) => s.split(c).join(key(c)), v);
  if (Array.isArray(v)) return v.map((x) => togOnly(x, { findCodes, codeKey }));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, togOnly(x, { findCodes, codeKey })]));
  return v;
}

/* ── Rate limit: sliding window, per IP, per instance ────── */
const RL_WINDOW = 60_000;
const RL_MAX = 20;
const rlHits = new Map();

function rateLimited(ip) {
  const now = Date.now();
  let arr = rlHits.get(ip);
  if (!arr) { arr = []; rlHits.set(ip, arr); }
  while (arr.length && now - arr[0] > RL_WINDOW) arr.shift();
  if (arr.length >= RL_MAX) return true;
  arr.push(now);
  if (rlHits.size > 5000) {
    for (const [k, v] of rlHits) {
      if (now - v[v.length - 1] > RL_WINDOW) rlHits.delete(k);
      if (rlHits.size <= 2500) break;
    }
  }
  return false;
}

/* ── Response cache: successful/404 lookups only ─────────── */
const CACHE_TTL = 5 * 60_000;
const CACHE_MAX = 300;
const cache = new Map();

function cacheGet(key) {
  const e = cache.get(key);
  if (!e) return null;
  if (Date.now() - e.t > CACHE_TTL) { cache.delete(key); return null; }
  return e;
}

function cacheSet(key, status, body) {
  if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value);
  cache.set(key, { t: Date.now(), status, body });
}

function clientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length) return xff.split(",")[0].trim();
  const rip = req.headers["x-real-ip"];
  if (typeof rip === "string" && rip.length) return rip.trim();
  return "unknown";
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (req.method !== "GET") {
    res.status(405).json({ error: "method_not_allowed" });
    return;
  }

  if (rateLimited(clientIp(req))) {
    res.status(429).json({ error: "rate_limited", detail: "Too many requests. Try again in a minute." });
    return;
  }

  const lib = await LIB;
  const c = classify(req.query && req.query.code, lib);
  if (c.error) {
    res.status(c.status).json({ error: c.error, detail: c.detail });
    return;
  }

  /* The steward's word beats the registry's: a false claim or a revoked registry is never asked (PG-CODE.md §9.1).
     One code under two spellings is one code. */
  const same = (a) => { try { return lib.codeKey(a) === c.code; } catch { return a === c.code; } };
  const falseClaim = (REGISTRIES.false_claims || []).find((f) => same(f.code));
  if (falseClaim) {
    res.status(410).json({ error: "false_claim", at: falseClaim.at,
      detail: "The steward recorded this code as a false claim." });
    return;
  }

  const cached = cacheGet(c.code);
  if (cached) {
    res.status(cached.status).json(cached.body);
    return;
  }

  /* The first prefix names the registry; bare codes belong to the origin registry. */
  const registry = REGISTRIES.registries.find((r) => (r.prefix || "") === c.issuer);
  if (!registry) {
    res.status(404).json({ error: "unknown_issuer", issuer: c.issuer,
      detail: "No listed registry holds the prefix " + c.issuer + "." });
    return;
  }
  if (registry.revoked) {
    res.status(410).json({ error: "registry_revoked", at: registry.revoked.at,
      detail: "The registry that issued this code was revoked." });
    return;
  }
  const base = (!c.issuer && process.env.PRAMPTA_API_URL) || registry.api;
  /* Every registry answers through the public lookup (extensions/lookup.md, TOG-CODE.md §12). */
  const path = "/v2/codes/" + encodeURIComponent(c.code);

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 5000);
  try {
    const upstream = await fetch(base + path, { headers: { Accept: "application/json" }, signal: ctrl.signal });
    const body = togOnly(await upstream.json().catch(() => ({})), lib);
    if (upstream.status < 500) cacheSet(c.code, upstream.status, body);
    res.status(upstream.status).json(body);
  } catch (e) {
    res.status(502).json({ error: "registry_unreachable" });
  } finally {
    clearTimeout(timer);
  }
};
