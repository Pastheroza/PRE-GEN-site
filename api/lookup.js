/* PRE-GEN registry lookup proxy — pregen.org/api/lookup?code=PG-...
   Read-only, hardened:
   - GET only, strict code validation (no proxy abuse)
   - per-IP sliding-window rate limit (per serverless instance)
   - in-memory response cache (absorbs replay floods, cuts upstream load)
   - 5s upstream timeout (no slow-loris cost amplification)
   - no secrets in responses; registry token stays in env */

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CHECK = ALPHABET + "*~$=!";

function checkChar(body) {
  let sum = 0;
  for (let i = 0; i < body.length; i++) sum += CHECK.indexOf(body[i]) * (i + 1);
  return CHECK[sum % 37];
}

/* Returns { kind, code } or { error, detail, status } */
function classify(raw) {
  const code = String(raw || "").trim().toUpperCase().replace(/\s+/g, "");
  if (!code) return { error: "missing_code", detail: "Provide ?code=PG-…", status: 400 };
  if (code.length > 40 || !/^PG-[0-9A-Z*~$=!-]+$/.test(code))
    return { error: "invalid_code", detail: "Not a PG code shape.", status: 422 };
  const rest = code.slice(3);
  if (/[ILOU]/.test(rest))
    return { error: "invalid_code", detail: "I, L, O, U are excluded from the PG alphabet (Crockford base32).", status: 422 };
  let m;
  m = /^([A-Z]{3})-([0-9]{6,})-([0-9A-Z]{6})([0-9A-Z*~$=!])$/.exec(rest);
  if (m) {
    if (checkChar(m[1] + m[2] + m[3]) !== m[4])
      return { error: "check_mismatch", detail: "License check character invalid.", status: 422 };
    return { kind: "license", code: "PG-" + rest };
  }
  m = /^(STD|SUB|PRM|RND)-([0-9]{4,})$/.exec(rest);
  if (m) return { kind: "subject", code: "PG-" + rest };
  m = /^([0-9]{4,})$/.exec(rest);
  if (m) return { kind: "subject", code: "PG-" + rest };
  m = /^([0-9A-Z]{6,})([0-9A-Z*~$=!])$/.exec(rest);
  if (m) {
    if (checkChar(m[1]) !== m[2])
      return { error: "check_mismatch", detail: "Subject check character invalid.", status: 422 };
    return { kind: "subject", code: "PG-" + rest };
  }
  return { error: "invalid_code", detail: "Not a PG code shape.", status: 422 };
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

  const c = classify(req.query && req.query.code);
  if (c.error) {
    res.status(c.status).json({ error: c.error, detail: c.detail });
    return;
  }

  const cacheKey = c.kind + ":" + c.code;
  const cached = cacheGet(cacheKey);
  if (cached) {
    res.status(cached.status).json(cached.body);
    return;
  }

  const base = process.env.PRAMPTA_API_URL || "https://api2.prampta.com";
  const path = (c.kind === "license" ? "/v1/licenses/" : "/v1/subjects/") + encodeURIComponent(c.code);
  const headers = { Accept: "application/json" };
  const token = process.env.PRAMPTA_TOKEN;
  if (token) headers["Authorization"] = "Bearer " + token;

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 5000);
  try {
    const upstream = await fetch(base + path, { headers, signal: ctrl.signal });
    const body = await upstream.json().catch(() => ({}));
    if (upstream.status < 500) cacheSet(cacheKey, upstream.status, body);
    res.status(upstream.status).json(body);
  } catch (e) {
    res.status(502).json({ error: "registry_unreachable" });
  } finally {
    clearTimeout(timer);
  }
};
