/* PRE-GEN registry lookup proxy — pregen.org/api/lookup?code=TOG-...
   Read-only, hardened:
   - GET only, strict code validation (no proxy abuse)
   - per-IP sliding-window rate limit (per serverless instance)
   - in-memory response cache (absorbs replay floods, cuts upstream load)
   - 5s upstream timeout (no slow-loris cost amplification)
   - no secrets in responses
   Codes are read with @pregen/verify (TOG-CODE.md). PG code is incompatible: a PG- string is not a code here and gets
   one neutral message, with no TOG suggestion. A registry is asked for the TOG code; one not yet migrated is asked
   through the transition shim below. No PG- string is ever shown. */

const REGISTRIES = require("../registries.json");
const LIB = import("../packages/verify-js/index.js");

/* Returns { code, shape, kind, issuer } or { error, detail, status }. Trimmed and case-folded as before; the page folds
   the rest of typed input. */
function classify(raw, { parseCode, CodeError, RETIRED }) {
  const code = String(raw || "").trim().toUpperCase().replace(/\s+/g, "");
  if (!code) return { error: "missing_code", detail: "Provide ?code=TOG-…", status: 400 };
  if (code.length > 64) return { error: "invalid_code", detail: "Not a code.", status: 422 };
  if (code.startsWith("PG-")) return { error: "invalid_code", detail: RETIRED, status: 422 };   // no mapping to TOG
  let p;
  try { p = parseCode(code); } catch (e) {
    if (!(e instanceof CodeError)) throw e;
    return e.reason === "mistyped"
      ? { error: "check_mismatch", detail: "Mistyped code: the check character does not fit.", status: 422 }
      : { error: "invalid_code", detail: "Not a code.", status: 422 };
  }
  return { code, shape: p.shape, kind: p.kind, issuer: p.issuer };
}

/* No PG- string is shown: the shim's own request string is the TOG code asked; any other PG- string in an answer
   is not shown. Nothing is converted to a TOG spelling. */
const PG_STRING = /(?<![A-Za-z0-9-])PG-[A-Z0-9]+(?:-[A-Z0-9]+)*[*~$=!]?(?![A-Za-z0-9])/g;
function noPg(v, wire, code) {
  if (typeof v === "string") return v.split(wire).join(code).replace(PG_STRING, "(a retired code)");
  if (Array.isArray(v)) return v.map((x) => noPg(x, wire, code));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, noPg(x, wire, code)]));
  return v;
}

/* The route a registry publishes: resolver_url_template of its /.well-known/pg-policy, on its own host; without one,
   /v1/pg/{code}, the route this site asked before. A policy answer is kept an hour. A registry announces TOG when its
   template is the lookup.md route, .../v2/codes/{code}. */
const POLICY_TTL = 60 * 60_000;
const policies = new Map();

async function resolverTemplate(api, signal) {
  const e = policies.get(api);
  if (e && Date.now() - e.t < POLICY_TTL) return e.template;
  let template = api + "/v1/pg/{code}";
  try {
    const r = await fetch(api + "/.well-known/pg-policy", { headers: { Accept: "application/json" }, signal });
    const t = r.ok ? (await r.json().catch(() => ({}))).resolver_url_template : null;
    if (typeof t === "string" && t.includes("{code}") && new URL(t.replace("{code}", "x")).origin === new URL(api).origin) template = t;
    policies.set(api, { t: Date.now(), template });
  } catch { /* unreachable: not kept; the lookup itself says so */ }
  return template;
}

/* TRANSITION SHIM, inside this proxy only (TOG-CODE.md §12). A registry not yet migrated (prampta.com today reads only
   PG- at /v1/pg/{code}, and bare codes at /v1/subjects/{code}) is asked for a person of the old shape in the PG
   spelling: PG + the TOG code after its marker, the same serial and check. Nothing else is asked there: any other
   code at such a registry is "not found". The answer is shown under the TOG code; users never type or see PG-.
   REMOVE this shim, the /v1 branches below and asLookup's /v1 shapes when every listed registry's
   .well-known/pg-policy announces TOG (resolver_url_template ending /v2/codes/{code}). */
function shimWire(c) {
  return c.shape.startsWith("old_") ? "PG" + c.code.slice(3) : null;
}

/* Both answer shapes read as extensions/lookup.md's: /v1 answers ({kind, found, status}, a subject record) gain the
   TOG code asked; a registry's "not found" is lookup.md's "unknown". A subject record (`record`) gives only what the
   site's card always showed: lookup.md's fields, and the registry's own words about owner, type and authority. */
function asLookup(status, body, code, record) {
  if (status === 404 && (body?.error === "not_found" || /^(Subject|License) not found$/.test(body?.detail))) {
    return [200, { code, status: "unknown" }];
  }
  if (status !== 200 || !body || typeof body !== "object" || Array.isArray(body)) return [status, body];
  if (record) {
    const d = body;
    return [200, { code, kind: "subject", status: d.status, visibility: d.visibility, aliases: d.aliases,
      owner_verified: d.owner_verified, subject_type: d.subject_type, lifecycle_status: d.lifecycle_status,
      authority_status: d.authority_status, subject_key: { public_key_hex: d.public_key_hex, custody: d.key_custody },
      rules_text: d.rules_text, registered_at: d.registered_at }];
  }
  const { found, ...rest } = body;
  return [200, { code, ...rest }];
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

  /* The steward's word beats the registry's: a false claim or a revoked registry is never asked. Compared by the code
     itself: a PG- line names no one. */
  const falseClaim = (REGISTRIES.false_claims || []).find((f) => f.code === c.code);
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
  const headers = { Accept: "application/json" };
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 5000);
  try {
    const template = await resolverTemplate(registry.api, ctrl.signal);
    let url, wire = c.code, record = false;
    if (template.endsWith("/v2/codes/{code}")) {
      url = template.replace("{code}", encodeURIComponent(c.code));                // a migrated registry: TOG only
    } else {
      wire = shimWire(c);                                                          // the transition shim (above)
      if (!wire) {
        const body = { code: c.code, status: "unknown" };
        cacheSet(c.code, 200, body);
        res.status(200).json(body);
        return;
      }
      if (!c.issuer) {
        /* A bare code at the origin registry, as before: its public subject record. */
        url = (process.env.PRAMPTA_API_URL || registry.api) + "/v1/subjects/" + encodeURIComponent(wire);
        record = true;
        if (process.env.PRAMPTA_TOKEN) headers.Authorization = "Bearer " + process.env.PRAMPTA_TOKEN;
      } else {
        url = template.replace("{code}", encodeURIComponent(wire));
      }
    }
    const upstream = await fetch(url, { headers, signal: ctrl.signal });
    const [status, raw] = asLookup(upstream.status, await upstream.json().catch(() => ({})), c.code, record);
    const body = noPg(raw, wire, c.code);
    if (status < 500) cacheSet(c.code, status, body);
    res.status(status).json(body);
  } catch (e) {
    res.status(502).json({ error: "registry_unreachable" });
  } finally {
    clearTimeout(timer);
  }
};
