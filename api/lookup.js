/* PRE-GEN registry lookup proxy — pregen.org/api/lookup?code=PG-...
   Read-only. Subjects resolve publicly; licenses require a registry token
   provided via the PRAMPTA_TOKEN environment variable (never sent to the client). */

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

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "GET") {
    res.status(405).json({ error: "method_not_allowed" });
    return;
  }
  const c = classify(req.query && req.query.code);
  if (c.error) {
    res.status(c.status).json({ error: c.error, detail: c.detail });
    return;
  }
  const base = process.env.PRAMPTA_API_URL || "https://api2.prampta.com";
  const path = (c.kind === "license" ? "/v1/licenses/" : "/v1/subjects/") + encodeURIComponent(c.code);
  const headers = { Accept: "application/json" };
  const token = process.env.PRAMPTA_TOKEN;
  if (token) headers["Authorization"] = "Bearer " + token;
  try {
    const upstream = await fetch(base + path, { headers });
    const body = await upstream.json().catch(() => ({}));
    res.status(upstream.status).json(body);
  } catch (e) {
    res.status(502).json({ error: "registry_unreachable" });
  }
};
