/* PRE-GEN registry lookup — page logic */
(function () {
  "use strict";

  var ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  var CHECK = ALPHABET + "*~$=!";

  function checkChar(body) {
    var sum = 0;
    for (var i = 0; i < body.length; i++) sum += CHECK.indexOf(body[i]) * (i + 1);
    return CHECK[sum % 37];
  }

  function normalize(raw) {
    return String(raw || "").trim().toUpperCase().replace(/\s+/g, "");
  }

  /* Returns { kind: "subject"|"license", code } or { error, hint } */
  function classify(code) {
    if (!code) return { error: "Enter a PG code to resolve.", hint: "" };
    if (code.indexOf("PG") !== 0 && code.indexOf("PG-") !== 0)
      return { error: "Codes start with the literal prefix “PG-”.", hint: "" };
    var rest = code.slice(3);
    if (/[ILOU]/.test(rest))
      return { error: "“" + (/./.exec(rest.split("").find(function (ch) { return "ILOU".indexOf(ch) >= 0; })) || ["?"])[0] + "” is never used in a PG body — Crockford base32 excludes I, L, O, U.", hint: "I and L are usually mistyped 1; O is usually a zero “0”." };
    var m;
    /* license: PG-CLASS-serial-tail+check */
    m = /^([A-Z]{3})-([0-9]{6,})-([0-9A-Z]{6})([0-9A-Z*~$=!])$/.exec(rest);
    if (m) {
      if (CHECK.indexOf(m[4]) < 0) return { error: "“" + m[4] + "” is not a valid check character.", hint: "Check characters come from: 0-9, A-Z (no I L O U), and * ~ $ = !" };
      var expect = checkChar(m[1] + m[2] + m[3]);
      if (m[4] !== expect) return { error: "Check character mismatch: expected “" + expect + "”, got “" + m[4] + "”.", hint: "A wrong check usually means a mistyped character — check the code against its source." };
      return { kind: "license", code: "PG-" + rest };
    }
    /* subject legacy with class: PG-STD-000123 / PG-SUB-000123 */
    m = /^(STD|SUB|PRM|RND)-([0-9]{4,})$/.exec(rest);
    if (m) return { kind: "subject", code: "PG-" + rest };
    /* subject legacy all digits */
    m = /^([0-9]{4,})$/.exec(rest);
    if (m) return { kind: "subject", code: "PG-" + rest };
    /* subject current: body + check */
    m = /^([0-9A-Z]{6,})([0-9A-Z*~$=!])$/.exec(rest);
    if (m) {
      var expect2 = checkChar(m[1]);
      if (m[2] !== expect2) return { error: "Check character mismatch: expected “" + expect2 + "”, got “" + m[2] + "”.", hint: "The check character catches every single-character typo — compare the code with its source." };
      return { kind: "subject", code: "PG-" + rest };
    }
    return { error: "That doesn’t match either PG code shape.", hint: "Subject: PG-000042* · License: PG-STD-000001-K7M2QX9" };
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }

  function badge(text, cls) {
    return '<span class="pg-badge ' + (cls || "") + '">' + esc(text) + "</span>";
  }

  function fmtDate(v) {
    if (!v) return null;
    var d = new Date(v);
    if (isNaN(d)) return esc(v);
    return d.toISOString().slice(0, 10);
  }

  function row(label, value) {
    if (value === null || value === undefined || value === "") return "";
    return '<div class="pg-row"><dt>' + label + '</dt><dd>' + value + "</dd></div>";
  }

  function renderSubject(d) {
    var aliases = (d.aliases || []).map(esc).join(" · ");
    var verified = d.owner_verified === true
      ? badge("owner verified", "ok")
      : d.owner_verified === false ? badge("owner unverified", "warn") : "";
    var html = '<article class="pg-card">'
      + '<div class="pg-card-head"><span class="pg-code">' + esc(d.pg_code || "") + "</span>"
      + badge(d.status || "unknown", d.status === "active" ? "ok" : "")
      + (d.visibility ? badge(d.visibility) : "") + verified + "</div>"
      + '<dl class="pg-rows">'
      + row("Aliases", aliases)
      + row("Type", esc(d.subject_type))
      + row("Lifecycle", esc(d.lifecycle_status))
      + row("Authority", esc(d.authority_status))
      + row("Key custody", esc(d.key_custody))
      + row("Subject key", d.public_key_hex ? '<span class="mono">' + esc(String(d.public_key_hex).slice(0, 20)) + "…</span>" : "")
      + row("Rules", d.rules_text ? esc(d.rules_text) : "")
      + row("Registered", fmtDate(d.registered_at))
      + "</dl>"
      + '<div class="pg-card-foot">Resolved live from the PRE-GEN registry. This is public metadata — it is not a generation permission. Providers need a signed <span class="mono">/v1/verify/</span> decision.</div>'
      + "</article>";
    return html;
  }

  function renderLicense(d) {
    var known = ["license_id", "pg_code", "status", "license_class", "subject_id", "subject_pg_code",
      "modality", "channel", "territory", "valid_from", "valid_until", "issued_at", "revoked_at", "price"];
    var rows = "";
    for (var i = 0; i < known.length; i++) {
      var k = known[i];
      if (d[k] === null || d[k] === undefined || d[k] === "") continue;
      var v = d[k];
      if (k === "valid_from" || k === "valid_until" || k === "issued_at" || k === "revoked_at") v = fmtDate(v);
      rows += row(k.replace(/_/g, " "), esc(v));
    }
    for (var k2 in d) {
      if (known.indexOf(k2) >= 0 || typeof d[k2] !== "string" || !d[k2]) continue;
      rows += row(k2.replace(/_/g, " "), esc(d[k2]));
    }
    return '<article class="pg-card">'
      + '<div class="pg-card-head"><span class="pg-code">' + esc(d.license_id || d.pg_code || "") + "</span>"
      + badge(d.status || "unknown", d.status === "active" ? "ok" : d.status === "revoked" ? "warn" : "")
      + (d.license_class ? badge(d.license_class) : "") + "</div>"
      + '<dl class="pg-rows">' + rows + "</dl>"
      + '<div class="pg-card-foot">Resolved live from the PRE-GEN registry. Scope fields define what this license permits — see <a href="/docs/versions">versioning</a> for semantics.</div>'
      + "</article>";
  }

  function renderError(title, hint, extra) {
    return '<article class="pg-card pg-card--error"><div class="pg-card-head"><span class="pg-code">✕</span>'
      + badge("error", "warn") + "</div><p>" + esc(title) + "</p>"
      + (hint ? '<p class="dim">' + esc(hint) + "</p>" : "") + (extra || "") + "</article>";
  }

  var form = document.getElementById("pgForm");
  var input = document.getElementById("pgInput");
  var out = document.getElementById("pgResult");
  var busy = false;

  function run(raw) {
    var code = normalize(raw);
    input.value = code;
    var c = classify(code);
    if (c.error) { out.innerHTML = renderError(c.error, c.hint); return; }
    if (busy) return;
    busy = true;
    out.innerHTML = '<article class="pg-card pg-card--pending"><span class="pg-prompt">&gt;_</span> resolving ' + esc(c.code) + " …</article>";
    fetch("/api/lookup?code=" + encodeURIComponent(c.code))
      .then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); })
      .then(function (res) {
        var d = res.body || {};
        if (res.status === 200 && c.kind === "subject") out.innerHTML = renderSubject(d);
        else if (res.status === 200) out.innerHTML = renderLicense(d);
        else if (res.status === 404) out.innerHTML = renderError("Nothing is registered under " + c.code + ".", "The code is well-formed but the registry has no record for it.");
        else if (res.status === 401 || res.status === 403) out.innerHTML = renderError("License records are restricted.",
          "Public resolution covers subjects. Full license records require registry credentials — verify the license via prampta.com or ask the rights holder for a signed decision.",
          '<p><a class="pg-link" href="https://prampta.com" target="_blank" rel="noopener noreferrer">prampta.com ↗</a></p>');
        else if (res.status === 422) out.innerHTML = renderError(d.error || "Invalid code.", d.detail || "");
        else out.innerHTML = renderError("Registry is not reachable right now.", "Try again in a moment." + (d.error ? " (" + d.error + ")" : ""));
      })
      .catch(function () {
        out.innerHTML = renderError("Network error.", "Could not reach the resolver. Try again in a moment.");
      })
      .then(function () { busy = false; });
    if (window.history && window.history.replaceState)
      window.history.replaceState(null, "", "/lookup?code=" + encodeURIComponent(c.code));
  }

  form.addEventListener("submit", function (e) { e.preventDefault(); run(input.value); });
  var initial = new URLSearchParams(window.location.search).get("code");
  if (initial) run(initial);
  else input.focus();
})();
