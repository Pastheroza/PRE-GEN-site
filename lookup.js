/* PRE-GEN registry lookup — page logic. Typed input folds with the library's own rules (TOG-CODE.md §7.4); only ToG
   codes are shown. PG codes are retired: a typed PG- string gets one neutral message and no TOG suggestion. */
import { normalizeTyped, CodeError, RETIRED } from "/packages/verify-js/index.js";

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
  var d = new Date(typeof v === "number" ? v * 1000 : v);
  if (isNaN(d)) return esc(v);
  return d.toISOString().slice(0, 10);
}

function link(url, text) {   // a registry's link, only if it is https
  return /^https:\/\//.test(String(url)) ? '<a class="pg-link" href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + esc(text) + " ↗</a>" : "";
}

function row(label, value) {
  if (value === null || value === undefined || value === "") return "";
  return '<div class="pg-row"><dt>' + label + '</dt><dd>' + value + "</dd></div>";
}

/* The registry's answer (spec/extensions/lookup.md), every code already in its TOG spelling (api/lookup.js). */
/* lookup.md, ToG codes: what pending and expired mean, in plain words. */
var STATUS = {
  pending: "Not verified yet. It permits nothing and forbids nothing. A code not verified within 7 days of its issue is deleted.",
  expired: "Deleted: it was not verified within 7 days. It permits nothing and forbids nothing, and is never issued again."
};

function renderAnswer(d) {
  var key = d.subject_key || {};
  var known = ["code", "kind", "status", "registry", "name", "level", "subject_key", "terms", "status_url", "moved",
    "alias", "issued_at", "directory", "visibility", "aliases", "owner_verified", "subject_type", "lifecycle_status",
    "authority_status", "rules_text", "registered_at", "holder", "domain", "subject", "subject_level", "conditions"];
  /* lookup.md, Conditions: a person's own words come first, as plain text, their line breaks kept (styles.css: the CSP
     refuses a style attribute). */
  var rows = row("Conditions", d.conditions ? '<span class="pg-said">' + esc(d.conditions) + "</span>" : "")
    + row("Status", STATUS[d.status] || "")
    + row("Name", esc(d.name))
    + row("Holder", d.holder === "company" ? "a company" : d.holder === "person" ? "a person" : esc(d.holder))
    + row("Domain", esc(d.domain))
    /* A licence or record is tied to one ToG code; its level says whether that holder's identity is verified. */
    + row("ToG code", d.subject ? '<span class="mono">' + esc(d.subject) + "</span>"
      + (d.subject_level ? " · " + (d.subject_level === "verified" ? "identity verified" : esc(d.subject_level) + ", identity not verified") : "") : "")
    + row("Aliases", (d.aliases || []).map(esc).join(" · "))
    /* The registry's own word about the owner: never a badge. Only a claim the person confirmed on their own
       channel (spec/extensions/identity.md) may earn one, and this page does not check that yet. */
    + row("Owner", d.owner_verified === true ? "the registry says it verified the owner" : d.owner_verified === false ? "the registry says it did not verify the owner" : "")
    /* The registry's own word about who may decide for the person: a claim, never a badge (lookup.md, Level). */
    + row("Level", d.level ? esc(d.level) + " (the registry's claim)" : "")
    + row("Registry", esc(d.registry))
    + row("Type", esc(d.subject_type))
    + row("Lifecycle", esc(d.lifecycle_status))
    + row("Authority", esc(d.authority_status))
    + row("Key custody", esc(key.custody))
    + row("Subject key", key.key_id ? '<span class="mono">' + esc(key.key_id) + "</span>"
      : key.public_key_hex ? '<span class="mono">' + esc(String(key.public_key_hex).slice(0, 20)) + "…</span>" : "")
    + row("Rules", esc(d.rules_text))
    + row("Terms", d.terms && d.terms.url ? link(d.terms.url, "current terms") : "")
    + row("Status page", link(d.status_url, "every version"))
    + row("Moved to", esc(d.moved))
    + row("Joined with", d.alias ? '<span class="mono">' + esc(d.alias) + "</span>" : "")
    + row("Issued", fmtDate(d.issued_at))
    + row("Registered", fmtDate(d.registered_at));
  for (var k in d) {
    if (known.indexOf(k) >= 0 || ["string", "number", "boolean"].indexOf(typeof d[k]) < 0) continue;
    rows += row(esc(k.replace(/_/g, " ")), esc(d[k]));
  }
  return '<article class="pg-card">'
    + '<div class="pg-card-head"><span class="pg-code">' + esc(d.code || "") + "</span>"
    + badge(d.status || "unknown", d.status === "active" || d.status === "valid" ? "ok" : "")
    + (d.visibility ? badge(d.visibility) : d.kind && d.kind !== "subject" ? badge(d.kind) : "") + "</div>"   // a person needs no kind word
    + '<dl class="pg-rows">' + rows + "</dl>"
    + '<div class="pg-card-foot">Resolved live from the registry that holds the code. Everything above is what the registry says. Identity: not confirmed on the person’s own channel by pregen.org. This is public metadata — it is not a generation permission. Providers need a signed allow from <span class="mono">POST /v2/requests</span>.</div>'
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

/* { code } or { error, hint }. */
function read(raw) {
  if (!String(raw || "").trim()) return { error: "Enter a code to resolve.", hint: "" };
  try {
    return { code: normalizeTyped(String(raw)) };
  } catch (e) {
    if (!(e instanceof CodeError)) throw e;
    if (e.message === RETIRED) return { error: RETIRED, hint: "" };
    if (e.hints) return { error: "Two codes match: " + e.hints.join(" or ") + ".", hint: "Type the one you mean." };
    if (e.reason === "mistyped") return { error: "Mistyped code.", hint: "The check character does not fit: compare the code with its source." };
    return { error: "Not a code.", hint: "A person: TOG-PRAM-000037J · a licence: TOG-LIC-…" };
  }
}

function run(raw) {
  var c = read(raw);
  if (c.error) { out.innerHTML = renderError(c.error, c.hint); return; }
  input.value = c.code;
  if (busy) return;
  busy = true;
  var named = c.code;
  out.innerHTML = '<article class="pg-card pg-card--pending"><span class="pg-prompt">&gt;_</span> resolving ' + esc(named) + " …</article>";
  fetch("/api/lookup?code=" + encodeURIComponent(c.code))
    .then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); })
    .then(function (res) {
      var d = res.body || {};
      var tog = /^TOG-/.test(d.code || "");
      if (tog) named = d.code;
      if (res.status === 200 && d.status === "unknown") out.innerHTML = renderError("Nothing is published under " + named + ".",
        "Either no one holds it, or the person chose not to be public: a registry answers both the same way.");
      else if (res.status === 200 && d.status === "other_registry") out.innerHTML = renderError("Another registry holds " + named + ".",
        "Ask the registry its prefix names.", '<p><a class="pg-link" href="/registries">Registries</a></p>');
      else if (res.status === 200) out.innerHTML = renderAnswer(d);
      else if (res.status === 404 && d.error === "unknown_issuer") out.innerHTML = renderError("No listed registry holds the prefix " + (d.issuer || "") + ".",
        "The code is well-formed. Its registry isn't on the registry list yet.",
        '<p><a class="pg-link" href="/registries">Registries</a></p>');
      else if (res.status === 410 && d.error === "false_claim") out.innerHTML = renderError("False claim: the steward recorded " + named + " as a false claim" + (d.at ? " on " + fmtDate(d.at) : "") + ".",
        "Whoever holds this code does not speak for the person. Nothing the registry says about it is shown.");
      else if (res.status === 410) out.innerHTML = renderError("Revoked: the registry that issued " + named + " was revoked" + (d.at ? " on " + fmtDate(d.at) : "") + ".",
        "Its codes no longer count. Nothing it says about this code is shown.");
      else if (res.status === 429) out.innerHTML = renderError("Too many requests.", "Give it a minute and try again.");
      else if (res.status === 400 || res.status === 422) out.innerHTML = renderError(   // the proxy's own refusals never reach a registry
        (/^(missing_code|invalid_code|check_mismatch)$/.test(d.error || "") ? "The resolver" : "The registry") + " did not accept this code.",
        typeof d.detail === "string" ? d.detail : "");
      else out.innerHTML = renderError("Registry is not reachable right now.", "Try again in a moment." + (d.error ? " (" + d.error + ")" : ""));
      if (tog && window.history && window.history.replaceState)
        window.history.replaceState(null, "", "/lookup?code=" + encodeURIComponent(d.code));
    })
    .catch(function () {
      out.innerHTML = renderError("Network error.", "Could not reach the resolver. Try again in a moment.");
    })
    .then(function () { busy = false; });
}

form.addEventListener("submit", function (e) { e.preventDefault(); run(input.value); });
var initial = new URLSearchParams(window.location.search).get("code");
if (initial) run(initial);
else input.focus();
