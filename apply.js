/* Registry application (PG-CODE.md §9, §9.1). No backend: the answers become a
   public GitHub issue the applicant submits — prefixes are assigned in the open. */
(function () {
  "use strict";
  var REPO = "https://github.com/Pastheroza/PRE-GEN-site/issues/new";
  var PREFIX = /^[ABCDEFGHJKMNPQRSTVWXYZ]{4}$/;
  var form = document.getElementById("applyForm");
  var errors = document.getElementById("applyErrors");
  var taken = null; // prefixes already in the signed directory

  fetch("/registries.json").then(function (r) { return r.json(); }).then(function (d) {
    taken = {};
    (d.registries || []).forEach(function (r) { if (r.prefix) taken[r.prefix] = r.name; });
    ["prefix", "prefix2"].forEach(function (id) { if (document.getElementById(id).value) check(id, id === "prefix"); });
  }).catch(function () { /* the steward checks again; the form still works */ });

  function prefixProblem(v, required) {
    if (!v) return required ? "Enter four letters." : "";
    if (!PREFIX.test(v)) return "Four letters from ABCDEFGHJKMNPQRSTVWXYZ only — no digits, no I, L, O or U.";
    if (taken && taken[v]) return v + " is held by " + taken[v] + ". Prefixes are never reassigned.";
    return "";
  }

  function check(id, required) {
    var el = document.getElementById(id);
    el.value = el.value.toUpperCase().replace(/\s/g, "");
    var help = document.getElementById(id + "Help");
    var p = prefixProblem(el.value, required);
    el.setAttribute("aria-invalid", p ? "true" : "false");
    if (p) help.textContent = p;
    else if (el.value) help.textContent = taken ? el.value + " is free in the current directory." : el.value + " has the right shape.";
    else help.textContent = id === "prefix" ? "Four letters from ABCDEFGHJKMNPQRSTVWXYZ — no digits, no I, L, O or U." : "";
    help.dataset.state = p ? "bad" : el.value ? "ok" : "";
    return p;
  }

  ["prefix", "prefix2"].forEach(function (id) {
    document.getElementById(id).addEventListener("input", function () { check(id, id === "prefix"); });
  });

  function httpsOnly(v) {
    try { var u = new URL(v); return u.protocol === "https:" && !u.username && !u.password && !u.search && !u.hash; }
    catch (e) { return false; }
  }

  /* A label as a list item: the first words, cut at a word. */
  function short(el) {
    var t = (el.labels[0] ? el.labels[0].textContent : el.id).replace(/\s+/g, " ").trim();
    return t.length <= 60 ? t : t.slice(0, t.lastIndexOf(" ", 60)) + "…";
  }

  function val(id) { return document.getElementById(id).value.trim(); }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var problems = [];
    var p1 = check("prefix", true), p2 = check("prefix2", false);
    if (p1) problems.push(["prefix", "Prefix: " + p1]);
    if (p2) problems.push(["prefix2", "Second choice: " + p2]);
    if (!p1 && val("prefix") === val("prefix2")) problems.push(["prefix2", "The second choice is the same as the first."]);
    Array.prototype.forEach.call(form.querySelectorAll("[required]"), function (el) {
      if (el.id === "prefix") return;
      var empty = el.type === "checkbox" ? !el.checked : !el.value.trim();
      if (empty) problems.push([el.id, short(el) + ": required."]);
      el.setAttribute("aria-invalid", empty ? "true" : "false");
    });
    ["website", "policy", "api"].forEach(function (id) {
      if (val(id) && !httpsOnly(val(id))) { problems.push([id, document.getElementById(id).labels[0].textContent + ": an https:// URL without credentials, query or fragment."]); document.getElementById(id).setAttribute("aria-invalid", "true"); }
    });
    var keys = val("keys").split(/\s+/).filter(Boolean);
    var badKey = keys.filter(function (k) { return !/^pg-ed25519:[0-9a-f]{32}$/.test(k); });
    if (keys.length && badKey.length) { problems.push(["keys", "Key fingerprints look like pg-ed25519: and 32 lowercase hex characters. Not: " + badKey.slice(0, 2).join(", ")]); document.getElementById("keys").setAttribute("aria-invalid", "true"); }

    if (problems.length) {
      errors.hidden = false;
      errors.innerHTML = "";
      var h = document.createElement("p"); h.textContent = "Fix " + (problems.length === 1 ? "this" : "these " + problems.length) + " first:"; errors.appendChild(h);
      var ul = document.createElement("ul");
      problems.forEach(function (pr) {
        var li = document.createElement("li"), a = document.createElement("a");
        a.href = "#" + pr[0]; a.textContent = pr[1];
        a.addEventListener("click", function (ev) { ev.preventDefault(); document.getElementById(pr[0]).focus(); });
        li.appendChild(a); ul.appendChild(li);
      });
      errors.appendChild(ul);
      errors.setAttribute("tabindex", "-1"); errors.focus();
      return;
    }
    errors.hidden = true;

    var api = val("api").replace(/\/+$/, "");
    var body = [
      "**Prefix asked for:** `" + val("prefix") + "`" + (val("prefix2") ? " (second choice: `" + val("prefix2") + "`)" : ""),
      "",
      "**1. Operator**",
      "- Legal name: " + val("operator"),
      "- Public address: " + val("address"),
      "- Contact for complaints and disputes: " + val("complaints"),
      "- Website: " + val("website"),
      "",
      "**2. Published policy** — " + val("policy"),
      "- How rights holders are verified: " + val("verify").replace(/\n+/g, " "),
      "- Anchor for every public person: " + val("anchor"),
      "",
      "**3. The core.** I accept the core, its floor of protections, the rule for a subject held by several registries (R-15, P-10) and the revocation grounds of PG-CODE.md §9.1. **yes**",
      "",
      "**4. Endpoints**",
      "- `api`: " + api,
      "- `keys`: " + api + "/keys",
      "- `/.well-known/pregen-registry.json`: " + api + "/.well-known/pregen-registry.json",
      "- Profiles: " + val("profiles"),
      "",
      "**5. Keys** (also sent to the steward by a second channel)",
      keys.map(function (k) { return "- `" + k + "`"; }).join("\n"),
      "",
      "**6. Conformance**",
      "```",
      val("conformance") || "(not run yet)",
      "```",
      "",
      "**Status:** " + val("status"),
      "",
      "_Sent with the form at https://www.pregen.org/apply_",
    ].join("\n");
    var title = "Registry application: " + val("prefix") + " — " + val("operator");
    window.open(REPO + "?title=" + encodeURIComponent(title) + "&body=" + encodeURIComponent(body), "_blank", "noopener");
  });
})();
