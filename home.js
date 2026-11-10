/* Homepage: who uses PRE-GEN, from the signed list of registries and providers (registries.json).
   The page shows the list; it does not verify the steward's signature (the libraries do). */
(function () {
  "use strict";

  function item(name, url) {
    var li = document.createElement("li");
    if (url && /^https:\/\//.test(url)) {
      var a = document.createElement("a");
      a.href = url;
      a.textContent = name;
      a.rel = "noopener";
      li.appendChild(a);
    } else {
      li.textContent = name;
    }
    return li;
  }

  function fill(id, entries) {
    var ul = document.getElementById(id);
    if (!ul || !entries.length) return;   // keep the markup's own text: PRAMPTA, or "None listed yet"
    ul.textContent = "";
    entries.forEach(function (e) { ul.appendChild(item(e.name, e.url)); });
  }

  fetch("/registries.json", { credentials: "omit" })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (d) {
      if (!d) return;
      var seen = {}, regs = [], ais = [];
      (d.registries || []).forEach(function (r) {   // one line per registry, however many namespaces it holds
        var name = String(r.name || "").trim();
        if (name && !seen[name]) { seen[name] = 1; regs.push({ name: name, url: r.website }); }
      });
      (d.providers || []).forEach(function (p) {
        var name = typeof p === "string" ? p : String(p.name || p.id || "").trim();
        if (name) ais.push({ name: name, url: typeof p === "string" ? p : p.website || p.id });
      });
      fill("users-reg", regs);
      fill("users-ai", ais);
    })
    .catch(function () { /* the markup's own text stays */ });
})();
