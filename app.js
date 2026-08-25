/* PRE-GEN Foundation — pregen.org */
(function () {
  "use strict";

  /* Theme: respects pp-theme ("light"/"dark"), else system preference. */
  var themeBtns = document.querySelectorAll("[data-theme-toggle]");
  function applyTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    themeBtns.forEach(function (b) { b.setAttribute("aria-label", "Toggle theme (current: " + t + ")"); });
  }
  var stored = null;
  try { stored = localStorage.getItem("pp-theme"); } catch (e) {}
  applyTheme(stored === "dark" || stored === "light" ? stored
    : (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));
  themeBtns.forEach(function (b) {
    b.addEventListener("click", function () {
      var cur = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      applyTheme(cur);
      try { localStorage.setItem("pp-theme", cur); } catch (e) {}
    });
  });

  /* Mobile drawer */
  var drawer = document.getElementById("drawer");
  var backdrop = document.getElementById("drawerBackdrop");
  function openDrawer() { drawer.classList.add("open"); backdrop.classList.add("open"); document.body.style.overflow = "hidden"; }
  function closeDrawer() { drawer.classList.remove("open"); backdrop.classList.remove("open"); document.body.style.overflow = ""; }
  var openBtn = document.getElementById("menuOpen");
  var closeBtn = document.getElementById("menuClose");
  if (openBtn) openBtn.addEventListener("click", openDrawer);
  if (closeBtn) closeBtn.addEventListener("click", closeDrawer);
  if (backdrop) backdrop.addEventListener("click", closeDrawer);
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeDrawer(); });

  /* Cookie consent: pp-cookies = "all" | "necessary" | "rejected" */
  var banner = document.getElementById("cookieBanner");
  if (banner) {
    var choice = null;
    try { choice = localStorage.getItem("pp-cookies"); } catch (e) {}
    if (!choice) banner.classList.add("show");
    banner.querySelectorAll("[data-cookie]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        try { localStorage.setItem("pp-cookies", btn.getAttribute("data-cookie")); } catch (e) {}
        banner.classList.remove("show");
      });
    });
  }

  /* Footer link: clear consent choice and reopen the banner */
  document.querySelectorAll("[data-cookie-reset]").forEach(function (link) {
    link.addEventListener("click", function (e) {
      e.preventDefault();
      try { localStorage.removeItem("pp-cookies"); } catch (err) {}
      if (banner) banner.classList.add("show");
    });
  });

  /* FAQ accordions */
  document.querySelectorAll(".faq-q").forEach(function (q) {
    q.addEventListener("click", function () {
      q.closest(".faq-item").classList.toggle("open");
    });
  });

  /* Refusal-code filter chips */
  var chips = document.querySelectorAll(".chip[data-filter]");
  if (chips.length) {
    chips.forEach(function (chip) {
      chip.addEventListener("click", function () {
        var f = chip.getAttribute("data-filter");
        chips.forEach(function (c) { c.classList.toggle("on", c === chip); });
        document.querySelectorAll("[data-category]").forEach(function (row) {
          row.style.display = (f === "all" || row.getAttribute("data-category") === f) ? "" : "none";
        });
      });
    });
  }
})();
