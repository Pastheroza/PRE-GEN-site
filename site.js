// Header menu (phones) and theme choice (every page).
(function () {
  var root = document.documentElement;
  var btn = document.querySelector(".menu-btn");
  var menu = document.getElementById("site-menu");

  function setOpen(open) {
    root.classList.toggle("menu-open", open);
    if (btn) {
      btn.setAttribute("aria-expanded", open ? "true" : "false");
      btn.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    }
  }
  if (btn && menu) {
    btn.addEventListener("click", function () { setOpen(!root.classList.contains("menu-open")); });
    menu.addEventListener("click", function (e) { if (e.target.closest("a")) setOpen(false); });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && root.classList.contains("menu-open")) { setOpen(false); btn.focus(); }
    });
    // Leaving phone width with the menu open must not leave the page locked.
    window.matchMedia("(min-width: 721px)").addEventListener("change", function (m) { if (m.matches) setOpen(false); });
  }

  var choices = document.querySelectorAll("[data-set-theme]");
  function current() { return root.getAttribute("data-theme") || "system"; }
  function mark() {
    choices.forEach(function (b) { b.setAttribute("aria-pressed", b.getAttribute("data-set-theme") === current() ? "true" : "false"); });
  }
  choices.forEach(function (b) {
    b.addEventListener("click", function () {
      var t = b.getAttribute("data-set-theme");
      try {
        if (t === "system") localStorage.removeItem("pg-theme"); else localStorage.setItem("pg-theme", t);
      } catch (e) {}
      if (t === "system") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", t);
      mark();
    });
  });
  mark();
})();
