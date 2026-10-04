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
    // A click anywhere outside the header closes the panel.
    document.addEventListener("click", function (e) {
      if (root.classList.contains("menu-open") && !e.target.closest(".top")) setOpen(false);
    });
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

// A Copy button on every code block.
(function () {
  document.querySelectorAll("pre").forEach(function (pre) {
    var box = document.createElement("div");
    box.className = "code";
    pre.parentNode.insertBefore(box, pre);
    box.appendChild(pre);
    var b = document.createElement("button");
    b.type = "button";
    b.className = "copy";
    b.textContent = "Copy";
    b.setAttribute("aria-label", "Copy code");
    box.appendChild(b);
    b.addEventListener("click", function () {
      var text = pre.innerText.replace(/\n$/, "");
      function done(ok) {
        b.textContent = ok ? "Copied" : "Select and copy";
        setTimeout(function () { b.textContent = "Copy"; }, 1600);
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
      } else {
        var r = document.createRange(); r.selectNodeContents(pre);
        var sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(r);
        var ok = false; try { ok = document.execCommand("copy"); } catch (e) {}
        done(ok);
      }
    });
  });
})();
