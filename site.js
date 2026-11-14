// Header menu (every page).
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

  // More (wide screens): a short list under the band. Escape, a click outside or focus leaving it closes it.
  var more = document.querySelector(".nav-group-btn");
  var list = document.getElementById("nav-more");
  if (more && list) {
    var show = function (open) {
      list.classList.toggle("open", open);
      more.setAttribute("aria-expanded", open ? "true" : "false");
    };
    more.addEventListener("click", function () { show(more.getAttribute("aria-expanded") !== "true"); });
    document.addEventListener("click", function (e) { if (!e.target.closest(".nav-group")) show(false); });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && more.getAttribute("aria-expanded") === "true") { show(false); more.focus(); }
    });
    list.parentNode.addEventListener("focusout", function (e) {
      if (!list.parentNode.contains(e.relatedTarget)) show(false);
    });
  }
})();

// Copy text to the clipboard; the button says whether it worked.
function pgCopy(text, b, label) {
  function done(ok) {
    b.textContent = ok ? "Copied" : "Select and copy";
    setTimeout(function () { b.textContent = label; }, 1600);
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
  } else {
    done(false);
  }
}

// Docs: a # after each section title, so a section can be linked to.
document.querySelectorAll(".doc article h2[id]").forEach(function (h) {
  var a = document.createElement("a");
  a.className = "anchor";
  a.href = "#" + h.id;
  a.textContent = "#";
  a.setAttribute("aria-label", "Link to this section: " + h.textContent);
  h.appendChild(a);
});

// Docs on a phone: the sidebar is one row that scrolls sideways; bring the current page into view.
(function () {
  var cur = document.querySelector(".doc aside a[aria-current]");
  var ul = cur && cur.closest("ul");
  if (ul && ul.scrollWidth > ul.clientWidth) ul.scrollLeft = cur.getBoundingClientRect().left - ul.getBoundingClientRect().left - 16;
})();

// A Copy button for one value (data-copy holds it).
document.querySelectorAll("button[data-copy]").forEach(function (b) {
  var label = b.textContent;
  b.addEventListener("click", function () { pgCopy(b.getAttribute("data-copy"), b, label); });
});

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
