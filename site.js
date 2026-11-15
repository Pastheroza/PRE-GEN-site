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

// Tables on phones: each cell carries its column's name, so a row can be read as a short list.
document.querySelectorAll(".table table").forEach(function (t) {
  var names = Array.prototype.map.call(t.querySelectorAll("thead th"), function (th) { return th.textContent.trim(); });
  if (names.length < 3) return;
  t.classList.add("stack");
  t.querySelectorAll("tbody tr").forEach(function (tr) {
    Array.prototype.forEach.call(tr.children, function (td, i) { if (names[i] && !td.hasAttribute("colspan")) td.setAttribute("data-label", names[i]); });
  });
});

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

// Copy for AI: this page as plain text, with its address, to paste into any assistant.
document.querySelectorAll(".ask-copy").forEach(function (b) {
  var label = b.textContent;
  b.addEventListener("click", function () {
    var main = document.getElementById("main");
    pgCopy(document.title + "\n" + location.href + "\nMore: https://www.pregen.org/llms.txt\n\n" + (main ? main.innerText : ""), b, label);
  });
});

// Search: the pages listed on /map are fetched once, on first open, and searched here in the browser.
(function () {
  var btn = document.querySelector(".nav-search");
  var top = document.querySelector(".top");
  if (!btn || !top) return;
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text) e.textContent = text; return e; }
  var box = el("div", "site-search"); box.id = "site-search"; box.hidden = true;
  var form = el("form"); form.setAttribute("role", "search");
  var input = el("input"); input.type = "search"; input.placeholder = "Search pregen.org"; input.setAttribute("aria-label", "Search pregen.org");
  var note = el("p"); note.setAttribute("aria-live", "polite");
  var list = el("ul");
  form.append(input, note, list); box.appendChild(form); top.appendChild(box);
  var pages = null;

  function load() {
    if (pages) return pages;
    var parse = function (html) { return new DOMParser().parseFromString(html, "text/html"); };
    pages = fetch("/map").then(function (r) { return r.text(); }).then(function (html) {
      var urls = Array.prototype.map.call(parse(html).querySelectorAll("main a[href^='/']"), function (a) { return a.getAttribute("href"); })
        .filter(function (u) { return !/\.\w+$/.test(u); });
      return Promise.all(urls.map(function (u) {
        return fetch(u).then(function (r) { return r.ok ? r.text() : ""; }).then(function (h) {
          var d = parse(h), m = d.querySelector("main");
          if (m) m.querySelectorAll("aside, nav, script").forEach(function (n) { n.remove(); });
          return { url: u, title: (d.title || u).replace(/ — PRE-GEN$/, ""), text: m ? m.textContent.replace(/\s+/g, " ").trim() : "" };
        }, function () { return null; });
      }));
    }).then(function (all) { return all.filter(function (p) { return p && p.text; }); });
    return pages;
  }

  function run() {
    var q = input.value.trim().toLowerCase();
    list.textContent = ""; note.textContent = "";
    if (q.length < 2) return;
    load().then(function (all) {
      if (input.value.trim().toLowerCase() !== q) return;
      var words = q.split(/\s+/);
      var hits = all.map(function (p) {
        var t = p.title.toLowerCase(), x = p.text.toLowerCase(), score = 0;
        for (var i = 0; i < words.length; i++) {
          if (x.indexOf(words[i]) < 0 && t.indexOf(words[i]) < 0) return null;
          score += (t.indexOf(words[i]) >= 0 ? 10 : 0) + x.split(words[i]).length - 1;
        }
        var at = x.indexOf(q) >= 0 ? x.indexOf(q) : x.indexOf(words[0]);
        var snip = (at > 60 ? "…" : "") + p.text.slice(Math.max(0, at - 60), at + 100) + "…";
        return { p: p, score: score, snip: snip };
      }).filter(Boolean).sort(function (a, b) { return b.score - a.score; }).slice(0, 8);
      list.textContent = "";
      note.textContent = hits.length ? "" : "Nothing found.";
      hits.forEach(function (h) {
        var a = el("a"); a.href = h.p.url + "#:~:text=" + encodeURIComponent(input.value.trim());
        a.append(el("b", "", h.p.title), el("span", "", h.snip));
        var li = el("li"); li.appendChild(a); list.appendChild(li);
      });
    }, function () { note.textContent = "Search is not available right now."; });
  }

  function show(open) {
    box.hidden = !open;
    btn.setAttribute("aria-expanded", open ? "true" : "false");
    if (open) { document.documentElement.classList.remove("menu-open"); input.focus(); load(); }
  }
  btn.addEventListener("click", function (e) { e.stopPropagation(); show(box.hidden); });
  form.addEventListener("submit", function (e) { e.preventDefault(); var a = list.querySelector("a"); if (a) location.href = a.href; });
  input.addEventListener("input", run);
  document.addEventListener("keydown", function (e) { if (e.key === "Escape" && !box.hidden) { show(false); btn.focus(); } });
  document.addEventListener("click", function (e) { if (!box.hidden && !e.target.closest(".site-search")) show(false); });
})();
