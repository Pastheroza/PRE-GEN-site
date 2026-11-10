/* Homepage: the house made of words (every word explains itself), and who uses PRE-GEN, from the signed list. */
(function () {
  "use strict";

  /* ── The house: what each word means, in plain words ─────────────────────────────────────────────────────────── */
  var WORDS = {
    tog: { kicker: "The foundation", title: "ToG",
      body: ["<b>Terms of Generation.</b> Your rules for your face, your voice and your name, written once in plain words: what AI may make with you, and what it may never make.",
        "Everything else in this house stands on them. An app, a platform or a deal can never go further than your ToG allows."] },
    pregen: { kicker: "A wall · before", title: "PRE-GEN",
      body: ["<b>Permission before generation.</b> Before an AI app makes a video of a real person, it asks that person's registry. Only a signed yes lets it go ahead.",
        "The yes travels with the video, so anyone can check later who allowed it, for what, and when."],
      link: ["/docs", "How it works"] },
    aftergen: { kicker: "A wall · after", title: "AFTER-GEN",
      body: ["<b>Approval after generation.</b> For a video that was already made, the person themself looks at that exact file and approves it, or not.",
        "The approval is signed, sealed into the file and can be checked by anyone. It never pretends to be permission given before."] },
    registries: { kicker: "The ceiling", title: "Rights registries",
      body: ["Where people and rights holders keep their rules and their licences. When an AI app asks, the registry answers with a signed yes or no.",
        "Anyone can run one. Registries are listed in one signed directory, so an app knows which ones to trust."],
      link: ["/create-registry", "Create a registry"] },
    platforms: { kicker: "The ceiling", title: "Content Platforms",
      body: ["Sites and apps where videos are published and watched.",
        "Before they publish, they can check the proof in a file: whose likeness it is, who approved it, and whether that still stands today."] },
    providers: { kicker: "The roof", title: "AI providers",
      body: ["Apps and services that generate video, voice and images.",
        "With PRE-GEN they ask before they make a real person, and keep the signed answer with what they make. It takes a few lines of code and no account."],
      link: ["/connect", "Connect your AI"] },
    marketplaces: { kicker: "The roof", title: "Marketplaces",
      body: ["Where licences are bought and sold: a brand pays to use a face in a campaign, and the person gets paid.",
        "The licence becomes part of the record, so its limits travel with every video made under it."] },
    people: { kicker: "Inside the house", title: "People",
      body: ["Everyone whose face, voice or name AI can copy.",
        "PRE-GEN starts with them: nothing is made of a person who said no, and what they allowed can always be traced back to them."] },
    holders: { kicker: "Inside the house", title: "Rights Holders",
      body: ["Whoever holds the rights to a likeness or a character: the person, their heirs, a studio, a label.",
        "They set the rules, approve the uses, and are paid for them."] },
    brands: { kicker: "Inside the house", title: "Brands",
      body: ["Companies whose names, logos, products and mascots appear in AI content.",
        "They can set their own rules and sell their own licences, the same way people do."] },
    agencies: { kicker: "Inside the house", title: "Agencies",
      body: ["Talent and model agencies that work for the people they represent.",
        "They handle requests and deals. The final yes on a person's likeness is always the person's own."] },
    creators: { kicker: "Inside the house", title: "AI creators",
      body: ["Studios, ad agencies and independent makers who create with AI.",
        "Instead of guessing what is allowed, they get a clear, signed answer, and can show it to anyone who asks."] },
    code: { kicker: "A person's code", title: "TOG-PRAM-900000037K",
      body: ["One short code for each person in a registry. <b>PRAM</b> is the registry, the number is the person, and the last letter checks for typos.",
        "Type it into an AI app and the app knows whose rules apply. (This one is an example.)"],
      link: ["/lookup", "Look up a code"] }
  };
  var ORDER = ["tog", "pregen", "aftergen", "registries", "platforms", "providers", "marketplaces",
    "people", "holders", "brands", "agencies", "creators", "code"];

  var wrap = document.getElementById("house");
  if (wrap) house(wrap);

  function house(wrap) {
    var svg = wrap.querySelector(".house");
    var panel = document.getElementById("explain");
    var kicker = document.getElementById("ex-kicker");
    var title = document.getElementById("ex-title");
    var body = document.getElementById("ex-body");
    var dots = document.getElementById("ex-dots");
    var nextName = document.getElementById("ex-next-name");
    var still = window.matchMedia("(prefers-reduced-motion: reduce)");
    var words = Array.prototype.slice.call(svg.querySelectorAll(".hw"));
    var byKey = {};
    words.forEach(function (w) { byKey[w.getAttribute("data-k")] = w; });
    var current = null, busy = false;

    ORDER.forEach(function () { dots.appendChild(document.createElement("i")); });
    var word = document.createElement("span");      // the title's word: it flies between the house and the panel
    word.className = "ex-word";
    word.style.display = "inline-block";
    title.appendChild(word);

    function centre(r) { return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; }

    // Pixel size of a house word on screen, from its font size and the SVG's scale.
    function wordPx(w) {
      var vb = svg.viewBox.baseVal;
      return parseFloat(w.getAttribute("font-size")) * svg.getBoundingClientRect().width / vb.width;
    }

    // The transform that puts the title's word exactly over the house word w (FLIP: first, last, invert, play).
    function over(w) {
      var a = centre(w.getBoundingClientRect());
      var t = word.style.transform;
      word.style.transform = "none";
      var b = centre(word.getBoundingClientRect());
      var s = wordPx(w) / parseFloat(getComputedStyle(title).fontSize);
      word.style.transform = t;
      return "translate(" + (a.x - b.x) + "px," + (a.y - b.y) + "px) rotate(" + (w.getAttribute("data-a") || 0) + "deg) scale(" + s + ")";
    }

    // The house dissolves as a ripple, from the chosen word outwards (and comes back the same way).
    function ripple(from) {
      var o = centre(from.getBoundingClientRect());
      words.forEach(function (w) {
        var c = centre(w.getBoundingClientRect());
        w.parentNode.style.setProperty("--d", Math.round(Math.hypot(c.x - o.x, c.y - o.y) * 0.55));
      });
    }

    function fill(k) {
      var d = WORDS[k];
      kicker.textContent = d.kicker;
      word.textContent = d.title;
      body.innerHTML = d.body.map(function (p, i) {
        return "<p" + (i ? ' class="ex-plain"' : "") + ">" + p + "</p>";
      }).join("") + (d.link ? '<p><a href="' + d.link[0] + '">' + d.link[1] + " →</a></p>" : "");
      var i = ORDER.indexOf(k);
      Array.prototype.forEach.call(dots.children, function (dot, j) { dot.className = j === i ? "on" : ""; });
      nextName.textContent = "Next: " + WORDS[ORDER[(i + 1) % ORDER.length]].title;
      current = k;
    }

    function open(k) {
      if (busy || current) return;
      var w = byKey[k];
      busy = true;
      ripple(w);
      fill(k);
      w.parentNode.classList.add("picked");
      wrap.classList.add("open");
      svg.setAttribute("aria-hidden", "true");
      panel.hidden = false;
      if (!still.matches) {
        word.style.transition = "none";
        word.style.transform = over(w);
        word.getBoundingClientRect();                 // commit the starting point before animating from it
        word.style.transition = "transform .8s cubic-bezier(.2,.8,.2,1)";
      }
      setTimeout(function () {                        // a tick after the start is committed (not rAF: it waits while hidden)
        word.style.transform = "";
        panel.classList.add("in");
        setTimeout(function () { busy = false; title.focus({ preventScroll: true }); }, still.matches ? 0 : 650);
      }, 20);
    }

    function close() {
      if (busy || !current) return;
      var w = byKey[current];
      busy = true;
      panel.classList.remove("in");
      ripple(w);
      if (!still.matches) {
        word.style.transition = "transform .65s cubic-bezier(.6,0,.3,1)";
        word.style.transform = over(w);
      }
      setTimeout(function () {
        wrap.classList.remove("open");                // the house comes back, from the word outwards
        w.parentNode.classList.remove("picked");
        svg.removeAttribute("aria-hidden");
        panel.hidden = true;
        word.style.transition = "none";
        word.style.transform = "";
        current = null;
        busy = false;
        w.focus({ preventScroll: true });
      }, still.matches ? 0 : 620);
    }

    function step(by) {
      if (busy || !current) return;
      var k = ORDER[(ORDER.indexOf(current) + by + ORDER.length) % ORDER.length];
      byKey[current].parentNode.classList.remove("picked");
      byKey[k].parentNode.classList.add("picked");
      busy = true;
      kicker.classList.add("swap");
      body.classList.add("swap");
      if (!still.matches) {
        word.style.transition = "transform .3s ease, opacity .3s ease";
        word.style.transform = "translateX(" + (by * -24) + "px)";
        word.style.opacity = "0";
      }
      setTimeout(function () {
        fill(k);
        if (!still.matches) {
          word.style.transition = "none";
          word.style.transform = "translateX(" + (by * 24) + "px)";
          word.getBoundingClientRect();
          word.style.transition = "transform .45s cubic-bezier(.2,.8,.2,1), opacity .45s ease";
        }
        word.style.transform = "";
        word.style.opacity = "";
        kicker.classList.remove("swap");
        body.classList.remove("swap");
        busy = false;
      }, still.matches ? 0 : 300);
    }

    words.forEach(function (w) {
      w.addEventListener("click", function () { open(w.getAttribute("data-k")); });
      w.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(w.getAttribute("data-k")); }
      });
    });
    panel.querySelector(".ex-back").addEventListener("click", close);
    Array.prototype.forEach.call(panel.querySelectorAll(".ex-step"), function (b) {
      b.addEventListener("click", function () { step(parseInt(b.getAttribute("data-step"), 10)); });
    });
    document.addEventListener("keydown", function (e) {
      if (!current) return;
      if (e.key === "Escape") close();
      else if (e.key === "ArrowRight" && e.target.tagName !== "A") step(1);
      else if (e.key === "ArrowLeft" && e.target.tagName !== "A") step(-1);
    });
  }

  /* ── Who uses PRE-GEN, from the signed list (the page shows it; the libraries verify its signature) ───────────── */
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function card(entry) {
    var li = document.createElement("li");
    var a = el(entry.url ? "a" : "div", "u-card");
    if (entry.url) { a.href = entry.url; a.rel = "noopener"; }
    a.appendChild(el("span", "u-name", entry.name));
    if (entry.meta) a.appendChild(el("span", "u-meta", entry.meta));
    if (entry.url) a.appendChild(el("span", "u-go", "↗")).setAttribute("aria-hidden", "true");
    li.appendChild(a);
    return li;
  }

  function count(id, n, one, many) {
    var num = document.getElementById(id + "-n"), word = document.getElementById(id + "-k");
    if (num) num.textContent = n;
    if (word) word.textContent = n === 1 ? one : many;
  }

  fetch("/registries.json", { credentials: "omit" })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (d) {
      if (!d) return;
      var byName = {}, regs = [];
      (d.registries || []).forEach(function (r) {   // one card per registry, however many namespaces it holds
        var name = String(r.name || "").trim();
        if (!name) return;
        var e = byName[name];
        if (!e) {
          e = byName[name] = { name: name, url: /^https:\/\//.test(r.website || "") ? r.website : null, prefixes: [],
            status: r.status, since: r.since };
          regs.push(e);
        }
        if (r.prefix) e.prefixes.push(r.prefix);
      });
      regs.forEach(function (e) {
        e.meta = [e.prefixes.length ? "Prefix " + e.prefixes.join(", ") : null, e.status, e.since ? "since " + e.since : null]
          .filter(Boolean).join(" · ");
      });
      var ais = (d.providers || []).map(function (p) {
        var name = typeof p === "string" ? p : String(p.name || p.id || "").trim();
        var url = typeof p === "string" ? p : p.website || p.id;
        return name ? { name: name, url: /^https:\/\//.test(url || "") ? url : null, meta: p.status || null } : null;
      }).filter(Boolean);
      var ul = document.getElementById("users-reg");
      if (ul && regs.length) { ul.textContent = ""; regs.forEach(function (e) { ul.appendChild(card(e)); }); }
      count("users-reg", regs.length || 1, "registry", "registries");
      var ua = document.getElementById("users-ai");
      if (ua && ais.length) { ua.textContent = ""; ais.forEach(function (e) { ua.appendChild(card(e)); }); }
      count("users-ai", ais.length, "AI provider", "AI providers");
    })
    .catch(function () { /* the markup's own cards stay */ });
})();
