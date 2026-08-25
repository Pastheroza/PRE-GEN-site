/* PRE-GEN Foundation — pregen.org */
(function () {
  "use strict";

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

  /* Hero ASCII fire — heat propagation rendered as characters, brand-red palette */
  var cv = document.getElementById("heroFire");
  if (cv && cv.getContext) {
    var ctx = cv.getContext("2d");
    var CELL = 9;
    var CHARS = " .·:;=+*x#%@";
    var STOPS = [
      [0.00,  26,   8,  10, 0],
      [0.25,  90,  22,  24, 0.35],
      [0.55, 219,  65,  65, 0.80],
      [0.80, 245, 120,  80, 0.95],
      [1.00, 255, 190, 140, 1]
    ];
    var PAL = [];
    (function () {
      for (var i = 0; i <= 36; i++) {
        var t = i / 36, s = 1;
        while (s < STOPS.length - 1 && t > STOPS[s][0]) s++;
        var a = STOPS[s - 1], b = STOPS[s];
        var k = (t - a[0]) / (b[0] - a[0]);
        PAL.push("rgba(" + Math.round(a[1] + (b[1] - a[1]) * k) + "," + Math.round(a[2] + (b[2] - a[2]) * k) + "," + Math.round(a[3] + (b[3] - a[3]) * k) + "," + (a[4] + (b[4] - a[4]) * k).toFixed(2) + ")");
      }
    })();
    var COLS = 0, ROWS = 0, heat = null, dpr = 1, W = 0, H = 0;

    function resizeFire() {
      var rect = cv.parentElement.getBoundingClientRect();
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      W = Math.max(1, Math.round(rect.width));
      H = Math.max(1, Math.round(rect.height));
      cv.width = W * dpr;
      cv.height = H * dpr;
      COLS = Math.ceil(W / CELL);
      ROWS = Math.ceil(H / CELL);
      heat = new Array(COLS * ROWS);
      for (var i = 0; i < heat.length; i++) heat[i] = 0;
      for (var x = 0; x < COLS; x++) heat[(ROWS - 1) * COLS + x] = 36;
    }

    function stepFire() {
      for (var y = 1; y < ROWS; y++) {
        for (var x = 0; x < COLS; x++) {
          var src = y * COLS + x;
          var r = (Math.random() * 4) | 0;
          var dst = src - COLS - r + 1;
          if (dst < 0) dst = 0;
          heat[dst] = Math.max(0, heat[src] - (r & 3));
        }
      }
    }

    function drawFire() {
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, W, H);
      ctx.font = CELL + 'px "Geist Mono", ui-monospace, monospace';
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      var last = CHARS.length - 1;
      for (var y = 0; y < ROWS; y++) {
        for (var x = 0; x < COLS; x++) {
          var h = heat[y * COLS + x];
          if (h < 3) continue;
          ctx.fillStyle = PAL[h];
          ctx.fillText(CHARS[Math.round(h / 36 * last)], x * CELL + CELL / 2, y * CELL + CELL / 2);
        }
      }
    }

    var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var frame = 0, looping = false, running = true;

    function loop() {
      if (!running) { looping = false; return; }
      if (frame++ % 2 === 0) { stepFire(); drawFire(); }
      requestAnimationFrame(loop);
    }
    function startFire() { if (!looping) { looping = true; requestAnimationFrame(loop); } }

    resizeFire();
    if (reduceMotion) {
      for (var i = 0; i < 140; i++) stepFire();
      drawFire();
    } else {
      startFire();
      var rt;
      window.addEventListener("resize", function () {
        clearTimeout(rt);
        rt = setTimeout(function () { resizeFire(); }, 150);
      });
    }
  }
})();
