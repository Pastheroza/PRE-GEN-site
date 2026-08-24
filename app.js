// Theme: system default, user override persisted
(function() {
  var root = document.documentElement;
  var stored = localStorage.getItem('pp-theme');
  if (stored === 'dark' || stored === 'light') {
    root.setAttribute('data-theme', stored);
  } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
    root.setAttribute('data-theme', 'dark');
  }
  function toggle() {
    var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    localStorage.setItem('pp-theme', next);
    document.querySelector('meta[name="theme-color"]').setAttribute('content', next === 'dark' ? '#000000' : '#FFFFFF');
  }
  ['themeToggle','themeToggleMobile'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('click', toggle);
  });
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function(e) {
    if (!localStorage.getItem('pp-theme')) {
      root.setAttribute('data-theme', e.matches ? 'dark' : 'light');
    }
  });
})();

// Mobile drawer toggle + desktop collapse
(function() {
  var sidebar  = document.getElementById('sidebar');
  var openBtn  = document.getElementById('menuOpen');
  var closeBtn = document.getElementById('menuClose');
  var backdrop = document.getElementById('drawerBackdrop');
  var app = document.querySelector('.app');
  var isMobile = function() { return window.matchMedia('(max-width: 900px)').matches; };

  function open()  {
    if (isMobile()) {
      sidebar.classList.add('is-open');
      backdrop.classList.add('is-open');
      document.body.style.overflow = 'hidden';
    } else {
      app.classList.remove('sidebar-collapsed');
    }
  }
  function close() {
    if (isMobile()) {
      sidebar.classList.remove('is-open');
      backdrop.classList.remove('is-open');
      document.body.style.overflow = '';
    } else {
      app.classList.add('sidebar-collapsed');
    }
  }

  openBtn.addEventListener('click', open);
  closeBtn.addEventListener('click', close);
  backdrop.addEventListener('click', close);
  var floatBtn = document.getElementById('openFloating');
  if (floatBtn) floatBtn.addEventListener('click', open);

  sidebar.querySelectorAll('.nav-item').forEach(function(a) {
    a.addEventListener('click', function() { if (isMobile()) close(); });
  });

  window.addEventListener('resize', function() { if (!isMobile()) close(); });
})();

// Logo → home, 5x rapid click → easter egg
(function() {
  var clicks = [];
  document.querySelectorAll('.brand__link').forEach(function(link) {
    link.addEventListener('click', function(e) {
      e.preventDefault();
      var now = Date.now();
      clicks.push(now);
      clicks = clicks.filter(function(t) { return now - t < 1200; });
      if (clicks.length >= 5) {
        clicks = [];
        window.location.href = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ';
        return;
      }
      clearTimeout(link._navTimer);
      link._navTimer = setTimeout(function() { window.location.href = '/'; }, 300);
    });
  });
})();

// FAQ accordion
(function() {
  document.querySelectorAll('.faq-q').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var item = btn.closest('.faq-item');
      var wasOpen = item.classList.contains('is-open');
      item.closest('.faq-list').querySelectorAll('.faq-item').forEach(function(i) { i.classList.remove('is-open'); });
      if (!wasOpen) item.classList.add('is-open');
    });
  });
})();

// Code toggle
(function() {
  document.querySelectorAll('.code-toggle-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var block = btn.closest('.code-toggle-wrap').querySelector('.code-block');
      block.classList.toggle('is-open');
    });
  });
})();

// Code copy button
(function() {
  document.querySelectorAll('[data-copy]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var pre = btn.closest('.code-block').querySelector('pre');
      var text = pre.textContent;
      navigator.clipboard.writeText(text).then(function() {
        btn.textContent = 'Copied';
        setTimeout(function() { btn.textContent = 'Copy'; }, 1500);
      });
    });
  });
})();

// Get Started popup
(function() {
  var popup = document.getElementById('getstartedPopup');
  if (!popup) return;
  var overlay = document.getElementById('getstartedOverlay');
  var closeBtn = document.getElementById('getstartedClose');

  function openPopup() {
    popup.classList.add('is-open');
    document.body.style.overflow = 'hidden';
  }
  function closePopup() {
    popup.classList.remove('is-open');
    document.body.style.overflow = '';
  }

  var desktopBtn = document.getElementById('desktopGetStarted');
  var mobileBtn = document.getElementById('mobileGetStarted');
  if (desktopBtn) desktopBtn.addEventListener('click', openPopup);
  if (mobileBtn) mobileBtn.addEventListener('click', openPopup);
  if (closeBtn) closeBtn.addEventListener('click', closePopup);
  if (overlay) overlay.addEventListener('click', closePopup);

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && popup.classList.contains('is-open')) closePopup();
  });
})();

// Cookie banner
(function() {
  var banner = document.getElementById('cookieBanner');
  if (!banner) return;
  if (localStorage.getItem('pp-cookies')) return;
  banner.classList.add('is-visible');

  banner.querySelectorAll('[data-cookie]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      localStorage.setItem('pp-cookies', btn.getAttribute('data-cookie'));
      banner.classList.remove('is-visible');
    });
  });
})();
