// Runs in <head> before the page paints: apply a saved theme choice so the
// page never flashes the other one. No choice saved = follow the system.
(function () {
  var root = document.documentElement;
  root.classList.add("js");
  try {
    var t = localStorage.getItem("pg-theme");
    if (t === "light" || t === "dark") root.setAttribute("data-theme", t);
  } catch (e) {}
})();
