// Show this page's full address so it can be copied into the demo app's terminal. Nothing is sent anywhere.
(function () {
  var box = document.getElementById("addr");
  if (!box) return;
  box.value = location.href;
  box.addEventListener("focus", function () { box.select(); });
})();
