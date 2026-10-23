// Navbar state and scroll reveals. Vanilla JS, no external requests.
(function () {
  var nav = document.getElementById('navbar');
  function onScroll() { nav.classList.toggle('scrolled', window.scrollY > 80); }
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
  var els = document.querySelectorAll('.rv');
  if (!('IntersectionObserver' in window)) { els.forEach(function (e) { e.classList.add('in'); }); return; }
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (en) { if (en.isIntersecting) { en.target.classList.add('in'); io.unobserve(en.target); } });
  }, { threshold: 0.05 });
  els.forEach(function (e) { io.observe(e); });
})();
