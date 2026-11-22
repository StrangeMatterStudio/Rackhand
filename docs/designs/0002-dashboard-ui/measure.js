// Measures the dashboard's pages in a browser: every page and dialog at every width, for what doesn't fit, is cut off, or
// is too small to touch. Pages come from the test `pages_for_measuring` (RACKHAND_PAGES=<dir>), served by any static
// server with this file beside them; run `await measure()` in a page of that server, and
// `await measure(null, null, true)` for the same with the pages' scripts off.
window.measure = async function (widths, only, noScript) {
  widths = widths || [320, 360, 390, 430, 600, 640, 641, 720, 820, 860, 861, 1024, 1180, 1181, 1280, 1440, 1680, 1920, 2560];
  var pages = only || await (await fetch("pages.json")).json();
  var bad = [], screens = 0, controls = 0;
  var frame = document.createElement("iframe");
  frame.style.cssText = "position:absolute;left:0;top:0;border:0;visibility:hidden";
  if (noScript) { frame.sandbox = "allow-same-origin"; }
  document.body.appendChild(frame);
  function load(url) {
    return new Promise(function (done) { frame.onload = function () { done(); }; frame.src = url; });
  }
  function look(w, name) {
    screens++;
    var doc = frame.contentDocument, win = frame.contentWindow, root = doc.scrollingElement, min = w <= 640 ? 44 : 40;
    function say(what) { bad.push(w + " " + name + ": " + what); }
    function label(e) { return "<" + e.tagName.toLowerCase() + "> " + (e.getAttribute("aria-label") || e.textContent.trim() || e.name || "").slice(0, 40); }
    if (root.scrollWidth > w) { say("scrolls sideways by " + (root.scrollWidth - w)); }
    var modal = doc.querySelector("dialog[open]");
    if (modal) {
      var m = modal.getBoundingClientRect();
      if (m.top < -0.5 || m.bottom > win.innerHeight + 0.5) { say("the dialog is taller than the screen"); }
    }
    doc.querySelectorAll("h1,h2,h3,p,dt,dd,td,b,small,pre,code,label,legend,summary,button,a,input,select,textarea,.badge,.card,dialog").forEach(function (e) {
      var r = e.getBoundingClientRect(), st = win.getComputedStyle(e);
      if (!r.width || st.display === "none" || st.visibility === "hidden" || e.closest(".sr, .skip, thead")) { return; }
      var clipped = e.closest(".output, textarea, .side");
      if (r.right > w + 0.5 && !clipped) { say("past the edge " + label(e)); }
      if (/^(H1|H2|H3|P|DT|DD|TD|PRE|LABEL|SMALL|BUTTON|A)$/.test(e.tagName) && st.display !== "inline" && e.clientWidth && e.scrollWidth > e.clientWidth + 1 && !clipped && !e.matches(".search, .menu *")) { say("text is cut " + label(e)); }
      if (!e.matches("button,a,input,select,textarea,summary") || e.type === "hidden" || (modal && !modal.contains(e))) { return; }
      controls++;
      var inText = e.tagName === "A" && !e.matches(".btn, .row, .brand, .mi, .stat, .search") && !e.closest("td.t, .side, .choices");
      var box = e.tagName === "A" && e.closest("td.t") ? e.closest("tr") : e.type === "checkbox" ? e.closest("label") : e;
      var b = box.getBoundingClientRect(), need = inText ? 24 : min;
      if (inText && b.height < 24 && b.height > 14) { b = { height: 24, width: b.width }; }
      if (b.height + 0.5 < need) { say("small: " + Math.round(b.width) + "x" + Math.round(b.height) + " " + label(e)); }
      if (!inText && b.width + 0.5 < need) { say("narrow: " + Math.round(b.width) + "x" + Math.round(b.height) + " " + label(e)); }
      if (w <= 640 && e.matches("input:not([type=checkbox]), select, textarea") && parseFloat(st.fontSize) < 16) { say(st.fontSize + " text in " + label(e)); }
      // what says what it is, to someone who can't see it
      if (e.matches("input:not([type=hidden]), select, textarea") && !e.labels.length && !e.getAttribute("aria-label")) { say("no label " + label(e)); }
    });
  }
  for (var name of pages) {
    frame.style.width = "1000px"; frame.style.height = "900px";
    await load(name + ".html");
    for (var w of widths) {
      frame.style.width = w + "px"; frame.style.height = (w <= 640 ? 740 : 900) + "px";
      look(w, name);
      if (name === "overview") {
        var menu = frame.contentDocument.querySelector("[data-menu]");
        menu.open = true; look(w, "account menu"); menu.open = false;
        if (w <= 860) { frame.contentWindow.location.hash = "side"; look(w, "drawer"); frame.contentWindow.location.hash = "main"; }
      }
    }
  }
  frame.remove();
  var counted = {};
  bad.forEach(function (b) { var k = b.replace(/^\d+ /, ""); (counted[k] = counted[k] || []).push(+b.split(" ")[0]); });
  return { pages: pages.length, widths: widths.length, screens: screens, controls: controls, bad: bad.length, list: Object.keys(counted).map(function (k) { var c = counted[k]; return k + " [" + c[0] + (c.length > 1 ? " to " + c[c.length - 1] + ", " + c.length : "") + "]"; }) };
};
