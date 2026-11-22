// Runs axe-core over the same pages as measure.js, one theme and width at a time. axe-core isn't part of the repository:
// put its axe.min.js beside the pages, then `await axePages("dark", 390)`.
window.axePages = async function (theme, width, only) {
  var pages = only || await (await fetch("pages.json")).json(), found = {};
  var frame = document.createElement("iframe");
  frame.style.cssText = "position:absolute;left:0;top:0;border:0;height:900px;width:" + width + "px";
  document.body.appendChild(frame);
  for (var page of pages) {
    await new Promise(function (done) { frame.onload = done; frame.src = page + ".html"; });
    var doc = frame.contentDocument;
    doc.documentElement.dataset.theme = theme;
    var still = doc.createElement("style");
    still.textContent = "*{animation:none!important;transition:none!important}";
    doc.head.appendChild(still);
    await new Promise(function (done) { var s = doc.createElement("script"); s.src = "axe.min.js"; s.onload = done; doc.head.appendChild(s); });
    var result = await frame.contentWindow.axe.run(doc, { resultTypes: ["violations"], runOnly: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"] });
    result.violations.forEach(function (v) {
      var key = v.id + " (" + v.impact + ")";
      (found[key] = found[key] || []).push(page + ": " + v.nodes.slice(0, 2).map(function (n) { return n.target.join(" "); }).join(", "));
    });
  }
  frame.remove();
  return { pages: pages.length, theme: theme, width: width, violations: found };
};
