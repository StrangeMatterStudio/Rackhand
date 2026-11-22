// The dashboard's shell in the browser: menus, dialogs, search as you type, shortcuts, and the notice after an update.
// Every page works without it: dialogs come drawn open by the hub, menus are details and targets, searches are forms.
(function () {
  "use strict";
  var root = document.documentElement;
  function all(selector, within) { return Array.prototype.slice.call((within || document).querySelectorAll(selector)); }

  // what a shortcut opens or closes doesn't animate
  function byHotkey(fn) {
    root.setAttribute("data-instant", "");
    fn();
    requestAnimationFrame(function () { requestAnimationFrame(function () { root.removeAttribute("data-instant"); }); });
  }

  // menus
  var menus = all("[data-menu]");
  function closeMenus(focus) {
    menus.forEach(function (m) {
      if (!m.open) { return; }
      m.open = false;
      if (focus) { m.querySelector("summary").focus(); }
    });
  }
  document.addEventListener("click", function (e) { menus.forEach(function (m) { if (!m.contains(e.target)) { m.open = false; } }); });
  menus.forEach(function (m) {
    m.addEventListener("keydown", function (e) {
      if (e.key !== "ArrowDown" && e.key !== "ArrowUp") { return; }
      var items = all("a, button", m).filter(function (i) { return i.offsetParent; });
      var at = items.indexOf(document.activeElement);
      var next = items[(at + (e.key === "ArrowDown" ? 1 : items.length - 1) + (at < 0 && e.key === "ArrowUp" ? 1 : 0)) % items.length];
      if (next) { e.preventDefault(); m.open = true; next.focus(); }
    });
  });
  function drawerOpen() { return location.hash === "#side"; }
  function closeDrawer() { history.replaceState(null, "", location.pathname + location.search); location.hash = "main"; }

  // dialogs: the newest on top; each has an address, and closing it goes back to the page's own
  var stack = [];
  function dirty(dialog) { return all("form", dialog).some(function (f) { return f.dataset.changed; }); }
  function closeNow(entry) {
    stack.splice(stack.indexOf(entry), 1);
    entry.dialog.close();
    entry.dialog.remove();
    if (entry.back && !entry.still) { history.replaceState(null, "", entry.back); }
    if (entry.from && entry.from.isConnected) { entry.from.focus(); }
  }
  function leave(entry) {
    if (!dirty(entry.dialog)) { closeNow(entry); return; }
    var ask = document.createElement("dialog");
    ask.className = "small";
    ask.setAttribute("role", "alertdialog");
    ask.setAttribute("aria-label", "Discard your changes?");
    ask.innerHTML = '<div class="d-h"><h2>Discard your changes?</h2></div><div class="d-b"><p>What you changed hasn\'t been saved.</p></div><div class="d-f"><button type="button" data-keep autofocus>Keep editing</button><button type="button" class="danger" data-drop>Discard changes</button></div>';
    document.body.appendChild(ask);
    var question = modal(ask, null, true);
    ask.querySelector("[data-keep]").addEventListener("click", function () { closeNow(question); });
    ask.querySelector("[data-drop]").addEventListener("click", function () { closeNow(question); closeNow(entry); });
  }
  function modal(dialog, from, still) {
    var entry = { dialog: dialog, from: from, back: dialog.dataset.back, still: still };
    if (dialog.open) { dialog.close(); }
    dialog.showModal();
    stack.push(entry);
    if (window.rackhandForms) { window.rackhandForms(dialog); }
    if (!dialog.querySelector("[autofocus], [data-focus]")) {
      var first = dialog.querySelector(".d-b input:not([type=hidden]):not([readonly]), .d-b select");
      if (first) { first.focus(); }
    }
    dialog.addEventListener("cancel", function (e) { e.preventDefault(); leave(entry); });
    dialog.addEventListener("click", function (e) {
      var close = e.target.closest("[data-close]");
      if (close) { e.preventDefault(); leave(entry); }
    });
    return entry;
  }
  all("dialog[data-modal]").forEach(function (d) { modal(d, null); });

  // a link to a dialog opens it here; if anything is in the way, it's a link
  function openDialog(link) {
    var href = link.href;
    fetch(href, { credentials: "same-origin" }).then(function (r) {
      if (!r.ok) { throw new Error(String(r.status)); }
      return r.text();
    }).then(function (html) {
      var found = new DOMParser().parseFromString(html, "text/html").querySelector("dialog[data-modal]") || null;
      var part = new DOMParser().parseFromString(html, "text/html").querySelector("template[data-as-dialog]");
      if (!found && part) { found = part.content.querySelector("dialog"); }
      if (!found) { throw new Error("no dialog"); }
      var dialog = document.importNode(found, true);
      dialog.removeAttribute("open");
      document.body.appendChild(dialog);
      closeMenus(false);
      var entry = modal(dialog, link, false);
      if (link.dataset.dialog === "") { entry.still = true; } else { history.replaceState(null, "", href); }
    }).catch(function () { location.href = href; });
  }
  document.addEventListener("click", function (e) {
    var link = e.target.closest("a[data-dialog], a[href*='?add='], a[href*='?edit='], a[href*='?confirm=']");
    if (!link || e.defaultPrevented || e.button || e.ctrlKey || e.metaKey || e.shiftKey) { return; }
    e.preventDefault();
    openDialog(link);
  });

  // an editor's Save is off until something differs from what is saved, and Undo puts it back
  function state(form) { return new URLSearchParams(new FormData(form)).toString(); }
  function watchEditor(form) {
    if (form.dataset.watched) { return; }
    form.dataset.watched = "1";
    var first = state(form), save = form.querySelector("[type=submit]"), undo = form.querySelector("[data-undo]"), refused = form.querySelector(".problems");
    function look() {
      var changed = state(form) !== first;
      if (changed) { form.dataset.changed = "1"; } else { delete form.dataset.changed; }
      if (form.dataset.edit !== undefined) { save.disabled = !changed && !refused; }
      if (undo) { undo.hidden = !changed; }
    }
    form.addEventListener("input", look);
    form.addEventListener("change", look);
    form.addEventListener("submit", function () { delete form.dataset.changed; });
    if (undo) { undo.addEventListener("click", function () { form.reset(); form.dispatchEvent(new Event("change", { bubbles: true })); look(); }); }
    look();
  }
  function watchEditors(within) { all("form[data-edit], dialog form[data-check]", within).forEach(watchEditor); }
  watchEditors(document);
  new MutationObserver(function () { watchEditors(document); }).observe(document.body, { childList: true });
  window.addEventListener("beforeunload", function (e) { if (document.querySelector("form[data-edit][data-changed], dialog form[data-changed]")) { e.preventDefault(); } });

  // a list that was sent whole filters as you type
  all("form.find").forEach(function (form) {
    var card = form.closest(".card") || document, input = form.querySelector("input[data-filter]");
    if (!input || input.value) { return; }
    form.setAttribute("data-live", "");
    var none = document.createElement("p");
    none.className = "empty";
    none.hidden = true;
    none.setAttribute("role", "status");
    card.appendChild(none);
    form.addEventListener("submit", function (e) { if (!input.value) { e.preventDefault(); } });
    input.addEventListener("input", function () {
      var wanted = input.value.toLowerCase().split(/\s+/).filter(Boolean), any = false, rows = all("tbody tr", card);
      rows.forEach(function (row) {
        var text = row.textContent.toLowerCase();
        row.hidden = !wanted.every(function (w) { return text.indexOf(w) >= 0; });
        any = any || !row.hidden;
      });
      none.hidden = any || !rows.length;
      none.textContent = "Nothing here matches. Press Enter to search everything.";
    });
  });

  // the palette: places at once, then what the hub finds
  var palette = null;
  function openPalette() {
    if (palette) { return; }
    var dialog = document.createElement("dialog");
    dialog.setAttribute("aria-label", "Find");
    dialog.innerHTML = '<div class="d-h"><h2>Find</h2><button type="button" class="ghost" data-close aria-label="Close">&#215;</button></div><form class="d-b" method="get" action="/find" role="search"><div class="field"><input name="q" type="search" autofocus autocomplete="off" aria-label="Find a machine, incident or page" placeholder="A machine, incident or page"></div><div data-results aria-live="polite"></div></form>';
    document.body.appendChild(dialog);
    var entry = modal(dialog, document.activeElement, true);
    palette = dialog;
    dialog.addEventListener("close", function () { palette = null; });
    var input = dialog.querySelector("input"), results = dialog.querySelector("[data-results]"), asked = 0, timer;
    function ask() {
      var n = ++asked;
      fetch("/find?q=" + encodeURIComponent(input.value), { credentials: "same-origin" }).then(function (r) { return r.text(); }).then(function (html) {
        if (n !== asked) { return; }
        var found = new DOMParser().parseFromString(html, "text/html").querySelector("[data-found]");
        results.replaceChildren();
        if (found) { results.appendChild(document.importNode(found, true)); }
      }, function () { });
    }
    input.addEventListener("input", function () { clearTimeout(timer); timer = setTimeout(ask, 120); });
    dialog.addEventListener("keydown", function (e) {
      if (e.key !== "ArrowDown" && e.key !== "ArrowUp") { return; }
      var items = [input].concat(all("a", results)), at = items.indexOf(document.activeElement);
      e.preventDefault();
      items[(at + (e.key === "ArrowDown" ? 1 : items.length - 1)) % items.length].focus();
    });
    dialog.querySelector("form").addEventListener("submit", function (e) {
      var first = results.querySelector("a");
      if (first) { e.preventDefault(); location.href = first.href; }
    });
    ask();
    return entry;
  }
  all("[data-palette]").forEach(function (a) { a.addEventListener("click", function (e) { e.preventDefault(); openPalette(); }); });

  // shortcuts: one listener; where they go is what the page's own links say
  var mac = /Mac|iPhone|iPad/.test(navigator.platform || "");
  if (mac) { all("[data-ctrl]").forEach(function (k) { k.textContent = "⌘"; }); }
  var going = 0;
  document.addEventListener("keydown", function (e) {
    var ctrl = e.ctrlKey || e.metaKey, target = e.target;
    if (ctrl && !e.altKey && e.key.toLowerCase() === "k") { e.preventDefault(); if (!palette) { byHotkey(openPalette); } return; }
    if (ctrl && e.key === "Enter" && target.form && target.tagName === "TEXTAREA") { e.preventDefault(); target.form.requestSubmit(); return; }
    if (e.key === "Escape") {
      if (stack.length) { e.preventDefault(); byHotkey(function () { leave(stack[stack.length - 1]); }); } else if (menus.some(function (m) { return m.open; })) { byHotkey(function () { closeMenus(true); }); } else if (drawerOpen()) { byHotkey(closeDrawer); }
      return;
    }
    if (ctrl || e.altKey || /^(INPUT|SELECT|TEXTAREA)$/.test(target.tagName) || target.isContentEditable || stack.length) { return; }
    var key = e.key;
    if (going && Date.now() - going < 1200) {
      going = 0;
      var link = all("[data-key]").filter(function (a) { return a.dataset.key === key.toLowerCase(); })[0];
      if (link) { e.preventDefault(); location.href = link.href; }
      return;
    }
    going = 0;
    if (key === "g") { going = Date.now(); } else if (key === "/") { e.preventDefault(); byHotkey(openPalette); } else if (key === "?") {
      var help = document.querySelector("[data-help]");
      if (help) { e.preventDefault(); byHotkey(function () { openDialog(help); }); }
    } else if (key === "c" || key === "n") {
      var create = document.querySelector("[data-create]");
      if (create) { e.preventDefault(); location.href = create.href + "?add=machine"; }
    }
  });

  // a newer hub behind an open page: said, never reloaded
  var built = (document.querySelector("meta[name=app-build]") || {}).content, told = false;
  function check() {
    if (told || document.hidden) { return; }
    fetch("/version", { credentials: "same-origin", cache: "no-store" }).then(function (r) { return r.ok ? r.json() : null; }).then(function (v) {
      if (!v || v.build === built || told) { return; }
      told = true;
      var notice = document.createElement("div");
      notice.className = "update-notice";
      notice.setAttribute("role", "status");
      notice.innerHTML = '<p>Rackhand was updated. Refresh to use the new version.</p><button type="button" class="primary" data-refresh>Refresh</button><button type="button" data-later>Later</button>';
      notice.querySelector("[data-refresh]").addEventListener("click", function () { location.reload(); });
      notice.querySelector("[data-later]").addEventListener("click", function () { notice.remove(); });
      document.body.appendChild(notice);
    }, function () { });
  }
  setInterval(check, 60000);
  window.addEventListener("focus", check);
})();
