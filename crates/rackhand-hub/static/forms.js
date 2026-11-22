// Forms that check themselves as they are filled in. The rules are the fields' own attributes (required, minlength,
// pattern with data-rule); the server checks the same ones and everything else. Nothing here is needed to use a form.
(function () {
  "use strict";

  function errorOf(input) { return document.getElementById(input.id + "-error"); }

  function problem(input) {
    var value = input.type === "password" ? input.value : input.value.trim();
    if (input.dataset.same) {
      var first = input.form.elements[input.dataset.same];
      if (!value) { return first.value ? "Type it again" : ""; }
      return value === first.value ? "" : "It isn't the same as the first";
    }
    if (!value) { return input.required ? (input.tagName === "SELECT" ? "Choose one" : "This is needed") : ""; }
    var length = Array.from(value).length;
    if (input.minLength > 0 && length < input.minLength) {
      var more = input.minLength - length;
      return more + " more character" + (more === 1 ? "" : "s") + " needed";
    }
    var pattern = input.getAttribute("pattern");
    if (pattern && !new RegExp("^(?:" + pattern + ")$", "u").test(value)) { return input.dataset.rule; }
    return "";
  }

  function show(input) {
    var error = errorOf(input);
    if (!error) { return; }
    var says = problem(input);
    error.textContent = says;
    error.hidden = !says;
    var field = input.closest(".field");
    field.classList.toggle("bad", !!says);
    field.classList.toggle("good", !says && !!input.value);
    if (says) { input.setAttribute("aria-invalid", "true"); } else { input.removeAttribute("aria-invalid"); }
  }

  function watch(form) {
    if (form.dataset.watching) { return; }
    form.dataset.watching = "1";
    // fields that only one choice needs come and go with it; what was typed stays
    var dependent = Array.prototype.slice.call(form.querySelectorAll("[data-when]"));
    function choose() {
      dependent.forEach(function (field) {
        var when = field.dataset.when.split("="), on = form.elements[when[0]];
        field.hidden = !!on && on.value !== when[1];
      });
    }
    form.addEventListener("change", choose);
    choose();
    form.querySelectorAll("input, select").forEach(function (input) {
      if (!errorOf(input)) { return; }
      var seen = input.getAttribute("aria-invalid") === "true";
      errorOf(input).setAttribute("aria-live", "polite");
      // not while a first value is still being typed, except for a character that can't be right
      input.addEventListener("input", function () {
        if (seen || input.minLength > 0 || (input.value && input.hasAttribute("pattern"))) { show(input); }
      });
      input.addEventListener("change", function () { seen = true; show(input); });
      input.addEventListener("blur", function () { if (input.value || seen) { seen = true; show(input); } });
    });
    // pressed once is sent once
    form.addEventListener("submit", function (event) {
      if (form.dataset.sent) { event.preventDefault(); return; }
      form.dataset.sent = "1";
    });
  }

  // coming back to a page with the Back button, its forms can be sent again
  window.addEventListener("pageshow", function () {
    document.querySelectorAll("form[data-check]").forEach(function (f) { delete f.dataset.sent; });
  });

  function reveal(input) {
    if (input.dataset.revealed) { return; }
    input.dataset.revealed = "1";
    var button = document.createElement("button");
    button.type = "button";
    button.className = "reveal";
    button.textContent = "Show";
    button.setAttribute("aria-controls", input.id);
    button.addEventListener("click", function () {
      var hidden = input.type === "password";
      input.type = hidden ? "text" : "password";
      button.textContent = hidden ? "Hide" : "Show";
    });
    input.insertAdjacentElement("afterend", button);
    input.form.addEventListener("submit", function () { input.type = "password"; });
  }

  // copy buttons: data-copy names the element
  function copier(button) {
    var source = document.getElementById(button.dataset.copy);
    if (!source || button.dataset.copies) { return; }
    button.dataset.copies = "1";
    var label = button.textContent;
    button.hidden = false;
    button.addEventListener("click", function () {
      var text = "value" in source ? source.value : source.textContent;
      function done() {
        button.textContent = "Copied";
        setTimeout(function () { button.textContent = label; }, 2000);
      }
      function fallback() {
        if (source.select) { source.select(); } else { window.getSelection().selectAllChildren(source); }
        if (document.execCommand("copy")) { done(); } else { button.textContent = "Press Ctrl+C to copy"; }
      }
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, fallback);
      } else {
        fallback();
      }
    });
  }

  function start(within) {
    within.querySelectorAll("form[data-check]").forEach(watch);
    // a timezone nobody has chosen yet is the browser's
    within.querySelectorAll("select[data-browser-timezone]").forEach(function (select) {
      if (select.value) { return; }
      var zone = "";
      try { zone = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) { return; }
      if (Array.prototype.some.call(select.options, function (o) { return o.value === zone; })) { select.value = zone; }
    });
    within.querySelectorAll("form[data-check] input[type=password]").forEach(reveal);
    within.querySelectorAll("[data-copy]").forEach(copier);
  }
  window.rackhandForms = start;
  start(document);

  var problems = document.querySelector("[data-focus]");
  if (problems) { problems.focus(); }
})();
