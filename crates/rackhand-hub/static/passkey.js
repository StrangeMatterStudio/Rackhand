// Passkeys in the browser (7.7.2): a button with data-passkey="create" or "get" fetches the options from its
// data-options URL, asks the browser's authenticator, and submits the answer in its form's "credential" field.
(function () {
  "use strict";
  function bytes(text) {
    var b64 = text.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) { b64 += "="; }
    return Uint8Array.from(atob(b64), function (c) { return c.charCodeAt(0); });
  }
  function text(buffer) {
    var s = "";
    new Uint8Array(buffer).forEach(function (b) { s += String.fromCharCode(b); });
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  async function run(button) {
    var form = button.closest("form");
    var csrf = form.querySelector("[name=csrf]").value;
    var resp = await fetch(button.dataset.options, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "csrf=" + encodeURIComponent(csrf),
      credentials: "same-origin",
    });
    if (!resp.ok) { throw new Error(await resp.text()); }
    var pk = (await resp.json()).publicKey;
    pk.challenge = bytes(pk.challenge);
    var answer;
    if (button.dataset.passkey === "create") {
      pk.user.id = bytes(pk.user.id);
      (pk.excludeCredentials || []).forEach(function (c) { c.id = bytes(c.id); });
      var made = await navigator.credentials.create({ publicKey: pk });
      answer = {
        id: made.id, rawId: text(made.rawId), type: made.type, extensions: {},
        response: {
          attestationObject: text(made.response.attestationObject),
          clientDataJSON: text(made.response.clientDataJSON),
        },
      };
    } else {
      (pk.allowCredentials || []).forEach(function (c) { c.id = bytes(c.id); });
      var got = await navigator.credentials.get({ publicKey: pk });
      answer = {
        id: got.id, rawId: text(got.rawId), type: got.type, extensions: {},
        response: {
          authenticatorData: text(got.response.authenticatorData),
          clientDataJSON: text(got.response.clientDataJSON),
          signature: text(got.response.signature),
          userHandle: got.response.userHandle ? text(got.response.userHandle) : null,
        },
      };
    }
    form.querySelector("[name=credential]").value = JSON.stringify(answer);
    form.submit();
  }
  document.querySelectorAll("[data-passkey]").forEach(function (button) {
    button.addEventListener("click", function () {
      var said = button.nextElementSibling;
      if (!said || !said.matches("[data-passkey-error]")) {
        said = document.createElement("p");
        said.className = "field-error";
        said.setAttribute("role", "alert");
        said.setAttribute("data-passkey-error", "");
        button.insertAdjacentElement("afterend", said);
      }
      said.textContent = "";
      run(button).catch(function (e) { said.textContent = e.message; });
    });
  });
})();
