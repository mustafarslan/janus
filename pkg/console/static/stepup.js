// The browser half of a step-up.
//
// This script decides nothing. It asks the server which challenge an assertion
// for this approval must be signed over, asks the authenticator to sign it, and
// puts the result in a form field. Everything that matters — that the challenge
// is the right one, that the credential belongs to the person the ID token
// names, that the signature verifies — is checked server-side against a binding
// the server recomputes and a trust store folded out of the evidence log.
//
// So the failure mode of a bug here is a refused approval with a reason on the
// screen, not a wrong one silently recorded. That is deliberate: no test in
// this repository executes this file, and it is only safe to ship untested
// because it cannot be believed.

(function () {
  "use strict";

  function fromBase64Url(s) {
    const padded = s.replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(padded + "===".slice((padded.length + 3) % 4));
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  function toBase64(bytes) {
    let s = "";
    const view = new Uint8Array(bytes);
    for (let i = 0; i < view.length; i++) s += String.fromCharCode(view[i]);
    return btoa(s);
  }

  function say(form, message, bad) {
    let note = form.nextElementSibling;
    if (!note || !note.classList.contains("js-stepup-note")) {
      note = document.createElement("p");
      note.className = "js-stepup-note";
      form.parentNode.insertBefore(note, form.nextSibling);
    }
    note.className = "js-stepup-note " + (bad ? "bad" : "dim");
    note.textContent = message;
  }

  // The challenge is fetched rather than computed here, and the attempt comes
  // back with it. An approval is for one attempt, and a page that named its own
  // would be able to collect an assertion for a decision that is not the one in
  // front of the person.
  async function challengeFor(form) {
    const q = new URLSearchParams({
      saga_id: form.saga_id.value,
      step_id: form.step_id.value,
      requirement_id: form.requirement_id.value,
    });
    const res = await fetch("/api/stepup?" + q.toString(), {
      headers: { Accept: "application/json" },
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || "the server would not issue a challenge");
    return body;
  }

  async function sign(challenge) {
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: fromBase64Url(challenge),
        userVerification: "preferred",
        timeout: 120000,
      },
    });
    if (!credential) throw new Error("no assertion was produced");
    const r = credential.response;
    return JSON.stringify({
      credential_id: credential.id,
      authenticator_data: toBase64(r.authenticatorData),
      client_data_json: toBase64(r.clientDataJSON),
      signature: toBase64(r.signature),
    });
  }

  function attach(form) {
    let done = false;
    form.addEventListener("submit", async function (event) {
      if (done) return;
      event.preventDefault();

      // Which button was pressed has to be carried over the async gap: the
      // browser drops the submitter when the form is resubmitted from script,
      // and losing it would turn a refusal into nothing at all.
      const submitter = event.submitter;
      if (submitter) {
        let carried = form.querySelector("input[name='verdict'][type='hidden']");
        if (!carried) {
          carried = document.createElement("input");
          carried.type = "hidden";
          carried.name = "verdict";
          form.appendChild(carried);
        }
        carried.value = submitter.value;
      }

      if (!window.PublicKeyCredential || !navigator.credentials) {
        say(form, "This browser cannot produce a step-up, or the console is not being " +
          "served over https or localhost — navigator.credentials exists only in a secure " +
          "context. The approval was not submitted.", true);
        return;
      }

      try {
        say(form, "Waiting for your authenticator…", false);
        const c = await challengeFor(form);
        form.step_up.value = await sign(c.challenge);
        say(form, "Signed for attempt " + c.attempt + ". Submitting…", false);
        done = true;
        form.submit();
      } catch (err) {
        say(form, "No step-up was captured, so nothing was recorded: " + err.message, true);
      }
    });
  }

  document.querySelectorAll("form[data-stepup]").forEach(attach);
})();
