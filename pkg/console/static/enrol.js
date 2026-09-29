// Enrolling an authenticator.
//
// Like the approval ceremony, this script decides nothing. It asks the server
// which challenge to register against — derived from the identity the
// authenticating layer established, never from anything on this page — has the
// browser create a credential, and posts back the public key. The server checks
// the ceremony type and the challenge before recording anything.
//
// getPublicKey() rather than the attestation object on purpose: with the "none"
// attestation asked for here, parsing the attestation CBOR would be a decoder,
// not a check, and getPublicKey() hands over the same key already in the SPKI
// DER that crypto/x509 reads.

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
    if (!note || !note.classList.contains("js-enrol-note")) {
      note = document.createElement("p");
      note.className = "js-enrol-note";
      form.parentNode.insertBefore(note, form.nextSibling);
    }
    note.className = "js-enrol-note " + (bad ? "bad" : "dim");
    note.textContent = message;
  }

  async function challenge() {
    const res = await fetch("/api/enrol", { headers: { Accept: "application/json" } });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || "the server would not issue a challenge");
    return body;
  }

  async function create(c) {
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: fromBase64Url(c.challenge),
        rp: { name: "Janus console" },
        // The user handle is the subject the server named, not anything this
        // page chose. It is what the authenticator shows the person when they
        // are later asked to sign.
        user: {
          id: new TextEncoder().encode(c.subject),
          name: c.subject,
          displayName: c.subject,
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },   // ES256
          { type: "public-key", alg: -8 },   // EdDSA
          { type: "public-key", alg: -257 }, // RS256
        ],
        attestation: "none",
        authenticatorSelection: { userVerification: "preferred" },
        timeout: 120000,
      },
    });
    if (!credential) throw new Error("no credential was created");
    const r = credential.response;
    if (typeof r.getPublicKey !== "function") {
      throw new Error(
        "this browser does not expose getPublicKey() on a registration, so the console " +
          "cannot read the credential's public key"
      );
    }
    const key = r.getPublicKey();
    if (!key) throw new Error("the authenticator produced a key this browser cannot export");
    return JSON.stringify({
      credential_id: credential.id,
      client_data_json: toBase64(r.clientDataJSON),
      public_key: toBase64(key),
    });
  }

  function attach(form) {
    let done = false;
    form.addEventListener("submit", async function (event) {
      if (done) return;
      event.preventDefault();

      if (!window.PublicKeyCredential || !navigator.credentials) {
        say(form, "This browser cannot enrol an authenticator, or the console is not being " +
          "served over https or localhost — navigator.credentials exists only in a secure " +
          "context. Nothing was registered.", true);
        return;
      }

      try {
        say(form, "Waiting for your authenticator…", false);
        const c = await challenge();
        form.enrolment.value = await create(c);
        say(form, "Registering…", false);
        done = true;
        form.submit();
      } catch (err) {
        say(form, "Nothing was registered: " + err.message, true);
      }
    });
  }

  document.querySelectorAll("form[data-enrol]").forEach(attach);
})();
