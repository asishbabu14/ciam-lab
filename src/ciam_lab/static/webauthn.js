function bytesToB64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlToBytes(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function credentialToJSON(credential) {
  const response = {
    clientDataJSON: bytesToB64url(credential.response.clientDataJSON),
  };
  if (credential.response.attestationObject) {
    response.attestationObject = bytesToB64url(credential.response.attestationObject);
  }
  if (credential.response.authenticatorData) {
    response.authenticatorData = bytesToB64url(credential.response.authenticatorData);
  }
  if (credential.response.signature) {
    response.signature = bytesToB64url(credential.response.signature);
  }
  if (credential.response.userHandle) {
    response.userHandle = bytesToB64url(credential.response.userHandle);
  }
  return {
    id: credential.id,
    rawId: bytesToB64url(credential.rawId),
    type: credential.type,
    response,
  };
}

function prepareCreation(publicKey) {
  const options = { ...publicKey };
  options.challenge = b64urlToBytes(publicKey.challenge);
  options.user = { ...publicKey.user, id: b64urlToBytes(publicKey.user.id) };
  if (publicKey.excludeCredentials) {
    options.excludeCredentials = publicKey.excludeCredentials.map((item) => ({
      ...item,
      id: b64urlToBytes(item.id),
    }));
  }
  return options;
}

function prepareRequest(publicKey) {
  const options = { ...publicKey };
  options.challenge = b64urlToBytes(publicKey.challenge);
  if (publicKey.allowCredentials) {
    options.allowCredentials = publicKey.allowCredentials.map((item) => ({
      ...item,
      id: b64urlToBytes(item.id),
    }));
  }
  return options;
}

function setStatus(text) {
  const node = document.getElementById("passkey-status");
  if (node) node.textContent = text;
}

async function registerPasskey() {
  setStatus("Asking the provider for a challenge.");
  const options = await fetch("/webauthn/register/options", { method: "POST" }).then((response) => response.json());
  if (options.error) {
    setStatus(options.error_description || options.error);
    return;
  }
  const credential = await navigator.credentials.create({ publicKey: prepareCreation(options.publicKey) });
  const verified = await fetch("/webauthn/register/verify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ challenge_id: options.challenge_id, credential: credentialToJSON(credential) }),
  }).then((response) => response.json());
  if (!verified.ok) {
    setStatus(verified.error_description || "Registration failed.");
    return;
  }
  window.location.reload();
}

async function authenticatePasskey() {
  const email = document.getElementById("passkey-email").value;
  const requestId = document.getElementById("passkey-request").value;
  setStatus("Asking the provider for a challenge.");
  const options = await fetch("/webauthn/authenticate/options", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, request_id: requestId }),
  }).then((response) => response.json());
  if (options.error) {
    setStatus(options.error_description || options.error);
    return;
  }
  const credential = await navigator.credentials.get({ publicKey: prepareRequest(options.publicKey) });
  const verified = await fetch("/webauthn/authenticate/verify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      challenge_id: options.challenge_id,
      request_id: requestId,
      credential: credentialToJSON(credential),
    }),
  }).then((response) => response.json());
  if (!verified.ok) {
    setStatus(verified.error_description || "Authentication failed.");
    return;
  }
  window.location = verified.next_url;
}

const registerButton = document.getElementById("register-passkey");
if (registerButton) registerButton.addEventListener("click", () => registerPasskey().catch((error) => setStatus(String(error))));

const passkeyButton = document.getElementById("passkey-button");
if (passkeyButton) passkeyButton.addEventListener("click", () => authenticatePasskey().catch((error) => setStatus(String(error))));
