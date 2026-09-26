// Passkeys (WebAuthn) between the API and the browser. The API speaks
// WebAuthn's JSON forms, binary values as unpadded base64url; the browser's
// navigator.credentials wants and returns ArrayBuffers. These conversions are
// done here by hand, the same in every browser, rather than with the newer
// parse*FromJSON / toJSON helpers that not every browser has yet.

export function toBase64Url(value) {
  const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) binary += String.fromCharCode(bytes[index]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new TypeError("Not base64url");
  }
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes.buffer;
}

function descriptors(list) {
  return (list || []).map((item) => ({
    type: item.type || "public-key",
    id: fromBase64Url(item.id),
    ...(item.transports?.length ? { transports: item.transports } : {}),
  }));
}

/** ``PublicKeyCredentialCreationOptions`` from the API's JSON options. */
export function creationOptions(json) {
  return {
    rp: { id: json.rp.id, name: json.rp.name },
    user: { id: fromBase64Url(json.user.id), name: json.user.name, displayName: json.user.displayName },
    challenge: fromBase64Url(json.challenge),
    pubKeyCredParams: json.pubKeyCredParams.map((item) => ({ type: item.type || "public-key", alg: item.alg })),
    timeout: json.timeout,
    excludeCredentials: descriptors(json.excludeCredentials),
    authenticatorSelection: json.authenticatorSelection,
    attestation: json.attestation || "none",
  };
}

/** ``PublicKeyCredentialRequestOptions`` from the API's JSON options. */
export function requestOptions(json) {
  return {
    challenge: fromBase64Url(json.challenge),
    timeout: json.timeout,
    rpId: json.rpId,
    allowCredentials: descriptors(json.allowCredentials),
    userVerification: json.userVerification || "required",
  };
}

function common(credential) {
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? null,
    clientExtensionResults: credential.getClientExtensionResults?.() ?? {},
  };
}

/** The JSON form of a new credential (``navigator.credentials.create``). */
export function registrationJSON(credential) {
  const response = credential.response;
  const publicKey = response.getPublicKey?.();
  return {
    ...common(credential),
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
      attestationObject: toBase64Url(response.attestationObject),
      transports: response.getTransports?.() ?? [],
      authenticatorData: response.getAuthenticatorData ? toBase64Url(response.getAuthenticatorData()) : null,
      publicKey: publicKey ? toBase64Url(publicKey) : null,
      publicKeyAlgorithm: response.getPublicKeyAlgorithm?.() ?? null,
    },
  };
}

/** The JSON form of an assertion (``navigator.credentials.get``). */
export function assertionJSON(credential) {
  const response = credential.response;
  return {
    ...common(credential),
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
      authenticatorData: toBase64Url(response.authenticatorData),
      signature: toBase64Url(response.signature),
      userHandle: response.userHandle && response.userHandle.byteLength ? toBase64Url(response.userHandle) : null,
    },
  };
}

export function passkeysSupported() {
  return typeof globalThis.PublicKeyCredential === "function" && Boolean(globalThis.navigator?.credentials);
}

/** Create a passkey from the API's creation options; returns its JSON form. */
export async function createPasskey(options, credentials = globalThis.navigator.credentials) {
  const credential = await credentials.create({ publicKey: creationOptions(options) });
  if (!credential) throw new DOMException("No passkey was created.", "NotAllowedError");
  return registrationJSON(credential);
}

/** Sign with a passkey for the API's request options; returns the assertion's JSON form. */
export async function usePasskey(options, credentials = globalThis.navigator.credentials) {
  const credential = await credentials.get({ publicKey: requestOptions(options) });
  if (!credential) throw new DOMException("No passkey was used.", "NotAllowedError");
  return assertionJSON(credential);
}

/** A sentence for a failed ceremony (the browser's own messages vary and leak little). */
export function describePasskeyError(error) {
  switch (error?.name) {
    case "NotAllowedError":
      return "The passkey request was cancelled or timed out.";
    case "InvalidStateError":
      return "This authenticator already holds a passkey for your account.";
    case "SecurityError":
      return "Passkeys need this console on its own HTTPS address.";
    case "NotSupportedError":
      return "This browser or authenticator does not support the passkey the platform asked for.";
    case "AbortError":
      return "The passkey request was interrupted.";
    default:
      return "The passkey could not be used.";
  }
}
