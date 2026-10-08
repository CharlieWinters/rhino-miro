/**
 * Stateless sealed values: AES-256-GCM under a key derived (HKDF) from the TOKEN_KEY
 * Worker secret. Used for the in-flight login state and the one-shot token ticket, so the Worker needs
 * no database. Miro tokens only ever cross the browser inside a ticket sealed here.
 *
 * `kind` is bound in as additional authenticated data, so a value sealed as one kind
 * (a login flow) can never be opened as another (a token ticket).
 *
 * Rotating TOKEN_KEY only breaks sign-ins that are in flight at that moment.
 */
const enc = new TextEncoder();
const dec = new TextDecoder();
let cached = null; // { secret, key }

function b64urlEncode(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
  const s = atob(str.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

async function sealKey(secret) {
  if (cached && cached.secret === secret) return cached.key;
  if (!secret) throw new Error("TOKEN_KEY secret is not set");
  const raw = b64urlDecode(secret.trim());
  if (raw.length < 32) throw new Error("TOKEN_KEY must be at least 32 random bytes, base64");
  const base = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode("rhino-miro-auth"), info: enc.encode("seal-v1") },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  cached = { secret, key };
  return key;
}

export async function seal(secret, kind, payload) {
  const key = await sealKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(kind) }, key, enc.encode(JSON.stringify(payload)))
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  return b64urlEncode(out);
}

/** Returns the payload, or null if the value is malformed, tampered, the wrong kind, or expired. */
export async function unseal(secret, kind, value) {
  const key = await sealKey(secret); // config errors should surface, not read as "invalid token"
  try {
    if (typeof value !== "string" || value.length < 40 || value.length > 8192) return null;
    const bytes = b64urlDecode(value);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12), additionalData: enc.encode(kind) }, key, bytes.slice(12));
    const payload = JSON.parse(dec.decode(pt));
    if (typeof payload.exp === "number" && Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

export async function sha256Hex(text) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text)));
  return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256B64url(text) {
  return b64urlEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text))));
}

/** Constant-time string comparison. */
export function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
