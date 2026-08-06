// Client-side key custody: the org's browser generates an Ed25519
// keypair via Web Crypto, the private key is created non-extractable
// (extractable: false -- SubtleCrypto never lets it be exported as raw
// bytes again, by construction, not by policy) and persisted in
// IndexedDB, which is specifically able to store CryptoKey objects
// directly, extractable or not, via the structured clone algorithm.
// localStorage/sessionStorage can't hold a CryptoKey at all.
//
// Losing the browser profile/device means losing the ability to sign
// with this key forever -- there is no export/backup path, by design.
// The only recovery is registering a new key (an unplanned rotation).
// This is exactly why the backend's versioned-key model exists: without
// painless rotation, that would be catastrophic; with it, it's routine.

const DB_NAME = "feoc-signing-keys";
const DB_VERSION = 1;
const STORE_NAME = "keypairs";

function openKeyDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(STORE_NAME, { keyPath: "issuerId" });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet(issuerId) {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const req = tx.objectStore(STORE_NAME).get(issuerId);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

async function idbPut(record) {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).put(record);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// Feature detection, not a version sniff: attempts the real operation
// and reports whether it actually worked, per the plan's explicit
// instruction not to assume support. Ed25519 in SubtleCrypto is
// Baseline-widely-available (Chrome/Edge 137+, Firefox 129+, Safari
// 17+, all shipped in 2025 or earlier) but a stale/embedded browser is
// still possible.
async function isEd25519Supported() {
  try {
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
    return !!(pair && pair.privateKey && pair.publicKey);
  } catch (e) {
    return false;
  }
}

function bufToB64(buf) {
  let binary = "";
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function b64ToBuf(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function exportPublicKeyRawB64(publicKey) {
  // "raw" is exactly the bare 32-byte RFC 8032 point per the WebCrypto
  // Secure Curves spec -- the same encoding crypto_utils.py already
  // uses server-side, so no format conversion is needed anywhere.
  const raw = await crypto.subtle.exportKey("raw", publicKey);
  return bufToB64(raw);
}

async function getStoredKeyRecord(issuerId) {
  return idbGet(issuerId);
}

// Generates a fresh keypair and overwrites any existing local record
// for this issuer -- explicit "start a rotation" semantics, matching
// the plan's combined "Generate & Register" action, rather than a
// separate "reuse my existing local key" path that could leave a
// stale, never-registered key lying around ambiguously.
async function generateAndStoreNewKeyPair(issuerId) {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  const record = { issuerId, publicKey: pair.publicKey, privateKey: pair.privateKey, keyId: null, registeredAt: null };
  await idbPut(record);
  return record;
}

async function markKeyRegistered(issuerId, keyId, registeredAt) {
  const record = await idbGet(issuerId);
  if (!record) throw new Error("no local key to mark as registered");
  record.keyId = keyId;
  record.registeredAt = registeredAt;
  await idbPut(record);
  return record;
}

async function signBytesB64(privateKey, bytesB64) {
  const signature = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, b64ToBuf(bytesB64));
  return bufToB64(signature);
}
