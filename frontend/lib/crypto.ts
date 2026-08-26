"use client";

/**
 * Officer signing keys, generated and held in the browser.
 *
 * The private key is created non-extractable and stored as a CryptoKey in
 * IndexedDB, so it cannot be read out by page script, cannot be serialised into
 * application state, and never reaches the backend. The server only ever sees
 * the public half and the signatures.
 */

const DB_NAME = "nyayvault-keys";
const STORE = "signing-keys";
const DB_VERSION = 1;

const ALGORITHM: RsaHashedKeyGenParams = {
  name: "RSA-PSS",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};

// Must match the salt length the backend verifies with.
const SALT_LENGTH = 32;

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE)) {
        request.result.createObjectStore(STORE);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function idbGet<T>(key: string): Promise<T | undefined> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const request = tx.objectStore(STORE).get(key);
    request.onsuccess = () => resolve(request.result as T | undefined);
    request.onerror = () => reject(request.error);
  });
}

async function idbPut(key: string, value: unknown): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function idbDelete(key: string): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function privateKeyId(badgeNumber: string) {
  return `${badgeNumber}:private`;
}

function publicKeyId(badgeNumber: string) {
  return `${badgeNumber}:public-pem`;
}

function toBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function toPem(spki: ArrayBuffer): string {
  const base64 = toBase64(spki);
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----`;
}

export function cryptoAvailable(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.crypto?.subtle !== "undefined" &&
    typeof window.indexedDB !== "undefined"
  );
}

/** Generate a keypair for this officer. The private half stays in IndexedDB. */
export async function generateKeypair(badgeNumber: string): Promise<string> {
  const pair = await crypto.subtle.generateKey(ALGORITHM, false, ["sign", "verify"]);
  const spki = await crypto.subtle.exportKey("spki", pair.publicKey);
  const pem = toPem(spki);

  await idbPut(privateKeyId(badgeNumber), pair.privateKey);
  await idbPut(publicKeyId(badgeNumber), pem);

  return pem;
}

export async function hasLocalKey(badgeNumber: string): Promise<boolean> {
  return (await idbGet<CryptoKey>(privateKeyId(badgeNumber))) !== undefined;
}

export async function localPublicKeyPem(badgeNumber: string): Promise<string | undefined> {
  return idbGet<string>(publicKeyId(badgeNumber));
}

export async function forgetLocalKey(badgeNumber: string): Promise<void> {
  await idbDelete(privateKeyId(badgeNumber));
  await idbDelete(publicKeyId(badgeNumber));
}

export class NoSigningKey extends Error {
  constructor() {
    super("No signing key on this device. Generate one under Security before continuing.");
    this.name = "NoSigningKey";
  }
}

/** Sign a message with this officer's private key. */
export async function signMessage(badgeNumber: string, message: string): Promise<string> {
  const key = await idbGet<CryptoKey>(privateKeyId(badgeNumber));
  if (!key) throw new NoSigningKey();

  const signature = await crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: SALT_LENGTH },
    key,
    new TextEncoder().encode(message),
  );
  return toBase64(signature);
}

/** SHA-256 of a file, hex encoded -- the value the officer signs on upload. */
export async function sha256Hex(file: Blob): Promise<string> {
  const buffer = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * The exact string the backend reconstructs for a custody transfer.
 * Key order and separators must match `transfer_message` in app/api/v1/assets.py.
 */
export function transferMessage(params: {
  qr_uuid: string;
  expected_prior_custody_status: string;
  new_custody_status: string;
  receiving_officer_badge_number: string;
}): string {
  return JSON.stringify({
    expected_prior_custody_status: params.expected_prior_custody_status,
    new_custody_status: params.new_custody_status,
    qr_uuid: params.qr_uuid,
    receiving_officer_badge_number: params.receiving_officer_badge_number,
  });
}
