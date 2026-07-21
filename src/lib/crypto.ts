export type Environment = "local" | "development" | "uat" | "production";
export type SecretType = "login" | "apiKey" | "licenseKey";

export type EncryptedPayload = {
  ciphertext: string;
  iv: string;
  wrappedKey: string;
  algorithm: "AES-256-GCM+AES-KW";
  aadVersion: 1;
};

export type SecretPayload = {
  notes: string;
  username?: string;
  password?: string;
  url?: string;
  apiKey?: string;
  endpoint?: string;
  licenseKey?: string;
  licensee?: string;
  expiresAt?: string;
};

export type AttachmentMetadata = {
  name: string;
  mimeType: string;
  originalSize: number;
};

type DeviceKeyMaterial = {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicJwk: string;
};

type StoredDeviceKey = DeviceKeyMaterial & { userId: string };

const DATABASE_NAME = "nebula-secrets-keys";
const STORE_NAME = "deviceKeys";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function openKeyDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME, { keyPath: "userId" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Unable to open device key storage."));
  });
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Device key storage failed."));
  });
}

export async function generateDeviceKeyMaterial(): Promise<DeviceKeyMaterial> {
  const generated = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"],
  );
  const [publicJwk, privatePkcs8] = await Promise.all([
    crypto.subtle.exportKey("jwk", generated.publicKey),
    crypto.subtle.exportKey("pkcs8", generated.privateKey),
  ]);
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    privatePkcs8,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"],
  );
  new Uint8Array(privatePkcs8).fill(0);
  return {
    privateKey,
    publicKey: generated.publicKey,
    publicJwk: JSON.stringify(publicJwk),
  };
}

export async function persistDeviceKey(userId: string, material: DeviceKeyMaterial) {
  const database = await openKeyDatabase();
  const transaction = database.transaction(STORE_NAME, "readwrite");
  await requestResult(
    transaction.objectStore(STORE_NAME).put({ userId, ...material } satisfies StoredDeviceKey),
  );
  database.close();
}

export async function getDeviceKey(userId: string): Promise<StoredDeviceKey | null> {
  const database = await openKeyDatabase();
  const transaction = database.transaction(STORE_NAME, "readonly");
  const result = await requestResult(
    transaction.objectStore(STORE_NAME).get(userId) as IDBRequest<StoredDeviceKey | undefined>,
  );
  database.close();
  return result ?? null;
}

export async function hasDeviceKey(userId: string) {
  return Boolean(await getDeviceKey(userId));
}

export function clearDeviceKeys(): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(DATABASE_NAME);
    request.onsuccess = () => resolve();
    request.onerror = () =>
      reject(request.error ?? new Error("Unable to clear device key storage."));
    request.onblocked = () =>
      reject(new Error("Close other Nebula Secrets tabs before clearing device keys."));
  });
}

export async function generateEnvironmentKey() {
  return await crypto.subtle.generateKey({ name: "AES-KW", length: 256 }, true, [
    "wrapKey",
    "unwrapKey",
  ]);
}

function bytesToBase64(value: ArrayBuffer | Uint8Array) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  const step = 0x8000;
  for (let index = 0; index < bytes.length; index += step) {
    binary += String.fromCharCode(...bytes.subarray(index, index + step));
  }
  return btoa(binary);
}

function base64ToBytes(value: string) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

async function importPublicKey(publicJwk: string) {
  return await crypto.subtle.importKey(
    "jwk",
    JSON.parse(publicJwk) as JsonWebKey,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"],
  );
}

export async function wrapEnvironmentKey(environmentKey: CryptoKey, publicJwk: string) {
  const publicKey = await importPublicKey(publicJwk);
  const raw = await crypto.subtle.exportKey("raw", environmentKey);
  const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, raw);
  new Uint8Array(raw).fill(0);
  return bytesToBase64(wrapped);
}

export async function unwrapEnvironmentKey(userId: string, wrappedKey: string) {
  const device = await getDeviceKey(userId);
  if (!device) throw new Error("This device does not hold the selected user’s private key.");
  const raw = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    device.privateKey,
    base64ToBytes(wrappedKey),
  );
  const key = await crypto.subtle.importKey("raw", raw, { name: "AES-KW" }, true, [
    "wrapKey",
    "unwrapKey",
  ]);
  new Uint8Array(raw).fill(0);
  return key;
}

async function createDataKey() {
  return await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
}

async function wrapDataKey(dataKey: CryptoKey, environmentKey: CryptoKey) {
  return await crypto.subtle.wrapKey("raw", dataKey, environmentKey, "AES-KW");
}

async function unwrapDataKey(wrappedKey: string, environmentKey: CryptoKey) {
  return await crypto.subtle.unwrapKey(
    "raw",
    base64ToBytes(wrappedKey),
    environmentKey,
    "AES-KW",
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export function secretAad(args: {
  cryptoId: string;
  environment: Environment;
  owner: string;
  type: SecretType;
  version: number;
}) {
  return `nebula-secret|v1|${args.cryptoId}|${args.environment}|${args.owner}|${args.type}|${args.version}`;
}

export async function encryptPayload<T>(
  payload: T,
  environmentKey: CryptoKey,
  aad: string,
): Promise<EncryptedPayload> {
  const dataKey = await createDataKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode(aad), tagLength: 128 },
    dataKey,
    encoder.encode(JSON.stringify(payload)),
  );
  const wrappedKey = await wrapDataKey(dataKey, environmentKey);
  return {
    ciphertext: bytesToBase64(ciphertext),
    iv: bytesToBase64(iv),
    wrappedKey: bytesToBase64(wrappedKey),
    algorithm: "AES-256-GCM+AES-KW",
    aadVersion: 1,
  };
}

export async function decryptPayload<T>(
  payload: EncryptedPayload,
  environmentKey: CryptoKey,
  aad: string,
) {
  const dataKey = await unwrapDataKey(payload.wrappedKey, environmentKey);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToBytes(payload.iv),
      additionalData: encoder.encode(aad),
      tagLength: 128,
    },
    dataKey,
    base64ToBytes(payload.ciphertext),
  );
  return JSON.parse(decoder.decode(plaintext)) as T;
}

function attachmentAad(kind: "metadata" | "file", cryptoId: string, secretValueId: string) {
  return `nebula-attachment-${kind}|v1|${cryptoId}|${secretValueId}`;
}

export async function encryptAttachment(
  file: File,
  environmentKey: CryptoKey,
  cryptoId: string,
  secretValueId: string,
) {
  const dataKey = await createDataKey();
  const fileIv = crypto.getRandomValues(new Uint8Array(12));
  const metadataIv = crypto.getRandomValues(new Uint8Array(12));
  const [encryptedFile, encryptedMetadata, wrappedKey] = await Promise.all([
    crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: fileIv,
        additionalData: encoder.encode(attachmentAad("file", cryptoId, secretValueId)),
      },
      dataKey,
      await file.arrayBuffer(),
    ),
    crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: metadataIv,
        additionalData: encoder.encode(attachmentAad("metadata", cryptoId, secretValueId)),
      },
      dataKey,
      encoder.encode(
        JSON.stringify({
          name: file.name,
          mimeType: file.type || "application/octet-stream",
          originalSize: file.size,
        } satisfies AttachmentMetadata),
      ),
    ),
    wrapDataKey(dataKey, environmentKey),
  ]);
  return {
    encryptedBlob: new Blob([encryptedFile], { type: "application/octet-stream" }),
    fileIv: bytesToBase64(fileIv),
    encryptedMetadata: {
      ciphertext: bytesToBase64(encryptedMetadata),
      iv: bytesToBase64(metadataIv),
      wrappedKey: bytesToBase64(wrappedKey),
      algorithm: "AES-256-GCM+AES-KW" as const,
      aadVersion: 1 as const,
    },
  };
}

export async function decryptAttachmentMetadata(
  payload: EncryptedPayload,
  environmentKey: CryptoKey,
  cryptoId: string,
  secretValueId: string,
) {
  return await decryptPayloadWithAad<AttachmentMetadata>(
    payload,
    environmentKey,
    attachmentAad("metadata", cryptoId, secretValueId),
  );
}

async function decryptPayloadWithAad<T>(
  payload: EncryptedPayload,
  environmentKey: CryptoKey,
  aad: string,
) {
  return await decryptPayload<T>(payload, environmentKey, aad);
}

export async function decryptAttachmentFile(args: {
  encryptedBytes: ArrayBuffer;
  encryptedMetadata: EncryptedPayload;
  fileIv: string;
  environmentKey: CryptoKey;
  cryptoId: string;
  secretValueId: string;
}) {
  const dataKey = await unwrapDataKey(args.encryptedMetadata.wrappedKey, args.environmentKey);
  return await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToBytes(args.fileIv),
      additionalData: encoder.encode(
        attachmentAad("file", args.cryptoId, args.secretValueId),
      ),
    },
    dataKey,
    args.encryptedBytes,
  );
}
