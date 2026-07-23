export type Environment = "local" | "development" | "uat" | "production";
export type SecretType =
  | "login"
  | "apiKey"
  | "introducerApiKey"
  | "licenseKey"
  | "webConfig";

export type WebConfigEntry = {
  key: string;
  value: string;
};

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
  introducerCode?: string;
  webserviceLogin?: string;
  licenseKey?: string;
  licensee?: string;
  expiresAt?: string;
  webConfigEntries?: WebConfigEntry[];
};

export type AttachmentMetadata = {
  name: string;
  mimeType: string;
  originalSize: number;
};

export type DeviceKeyMaterial = {
  encryptionPrivateKey: CryptoKey;
  encryptionPublicKey: CryptoKey;
  publicEncryptionKeyJwk: string;
  signingPrivateKey: CryptoKey;
  signingPublicKey: CryptoKey;
  publicSigningKeyJwk: string;
};

type LegacyDeviceKeyMaterial = {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicJwk: string;
};

export type StoredDeviceKey = DeviceKeyMaterial & {
  deviceId: string;
  userId: string;
};

type CurrentDeviceReference = { userId: string; deviceId: string };
type StoredLegacyDeviceKey = LegacyDeviceKeyMaterial & { userId: string };

const DATABASE_NAME = "nebula-secrets-keys";
const DATABASE_VERSION = 2;
const LEGACY_STORE_NAME = "deviceKeys";
const DEVICE_STORE_NAME = "browserDevices";
const CURRENT_DEVICE_STORE_NAME = "currentDevices";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function openKeyDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(LEGACY_STORE_NAME)) {
        request.result.createObjectStore(LEGACY_STORE_NAME, {
          keyPath: "userId",
        });
      }
      if (!request.result.objectStoreNames.contains(DEVICE_STORE_NAME)) {
        request.result.createObjectStore(DEVICE_STORE_NAME, {
          keyPath: "deviceId",
        });
      }
      if (
        !request.result.objectStoreNames.contains(CURRENT_DEVICE_STORE_NAME)
      ) {
        request.result.createObjectStore(CURRENT_DEVICE_STORE_NAME, {
          keyPath: "userId",
        });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(request.error ?? new Error("Unable to open device key storage."));
  });
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(request.error ?? new Error("Device key storage failed."));
  });
}

export async function generateDeviceKeyMaterial(): Promise<DeviceKeyMaterial> {
  const encryptionKeys = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"],
  );
  const [publicEncryptionJwk, encryptionPrivatePkcs8] = await Promise.all([
    crypto.subtle.exportKey("jwk", encryptionKeys.publicKey),
    crypto.subtle.exportKey("pkcs8", encryptionKeys.privateKey),
  ]);
  const encryptionPrivateKey = await crypto.subtle.importKey(
    "pkcs8",
    encryptionPrivatePkcs8,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"],
  );
  new Uint8Array(encryptionPrivatePkcs8).fill(0);
  const signing = await generateSigningKeyMaterial();
  return {
    encryptionPrivateKey,
    encryptionPublicKey: encryptionKeys.publicKey,
    publicEncryptionKeyJwk: JSON.stringify(publicEncryptionJwk),
    ...signing,
  };
}

async function generateSigningKeyMaterial() {
  const signingKeys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const [publicSigningJwk, signingPrivatePkcs8] = await Promise.all([
    crypto.subtle.exportKey("jwk", signingKeys.publicKey),
    crypto.subtle.exportKey("pkcs8", signingKeys.privateKey),
  ]);
  const signingPrivateKey = await crypto.subtle.importKey(
    "pkcs8",
    signingPrivatePkcs8,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  new Uint8Array(signingPrivatePkcs8).fill(0);
  return {
    signingPrivateKey,
    signingPublicKey: signingKeys.publicKey,
    publicSigningKeyJwk: JSON.stringify(publicSigningJwk),
  };
}

export async function upgradeLegacyDeviceKey(
  legacy: StoredLegacyDeviceKey,
): Promise<DeviceKeyMaterial> {
  return {
    encryptionPrivateKey: legacy.privateKey,
    encryptionPublicKey: legacy.publicKey,
    publicEncryptionKeyJwk: legacy.publicJwk,
    ...(await generateSigningKeyMaterial()),
  };
}

export async function persistDeviceKey(
  userId: string,
  deviceId: string,
  material: DeviceKeyMaterial,
) {
  const database = await openKeyDatabase();
  const transaction = database.transaction(
    [DEVICE_STORE_NAME, CURRENT_DEVICE_STORE_NAME],
    "readwrite",
  );
  await Promise.all([
    requestResult(
      transaction
        .objectStore(DEVICE_STORE_NAME)
        .put({ userId, deviceId, ...material } satisfies StoredDeviceKey),
    ),
    requestResult(
      transaction
        .objectStore(CURRENT_DEVICE_STORE_NAME)
        .put({ userId, deviceId } satisfies CurrentDeviceReference),
    ),
  ]);
  database.close();
}

export async function getDeviceKey(
  deviceId: string,
): Promise<StoredDeviceKey | null> {
  const database = await openKeyDatabase();
  const transaction = database.transaction(DEVICE_STORE_NAME, "readonly");
  const result = await requestResult(
    transaction.objectStore(DEVICE_STORE_NAME).get(deviceId) as IDBRequest<
      StoredDeviceKey | undefined
    >,
  );
  database.close();
  return result ?? null;
}

export async function getCurrentDeviceKey(userId: string) {
  const database = await openKeyDatabase();
  const transaction = database.transaction(
    CURRENT_DEVICE_STORE_NAME,
    "readonly",
  );
  const reference = await requestResult(
    transaction
      .objectStore(CURRENT_DEVICE_STORE_NAME)
      .get(userId) as IDBRequest<CurrentDeviceReference | undefined>,
  );
  database.close();
  return reference ? await getDeviceKey(reference.deviceId) : null;
}

export async function getLegacyDeviceKey(
  userId: string,
): Promise<StoredLegacyDeviceKey | null> {
  const database = await openKeyDatabase();
  const transaction = database.transaction(LEGACY_STORE_NAME, "readonly");
  const result = await requestResult(
    transaction.objectStore(LEGACY_STORE_NAME).get(userId) as IDBRequest<
      StoredLegacyDeviceKey | undefined
    >,
  );
  database.close();
  return result ?? null;
}

export async function removeDeviceKey(userId: string, deviceId: string) {
  const database = await openKeyDatabase();
  const transaction = database.transaction(
    [DEVICE_STORE_NAME, CURRENT_DEVICE_STORE_NAME],
    "readwrite",
  );
  const referenceStore = transaction.objectStore(CURRENT_DEVICE_STORE_NAME);
  const reference = await requestResult(
    referenceStore.get(userId) as IDBRequest<
      CurrentDeviceReference | undefined
    >,
  );
  await Promise.all([
    requestResult(transaction.objectStore(DEVICE_STORE_NAME).delete(deviceId)),
    reference?.deviceId === deviceId
      ? requestResult(referenceStore.delete(userId))
      : Promise.resolve(undefined),
  ]);
  database.close();
}

export function clearDeviceKeys(): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(DATABASE_NAME);
    request.onsuccess = () => resolve();
    request.onerror = () =>
      reject(request.error ?? new Error("Unable to clear device key storage."));
    request.onblocked = () =>
      reject(
        new Error(
          "Close other Nebula Secrets tabs before clearing device keys.",
        ),
      );
  });
}

export async function generateEnvironmentKey() {
  return await crypto.subtle.generateKey(
    { name: "AES-KW", length: 256 },
    true,
    ["wrapKey", "unwrapKey"],
  );
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
  for (let index = 0; index < binary.length; index += 1)
    bytes[index] = binary.charCodeAt(index);
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

export async function wrapEnvironmentKey(
  environmentKey: CryptoKey,
  publicJwk: string,
) {
  const publicKey = await importPublicKey(publicJwk);
  const raw = await crypto.subtle.exportKey("raw", environmentKey);
  const wrapped = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    raw,
  );
  new Uint8Array(raw).fill(0);
  return bytesToBase64(wrapped);
}

export async function unwrapEnvironmentKey(
  deviceId: string,
  wrappedKey: string,
) {
  const device = await getDeviceKey(deviceId);
  if (!device)
    throw new Error(
      "This device does not hold the selected user’s private key.",
    );
  const raw = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    device.encryptionPrivateKey,
    base64ToBytes(wrappedKey),
  );
  const key = await crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-KW" },
    true,
    ["wrapKey", "unwrapKey"],
  );
  new Uint8Array(raw).fill(0);
  return key;
}

export async function deviceKeyFingerprint(publicEncryptionKeyJwk: string) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(publicEncryptionKeyJwk),
  );
  return Array.from(new Uint8Array(digest), (value) =>
    value.toString(16).padStart(2, "0"),
  ).join("");
}

export function createDeviceRequestProof() {
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const codeBytes = crypto.getRandomValues(new Uint32Array(1));
  return {
    approvalNonce: bytesToBase64(nonce),
    verificationCode: String(codeBytes[0] % 1_000_000).padStart(6, "0"),
  };
}

export function currentBrowserDescription() {
  const userAgent = navigator.userAgent;
  const browserName = userAgent.includes("Edg/")
    ? "Microsoft Edge"
    : userAgent.includes("Chrome/")
      ? "Google Chrome"
      : userAgent.includes("Firefox/")
        ? "Mozilla Firefox"
        : userAgent.includes("Safari/")
          ? "Safari"
          : "Web browser";
  const platform =
    (navigator as Navigator & { userAgentData?: { platform?: string } })
      .userAgentData?.platform ||
    navigator.platform ||
    "Unknown platform";
  return { browserName, platform };
}

function canonicalDeviceApproval(args: {
  targetDeviceId: string;
  approverDeviceId: string;
  approvalNonce: string;
  envelopes: Array<{
    environment: Environment;
    keyVersion: number;
    wrappedKey: string;
  }>;
}) {
  const order: Record<Environment, number> = {
    local: 0,
    development: 1,
    uat: 2,
    production: 3,
  };
  const envelopes = [...args.envelopes].sort(
    (left, right) => order[left.environment] - order[right.environment],
  );
  return [
    "nebula-device-approval-v1",
    args.targetDeviceId,
    args.approverDeviceId,
    args.approvalNonce,
    ...envelopes.map(
      (envelope) =>
        `${envelope.environment}:${envelope.keyVersion}:${envelope.wrappedKey}`,
    ),
  ].join("|");
}

export async function signDeviceApproval(
  deviceId: string,
  args: {
    targetDeviceId: string;
    approverDeviceId: string;
    approvalNonce: string;
    envelopes: Array<{
      environment: Environment;
      keyVersion: number;
      wrappedKey: string;
    }>;
  },
) {
  const device = await getDeviceKey(deviceId);
  if (!device) throw new Error("The approving device key is not available.");
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    device.signingPrivateKey,
    encoder.encode(canonicalDeviceApproval(args)),
  );
  return bytesToBase64(signature);
}

async function createDataKey() {
  return await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
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
    {
      name: "AES-GCM",
      iv,
      additionalData: encoder.encode(aad),
      tagLength: 128,
    },
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

function attachmentAad(
  kind: "metadata" | "file",
  cryptoId: string,
  secretValueId: string,
) {
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
        additionalData: encoder.encode(
          attachmentAad("file", cryptoId, secretValueId),
        ),
      },
      dataKey,
      await file.arrayBuffer(),
    ),
    crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: metadataIv,
        additionalData: encoder.encode(
          attachmentAad("metadata", cryptoId, secretValueId),
        ),
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
    encryptedBlob: new Blob([encryptedFile], {
      type: "application/octet-stream",
    }),
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
  const dataKey = await unwrapDataKey(
    args.encryptedMetadata.wrappedKey,
    args.environmentKey,
  );
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
