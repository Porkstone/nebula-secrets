/// <reference types="vite/client" />
import { convexTest, type TestConvex } from "convex-test";
import { describe, expect, test } from "vitest";
import { api, internal } from "./_generated/api";
import schema from "./schema";

const modules = import.meta.glob("./**/*.ts");
const workosIssuer = "https://api.workos.com/user_management/client_test";

const encryptedPayload = {
  ciphertext: "ciphertext",
  iv: "iv",
  wrappedKey: "wrapped-data-key",
  algorithm: "AES-256-GCM+AES-KW" as const,
  aadVersion: 1 as const,
};

function authenticated(
  t: TestConvex<typeof schema>,
  subject: string,
  email: string,
) {
  return t.withIdentity({
    issuer: workosIssuer,
    subject,
    tokenIdentifier: `${workosIssuer}|${subject}`,
    email,
    emailVerified: true,
  });
}

function verifiedWorkosIdentity(subject: string, email: string) {
  return {
    issuer: workosIssuer,
    tokenIdentifier: `${workosIssuer}|${subject}`,
    providerUserId: subject,
    email,
    emailVerified: true,
  };
}

async function initializedVault() {
  const t = convexTest(schema, modules);
  const admin = authenticated(t, "user_admin", "admin@example.test");
  const adminId = await admin.mutation(
    internal.bootstrap.initializeVerifiedWorkos,
    {
      ...verifiedWorkosIdentity("user_admin", "admin@example.test"),
      displayName: "Admin",
      publicKeyJwk: "admin-public-key",
      keyEnvelopes: [
        { environment: "local", wrappedKey: "local-key" },
        { environment: "development", wrappedKey: "development-key" },
        { environment: "uat", wrappedKey: "uat-key" },
        { environment: "production", wrappedKey: "production-key" },
      ],
    },
  );
  return { t, admin, adminId };
}

async function inviteAndLinkDeveloper(
  t: TestConvex<typeof schema>,
  admin: ReturnType<typeof authenticated>,
) {
  const developerId = await admin.mutation(api.users.create, {
    displayName: "Developer",
    email: "developer@example.test",
    role: "developer",
  });
  const developer = authenticated(
    t,
    "user_developer",
    "developer@example.test",
  );
  await developer.mutation(internal.users.linkVerifiedWorkosIdentity, {
    ...verifiedWorkosIdentity("user_developer", "developer@example.test"),
  });
  return { developer, developerId };
}

describe("authenticated secrets access model", () => {
  test("bootstraps exactly once as a System Administrator", async () => {
    const { admin, adminId } = await initializedVault();
    const access = await admin.query(api.access.listMine, {});
    const current = await admin.query(api.users.current, {});

    expect(current).toMatchObject({
      _id: adminId,
      role: "systemAdministrator",
      authProvider: "workos",
    });
    expect(access).toHaveLength(4);
    expect(access.every((item) => item.granted && item.hasKey)).toBe(true);
    await expect(
      admin.mutation(internal.bootstrap.initializeVerifiedWorkos, {
        ...verifiedWorkosIdentity("user_admin", "admin@example.test"),
        displayName: "Second Admin",
        publicKeyJwk: "public-key",
        keyEnvelopes: [],
      }),
    ).rejects.toThrow("already been initialized");
  });

  test("rejects anonymous calls instead of trusting a client user ID", async () => {
    const { t } = await initializedVault();
    await expect(t.query(api.projects.list, {})).rejects.toThrow(
      "Not authenticated",
    );
    await expect(t.query(api.access.listMine, {})).rejects.toThrow(
      "Not authenticated",
    );
  });

  test("links an invited user by exact WorkOS email", async () => {
    const { t, admin } = await initializedVault();
    const { developer, developerId } = await inviteAndLinkDeveloper(t, admin);
    expect(await developer.query(api.users.current, {})).toMatchObject({
      _id: developerId,
      email: "developer@example.test",
      isIdentityLinked: true,
    });

    const stranger = authenticated(t, "user_stranger", "stranger@example.test");
    await expect(
      stranger.mutation(internal.users.linkVerifiedWorkosIdentity, {
        ...verifiedWorkosIdentity("user_stranger", "stranger@example.test"),
      }),
    ).rejects.toThrow("No invited Nebula user matches");
  });

  test("keeps Local values private to the authenticated user", async () => {
    const { t, admin } = await initializedVault();
    const { developer } = await inviteAndLinkDeveloper(t, admin);

    await admin.mutation(api.secrets.save, {
      environment: "local",
      cryptoId: "local-secret",
      name: "Local database",
      type: "login",
      payload: encryptedPayload,
    });

    const adminRows = await admin.query(api.secrets.list, {
      environment: "local",
    });
    const developerRows = await developer.query(api.secrets.list, {
      environment: "local",
    });
    expect(adminRows[0]?.value).not.toBeNull();
    expect(developerRows[0]?.value).toBeNull();
  });

  test("requires Admin role and an active shared-environment grant", async () => {
    const { t, admin } = await initializedVault();
    const { developer, developerId } = await inviteAndLinkDeveloper(t, admin);
    await developer.mutation(api.users.enrollDevice, {
      publicKeyJwk: "developer-public-key",
      localKeyEnvelope: "developer-local-key",
    });

    await expect(
      developer.mutation(api.users.create, {
        displayName: "Not allowed",
        email: "blocked@example.test",
        role: "developer",
      }),
    ).rejects.toThrow("Admin role required");
    await expect(
      developer.query(api.secrets.list, { environment: "development" }),
    ).rejects.toThrow("Access to development is required");

    await admin.mutation(api.access.setGrant, {
      targetUserId: developerId,
      environment: "development",
      enabled: true,
      wrappedKey: "developer-development-key",
    });
    await admin.mutation(api.secrets.save, {
      environment: "development",
      cryptoId: "shared-secret",
      name: "Shared API",
      type: "apiKey",
      payload: encryptedPayload,
    });

    const rows = await developer.query(api.secrets.list, {
      environment: "development",
    });
    expect(rows[0]?.definition.name).toBe("Shared API");
    expect(rows[0]?.value?.payload.ciphertext).toBe("ciphertext");
  });

  test("reserves authentication configuration and reset for System Administrators", async () => {
    const { t, admin } = await initializedVault();
    const { developer } = await inviteAndLinkDeveloper(t, admin);

    await expect(
      developer.query(api.authSettings.getForSystemAdministrator, {}),
    ).rejects.toThrow("System Administrator role required");
    await expect(
      developer.mutation(api.devtools.resetWorkspace, {
        confirmation: "RESET NEBULA",
      }),
    ).rejects.toThrow("System Administrator role required");

    await admin.mutation(api.authSettings.save, {
      provider: "workos",
      clientId: "client_test",
      redirectUri: "http://127.0.0.1:5173/callback",
      allowedEmailDomains: ["example.test"],
    });
    const settings = await admin.query(
      api.authSettings.getForSystemAdministrator,
      {},
    );
    expect(settings.configuration).toMatchObject({
      provider: "workos",
      state: "staged",
    });

    const result = await admin.mutation(api.devtools.resetWorkspace, {
      confirmation: "RESET NEBULA",
    });
    expect(result.deletedDocuments).toBeGreaterThan(0);
    expect(await t.query(api.bootstrap.state, {})).toEqual({
      initialized: false,
    });
  });

  test("groups secrets into projects and protects projects in use", async () => {
    const { admin } = await initializedVault();
    const generalProject = (await admin.query(api.projects.list, {})).find(
      (project) => project.normalizedName === "general",
    );
    const projectId = await admin.mutation(api.projects.create, {
      name: "  Nebula   Platform  ",
    });
    const saved = await admin.mutation(api.secrets.save, {
      environment: "local",
      projectId,
      cryptoId: "project-secret",
      name: "Project API",
      type: "apiKey",
      payload: encryptedPayload,
    });

    expect(
      (await admin.query(api.secrets.list, { environment: "local" })).find(
        (row) => row.definition._id === saved.secretId,
      )?.definition.projectId,
    ).toBe(projectId);
    await expect(
      admin.mutation(api.projects.archive, { projectId }),
    ).rejects.toThrow("Move this project's secrets");

    await admin.mutation(api.secrets.save, {
      environment: "local",
      secretId: saved.secretId,
      projectId: generalProject?._id,
      cryptoId: "project-secret",
      name: "Project API",
      type: "apiKey",
      payload: encryptedPayload,
      expectedVersion: 1,
    });
    await expect(
      admin.mutation(api.projects.archive, { projectId }),
    ).resolves.toBeNull();
  });

  test("approves and revokes a second browser with signed device envelopes", async () => {
    const t = convexTest(schema, modules);
    const admin = authenticated(t, "device_admin", "devices@example.test");
    const signingKeys = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const publicSigningKeyJwk = JSON.stringify(
      await crypto.subtle.exportKey("jwk", signingKeys.publicKey),
    );
    await admin.mutation(internal.bootstrap.initializeVerifiedWorkos, {
      ...verifiedWorkosIdentity("device_admin", "devices@example.test"),
      displayName: "Device Admin",
      publicKeyJwk: "initial-encryption-key",
      publicSigningKeyJwk,
      deviceLabel: "Trusted browser",
      keyFingerprint: "initial-fingerprint",
      browserName: "Test browser",
      platform: "Test platform",
      keyEnvelopes: [
        { environment: "local", wrappedKey: "initial-local-key" },
        { environment: "development", wrappedKey: "initial-development-key" },
        { environment: "uat", wrappedKey: "initial-uat-key" },
        { environment: "production", wrappedKey: "initial-production-key" },
      ],
    });
    const initialDevice = (
      await admin.query(api.devices.listMine, { now: Date.now() })
    ).find((device) => device.status === "active");
    expect(initialDevice).toBeDefined();

    const request = await admin.mutation(api.devices.requestEnrollment, {
      label: "Second browser",
      publicEncryptionKeyJwk: "second-encryption-key",
      publicSigningKeyJwk,
      keyFingerprint: "second-fingerprint",
      browserName: "Test browser",
      platform: "Test platform",
      verificationCode: "123456",
      approvalNonce: "approval-nonce",
    });
    const context = await admin.query(api.devices.getApprovalContext, {
      targetDeviceId: request.deviceId,
      approverDeviceId: initialDevice!._id,
      now: Date.now(),
    });
    const envelopes = context.envelopes.map((envelope) => ({
      environment: envelope.environment,
      keyVersion: envelope.keyVersion,
      wrappedKey: `second-${envelope.environment}-key`,
    }));
    const canonical = [
      "nebula-device-approval-v1",
      request.deviceId,
      initialDevice!._id,
      context.approvalNonce,
      ...envelopes.map(
        (envelope) =>
          `${envelope.environment}:${envelope.keyVersion}:${envelope.wrappedKey}`,
      ),
    ].join("|");
    const signatureBytes = new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        signingKeys.privateKey,
        new TextEncoder().encode(canonical),
      ),
    );
    let signatureBinary = "";
    for (const byte of signatureBytes)
      signatureBinary += String.fromCharCode(byte);
    await admin.mutation(api.devices.approveEnrollment, {
      targetDeviceId: request.deviceId,
      approverDeviceId: initialDevice!._id,
      envelopes,
      signature: btoa(signatureBinary),
    });

    expect(
      await admin.query(api.access.getKeyEnvelope, {
        environment: "local",
        deviceId: request.deviceId,
      }),
    ).toEqual({ wrappedKey: "second-local-key", keyVersion: 1 });
    await admin.mutation(api.devices.revoke, { deviceId: request.deviceId });
    await expect(
      admin.query(api.access.getKeyEnvelope, {
        environment: "local",
        deviceId: request.deviceId,
      }),
    ).rejects.toThrow("An active device is required");
  });
});
