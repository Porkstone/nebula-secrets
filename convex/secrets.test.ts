/// <reference types="vite/client" />
import { convexTest } from "convex-test";
import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import schema from "./schema";

const modules = import.meta.glob("./**/*.ts");

const encryptedPayload = {
  ciphertext: "ciphertext",
  iv: "iv",
  wrappedKey: "wrapped-data-key",
  algorithm: "AES-256-GCM+AES-KW" as const,
  aadVersion: 1 as const,
};

async function initializedVault() {
  const t = convexTest(schema, modules);
  const adminId = await t.mutation(api.bootstrap.initialize, {
    displayName: "Admin",
    email: "admin@example.test",
    publicKeyJwk: "admin-public-key",
    keyEnvelopes: [
      { environment: "local", wrappedKey: "local-key" },
      { environment: "development", wrappedKey: "development-key" },
      { environment: "uat", wrappedKey: "uat-key" },
      { environment: "production", wrappedKey: "production-key" },
    ],
  });
  return { t, adminId };
}

describe("secrets MVP access model", () => {
  test("bootstraps exactly once and creates environment access for the first Admin", async () => {
    const { t, adminId } = await initializedVault();
    const access = await t.query(api.access.listMine, { actorUserId: adminId });

    expect(access).toHaveLength(4);
    expect(access.every((item) => item.granted && item.hasKey)).toBe(true);
    await expect(
      t.mutation(api.bootstrap.initialize, {
        displayName: "Second Admin",
        email: "second@example.test",
        publicKeyJwk: "public-key",
        keyEnvelopes: [],
      }),
    ).rejects.toThrow("already been initialized");
  });

  test("keeps Local values private to their selected user", async () => {
    const { t, adminId } = await initializedVault();
    const developerId = await t.mutation(api.users.create, {
      actorUserId: adminId,
      displayName: "Developer",
      email: "developer@example.test",
      role: "developer",
    });

    await t.mutation(api.secrets.save, {
      actorUserId: adminId,
      environment: "local",
      cryptoId: "local-secret",
      name: "Local database",
      type: "login",
      payload: encryptedPayload,
    });

    const adminRows = await t.query(api.secrets.list, {
      actorUserId: adminId,
      environment: "local",
    });
    const developerRows = await t.query(api.secrets.list, {
      actorUserId: developerId,
      environment: "local",
    });
    expect(adminRows[0]?.value).not.toBeNull();
    expect(developerRows[0]?.value).toBeNull();
  });

  test("requires Admin role and an active shared-environment grant", async () => {
    const { t, adminId } = await initializedVault();
    const developerId = await t.mutation(api.users.create, {
      actorUserId: adminId,
      displayName: "Developer",
      email: "developer@example.test",
      role: "developer",
    });
    await t.mutation(api.users.enrollDevice, {
      actorUserId: developerId,
      publicKeyJwk: "developer-public-key",
      localKeyEnvelope: "developer-local-key",
    });

    await expect(
      t.mutation(api.users.create, {
        actorUserId: developerId,
        displayName: "Not allowed",
        email: "blocked@example.test",
        role: "developer",
      }),
    ).rejects.toThrow("Admin role required");
    await expect(
      t.query(api.secrets.list, {
        actorUserId: developerId,
        environment: "development",
      }),
    ).rejects.toThrow("Access to development is required");

    await t.mutation(api.access.setGrant, {
      actorUserId: adminId,
      targetUserId: developerId,
      environment: "development",
      enabled: true,
      wrappedKey: "developer-development-key",
    });
    await t.mutation(api.secrets.save, {
      actorUserId: adminId,
      environment: "development",
      cryptoId: "shared-secret",
      name: "Shared API",
      type: "apiKey",
      payload: encryptedPayload,
    });

    const rows = await t.query(api.secrets.list, {
      actorUserId: developerId,
      environment: "development",
    });
    expect(rows[0]?.definition.name).toBe("Shared API");
    expect(rows[0]?.value?.payload.ciphertext).toBe("ciphertext");
  });

  test("allows only an Admin to reset a disposable development workspace", async () => {
    const { t, adminId } = await initializedVault();
    const developerId = await t.mutation(api.users.create, {
      actorUserId: adminId,
      displayName: "Developer",
      email: "developer@example.test",
      role: "developer",
    });

    await expect(
      t.mutation(api.devtools.resetWorkspace, {
        actorUserId: developerId,
        confirmation: "RESET NEBULA",
      }),
    ).rejects.toThrow("Admin role required");

    const result = await t.mutation(api.devtools.resetWorkspace, {
      actorUserId: adminId,
      confirmation: "RESET NEBULA",
    });
    expect(result.deletedDocuments).toBeGreaterThan(0);
    expect(await t.query(api.bootstrap.state, {})).toEqual({ initialized: false });
  });

  test("groups secrets into projects and protects projects in use", async () => {
    const { t, adminId } = await initializedVault();
    const generalProject = (await t.query(api.projects.list, { actorUserId: adminId })).find(
      (project) => project.normalizedName === "general",
    );
    expect(generalProject?.name).toBe("General");
    const projectId = await t.mutation(api.projects.create, {
      actorUserId: adminId,
      name: "  Nebula   Platform  ",
    });

    const saved = await t.mutation(api.secrets.save, {
      actorUserId: adminId,
      environment: "local",
      projectId,
      cryptoId: "project-secret",
      name: "Project API",
      type: "apiKey",
      payload: encryptedPayload,
    });
    const rows = await t.query(api.secrets.list, {
      actorUserId: adminId,
      environment: "local",
    });
    expect(rows.find((row) => row.definition._id === saved.secretId)?.definition.projectId).toBe(
      projectId,
    );
    expect(
      (await t.query(api.projects.list, { actorUserId: adminId })).some(
        (project) => project.name === "Nebula Platform",
      ),
    ).toBe(true);
    await expect(
      t.mutation(api.projects.archive, { actorUserId: adminId, projectId }),
    ).rejects.toThrow("Move this project's secrets");

    await t.mutation(api.secrets.save, {
      actorUserId: adminId,
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
      t.mutation(api.projects.archive, { actorUserId: adminId, projectId }),
    ).resolves.toBeNull();
  });

  test("uses General when a caller does not specify a project", async () => {
    const { t, adminId } = await initializedVault();
    const saved = await t.mutation(api.secrets.save, {
      actorUserId: adminId,
      environment: "local",
      cryptoId: "default-project-secret",
      name: "Default project API",
      type: "apiKey",
      payload: encryptedPayload,
    });
    const generalProject = (await t.query(api.projects.list, { actorUserId: adminId })).find(
      (project) => project.normalizedName === "general",
    );
    const rows = await t.query(api.secrets.list, {
      actorUserId: adminId,
      environment: "local",
    });
    expect(rows.find((row) => row.definition._id === saved.secretId)?.definition.projectId).toBe(
      generalProject?._id,
    );
  });
});
