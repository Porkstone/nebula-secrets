import { env, internalMutation, query } from "./_generated/server";
import { ConvexError, v } from "convex/values";
import {
  environmentValidator,
  verifiedWorkosIdentityValidator,
} from "./validators";
import { getOrCreateGeneralProject } from "./lib/projects";
import { isWorkosIssuer, normalizeEmail } from "./lib/access";

export const state = query({
  args: {},
  handler: async (ctx) => {
    const firstUser = await ctx.db.query("users").take(1);
    return { initialized: firstUser.length > 0 };
  },
});

function bootstrapError(code: string, message: string): never {
  throw new ConvexError({ code, message });
}

export const initializeVerifiedWorkos = internalMutation({
  args: {
    ...verifiedWorkosIdentityValidator.fields,
    displayName: v.string(),
    publicKeyJwk: v.string(),
    publicSigningKeyJwk: v.optional(v.string()),
    deviceLabel: v.optional(v.string()),
    keyFingerprint: v.optional(v.string()),
    browserName: v.optional(v.string()),
    platform: v.optional(v.string()),
    keyEnvelopes: v.array(
      v.object({
        environment: environmentValidator,
        wrappedKey: v.string(),
      }),
    ),
  },
  handler: async (ctx, args) => {
    if (!isWorkosIssuer(args.issuer)) {
      bootstrapError(
        "UNSUPPORTED_PROVIDER",
        "The configured authentication provider is not supported.",
      );
    }
    if (!args.emailVerified) {
      bootstrapError(
        "EMAIL_NOT_VERIFIED",
        "Verify the WorkOS email address before initializing the workspace.",
      );
    }
    const email = normalizeEmail(args.email);
    const requiredBootstrapEmail = env.NEBULA_BOOTSTRAP_ADMIN_EMAIL
      ? normalizeEmail(env.NEBULA_BOOTSTRAP_ADMIN_EMAIL)
      : null;
    if (requiredBootstrapEmail && email !== requiredBootstrapEmail) {
      bootstrapError(
        "BOOTSTRAP_EMAIL_NOT_ALLOWED",
        "This WorkOS account is not authorized to initialize the workspace.",
      );
    }
    if ((await ctx.db.query("users").take(1)).length > 0) {
      bootstrapError(
        "WORKSPACE_ALREADY_INITIALIZED",
        "The workspace has already been initialized.",
      );
    }
    const required = new Set(["local", "development", "uat", "production"]);
    for (const envelope of args.keyEnvelopes)
      required.delete(envelope.environment);
    if (required.size > 0 || args.keyEnvelopes.length !== 4) {
      bootstrapError(
        "INVALID_KEY_ENVELOPES",
        "One key envelope is required for every environment.",
      );
    }

    const now = Date.now();
    const adminId = await ctx.db.insert("users", {
      displayName: args.displayName.trim(),
      email,
      role: "systemAdministrator",
      status: "active",
      publicKeyJwk: args.publicKeyJwk,
      authProvider: "workos",
      tokenIdentifier: args.tokenIdentifier,
      providerUserId: args.providerUserId,
      identityLinkedAt: now,
      lastAuthenticatedAt: now,
      createdAt: now,
      updatedAt: now,
    });
    await getOrCreateGeneralProject(ctx, adminId);

    const deviceId = await ctx.db.insert("devices", {
      userId: adminId,
      label: args.deviceLabel?.trim() || "Initial browser",
      publicEncryptionKeyJwk: args.publicKeyJwk,
      publicSigningKeyJwk: args.publicSigningKeyJwk,
      keyFingerprint: args.keyFingerprint,
      browserName: args.browserName,
      platform: args.platform,
      status: "active",
      requestedAt: now,
      approvedAt: now,
      claimedAt: args.publicSigningKeyJwk ? now : undefined,
      lastUsedAt: now,
      legacy: args.publicSigningKeyJwk ? undefined : true,
    });

    for (const envelope of args.keyEnvelopes) {
      await ctx.db.insert("environmentKeyEnvelopes", {
        userId: adminId,
        environment: envelope.environment,
        keyVersion: 1,
        wrappedKey: envelope.wrappedKey,
        createdBy: adminId,
        createdAt: now,
      });
      await ctx.db.insert("deviceKeyEnvelopes", {
        userId: adminId,
        deviceId,
        environment: envelope.environment,
        keyVersion: 1,
        wrappedKey: envelope.wrappedKey,
        createdByUserId: adminId,
        createdByDeviceId: deviceId,
        createdAt: now,
      });
      if (envelope.environment !== "local") {
        await ctx.db.insert("environmentGrants", {
          userId: adminId,
          environment: envelope.environment,
          status: "active",
          grantedBy: adminId,
          grantedAt: now,
        });
      }
    }
    await ctx.db.insert("auditEvents", {
      actorUserId: adminId,
      action: "workspace.initialized",
      targetType: "workspace",
      outcome: "success",
      context: "workos/system-administrator",
      createdAt: now,
    });
    return adminId;
  },
});
