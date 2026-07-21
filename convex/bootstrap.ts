import { env, mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { environmentValidator } from "./validators";
import { getOrCreateGeneralProject } from "./lib/projects";
import { isWorkosIssuer, normalizeEmail } from "./lib/access";

export const state = query({
  args: {},
  handler: async (ctx) => {
    const firstUser = await ctx.db.query("users").take(1);
    return { initialized: firstUser.length > 0 };
  },
});

export const initialize = mutation({
  args: {
    displayName: v.string(),
    publicKeyJwk: v.string(),
    keyEnvelopes: v.array(
      v.object({
        environment: environmentValidator,
        wrappedKey: v.string(),
      }),
    ),
  },
  handler: async (ctx, args) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error("Not authenticated.");
    if (!isWorkosIssuer(identity.issuer)) {
      throw new Error(
        "The configured authentication provider is not supported.",
      );
    }
    if (!identity.email) {
      throw new Error(
        "WorkOS did not provide an email address for this identity.",
      );
    }
    if (identity.emailVerified === false) {
      throw new Error(
        "Verify the WorkOS email address before initializing the workspace.",
      );
    }
    const email = normalizeEmail(identity.email);
    const requiredBootstrapEmail = env.NEBULA_BOOTSTRAP_ADMIN_EMAIL
      ? normalizeEmail(env.NEBULA_BOOTSTRAP_ADMIN_EMAIL)
      : null;
    if (requiredBootstrapEmail && email !== requiredBootstrapEmail) {
      throw new Error(
        "This WorkOS account is not authorized to initialize the workspace.",
      );
    }
    if ((await ctx.db.query("users").take(1)).length > 0) {
      throw new Error("The workspace has already been initialized.");
    }
    const required = new Set(["local", "development", "uat", "production"]);
    for (const envelope of args.keyEnvelopes)
      required.delete(envelope.environment);
    if (required.size > 0 || args.keyEnvelopes.length !== 4) {
      throw new Error("One key envelope is required for every environment.");
    }

    const now = Date.now();
    const adminId = await ctx.db.insert("users", {
      displayName: args.displayName.trim(),
      email,
      role: "systemAdministrator",
      status: "active",
      publicKeyJwk: args.publicKeyJwk,
      authProvider: "workos",
      tokenIdentifier: identity.tokenIdentifier,
      providerUserId: identity.subject,
      identityLinkedAt: now,
      lastAuthenticatedAt: now,
      createdAt: now,
      updatedAt: now,
    });
    await getOrCreateGeneralProject(ctx, adminId);

    for (const envelope of args.keyEnvelopes) {
      await ctx.db.insert("environmentKeyEnvelopes", {
        userId: adminId,
        environment: envelope.environment,
        keyVersion: 1,
        wrappedKey: envelope.wrappedKey,
        createdBy: adminId,
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
