import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { environmentValidator } from "./validators";
import { getOrCreateGeneralProject } from "./lib/projects";

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
    email: v.string(),
    publicKeyJwk: v.string(),
    keyEnvelopes: v.array(
      v.object({
        environment: environmentValidator,
        wrappedKey: v.string(),
      }),
    ),
  },
  handler: async (ctx, args) => {
    if ((await ctx.db.query("users").take(1)).length > 0) {
      throw new Error("The workspace has already been initialized.");
    }
    const required = new Set(["local", "development", "uat", "production"]);
    for (const envelope of args.keyEnvelopes) required.delete(envelope.environment);
    if (required.size > 0 || args.keyEnvelopes.length !== 4) {
      throw new Error("One key envelope is required for every environment.");
    }

    const now = Date.now();
    const adminId = await ctx.db.insert("users", {
      displayName: args.displayName.trim(),
      email: args.email.trim().toLowerCase(),
      role: "admin",
      status: "active",
      publicKeyJwk: args.publicKeyJwk,
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
      context: "Development-only identity mode",
      createdAt: now,
    });
    return adminId;
  },
});
