import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import {
  appendAudit,
  getActiveGrant,
  requireActor,
  requireAdmin,
  requireEnvironmentAccess,
} from "./lib/access";
import {
  environmentValidator,
  sharedEnvironmentValidator,
} from "./validators";

export const listMine = query({
  args: { actorUserId: v.id("users") },
  handler: async (ctx, args) => {
    await requireActor(ctx, args.actorUserId);
    return await Promise.all(
      (["local", "development", "uat", "production"] as const).map(
        async (environment) => {
          const granted =
            environment === "local"
              ? true
              : Boolean(await getActiveGrant(ctx, args.actorUserId, environment));
          const envelope = await ctx.db
            .query("environmentKeyEnvelopes")
            .withIndex("by_userId_and_environment_and_keyVersion", (q) =>
              q
                .eq("userId", args.actorUserId)
                .eq("environment", environment)
                .eq("keyVersion", 1),
            )
            .unique();
          return { environment, granted, hasKey: Boolean(envelope) };
        },
      ),
    );
  },
});

export const getKeyEnvelope = query({
  args: {
    actorUserId: v.id("users"),
    environment: environmentValidator,
  },
  handler: async (ctx, args) => {
    await requireEnvironmentAccess(ctx, args.actorUserId, args.environment);
    const envelope = await ctx.db
      .query("environmentKeyEnvelopes")
      .withIndex("by_userId_and_environment_and_keyVersion", (q) =>
        q
          .eq("userId", args.actorUserId)
          .eq("environment", args.environment)
          .eq("keyVersion", 1),
      )
      .unique();
    return envelope
      ? { wrappedKey: envelope.wrappedKey, keyVersion: envelope.keyVersion }
      : null;
  },
});

export const setGrant = mutation({
  args: {
    actorUserId: v.id("users"),
    targetUserId: v.id("users"),
    environment: sharedEnvironmentValidator,
    enabled: v.boolean(),
    wrappedKey: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    await requireAdmin(ctx, args.actorUserId);
    await requireEnvironmentAccess(ctx, args.actorUserId, args.environment);
    const target = await ctx.db.get("users", args.targetUserId);
    if (!target || target.status !== "active") throw new Error("Target user is not active.");
    if (args.enabled && (!target.publicKeyJwk || !args.wrappedKey)) {
      throw new Error("The target user must enroll a device key before access is granted.");
    }
    const now = Date.now();
    const existingGrant = await ctx.db
      .query("environmentGrants")
      .withIndex("by_userId_and_environment", (q) =>
        q.eq("userId", args.targetUserId).eq("environment", args.environment),
      )
      .unique();
    if (existingGrant) {
      await ctx.db.patch("environmentGrants", existingGrant._id, {
        status: args.enabled ? "active" : "revoked",
        grantedBy: args.actorUserId,
        grantedAt: args.enabled ? now : existingGrant.grantedAt,
        revokedAt: args.enabled ? undefined : now,
      });
    } else if (args.enabled) {
      await ctx.db.insert("environmentGrants", {
        userId: args.targetUserId,
        environment: args.environment,
        status: "active",
        grantedBy: args.actorUserId,
        grantedAt: now,
      });
    }

    const envelope = await ctx.db
      .query("environmentKeyEnvelopes")
      .withIndex("by_userId_and_environment_and_keyVersion", (q) =>
        q
          .eq("userId", args.targetUserId)
          .eq("environment", args.environment)
          .eq("keyVersion", 1),
      )
      .unique();
    if (args.enabled && args.wrappedKey) {
      if (envelope) {
        await ctx.db.patch("environmentKeyEnvelopes", envelope._id, {
          wrappedKey: args.wrappedKey,
          createdBy: args.actorUserId,
          createdAt: now,
        });
      } else {
        await ctx.db.insert("environmentKeyEnvelopes", {
          userId: args.targetUserId,
          environment: args.environment,
          keyVersion: 1,
          wrappedKey: args.wrappedKey,
          createdBy: args.actorUserId,
          createdAt: now,
        });
      }
    } else if (!args.enabled && envelope) {
      await ctx.db.delete("environmentKeyEnvelopes", envelope._id);
    }

    await appendAudit(ctx, {
      actorUserId: args.actorUserId,
      action: args.enabled ? "environment.granted" : "environment.revoked",
      targetType: "user",
      targetId: args.targetUserId,
      environment: args.environment,
    });
    return null;
  },
});
