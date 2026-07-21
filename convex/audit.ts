import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { appendAudit, requireActor, requireAdmin, requireEnvironmentAccess } from "./lib/access";

export const recordSecretAction = mutation({
  args: {
    actorUserId: v.id("users"),
    secretValueId: v.id("secretValues"),
    action: v.union(v.literal("secret.revealed"), v.literal("secret.copied")),
    context: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const value = await ctx.db.get("secretValues", args.secretValueId);
    if (!value) throw new Error("Secret value not found.");
    await requireEnvironmentAccess(ctx, args.actorUserId, value.environment);
    if (value.environment === "local" && value.ownerUserId !== args.actorUserId) {
      throw new Error("Local values are private to their owner.");
    }
    await appendAudit(ctx, {
      actorUserId: args.actorUserId,
      action: args.action,
      targetType: "secretValue",
      targetId: args.secretValueId,
      environment: value.environment,
      context: args.context,
    });
    return null;
  },
});

export const listRecent = query({
  args: { actorUserId: v.id("users") },
  handler: async (ctx, args) => {
    await requireAdmin(ctx, args.actorUserId);
    return await ctx.db.query("auditEvents").order("desc").take(100);
  },
});

export const listMine = query({
  args: { actorUserId: v.id("users") },
  handler: async (ctx, args) => {
    await requireActor(ctx, args.actorUserId);
    return await ctx.db
      .query("auditEvents")
      .withIndex("by_actorUserId", (q) => q.eq("actorUserId", args.actorUserId))
      .order("desc")
      .take(50);
  },
});
