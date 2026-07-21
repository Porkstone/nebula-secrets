import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { appendAudit, requireActor, requireAdmin, requireEnvironmentAccess } from "./lib/access";

export const recordSecretAction = mutation({
  args: {
    secretValueId: v.id("secretValues"),
    action: v.union(v.literal("secret.revealed"), v.literal("secret.copied")),
    context: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const value = await ctx.db.get("secretValues", args.secretValueId);
    if (!value) throw new Error("Secret value not found.");
    const actor = await requireEnvironmentAccess(ctx, value.environment);
    if (value.environment === "local" && value.ownerUserId !== actor._id) {
      throw new Error("Local values are private to their owner.");
    }
    await appendAudit(ctx, {
      actorUserId: actor._id,
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
  args: {},
  handler: async (ctx) => {
    await requireAdmin(ctx);
    return await ctx.db.query("auditEvents").order("desc").take(100);
  },
});

export const listMine = query({
  args: {},
  handler: async (ctx) => {
    const actor = await requireActor(ctx);
    return await ctx.db
      .query("auditEvents")
      .withIndex("by_actorUserId", (q) => q.eq("actorUserId", actor._id))
      .order("desc")
      .take(50);
  },
});
