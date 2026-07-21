import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { appendAudit, requireActor, requireAdmin } from "./lib/access";
import { roleValidator } from "./validators";

export const listSelectable = query({
  args: {},
  handler: async (ctx) => {
    const users = await ctx.db.query("users").order("asc").take(100);
    return users.map((user) => ({
      _id: user._id,
      displayName: user.displayName,
      email: user.email,
      role: user.role,
      status: user.status,
      hasPublicKey: Boolean(user.publicKeyJwk),
    }));
  },
});

export const create = mutation({
  args: {
    actorUserId: v.id("users"),
    displayName: v.string(),
    email: v.string(),
    role: roleValidator,
  },
  handler: async (ctx, args) => {
    await requireAdmin(ctx, args.actorUserId);
    const email = args.email.trim().toLowerCase();
    if (
      await ctx.db
        .query("users")
        .withIndex("by_email", (q) => q.eq("email", email))
        .unique()
    ) {
      throw new Error("A user with this email already exists.");
    }
    const now = Date.now();
    const userId = await ctx.db.insert("users", {
      displayName: args.displayName.trim(),
      email,
      role: args.role,
      status: "active",
      createdAt: now,
      updatedAt: now,
    });
    await appendAudit(ctx, {
      actorUserId: args.actorUserId,
      action: "user.created",
      targetType: "user",
      targetId: userId,
      context: args.role,
    });
    return userId;
  },
});

export const enrollDevice = mutation({
  args: {
    actorUserId: v.id("users"),
    publicKeyJwk: v.string(),
    localKeyEnvelope: v.string(),
  },
  handler: async (ctx, args) => {
    const actor = await requireActor(ctx, args.actorUserId);
    if (actor.publicKeyJwk && actor.publicKeyJwk !== args.publicKeyJwk) {
      throw new Error("A different device key is already enrolled for this user.");
    }
    const existingEnvelope = await ctx.db
      .query("environmentKeyEnvelopes")
      .withIndex("by_userId_and_environment_and_keyVersion", (q) =>
        q
          .eq("userId", args.actorUserId)
          .eq("environment", "local")
          .eq("keyVersion", 1),
      )
      .unique();
    if (!existingEnvelope) {
      await ctx.db.insert("environmentKeyEnvelopes", {
        userId: args.actorUserId,
        environment: "local",
        keyVersion: 1,
        wrappedKey: args.localKeyEnvelope,
        createdBy: args.actorUserId,
        createdAt: Date.now(),
      });
    }
    await ctx.db.patch("users", args.actorUserId, {
      publicKeyJwk: args.publicKeyJwk,
      updatedAt: Date.now(),
    });
    await appendAudit(ctx, {
      actorUserId: args.actorUserId,
      action: "device.enrolled",
      targetType: "user",
      targetId: args.actorUserId,
    });
    return null;
  },
});

export const listForAdmin = query({
  args: { actorUserId: v.id("users") },
  handler: async (ctx, args) => {
    await requireAdmin(ctx, args.actorUserId);
    const users = await ctx.db.query("users").order("asc").take(100);
    return await Promise.all(
      users.map(async (user) => {
        const grants = await Promise.all(
          (["development", "uat", "production"] as const).map(async (environment) => {
            const grant = await ctx.db
              .query("environmentGrants")
              .withIndex("by_userId_and_environment", (q) =>
                q.eq("userId", user._id).eq("environment", environment),
              )
              .unique();
            return [environment, grant?.status === "active"] as const;
          }),
        );
        return {
          ...user,
          publicKeyJwk: undefined,
          hasPublicKey: Boolean(user.publicKeyJwk),
          grants: Object.fromEntries(grants),
        };
      }),
    );
  },
});

export const getPublicKey = query({
  args: { actorUserId: v.id("users"), targetUserId: v.id("users") },
  handler: async (ctx, args) => {
    await requireAdmin(ctx, args.actorUserId);
    const target = await ctx.db.get("users", args.targetUserId);
    if (!target || target.status !== "active") throw new Error("User is not active.");
    return target.publicKeyJwk ?? null;
  },
});

export const update = mutation({
  args: {
    actorUserId: v.id("users"),
    targetUserId: v.id("users"),
    role: roleValidator,
    status: v.union(v.literal("active"), v.literal("suspended")),
  },
  handler: async (ctx, args) => {
    await requireAdmin(ctx, args.actorUserId);
    const target = await ctx.db.get("users", args.targetUserId);
    if (!target) throw new Error("User not found.");
    if (args.targetUserId === args.actorUserId && args.status === "suspended") {
      throw new Error("You cannot suspend the current development identity.");
    }
    await ctx.db.patch("users", args.targetUserId, {
      role: args.role,
      status: args.status,
      updatedAt: Date.now(),
    });
    await appendAudit(ctx, {
      actorUserId: args.actorUserId,
      action: "user.updated",
      targetType: "user",
      targetId: args.targetUserId,
      context: `${args.role}/${args.status}`,
    });
    return null;
  },
});
