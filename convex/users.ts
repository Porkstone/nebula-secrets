import { mutation, query, env } from "./_generated/server";
import { v } from "convex/values";
import type { Doc } from "./_generated/dataModel";
import {
  appendAudit,
  getCurrentUser,
  isWorkosIssuer,
  normalizeEmail,
  requireActor,
  requireAdmin,
} from "./lib/access";
import { roleValidator } from "./validators";

function publicUser(user: Doc<"users">) {
  return {
    _id: user._id,
    displayName: user.displayName,
    email: user.email,
    role: user.role,
    status: user.status,
    hasPublicKey: Boolean(user.publicKeyJwk),
    authProvider: user.authProvider ?? null,
    isIdentityLinked: Boolean(user.tokenIdentifier),
    identityLinkedAt: user.identityLinkedAt ?? null,
  };
}

export const current = query({
  args: {},
  handler: async (ctx) => {
    const user = await getCurrentUser(ctx);
    return user ? publicUser(user) : null;
  },
});

export const linkCurrentIdentity = mutation({
  args: {},
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error("Not authenticated.");
    if (!isWorkosIssuer(identity.issuer)) {
      throw new Error(
        "The configured authentication provider is not supported.",
      );
    }

    const alreadyLinked = await ctx.db
      .query("users")
      .withIndex("by_tokenIdentifier", (q) =>
        q.eq("tokenIdentifier", identity.tokenIdentifier),
      )
      .unique();
    if (alreadyLinked) {
      if (alreadyLinked.status !== "active") {
        throw new Error("This user account is suspended.");
      }
      await ctx.db.patch("users", alreadyLinked._id, {
        lastAuthenticatedAt: Date.now(),
        updatedAt: Date.now(),
      });
      return publicUser(alreadyLinked);
    }

    if (!identity.email) {
      throw new Error(
        "WorkOS did not provide an email address for this identity.",
      );
    }
    if (identity.emailVerified === false) {
      throw new Error(
        "Verify the WorkOS email address before linking this account.",
      );
    }
    const email = normalizeEmail(identity.email);
    const authConfiguration = await ctx.db
      .query("authConfiguration")
      .withIndex("by_singletonKey", (q) =>
        q.eq("singletonKey", "authentication"),
      )
      .unique();
    const emailDomain = email.slice(email.lastIndexOf("@") + 1);
    if (
      authConfiguration &&
      authConfiguration.allowedEmailDomains.length > 0 &&
      !authConfiguration.allowedEmailDomains.includes(emailDomain)
    ) {
      throw new Error(
        "This email domain is not allowed by the authentication configuration.",
      );
    }
    let target = await ctx.db
      .query("users")
      .withIndex("by_email", (q) => q.eq("email", email))
      .unique();

    const bootstrapEmail = env.NEBULA_BOOTSTRAP_ADMIN_EMAIL
      ? normalizeEmail(env.NEBULA_BOOTSTRAP_ADMIN_EMAIL)
      : null;
    if (!target && bootstrapEmail === email) {
      const existingSystemAdministrator = await ctx.db
        .query("users")
        .withIndex("by_role", (q) => q.eq("role", "systemAdministrator"))
        .take(1);
      if (existingSystemAdministrator.length === 0) {
        const bootstrapAdmins = await ctx.db
          .query("users")
          .withIndex("by_role", (q) => q.eq("role", "admin"))
          .order("asc")
          .take(1);
        target = bootstrapAdmins[0] ?? null;
      }
    }

    if (!target) {
      throw new Error(
        "No invited Nebula user matches this WorkOS email address. Contact a System Administrator.",
      );
    }
    if (target.tokenIdentifier) {
      throw new Error(
        "This Nebula user is already linked to another identity.",
      );
    }
    if (target.status !== "active") {
      throw new Error("This user account is suspended.");
    }

    const existingSystemAdministrator = await ctx.db
      .query("users")
      .withIndex("by_role", (q) => q.eq("role", "systemAdministrator"))
      .take(1);
    const becomesSystemAdministrator =
      target.role === "admin" && existingSystemAdministrator.length === 0;
    const now = Date.now();
    await ctx.db.patch("users", target._id, {
      email,
      role: becomesSystemAdministrator ? "systemAdministrator" : target.role,
      authProvider: "workos",
      tokenIdentifier: identity.tokenIdentifier,
      providerUserId: identity.subject,
      identityLinkedAt: now,
      lastAuthenticatedAt: now,
      updatedAt: now,
    });
    await appendAudit(ctx, {
      actorUserId: target._id,
      action: "auth.identityLinked",
      targetType: "user",
      targetId: target._id,
      context: becomesSystemAdministrator
        ? "workos/bootstrap-system-administrator"
        : "workos",
    });

    const linked = await ctx.db.get("users", target._id);
    if (!linked) throw new Error("The linked user could not be loaded.");
    return publicUser(linked);
  },
});

export const listVisible = query({
  args: {},
  handler: async (ctx) => {
    await requireActor(ctx);
    const users = await ctx.db.query("users").order("asc").take(100);
    return users.map(publicUser);
  },
});

export const create = mutation({
  args: {
    displayName: v.string(),
    email: v.string(),
    role: roleValidator,
  },
  handler: async (ctx, args) => {
    const actor = await requireAdmin(ctx);
    if (
      args.role === "systemAdministrator" &&
      actor.role !== "systemAdministrator"
    ) {
      throw new Error("Only a System Administrator can assign that role.");
    }
    const email = normalizeEmail(args.email);
    if (
      await ctx.db
        .query("users")
        .withIndex("by_email", (q) => q.eq("email", email))
        .unique()
    ) {
      throw new Error("A user with this email already exists.");
    }
    const displayName = args.displayName.trim();
    if (!displayName) throw new Error("Display name is required.");
    const now = Date.now();
    const userId = await ctx.db.insert("users", {
      displayName,
      email,
      role: args.role,
      status: "active",
      createdAt: now,
      updatedAt: now,
    });
    await appendAudit(ctx, {
      actorUserId: actor._id,
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
    publicKeyJwk: v.string(),
    localKeyEnvelope: v.string(),
  },
  handler: async (ctx, args) => {
    const actor = await requireActor(ctx);
    if (actor.publicKeyJwk && actor.publicKeyJwk !== args.publicKeyJwk) {
      throw new Error(
        "A different device key is already enrolled for this user.",
      );
    }
    const existingEnvelope = await ctx.db
      .query("environmentKeyEnvelopes")
      .withIndex("by_userId_and_environment_and_keyVersion", (q) =>
        q
          .eq("userId", actor._id)
          .eq("environment", "local")
          .eq("keyVersion", 1),
      )
      .unique();
    if (!existingEnvelope) {
      await ctx.db.insert("environmentKeyEnvelopes", {
        userId: actor._id,
        environment: "local",
        keyVersion: 1,
        wrappedKey: args.localKeyEnvelope,
        createdBy: actor._id,
        createdAt: Date.now(),
      });
    }
    await ctx.db.patch("users", actor._id, {
      publicKeyJwk: args.publicKeyJwk,
      updatedAt: Date.now(),
    });
    await appendAudit(ctx, {
      actorUserId: actor._id,
      action: "device.enrolled",
      targetType: "user",
      targetId: actor._id,
    });
    return null;
  },
});

export const listForAdmin = query({
  args: {},
  handler: async (ctx) => {
    await requireAdmin(ctx);
    const users = await ctx.db.query("users").order("asc").take(100);
    return await Promise.all(
      users.map(async (user) => {
        const grants = await Promise.all(
          (["development", "uat", "production"] as const).map(
            async (environment) => {
              const grant = await ctx.db
                .query("environmentGrants")
                .withIndex("by_userId_and_environment", (q) =>
                  q.eq("userId", user._id).eq("environment", environment),
                )
                .unique();
              return [environment, grant?.status === "active"] as const;
            },
          ),
        );
        return {
          ...publicUser(user),
          grants: Object.fromEntries(grants),
        };
      }),
    );
  },
});

export const getPublicKey = query({
  args: { targetUserId: v.id("users") },
  handler: async (ctx, args) => {
    await requireAdmin(ctx);
    const target = await ctx.db.get("users", args.targetUserId);
    if (!target || target.status !== "active")
      throw new Error("User is not active.");
    return target.publicKeyJwk ?? null;
  },
});

export const update = mutation({
  args: {
    targetUserId: v.id("users"),
    role: roleValidator,
    status: v.union(v.literal("active"), v.literal("suspended")),
  },
  handler: async (ctx, args) => {
    const actor = await requireAdmin(ctx);
    const target = await ctx.db.get("users", args.targetUserId);
    if (!target) throw new Error("User not found.");
    const changesSystemAdministrator =
      target.role === "systemAdministrator" ||
      args.role === "systemAdministrator";
    if (changesSystemAdministrator && actor.role !== "systemAdministrator") {
      throw new Error("Only a System Administrator can change that role.");
    }
    if (target._id === actor._id && args.status === "suspended") {
      throw new Error("You cannot suspend your own account.");
    }
    if (
      target._id === actor._id &&
      target.role === "systemAdministrator" &&
      args.role !== "systemAdministrator"
    ) {
      throw new Error("You cannot remove your own System Administrator role.");
    }
    if (
      target.role === "systemAdministrator" &&
      (args.role !== "systemAdministrator" || args.status !== "active")
    ) {
      const activeSystemAdministrators = await ctx.db
        .query("users")
        .withIndex("by_role", (q) => q.eq("role", "systemAdministrator"))
        .take(100);
      if (
        !activeSystemAdministrators.some(
          (candidate) =>
            candidate._id !== target._id && candidate.status === "active",
        )
      ) {
        throw new Error(
          "At least one active System Administrator is required.",
        );
      }
    }
    await ctx.db.patch("users", target._id, {
      role: args.role,
      status: args.status,
      updatedAt: Date.now(),
    });
    await appendAudit(ctx, {
      actorUserId: actor._id,
      action: "user.updated",
      targetType: "user",
      targetId: target._id,
      context: `${args.role}/${args.status}`,
    });
    return null;
  },
});
