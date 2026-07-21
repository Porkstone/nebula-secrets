import type { Doc, Id } from "../_generated/dataModel";
import type { MutationCtx, QueryCtx } from "../_generated/server";
import type { Environment, SharedEnvironment } from "../validators";

type ReadCtx = QueryCtx | MutationCtx;

export function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

export function isWorkosIssuer(issuer: string) {
  return (
    issuer === "https://api.workos.com/" ||
    issuer.startsWith("https://api.workos.com/user_management/")
  );
}

export async function getCurrentUser(
  ctx: ReadCtx,
): Promise<Doc<"users"> | null> {
  const identity = await ctx.auth.getUserIdentity();
  if (!identity) return null;
  return await ctx.db
    .query("users")
    .withIndex("by_tokenIdentifier", (q) =>
      q.eq("tokenIdentifier", identity.tokenIdentifier),
    )
    .unique();
}

export async function requireActor(ctx: ReadCtx) {
  const identity = await ctx.auth.getUserIdentity();
  if (!identity) throw new Error("Not authenticated.");

  const actor = await ctx.db
    .query("users")
    .withIndex("by_tokenIdentifier", (q) =>
      q.eq("tokenIdentifier", identity.tokenIdentifier),
    )
    .unique();
  if (!actor) {
    throw new Error(
      "This authenticated identity is not linked to a Nebula user.",
    );
  }
  if (actor.status !== "active") {
    throw new Error("This user account is suspended.");
  }
  return actor;
}

export async function requireAdmin(ctx: ReadCtx) {
  const actor = await requireActor(ctx);
  if (actor.role !== "admin" && actor.role !== "systemAdministrator") {
    throw new Error("Admin role required.");
  }
  return actor;
}

export async function requireSystemAdministrator(ctx: ReadCtx) {
  const actor = await requireActor(ctx);
  if (actor.role !== "systemAdministrator") {
    throw new Error("System Administrator role required.");
  }
  return actor;
}

export async function requireEnvironmentAccess(
  ctx: ReadCtx,
  environment: Environment,
) {
  const actor = await requireActor(ctx);
  if (environment === "local") return actor;

  const grant = await ctx.db
    .query("environmentGrants")
    .withIndex("by_userId_and_environment", (q) =>
      q.eq("userId", actor._id).eq("environment", environment),
    )
    .unique();
  if (!grant || grant.status !== "active") {
    throw new Error(`Access to ${environment} is required.`);
  }
  return actor;
}

export async function getActiveGrant(
  ctx: ReadCtx,
  userId: Id<"users">,
  environment: SharedEnvironment,
) {
  const grant = await ctx.db
    .query("environmentGrants")
    .withIndex("by_userId_and_environment", (q) =>
      q.eq("userId", userId).eq("environment", environment),
    )
    .unique();
  return grant?.status === "active" ? grant : null;
}

export function ownerForEnvironment(
  environment: Environment,
  actorUserId: Id<"users">,
) {
  return environment === "local" ? actorUserId : null;
}

export async function appendAudit(
  ctx: MutationCtx,
  args: {
    actorUserId: Id<"users">;
    action: string;
    targetType: string;
    targetId?: string;
    environment?: Environment;
    context?: string;
  },
) {
  await ctx.db.insert("auditEvents", {
    ...args,
    outcome: "success",
    createdAt: Date.now(),
  });
}
