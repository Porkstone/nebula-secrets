import type { Id } from "../_generated/dataModel";
import type { MutationCtx, QueryCtx } from "../_generated/server";
import type { Environment, SharedEnvironment } from "../validators";

type ReadCtx = QueryCtx | MutationCtx;

export async function requireActor(ctx: ReadCtx, actorUserId: Id<"users">) {
  const actor = await ctx.db.get("users", actorUserId);
  if (!actor || actor.status !== "active") {
    throw new Error("This development identity is not active.");
  }
  return actor;
}

export async function requireAdmin(ctx: ReadCtx, actorUserId: Id<"users">) {
  const actor = await requireActor(ctx, actorUserId);
  if (actor.role !== "admin") {
    throw new Error("Admin role required.");
  }
  return actor;
}

export async function requireEnvironmentAccess(
  ctx: ReadCtx,
  actorUserId: Id<"users">,
  environment: Environment,
) {
  const actor = await requireActor(ctx, actorUserId);
  if (environment === "local") return actor;

  const grant = await ctx.db
    .query("environmentGrants")
    .withIndex("by_userId_and_environment", (q) =>
      q.eq("userId", actorUserId).eq("environment", environment),
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
