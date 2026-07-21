import type { Id } from "../_generated/dataModel";
import type { MutationCtx } from "../_generated/server";

export const GENERAL_PROJECT_NAME = "General";
export const GENERAL_PROJECT_NORMALIZED_NAME = "general";

export async function getOrCreateGeneralProject(
  ctx: MutationCtx,
  actorUserId: Id<"users">,
) {
  const existing = await ctx.db
    .query("projects")
    .withIndex("by_normalizedName", (q) =>
      q.eq("normalizedName", GENERAL_PROJECT_NORMALIZED_NAME),
    )
    .unique();
  const now = Date.now();
  if (existing) {
    if (existing.status === "archived") {
      await ctx.db.patch("projects", existing._id, {
        status: "active",
        archivedAt: undefined,
        updatedAt: now,
      });
    }
    return existing._id;
  }
  return await ctx.db.insert("projects", {
    name: GENERAL_PROJECT_NAME,
    normalizedName: GENERAL_PROJECT_NORMALIZED_NAME,
    status: "active",
    createdBy: actorUserId,
    createdAt: now,
    updatedAt: now,
  });
}
