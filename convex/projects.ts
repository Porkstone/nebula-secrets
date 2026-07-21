import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { appendAudit, requireActor } from "./lib/access";
import { GENERAL_PROJECT_NORMALIZED_NAME } from "./lib/projects";

function cleanProjectName(name: string) {
  const cleaned = name.trim().replace(/\s+/g, " ");
  if (!cleaned) throw new Error("Project name is required.");
  if (cleaned.length > 80) throw new Error("Project name must be 80 characters or fewer.");
  return { name: cleaned, normalizedName: cleaned.toLowerCase() };
}

async function ensureUniqueName(
  ctx: Parameters<typeof requireActor>[0],
  normalizedName: string,
  excludingId?: string,
) {
  const existing = await ctx.db
    .query("projects")
    .withIndex("by_normalizedName", (q) => q.eq("normalizedName", normalizedName))
    .unique();
  if (existing && existing._id !== excludingId) {
    throw new Error("A project with this name already exists.");
  }
}

export const list = query({
  args: { actorUserId: v.id("users") },
  handler: async (ctx, args) => {
    await requireActor(ctx, args.actorUserId);
    return await ctx.db
      .query("projects")
      .withIndex("by_status", (q) => q.eq("status", "active"))
      .take(200);
  },
});

export const create = mutation({
  args: { actorUserId: v.id("users"), name: v.string() },
  handler: async (ctx, args) => {
    await requireActor(ctx, args.actorUserId);
    const project = cleanProjectName(args.name);
    await ensureUniqueName(ctx, project.normalizedName);
    const now = Date.now();
    const projectId = await ctx.db.insert("projects", {
      ...project,
      status: "active",
      createdBy: args.actorUserId,
      createdAt: now,
      updatedAt: now,
    });
    await appendAudit(ctx, {
      actorUserId: args.actorUserId,
      action: "project.created",
      targetType: "project",
      targetId: projectId,
    });
    return projectId;
  },
});

export const rename = mutation({
  args: {
    actorUserId: v.id("users"),
    projectId: v.id("projects"),
    name: v.string(),
  },
  handler: async (ctx, args) => {
    await requireActor(ctx, args.actorUserId);
    const existing = await ctx.db.get("projects", args.projectId);
    if (!existing || existing.status !== "active") throw new Error("Project not found.");
    if (existing.normalizedName === GENERAL_PROJECT_NORMALIZED_NAME) {
      throw new Error("The General project cannot be renamed.");
    }
    const project = cleanProjectName(args.name);
    await ensureUniqueName(ctx, project.normalizedName, args.projectId);
    await ctx.db.patch("projects", args.projectId, { ...project, updatedAt: Date.now() });
    await appendAudit(ctx, {
      actorUserId: args.actorUserId,
      action: "project.renamed",
      targetType: "project",
      targetId: args.projectId,
    });
    return null;
  },
});

export const archive = mutation({
  args: { actorUserId: v.id("users"), projectId: v.id("projects") },
  handler: async (ctx, args) => {
    await requireActor(ctx, args.actorUserId);
    const existing = await ctx.db.get("projects", args.projectId);
    if (!existing || existing.status !== "active") throw new Error("Project not found.");
    if (existing.normalizedName === GENERAL_PROJECT_NORMALIZED_NAME) {
      throw new Error("The General project cannot be archived.");
    }
    const assignedSecret = await ctx.db
      .query("secretDefinitions")
      .withIndex("by_projectId_and_status", (q) =>
        q.eq("projectId", args.projectId),
      )
      .take(1);
    if (assignedSecret.length > 0) {
      throw new Error("Move this project's secrets before archiving it.");
    }
    const now = Date.now();
    await ctx.db.patch("projects", args.projectId, {
      status: "archived",
      archivedAt: now,
      updatedAt: now,
    });
    await appendAudit(ctx, {
      actorUserId: args.actorUserId,
      action: "project.archived",
      targetType: "project",
      targetId: args.projectId,
    });
    return null;
  },
});
