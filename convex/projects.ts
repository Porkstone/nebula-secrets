import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { appendAudit, requireActor, requireAdmin } from "./lib/access";
import { GENERAL_PROJECT_NORMALIZED_NAME } from "./lib/projects";
import { secretTypeValidator, type SecretType } from "./validators";

const ALL_SECRET_TYPES: SecretType[] = [
  "login",
  "apiKey",
  "introducerApiKey",
  "licenseKey",
];

function cleanAllowedSecretTypes(secretTypes: SecretType[]) {
  const cleaned = [...new Set(secretTypes)];
  if (cleaned.length === 0) {
    throw new Error("Select at least one allowed secret type.");
  }
  return cleaned;
}

function secretTypeLabel(secretType: SecretType) {
  if (secretType === "apiKey") return "API Key";
  if (secretType === "introducerApiKey") return "Introducer API Key";
  if (secretType === "licenseKey") return "License Key";
  return "Login";
}

function cleanProjectName(name: string) {
  const cleaned = name.trim().replace(/\s+/g, " ");
  if (!cleaned) throw new Error("Project name is required.");
  if (cleaned.length > 80)
    throw new Error("Project name must be 80 characters or fewer.");
  return { name: cleaned, normalizedName: cleaned.toLowerCase() };
}

async function ensureUniqueName(
  ctx: Parameters<typeof requireActor>[0],
  normalizedName: string,
  excludingId?: string,
) {
  const existing = await ctx.db
    .query("projects")
    .withIndex("by_normalizedName", (q) =>
      q.eq("normalizedName", normalizedName),
    )
    .unique();
  if (existing && existing._id !== excludingId) {
    throw new Error("A project with this name already exists.");
  }
}

export const list = query({
  args: {},
  handler: async (ctx) => {
    await requireActor(ctx);
    return await ctx.db
      .query("projects")
      .withIndex("by_status", (q) => q.eq("status", "active"))
      .take(200);
  },
});

export const create = mutation({
  args: {
    name: v.string(),
    allowedSecretTypes: v.optional(v.array(secretTypeValidator)),
  },
  handler: async (ctx, args) => {
    const actor = await requireActor(ctx);
    const project = cleanProjectName(args.name);
    const allowedSecretTypes = args.allowedSecretTypes
      ? cleanAllowedSecretTypes(args.allowedSecretTypes)
      : ALL_SECRET_TYPES;
    await ensureUniqueName(ctx, project.normalizedName);
    const now = Date.now();
    const projectId = await ctx.db.insert("projects", {
      ...project,
      allowedSecretTypes,
      status: "active",
      createdBy: actor._id,
      createdAt: now,
      updatedAt: now,
    });
    await appendAudit(ctx, {
      actorUserId: actor._id,
      action: "project.created",
      targetType: "project",
      targetId: projectId,
    });
    return projectId;
  },
});

export const setAllowedSecretTypes = mutation({
  args: {
    projectId: v.id("projects"),
    allowedSecretTypes: v.array(secretTypeValidator),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const actor = await requireAdmin(ctx);
    const project = await ctx.db.get("projects", args.projectId);
    if (!project || project.status !== "active") {
      throw new Error("Project not found.");
    }
    const allowedSecretTypes = cleanAllowedSecretTypes(args.allowedSecretTypes);
    for (const secretType of ALL_SECRET_TYPES) {
      if (allowedSecretTypes.includes(secretType)) continue;
      const conflictingSecret = await ctx.db
        .query("secretDefinitions")
        .withIndex("by_projectId_and_type_and_status", (q) =>
          q
            .eq("projectId", args.projectId)
            .eq("type", secretType)
            .eq("status", "active"),
        )
        .take(1);
      if (conflictingSecret.length > 0) {
        throw new Error(
          `Move or archive this project's ${secretTypeLabel(secretType)} secrets before removing that type.`,
        );
      }
    }
    await ctx.db.patch("projects", args.projectId, {
      allowedSecretTypes,
      updatedAt: Date.now(),
    });
    await appendAudit(ctx, {
      actorUserId: actor._id,
      action: "project.secretTypesUpdated",
      targetType: "project",
      targetId: args.projectId,
      context: allowedSecretTypes.join(","),
    });
    return null;
  },
});

export const rename = mutation({
  args: {
    projectId: v.id("projects"),
    name: v.string(),
  },
  handler: async (ctx, args) => {
    const actor = await requireActor(ctx);
    const existing = await ctx.db.get("projects", args.projectId);
    if (!existing || existing.status !== "active")
      throw new Error("Project not found.");
    if (existing.normalizedName === GENERAL_PROJECT_NORMALIZED_NAME) {
      throw new Error("The General project cannot be renamed.");
    }
    const project = cleanProjectName(args.name);
    await ensureUniqueName(ctx, project.normalizedName, args.projectId);
    await ctx.db.patch("projects", args.projectId, {
      ...project,
      updatedAt: Date.now(),
    });
    await appendAudit(ctx, {
      actorUserId: actor._id,
      action: "project.renamed",
      targetType: "project",
      targetId: args.projectId,
    });
    return null;
  },
});

export const archive = mutation({
  args: { projectId: v.id("projects") },
  handler: async (ctx, args) => {
    const actor = await requireActor(ctx);
    const existing = await ctx.db.get("projects", args.projectId);
    if (!existing || existing.status !== "active")
      throw new Error("Project not found.");
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
      actorUserId: actor._id,
      action: "project.archived",
      targetType: "project",
      targetId: args.projectId,
    });
    return null;
  },
});
