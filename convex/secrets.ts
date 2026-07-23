import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import {
  appendAudit,
  ownerForEnvironment,
  requireEnvironmentAccess,
} from "./lib/access";
import {
  encryptedPayloadValidator,
  environmentValidator,
  secretTypeValidator,
} from "./validators";
import {
  getOrCreateGeneralProject,
  projectAllowsSecretType,
} from "./lib/projects";

export const list = query({
  args: {
    environment: environmentValidator,
  },
  handler: async (ctx, args) => {
    const actor = await requireEnvironmentAccess(ctx, args.environment);
    const owner = ownerForEnvironment(args.environment, actor._id);
    const definitions = await ctx.db
      .query("secretDefinitions")
      .withIndex("by_status", (q) => q.eq("status", "active"))
      .order("desc")
      .take(200);
    return await Promise.all(
      definitions.map(async (definition) => {
        const value = await ctx.db
          .query("secretValues")
          .withIndex("by_secretId_and_environment_and_ownerUserId", (q) =>
            q
              .eq("secretId", definition._id)
              .eq("environment", args.environment)
              .eq("ownerUserId", owner),
          )
          .unique();
        return { definition, value };
      }),
    );
  },
});

export const save = mutation({
  args: {
    environment: environmentValidator,
    secretId: v.optional(v.id("secretDefinitions")),
    projectId: v.optional(v.id("projects")),
    cryptoId: v.string(),
    name: v.string(),
    type: secretTypeValidator,
    payload: encryptedPayloadValidator,
    expectedVersion: v.optional(v.number()),
  },
  returns: v.object({
    secretId: v.id("secretDefinitions"),
    valueId: v.id("secretValues"),
    version: v.number(),
  }),
  handler: async (ctx, args) => {
    const actor = await requireEnvironmentAccess(ctx, args.environment);
    const projectId =
      args.projectId ?? (await getOrCreateGeneralProject(ctx, actor._id));
    const project = await ctx.db.get("projects", projectId);
    if (!project || project.status !== "active")
      throw new Error("Project not found.");
    if (!projectAllowsSecretType(project, args.type)) {
      throw new Error("This project does not allow the selected secret type.");
    }
    const owner = ownerForEnvironment(args.environment, actor._id);
    const now = Date.now();
    let secretId = args.secretId;
    let convertedFromApiKey = false;
    if (secretId) {
      const definition = await ctx.db.get("secretDefinitions", secretId);
      if (!definition || definition.status !== "active") {
        throw new Error("Secret definition not found.");
      }
      if (definition.cryptoId !== args.cryptoId)
        throw new Error("Secret identity mismatch.");
      if (definition.type !== args.type) {
        if (definition.type !== "apiKey" || args.type !== "introducerApiKey") {
          throw new Error(
            "Only API Key secrets can be converted to Introducer API Key.",
          );
        }
        const storedValues = await ctx.db
          .query("secretValues")
          .withIndex("by_secretId", (q) => q.eq("secretId", definition._id))
          .take(2);
        const currentStoredValue = storedValues.find(
          (value) =>
            value.environment === args.environment &&
            value.ownerUserId === owner,
        );
        if (
          storedValues.some((value) => value._id !== currentStoredValue?._id)
        ) {
          throw new Error(
            "Conversion is only available when this is the secret's only stored value.",
          );
        }
        if (
          currentStoredValue &&
          args.expectedVersion !== currentStoredValue.version
        ) {
          throw new Error(
            "This secret changed in another session. Refresh and try again.",
          );
        }
        convertedFromApiKey = true;
      }
      await ctx.db.patch("secretDefinitions", secretId, {
        name: args.name.trim(),
        type: args.type,
        projectId,
        updatedAt: now,
      });
    } else {
      if (
        await ctx.db
          .query("secretDefinitions")
          .withIndex("by_cryptoId", (q) => q.eq("cryptoId", args.cryptoId))
          .unique()
      ) {
        throw new Error("Secret identity already exists.");
      }
      secretId = await ctx.db.insert("secretDefinitions", {
        cryptoId: args.cryptoId,
        name: args.name.trim(),
        projectId,
        type: args.type,
        status: "active",
        createdBy: actor._id,
        createdAt: now,
        updatedAt: now,
      });
    }

    const existing = await ctx.db
      .query("secretValues")
      .withIndex("by_secretId_and_environment_and_ownerUserId", (q) =>
        q
          .eq("secretId", secretId)
          .eq("environment", args.environment)
          .eq("ownerUserId", owner),
      )
      .unique();
    let valueId;
    if (existing) {
      if (
        args.expectedVersion !== undefined &&
        existing.version !== args.expectedVersion
      ) {
        throw new Error(
          "This secret changed in another session. Refresh and try again.",
        );
      }
      await ctx.db.insert("secretValueVersions", {
        secretValueId: existing._id,
        payload: existing.payload,
        secretType: convertedFromApiKey ? "apiKey" : args.type,
        version: existing.version,
        changedBy: existing.updatedBy,
        changedAt: existing.updatedAt,
      });
      await ctx.db.patch("secretValues", existing._id, {
        payload: args.payload,
        version: existing.version + 1,
        updatedBy: actor._id,
        updatedAt: now,
      });
      valueId = existing._id;
    } else {
      valueId = await ctx.db.insert("secretValues", {
        secretId,
        environment: args.environment,
        ownerUserId: owner,
        payload: args.payload,
        version: 1,
        updatedBy: actor._id,
        updatedAt: now,
      });
    }
    await appendAudit(ctx, {
      actorUserId: actor._id,
      action: convertedFromApiKey
        ? "secret.typeConverted"
        : existing
          ? "secret.updated"
          : "secret.valueCreated",
      targetType: "secret",
      targetId: secretId,
      environment: args.environment,
      context: convertedFromApiKey ? "apiKey->introducerApiKey" : args.type,
    });
    return { secretId, valueId, version: existing ? existing.version + 1 : 1 };
  },
});

export const setArchiveStatus = mutation({
  args: {
    secretId: v.id("secretDefinitions"),
    environment: environmentValidator,
    archived: v.boolean(),
  },
  handler: async (ctx, args) => {
    const actor = await requireEnvironmentAccess(ctx, args.environment);
    const definition = await ctx.db.get("secretDefinitions", args.secretId);
    if (!definition) throw new Error("Secret not found.");
    if (!args.archived) {
      const project = await ctx.db.get("projects", definition.projectId);
      if (!project || project.status !== "active") {
        throw new Error("Project not found.");
      }
      if (!projectAllowsSecretType(project, definition.type)) {
        throw new Error(
          "This project does not allow this secret type. Move the secret before restoring it.",
        );
      }
    }
    await ctx.db.patch("secretDefinitions", args.secretId, {
      status: args.archived ? "archived" : "active",
      archivedAt: args.archived ? Date.now() : undefined,
      updatedAt: Date.now(),
    });
    await appendAudit(ctx, {
      actorUserId: actor._id,
      action: args.archived ? "secret.archived" : "secret.restored",
      targetType: "secret",
      targetId: args.secretId,
      environment: args.environment,
    });
    return null;
  },
});

export const listVersions = query({
  args: {
    secretValueId: v.id("secretValues"),
  },
  returns: v.array(
    v.object({
      payload: encryptedPayloadValidator,
      secretType: secretTypeValidator,
      version: v.number(),
      changedBy: v.id("users"),
      changedAt: v.number(),
      current: v.boolean(),
    }),
  ),
  handler: async (ctx, args) => {
    const value = await ctx.db.get("secretValues", args.secretValueId);
    if (!value) throw new Error("Secret value not found.");
    const actor = await requireEnvironmentAccess(ctx, value.environment);
    if (value.environment === "local" && value.ownerUserId !== actor._id) {
      throw new Error("Local values are private to their owner.");
    }
    const definition = await ctx.db.get("secretDefinitions", value.secretId);
    if (!definition) throw new Error("Secret definition not found.");
    const history = await ctx.db
      .query("secretValueVersions")
      .withIndex("by_secretValueId_and_version", (q) =>
        q.eq("secretValueId", args.secretValueId),
      )
      .order("desc")
      .take(25);
    return [
      {
        payload: value.payload,
        secretType: definition.type,
        version: value.version,
        changedBy: value.updatedBy,
        changedAt: value.updatedAt,
        current: true,
      },
      ...history.map((item) => ({
        payload: item.payload,
        secretType:
          item.secretType ??
          (definition.type === "introducerApiKey" ? "apiKey" : definition.type),
        version: item.version,
        changedBy: item.changedBy,
        changedAt: item.changedAt,
        current: false,
      })),
    ];
  },
});
