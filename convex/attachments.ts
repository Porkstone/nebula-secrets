import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import type { Id } from "./_generated/dataModel";
import type { MutationCtx, QueryCtx } from "./_generated/server";
import { appendAudit, requireEnvironmentAccess } from "./lib/access";
import { encryptedPayloadValidator } from "./validators";

async function requireValueAccess(
  ctx: QueryCtx | MutationCtx,
  actorUserId: Id<"users">,
  secretValueId: Id<"secretValues">,
) {
  const value = await ctx.db.get("secretValues", secretValueId);
  if (!value) throw new Error("Secret value not found.");
  await requireEnvironmentAccess(ctx, actorUserId, value.environment);
  if (value.environment === "local" && value.ownerUserId !== actorUserId) {
    throw new Error("Local attachments are private to their owner.");
  }
  return value;
}

export const list = query({
  args: {
    actorUserId: v.id("users"),
    secretValueId: v.id("secretValues"),
  },
  handler: async (ctx, args) => {
    await requireValueAccess(ctx, args.actorUserId, args.secretValueId);
    return await ctx.db
      .query("attachments")
      .withIndex("by_secretValueId", (q) => q.eq("secretValueId", args.secretValueId))
      .order("desc")
      .take(50);
  },
});

export const generateUploadUrl = mutation({
  args: {
    actorUserId: v.id("users"),
    secretValueId: v.id("secretValues"),
  },
  handler: async (ctx, args) => {
    await requireValueAccess(ctx, args.actorUserId, args.secretValueId);
    return await ctx.storage.generateUploadUrl();
  },
});

export const commit = mutation({
  args: {
    actorUserId: v.id("users"),
    secretValueId: v.id("secretValues"),
    cryptoId: v.string(),
    storageId: v.id("_storage"),
    encryptedMetadata: encryptedPayloadValidator,
    fileIv: v.string(),
    encryptedSize: v.number(),
  },
  handler: async (ctx, args) => {
    const value = await requireValueAccess(ctx, args.actorUserId, args.secretValueId);
    const stored = await ctx.db.system.get("_storage", args.storageId);
    if (!stored) throw new Error("Encrypted upload was not found.");
    if (stored.size !== args.encryptedSize) throw new Error("Encrypted upload size mismatch.");
    const attachmentId = await ctx.db.insert("attachments", {
      secretValueId: args.secretValueId,
      cryptoId: args.cryptoId,
      storageId: args.storageId,
      encryptedMetadata: args.encryptedMetadata,
      fileIv: args.fileIv,
      encryptedSize: args.encryptedSize,
      createdBy: args.actorUserId,
      createdAt: Date.now(),
    });
    await appendAudit(ctx, {
      actorUserId: args.actorUserId,
      action: "attachment.uploaded",
      targetType: "attachment",
      targetId: attachmentId,
      environment: value.environment,
    });
    return attachmentId;
  },
});

export const getDownload = mutation({
  args: { actorUserId: v.id("users"), attachmentId: v.id("attachments") },
  handler: async (ctx, args) => {
    const attachment = await ctx.db.get("attachments", args.attachmentId);
    if (!attachment) throw new Error("Attachment not found.");
    await requireValueAccess(ctx, args.actorUserId, attachment.secretValueId);
    const url = await ctx.storage.getUrl(attachment.storageId);
    if (!url) throw new Error("Encrypted attachment data is unavailable.");
    const value = await ctx.db.get("secretValues", attachment.secretValueId);
    await appendAudit(ctx, {
      actorUserId: args.actorUserId,
      action: "attachment.downloaded",
      targetType: "attachment",
      targetId: attachment._id,
      environment: value?.environment,
    });
    return { ...attachment, url };
  },
});

export const remove = mutation({
  args: { actorUserId: v.id("users"), attachmentId: v.id("attachments") },
  handler: async (ctx, args) => {
    const attachment = await ctx.db.get("attachments", args.attachmentId);
    if (!attachment) return null;
    const value = await requireValueAccess(ctx, args.actorUserId, attachment.secretValueId);
    await ctx.storage.delete(attachment.storageId);
    await ctx.db.delete("attachments", attachment._id);
    await appendAudit(ctx, {
      actorUserId: args.actorUserId,
      action: "attachment.deleted",
      targetType: "attachment",
      targetId: attachment._id,
      environment: value.environment,
    });
    return null;
  },
});
