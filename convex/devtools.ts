import { mutation } from "./_generated/server";
import { v } from "convex/values";
import { requireSystemAdministrator } from "./lib/access";

const MAX_RESET_ROWS_PER_TABLE = 500;

/**
 * Development-only escape hatch for disposable workspaces whose browser-held
 * private key is no longer available.
 */
export const resetWorkspace = mutation({
  args: {
    confirmation: v.literal("RESET NEBULA"),
  },
  handler: async (ctx, _args) => {
    await requireSystemAdministrator(ctx);

    const [
      attachments,
      auditEvents,
      secretValueVersions,
      secretValues,
      secretDefinitions,
      environmentKeyEnvelopes,
      environmentGrants,
      projects,
      authConfiguration,
      users,
    ] = await Promise.all([
      ctx.db.query("attachments").take(MAX_RESET_ROWS_PER_TABLE + 1),
      ctx.db.query("auditEvents").take(MAX_RESET_ROWS_PER_TABLE + 1),
      ctx.db.query("secretValueVersions").take(MAX_RESET_ROWS_PER_TABLE + 1),
      ctx.db.query("secretValues").take(MAX_RESET_ROWS_PER_TABLE + 1),
      ctx.db.query("secretDefinitions").take(MAX_RESET_ROWS_PER_TABLE + 1),
      ctx.db
        .query("environmentKeyEnvelopes")
        .take(MAX_RESET_ROWS_PER_TABLE + 1),
      ctx.db.query("environmentGrants").take(MAX_RESET_ROWS_PER_TABLE + 1),
      ctx.db.query("projects").take(MAX_RESET_ROWS_PER_TABLE + 1),
      ctx.db.query("authConfiguration").take(2),
      ctx.db.query("users").take(MAX_RESET_ROWS_PER_TABLE + 1),
    ]);

    const collections = [
      attachments,
      auditEvents,
      secretValueVersions,
      secretValues,
      secretDefinitions,
      environmentKeyEnvelopes,
      environmentGrants,
      projects,
      authConfiguration,
      users,
    ];
    if (
      collections.some(
        (documents) => documents.length > MAX_RESET_ROWS_PER_TABLE,
      )
    ) {
      throw new Error(
        "This workspace is too large for the development reset. Use a controlled migration instead.",
      );
    }

    for (const attachment of attachments)
      await ctx.storage.delete(attachment.storageId);
    for (const document of attachments)
      await ctx.db.delete("attachments", document._id);
    for (const document of auditEvents)
      await ctx.db.delete("auditEvents", document._id);
    for (const document of secretValueVersions) {
      await ctx.db.delete("secretValueVersions", document._id);
    }
    for (const document of secretValues)
      await ctx.db.delete("secretValues", document._id);
    for (const document of secretDefinitions) {
      await ctx.db.delete("secretDefinitions", document._id);
    }
    for (const document of environmentKeyEnvelopes) {
      await ctx.db.delete("environmentKeyEnvelopes", document._id);
    }
    for (const document of environmentGrants) {
      await ctx.db.delete("environmentGrants", document._id);
    }
    for (const document of projects)
      await ctx.db.delete("projects", document._id);
    for (const document of authConfiguration) {
      await ctx.db.delete("authConfiguration", document._id);
    }
    for (const document of users) await ctx.db.delete("users", document._id);

    return {
      deletedDocuments: collections.reduce(
        (total, documents) => total + documents.length,
        0,
      ),
      deletedFiles: attachments.length,
    };
  },
});
