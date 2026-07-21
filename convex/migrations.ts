import { internalMutation, internalQuery } from "./_generated/server";

/**
 * Optional pre-deploy migration for existing workspaces. Identity linking also
 * promotes the first matching Admin when no System Administrator exists, so
 * this mutation is safe to run before or after WorkOS is configured.
 */
export const promoteBootstrapAdmin = internalMutation({
  args: {},
  handler: async (ctx) => {
    const existing = await ctx.db
      .query("users")
      .withIndex("by_role", (q) => q.eq("role", "systemAdministrator"))
      .take(1);
    if (existing.length > 0) return existing[0]._id;

    const admins = await ctx.db
      .query("users")
      .withIndex("by_role", (q) => q.eq("role", "admin"))
      .order("asc")
      .take(1);
    const bootstrapAdmin = admins[0];
    if (!bootstrapAdmin) return null;
    await ctx.db.patch("users", bootstrapAdmin._id, {
      role: "systemAdministrator",
      updatedAt: Date.now(),
    });
    return bootstrapAdmin._id;
  },
});

export const identityMigrationStatus = internalQuery({
  args: {},
  handler: async (ctx) => {
    const users = await ctx.db.query("users").order("asc").take(101);
    return {
      sampleLimited: users.length > 100,
      usersChecked: Math.min(users.length, 100),
      unlinkedUserIds: users
        .slice(0, 100)
        .filter((user) => !user.tokenIdentifier)
        .map((user) => user._id),
      activeSystemAdministrators: users
        .slice(0, 100)
        .filter(
          (user) =>
            user.role === "systemAdministrator" && user.status === "active",
        ).length,
    };
  },
});
