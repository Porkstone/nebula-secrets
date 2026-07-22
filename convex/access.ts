import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import {
  appendAudit,
  getActiveGrant,
  requireActor,
  requireAdmin,
  requireEnvironmentAccess,
} from "./lib/access";
import {
  environmentValidator,
  sharedEnvironmentValidator,
} from "./validators";

export const listMine = query({
  args: { deviceId: v.optional(v.id("devices")) },
  handler: async (ctx, args) => {
    const actor = await requireActor(ctx);
    const device = args.deviceId
      ? await ctx.db.get("devices", args.deviceId)
      : null;
    if (
      args.deviceId &&
      (!device || device.userId !== actor._id || device.status !== "active")
    ) {
      throw new Error("An active device is required.");
    }
    return await Promise.all(
      (["local", "development", "uat", "production"] as const).map(
        async (environment) => {
          const granted =
            environment === "local"
              ? true
              : Boolean(await getActiveGrant(ctx, actor._id, environment));
          const envelope = device
            ? await ctx.db
                .query("deviceKeyEnvelopes")
                .withIndex(
                  "by_deviceId_and_environment_and_keyVersion",
                  (q) =>
                    q
                      .eq("deviceId", device._id)
                      .eq("environment", environment)
                      .eq("keyVersion", 1),
                )
                .unique()
            : await ctx.db
                .query("environmentKeyEnvelopes")
                .withIndex(
                  "by_userId_and_environment_and_keyVersion",
                  (q) =>
                    q
                      .eq("userId", actor._id)
                      .eq("environment", environment)
                      .eq("keyVersion", 1),
                )
                .unique();
          return { environment, granted, hasKey: Boolean(envelope) };
        },
      ),
    );
  },
});

export const getKeyEnvelope = query({
  args: {
    environment: environmentValidator,
    deviceId: v.optional(v.id("devices")),
  },
  handler: async (ctx, args) => {
    const actor = await requireEnvironmentAccess(ctx, args.environment);
    const device = args.deviceId
      ? await ctx.db.get("devices", args.deviceId)
      : null;
    if (
      args.deviceId &&
      (!device || device.userId !== actor._id || device.status !== "active")
    ) {
      throw new Error("An active device is required.");
    }
    const envelope = device
      ? await ctx.db
          .query("deviceKeyEnvelopes")
          .withIndex(
            "by_deviceId_and_environment_and_keyVersion",
            (q) =>
              q
                .eq("deviceId", device._id)
                .eq("environment", args.environment)
                .eq("keyVersion", 1),
          )
          .unique()
      : await ctx.db
          .query("environmentKeyEnvelopes")
          .withIndex("by_userId_and_environment_and_keyVersion", (q) =>
            q
              .eq("userId", actor._id)
              .eq("environment", args.environment)
              .eq("keyVersion", 1),
          )
          .unique();
    return envelope
      ? { wrappedKey: envelope.wrappedKey, keyVersion: envelope.keyVersion }
      : null;
  },
});

export const setGrant = mutation({
  args: {
    targetUserId: v.id("users"),
    environment: sharedEnvironmentValidator,
    enabled: v.boolean(),
    wrappedKey: v.optional(v.string()),
    deviceEnvelopes: v.optional(
      v.array(
        v.object({
          deviceId: v.id("devices"),
          keyVersion: v.number(),
          wrappedKey: v.string(),
        }),
      ),
    ),
  },
  handler: async (ctx, args) => {
    const actor = await requireAdmin(ctx);
    await requireEnvironmentAccess(ctx, args.environment);
    const target = await ctx.db.get("users", args.targetUserId);
    if (!target || target.status !== "active") throw new Error("Target user is not active.");
    if (
      args.enabled &&
      !args.wrappedKey &&
      (!args.deviceEnvelopes || args.deviceEnvelopes.length === 0)
    ) {
      throw new Error("The target user must enroll a device key before access is granted.");
    }
    const now = Date.now();
    const existingGrant = await ctx.db
      .query("environmentGrants")
      .withIndex("by_userId_and_environment", (q) =>
        q.eq("userId", args.targetUserId).eq("environment", args.environment),
      )
      .unique();
    if (existingGrant) {
      await ctx.db.patch("environmentGrants", existingGrant._id, {
        status: args.enabled ? "active" : "revoked",
        grantedBy: actor._id,
        grantedAt: args.enabled ? now : existingGrant.grantedAt,
        revokedAt: args.enabled ? undefined : now,
      });
    } else if (args.enabled) {
      await ctx.db.insert("environmentGrants", {
        userId: args.targetUserId,
        environment: args.environment,
        status: "active",
        grantedBy: actor._id,
        grantedAt: now,
      });
    }

    const envelope = await ctx.db
      .query("environmentKeyEnvelopes")
      .withIndex("by_userId_and_environment_and_keyVersion", (q) =>
        q
          .eq("userId", args.targetUserId)
          .eq("environment", args.environment)
          .eq("keyVersion", 1),
      )
      .unique();
    if (args.enabled && args.wrappedKey) {
      if (envelope) {
        await ctx.db.patch("environmentKeyEnvelopes", envelope._id, {
          wrappedKey: args.wrappedKey,
          createdBy: actor._id,
          createdAt: now,
        });
      } else {
        await ctx.db.insert("environmentKeyEnvelopes", {
          userId: args.targetUserId,
          environment: args.environment,
          keyVersion: 1,
          wrappedKey: args.wrappedKey,
          createdBy: actor._id,
          createdAt: now,
        });
      }
    } else if (!args.enabled && envelope) {
      await ctx.db.delete("environmentKeyEnvelopes", envelope._id);
    }

    if (args.enabled && args.deviceEnvelopes) {
      const activeDevices = await ctx.db
        .query("devices")
        .withIndex("by_userId_and_status", (q) =>
          q.eq("userId", args.targetUserId).eq("status", "active"),
        )
        .take(51);
      if (activeDevices.length > 50) throw new Error("The target has too many active devices.");
      const supplied = new Map(
        args.deviceEnvelopes.map((item) => [item.deviceId, item]),
      );
      if (
        supplied.size !== args.deviceEnvelopes.length ||
        supplied.size !== activeDevices.length ||
        activeDevices.some((device) => !supplied.has(device._id))
      ) {
        throw new Error("A key envelope is required for every active target device.");
      }
      for (const device of activeDevices) {
        const deviceEnvelope = supplied.get(device._id);
        if (!deviceEnvelope || deviceEnvelope.keyVersion !== 1) {
          throw new Error("Unsupported environment key version.");
        }
        const existing = await ctx.db
          .query("deviceKeyEnvelopes")
          .withIndex("by_deviceId_and_environment_and_keyVersion", (q) =>
            q
              .eq("deviceId", device._id)
              .eq("environment", args.environment)
              .eq("keyVersion", 1),
          )
          .unique();
        if (existing) {
          await ctx.db.patch("deviceKeyEnvelopes", existing._id, {
            wrappedKey: deviceEnvelope.wrappedKey,
            createdByUserId: actor._id,
            createdAt: now,
          });
        } else {
          await ctx.db.insert("deviceKeyEnvelopes", {
            userId: target._id,
            deviceId: device._id,
            environment: args.environment,
            keyVersion: 1,
            wrappedKey: deviceEnvelope.wrappedKey,
            createdByUserId: actor._id,
            createdAt: now,
          });
        }
      }
    } else if (!args.enabled) {
      const deviceEnvelopes = await ctx.db
        .query("deviceKeyEnvelopes")
        .withIndex("by_userId_and_environment", (q) =>
          q.eq("userId", target._id).eq("environment", args.environment),
        )
        .take(50);
      for (const deviceEnvelope of deviceEnvelopes) {
        await ctx.db.delete("deviceKeyEnvelopes", deviceEnvelope._id);
      }
    }

    await appendAudit(ctx, {
      actorUserId: actor._id,
      action: args.enabled ? "environment.granted" : "environment.revoked",
      targetType: "user",
      targetId: args.targetUserId,
      environment: args.environment,
    });
    return null;
  },
});
