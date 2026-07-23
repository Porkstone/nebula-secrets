import { internal } from "./_generated/api";
import type { Doc, Id } from "./_generated/dataModel";
import {
  internalMutation,
  internalQuery,
  mutation,
  query,
  type MutationCtx,
  type QueryCtx,
} from "./_generated/server";
import { v } from "convex/values";
import {
  appendAudit,
  getActiveGrant,
  requireActor,
  requireSystemAdministrator,
} from "./lib/access";
import { deviceEnvelopeValidator, type Environment } from "./validators";

const environments = ["local", "development", "uat", "production"] as const;
const sharedEnvironments = ["development", "uat", "production"] as const;
const MAX_DEVICES_PER_USER = 50;
const MAX_PENDING_DEVICES = 5;
const REQUEST_LIFETIME_MS = 15 * 60 * 1000;

function assertText(value: string, label: string, maxLength: number) {
  const trimmed = value.trim();
  if (!trimmed) throw new Error(`${label} is required.`);
  if (trimmed.length > maxLength) {
    throw new Error(`${label} must be ${maxLength} characters or fewer.`);
  }
  return trimmed;
}

function summarizeDevice(device: Doc<"devices">, now: number) {
  return {
    _id: device._id,
    userId: device.userId,
    label: device.label,
    publicEncryptionKeyJwk: device.publicEncryptionKeyJwk,
    publicSigningKeyJwk: device.publicSigningKeyJwk ?? null,
    keyFingerprint: device.keyFingerprint ?? null,
    browserName: device.browserName ?? null,
    platform: device.platform ?? null,
    status: device.status,
    verificationCode: device.verificationCode ?? null,
    requestedAt: device.requestedAt,
    expiresAt: device.expiresAt ?? null,
    approvedAt: device.approvedAt ?? null,
    approvedByDeviceId: device.approvedByDeviceId ?? null,
    claimedAt: device.claimedAt ?? null,
    lastUsedAt: device.lastUsedAt ?? null,
    revokedAt: device.revokedAt ?? null,
    legacy: device.legacy ?? false,
    isExpired:
      device.status === "pending" &&
      device.expiresAt !== undefined &&
      device.expiresAt <= now,
  };
}

async function copyLegacyEnvelopes(
  ctx: MutationCtx,
  userId: Id<"users">,
  deviceId: Id<"devices">,
  createdByUserId: Id<"users">,
) {
  for (const environment of environments) {
    const legacyEnvelope = await ctx.db
      .query("environmentKeyEnvelopes")
      .withIndex("by_userId_and_environment_and_keyVersion", (q) =>
        q
          .eq("userId", userId)
          .eq("environment", environment)
          .eq("keyVersion", 1),
      )
      .unique();
    if (!legacyEnvelope) continue;
    const existing = await ctx.db
      .query("deviceKeyEnvelopes")
      .withIndex("by_deviceId_and_environment_and_keyVersion", (q) =>
        q
          .eq("deviceId", deviceId)
          .eq("environment", environment)
          .eq("keyVersion", legacyEnvelope.keyVersion),
      )
      .unique();
    if (!existing) {
      await ctx.db.insert("deviceKeyEnvelopes", {
        userId,
        deviceId,
        environment,
        keyVersion: legacyEnvelope.keyVersion,
        wrappedKey: legacyEnvelope.wrappedKey,
        createdByUserId,
        createdAt: legacyEnvelope.createdAt,
      });
    }
  }
}

async function activeDeviceForActor(
  ctx: QueryCtx | MutationCtx,
  userId: Id<"users">,
  deviceId: Id<"devices">,
) {
  const device = await ctx.db.get("devices", deviceId);
  if (!device || device.userId !== userId || device.status !== "active") {
    throw new Error("An active device is required.");
  }
  return device;
}

async function requiredEnvironmentsForUser(
  ctx: QueryCtx | MutationCtx,
  userId: Id<"users">,
) {
  const required: Environment[] = ["local"];
  for (const environment of sharedEnvironments) {
    if (await getActiveGrant(ctx, userId, environment))
      required.push(environment);
  }
  return required;
}

function canonicalApproval(args: {
  targetDeviceId: Id<"devices">;
  approverDeviceId: Id<"devices">;
  approvalNonce: string;
  envelopes: Array<{
    environment: Environment;
    keyVersion: number;
    wrappedKey: string;
  }>;
}) {
  const order = new Map(
    environments.map((environment, index) => [environment, index]),
  );
  const envelopes = [...args.envelopes].sort(
    (left, right) =>
      (order.get(left.environment) ?? 99) -
      (order.get(right.environment) ?? 99),
  );
  return [
    "nebula-device-approval-v1",
    args.targetDeviceId,
    args.approverDeviceId,
    args.approvalNonce,
    ...envelopes.map(
      (envelope) =>
        `${envelope.environment}:${envelope.keyVersion}:${envelope.wrappedKey}`,
    ),
  ].join("|");
}

function base64ToBytes(value: string) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function verifyApprovalSignature(
  publicSigningKeyJwk: string,
  message: string,
  signature: string,
) {
  try {
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      JSON.parse(publicSigningKeyJwk) as JsonWebKey,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      base64ToBytes(signature),
      new TextEncoder().encode(message),
    );
  } catch {
    return false;
  }
}

export const listMine = query({
  args: { now: v.number() },
  handler: async (ctx, args) => {
    const actor = await requireActor(ctx);
    const devices = await ctx.db
      .query("devices")
      .withIndex("by_userId", (q) => q.eq("userId", actor._id))
      .order("desc")
      .take(MAX_DEVICES_PER_USER);
    return devices.map((device) => summarizeDevice(device, args.now));
  },
});

export const listForSystemAdministrator = query({
  args: { now: v.number() },
  handler: async (ctx, args) => {
    await requireSystemAdministrator(ctx);
    const devices = await ctx.db.query("devices").order("desc").take(200);
    return devices.map((device) => {
      const summary = summarizeDevice(device, args.now);
      return {
        _id: summary._id,
        userId: summary.userId,
        label: summary.label,
        keyFingerprint: summary.keyFingerprint,
        browserName: summary.browserName,
        platform: summary.platform,
        status: summary.status,
        requestedAt: summary.requestedAt,
        approvedAt: summary.approvedAt,
        lastUsedAt: summary.lastUsedAt,
        revokedAt: summary.revokedAt,
        isExpired: summary.isExpired,
      };
    });
  },
});

export const enrollFirst = mutation({
  args: {
    label: v.string(),
    publicEncryptionKeyJwk: v.string(),
    publicSigningKeyJwk: v.string(),
    keyFingerprint: v.string(),
    browserName: v.string(),
    platform: v.string(),
    localKeyEnvelope: v.string(),
  },
  handler: async (ctx, args) => {
    const actor = await requireActor(ctx);
    const existingDevices = await ctx.db
      .query("devices")
      .withIndex("by_userId", (q) => q.eq("userId", actor._id))
      .take(1);
    if (existingDevices.length > 0 || actor.publicKeyJwk) {
      throw new Error("This user already has an enrolled device.");
    }
    const now = Date.now();
    const deviceId = await ctx.db.insert("devices", {
      userId: actor._id,
      label: assertText(args.label, "Device name", 80),
      publicEncryptionKeyJwk: args.publicEncryptionKeyJwk,
      publicSigningKeyJwk: args.publicSigningKeyJwk,
      keyFingerprint: assertText(args.keyFingerprint, "Key fingerprint", 128),
      browserName: assertText(args.browserName, "Browser", 100),
      platform: assertText(args.platform, "Platform", 100),
      status: "active",
      requestedAt: now,
      approvedAt: now,
      claimedAt: now,
      lastUsedAt: now,
    });
    await ctx.db.insert("deviceKeyEnvelopes", {
      userId: actor._id,
      deviceId,
      environment: "local",
      keyVersion: 1,
      wrappedKey: args.localKeyEnvelope,
      createdByUserId: actor._id,
      createdByDeviceId: deviceId,
      createdAt: now,
    });

    // Dual-write the legacy fields during the widen/migrate window.
    await ctx.db.patch("users", actor._id, {
      publicKeyJwk: args.publicEncryptionKeyJwk,
      updatedAt: now,
    });
    await ctx.db.insert("environmentKeyEnvelopes", {
      userId: actor._id,
      environment: "local",
      keyVersion: 1,
      wrappedKey: args.localKeyEnvelope,
      createdBy: actor._id,
      createdAt: now,
    });
    await appendAudit(ctx, {
      actorUserId: actor._id,
      action: "device.enrolled",
      targetType: "device",
      targetId: deviceId,
      context: "first-device",
    });
    return deviceId;
  },
});

export const claimLegacyDevice = mutation({
  args: {
    label: v.string(),
    publicEncryptionKeyJwk: v.string(),
    publicSigningKeyJwk: v.string(),
    keyFingerprint: v.string(),
    browserName: v.string(),
    platform: v.string(),
  },
  handler: async (ctx, args) => {
    const actor = await requireActor(ctx);
    const devices = await ctx.db
      .query("devices")
      .withIndex("by_userId", (q) => q.eq("userId", actor._id))
      .take(MAX_DEVICES_PER_USER);
    const matchingDevice = devices.find(
      (candidate) =>
        candidate.publicEncryptionKeyJwk === args.publicEncryptionKeyJwk,
    );
    if (matchingDevice?.status === "revoked") {
      throw new Error(
        "This legacy browser was revoked and cannot be reclaimed.",
      );
    }
    let device =
      matchingDevice?.status === "active" ? matchingDevice : undefined;
    const now = Date.now();
    if (!device) {
      if (actor.publicKeyJwk !== args.publicEncryptionKeyJwk) {
        throw new Error(
          "This browser key does not match the legacy device key.",
        );
      }
      const deviceId = await ctx.db.insert("devices", {
        userId: actor._id,
        label: assertText(args.label, "Device name", 80),
        publicEncryptionKeyJwk: args.publicEncryptionKeyJwk,
        publicSigningKeyJwk: args.publicSigningKeyJwk,
        keyFingerprint: assertText(args.keyFingerprint, "Key fingerprint", 128),
        browserName: assertText(args.browserName, "Browser", 100),
        platform: assertText(args.platform, "Platform", 100),
        status: "active",
        requestedAt: actor.createdAt,
        approvedAt: actor.createdAt,
        claimedAt: now,
        lastUsedAt: now,
        legacy: true,
      });
      device = (await ctx.db.get("devices", deviceId)) ?? undefined;
    }
    if (!device) throw new Error("Unable to create the legacy device record.");
    if (
      device.publicSigningKeyJwk &&
      device.publicSigningKeyJwk !== args.publicSigningKeyJwk
    ) {
      throw new Error("This legacy device has already been claimed elsewhere.");
    }
    await ctx.db.patch("devices", device._id, {
      label: assertText(args.label, "Device name", 80),
      publicSigningKeyJwk: args.publicSigningKeyJwk,
      keyFingerprint: assertText(args.keyFingerprint, "Key fingerprint", 128),
      browserName: assertText(args.browserName, "Browser", 100),
      platform: assertText(args.platform, "Platform", 100),
      claimedAt: now,
      lastUsedAt: now,
    });
    await copyLegacyEnvelopes(ctx, actor._id, device._id, actor._id);
    await appendAudit(ctx, {
      actorUserId: actor._id,
      action: "device.legacyClaimed",
      targetType: "device",
      targetId: device._id,
    });
    return device._id;
  },
});

export const requestEnrollment = mutation({
  args: {
    label: v.string(),
    publicEncryptionKeyJwk: v.string(),
    publicSigningKeyJwk: v.string(),
    keyFingerprint: v.string(),
    browserName: v.string(),
    platform: v.string(),
    verificationCode: v.string(),
    approvalNonce: v.string(),
  },
  handler: async (ctx, args) => {
    const actor = await requireActor(ctx);
    const now = Date.now();
    const devices = await ctx.db
      .query("devices")
      .withIndex("by_userId", (q) => q.eq("userId", actor._id))
      .take(MAX_DEVICES_PER_USER + 1);
    if (devices.length === 0 && actor.publicKeyJwk) {
      const legacyDeviceId = await ctx.db.insert("devices", {
        userId: actor._id,
        label: "Legacy browser",
        publicEncryptionKeyJwk: actor.publicKeyJwk,
        status: "active",
        requestedAt: actor.createdAt,
        approvedAt: actor.createdAt,
        legacy: true,
      });
      await copyLegacyEnvelopes(ctx, actor._id, legacyDeviceId, actor._id);
    }
    if (devices.length > MAX_DEVICES_PER_USER) {
      throw new Error("This user has reached the device limit.");
    }
    if (
      devices.filter(
        (device) =>
          device.status === "pending" &&
          device.expiresAt !== undefined &&
          device.expiresAt > now,
      ).length >= MAX_PENDING_DEVICES
    ) {
      throw new Error("Too many device requests are already pending.");
    }
    if (
      devices.some(
        (device) =>
          device.status !== "revoked" &&
          device.publicEncryptionKeyJwk === args.publicEncryptionKeyJwk,
      )
    ) {
      throw new Error("This browser key is already registered.");
    }
    if (!/^\d{6}$/.test(args.verificationCode)) {
      throw new Error("The verification code is invalid.");
    }
    const expiresAt = now + REQUEST_LIFETIME_MS;
    const deviceId = await ctx.db.insert("devices", {
      userId: actor._id,
      label: assertText(args.label, "Device name", 80),
      publicEncryptionKeyJwk: args.publicEncryptionKeyJwk,
      publicSigningKeyJwk: args.publicSigningKeyJwk,
      keyFingerprint: assertText(args.keyFingerprint, "Key fingerprint", 128),
      browserName: assertText(args.browserName, "Browser", 100),
      platform: assertText(args.platform, "Platform", 100),
      status: "pending",
      verificationCode: args.verificationCode,
      approvalNonce: assertText(args.approvalNonce, "Approval nonce", 256),
      requestedAt: now,
      expiresAt,
    });
    await appendAudit(ctx, {
      actorUserId: actor._id,
      action: "device.requested",
      targetType: "device",
      targetId: deviceId,
      context: args.keyFingerprint.slice(0, 16),
    });
    return { deviceId, expiresAt };
  },
});

export const getApprovalContext = query({
  args: {
    targetDeviceId: v.id("devices"),
    approverDeviceId: v.id("devices"),
    now: v.number(),
  },
  handler: async (ctx, args) => {
    const actor = await requireActor(ctx);
    const approver = await activeDeviceForActor(
      ctx,
      actor._id,
      args.approverDeviceId,
    );
    if (!approver.publicSigningKeyJwk) {
      throw new Error(
        "This device must finish its legacy-key upgrade before approving others.",
      );
    }
    const target = await ctx.db.get("devices", args.targetDeviceId);
    if (!target || target.userId !== actor._id || target.status !== "pending") {
      throw new Error("The pending device request was not found.");
    }
    if (
      !target.expiresAt ||
      target.expiresAt <= args.now ||
      !target.approvalNonce
    ) {
      throw new Error("The device request has expired.");
    }
    const required = await requiredEnvironmentsForUser(ctx, actor._id);
    const envelopes = await Promise.all(
      required.map(async (environment) => {
        const envelope = await ctx.db
          .query("deviceKeyEnvelopes")
          .withIndex("by_deviceId_and_environment_and_keyVersion", (q) =>
            q
              .eq("deviceId", approver._id)
              .eq("environment", environment)
              .eq("keyVersion", 1),
          )
          .unique();
        if (!envelope) {
          throw new Error(
            `This device does not hold the ${environment} key required for approval.`,
          );
        }
        return {
          environment,
          keyVersion: envelope.keyVersion,
          wrappedKey: envelope.wrappedKey,
        };
      }),
    );
    return {
      targetDeviceId: target._id,
      targetPublicEncryptionKeyJwk: target.publicEncryptionKeyJwk,
      approverDeviceId: approver._id,
      approvalNonce: target.approvalNonce,
      envelopes,
    };
  },
});

export const approveEnrollment = mutation({
  args: {
    targetDeviceId: v.id("devices"),
    approverDeviceId: v.id("devices"),
    envelopes: v.array(deviceEnvelopeValidator),
    signature: v.string(),
  },
  handler: async (ctx, args) => {
    const actor = await requireActor(ctx);
    const approver = await activeDeviceForActor(
      ctx,
      actor._id,
      args.approverDeviceId,
    );
    if (!approver.publicSigningKeyJwk) {
      throw new Error("This device cannot sign an approval yet.");
    }
    const target = await ctx.db.get("devices", args.targetDeviceId);
    const now = Date.now();
    if (!target || target.userId !== actor._id || target.status !== "pending") {
      throw new Error("The pending device request was not found.");
    }
    if (!target.expiresAt || target.expiresAt <= now || !target.approvalNonce) {
      throw new Error("The device request has expired.");
    }
    const required = await requiredEnvironmentsForUser(ctx, actor._id);
    const supplied = new Map(
      args.envelopes.map((envelope) => [envelope.environment, envelope]),
    );
    if (
      supplied.size !== args.envelopes.length ||
      supplied.size !== required.length ||
      required.some((environment) => !supplied.has(environment))
    ) {
      throw new Error(
        "One device envelope is required for every authorized environment.",
      );
    }
    const canonical = canonicalApproval({
      targetDeviceId: target._id,
      approverDeviceId: approver._id,
      approvalNonce: target.approvalNonce,
      envelopes: args.envelopes,
    });
    if (
      !(await verifyApprovalSignature(
        approver.publicSigningKeyJwk,
        canonical,
        args.signature,
      ))
    ) {
      throw new Error("The device approval signature is invalid.");
    }

    for (const envelope of args.envelopes) {
      if (envelope.keyVersion !== 1) {
        throw new Error("Unsupported environment key version.");
      }
      await ctx.db.insert("deviceKeyEnvelopes", {
        userId: actor._id,
        deviceId: target._id,
        environment: envelope.environment,
        keyVersion: envelope.keyVersion,
        wrappedKey: envelope.wrappedKey,
        createdByUserId: actor._id,
        createdByDeviceId: approver._id,
        createdAt: now,
      });
    }
    await ctx.db.patch("devices", target._id, {
      status: "active",
      approvedAt: now,
      approvedByDeviceId: approver._id,
      verificationCode: undefined,
      approvalNonce: undefined,
      expiresAt: undefined,
      lastUsedAt: now,
    });
    await appendAudit(ctx, {
      actorUserId: actor._id,
      action: "device.approved",
      targetType: "device",
      targetId: target._id,
      context: `approved-by:${approver._id}`,
    });
    return null;
  },
});

export const rejectEnrollment = mutation({
  args: { targetDeviceId: v.id("devices") },
  handler: async (ctx, args) => {
    const actor = await requireActor(ctx);
    const target = await ctx.db.get("devices", args.targetDeviceId);
    if (!target || target.userId !== actor._id || target.status !== "pending") {
      throw new Error("The pending device request was not found.");
    }
    const now = Date.now();
    await ctx.db.patch("devices", target._id, {
      status: "revoked",
      revokedAt: now,
      revokedByUserId: actor._id,
      verificationCode: undefined,
      approvalNonce: undefined,
      expiresAt: undefined,
    });
    await appendAudit(ctx, {
      actorUserId: actor._id,
      action: "device.rejected",
      targetType: "device",
      targetId: target._id,
    });
    return null;
  },
});

export const rename = mutation({
  args: { deviceId: v.id("devices"), label: v.string() },
  handler: async (ctx, args) => {
    const actor = await requireActor(ctx);
    const device = await ctx.db.get("devices", args.deviceId);
    if (!device || device.userId !== actor._id || device.status === "revoked") {
      throw new Error("Device not found.");
    }
    await ctx.db.patch("devices", device._id, {
      label: assertText(args.label, "Device name", 80),
    });
    await appendAudit(ctx, {
      actorUserId: actor._id,
      action: "device.renamed",
      targetType: "device",
      targetId: device._id,
    });
    return null;
  },
});

export const revoke = mutation({
  args: { deviceId: v.id("devices") },
  handler: async (ctx, args) => {
    const actor = await requireActor(ctx);
    const device = await ctx.db.get("devices", args.deviceId);
    if (!device || device.status === "revoked")
      throw new Error("Device not found.");
    const ownsDevice = device.userId === actor._id;
    if (!ownsDevice && actor.role !== "systemAdministrator") {
      throw new Error("System Administrator role required.");
    }
    if (ownsDevice && device.status === "active") {
      const activeDevices = await ctx.db
        .query("devices")
        .withIndex("by_userId_and_status", (q) =>
          q.eq("userId", actor._id).eq("status", "active"),
        )
        .take(2);
      if (activeDevices.length < 2) {
        throw new Error("The last active device cannot be revoked.");
      }
    }
    const envelopes = await ctx.db
      .query("deviceKeyEnvelopes")
      .withIndex("by_deviceId", (q) => q.eq("deviceId", device._id))
      .take(10);
    for (const envelope of envelopes) {
      await ctx.db.delete("deviceKeyEnvelopes", envelope._id);
    }
    const owner = await ctx.db.get("users", device.userId);
    if (owner?.publicKeyJwk === device.publicEncryptionKeyJwk) {
      for (const environment of environments) {
        const legacyEnvelope = await ctx.db
          .query("environmentKeyEnvelopes")
          .withIndex("by_userId_and_environment_and_keyVersion", (q) =>
            q
              .eq("userId", device.userId)
              .eq("environment", environment)
              .eq("keyVersion", 1),
          )
          .unique();
        if (legacyEnvelope) {
          await ctx.db.delete("environmentKeyEnvelopes", legacyEnvelope._id);
        }
      }
    }
    const now = Date.now();
    await ctx.db.patch("devices", device._id, {
      status: "revoked",
      revokedAt: now,
      revokedByUserId: actor._id,
      verificationCode: undefined,
      approvalNonce: undefined,
      expiresAt: undefined,
    });
    await appendAudit(ctx, {
      actorUserId: actor._id,
      action: "device.revoked",
      targetType: "device",
      targetId: device._id,
      context: ownsDevice ? "self-service" : "system-administrator",
    });
    return null;
  },
});

export const touch = mutation({
  args: { deviceId: v.id("devices") },
  handler: async (ctx, args) => {
    const actor = await requireActor(ctx);
    const device = await activeDeviceForActor(ctx, actor._id, args.deviceId);
    const now = Date.now();
    if (!device.lastUsedAt || now - device.lastUsedAt > 5 * 60 * 1000) {
      await ctx.db.patch("devices", device._id, { lastUsedAt: now });
    }
    return null;
  },
});

export const startLegacyDeviceBackfill = internalMutation({
  args: {},
  handler: async (ctx) => {
    await ctx.scheduler.runAfter(
      0,
      internal.devices.runLegacyDeviceBackfillPage,
      {
        cursor: null,
      },
    );
    return null;
  },
});

export const runLegacyDeviceBackfillPage = internalMutation({
  args: { cursor: v.union(v.string(), v.null()) },
  handler: async (ctx, args): Promise<null> => {
    const page = await ctx.db.query("users").paginate({
      numItems: 20,
      cursor: args.cursor,
    });
    for (const user of page.page) {
      if (!user.publicKeyJwk) continue;
      const existing = await ctx.db
        .query("devices")
        .withIndex("by_userId", (q) => q.eq("userId", user._id))
        .take(1);
      if (existing.length > 0) continue;
      const deviceId = await ctx.db.insert("devices", {
        userId: user._id,
        label: "Legacy browser",
        publicEncryptionKeyJwk: user.publicKeyJwk,
        status: "active",
        requestedAt: user.createdAt,
        approvedAt: user.createdAt,
        legacy: true,
      });
      await copyLegacyEnvelopes(ctx, user._id, deviceId, user._id);
    }
    if (!page.isDone) {
      await ctx.scheduler.runAfter(
        0,
        internal.devices.runLegacyDeviceBackfillPage,
        {
          cursor: page.continueCursor,
        },
      );
    }
    return null;
  },
});

export const legacyDeviceMigrationStatus = internalQuery({
  args: {},
  handler: async (ctx) => {
    const users = await ctx.db.query("users").order("asc").take(101);
    const missingDeviceUserIds: Id<"users">[] = [];
    for (const user of users.slice(0, 100)) {
      if (!user.publicKeyJwk) continue;
      const devices = await ctx.db
        .query("devices")
        .withIndex("by_userId", (q) => q.eq("userId", user._id))
        .take(1);
      if (devices.length === 0) missingDeviceUserIds.push(user._id);
    }
    return {
      sampleLimited: users.length > 100,
      usersChecked: Math.min(users.length, 100),
      missingDeviceUserIds,
    };
  },
});

export const getFirstActiveDeviceIdForUser = internalQuery({
  args: { userId: v.id("users") },
  handler: async (ctx, args) => {
    const devices = await ctx.db
      .query("devices")
      .withIndex("by_userId_and_status", (q) =>
        q.eq("userId", args.userId).eq("status", "active"),
      )
      .take(1);
    return devices[0]?._id ?? null;
  },
});
