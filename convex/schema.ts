import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

const environment = v.union(
  v.literal("local"),
  v.literal("development"),
  v.literal("uat"),
  v.literal("production"),
);

const encryptedPayload = v.object({
  ciphertext: v.string(),
  iv: v.string(),
  wrappedKey: v.string(),
  algorithm: v.literal("AES-256-GCM+AES-KW"),
  aadVersion: v.literal(1),
});

export default defineSchema({
  users: defineTable({
    displayName: v.string(),
    email: v.string(),
    role: v.union(
      v.literal("developer"),
      v.literal("admin"),
      v.literal("systemAdministrator"),
    ),
    status: v.union(v.literal("active"), v.literal("suspended")),
    publicKeyJwk: v.optional(v.string()),
    authProvider: v.optional(v.literal("workos")),
    tokenIdentifier: v.optional(v.string()),
    providerUserId: v.optional(v.string()),
    identityLinkedAt: v.optional(v.number()),
    lastAuthenticatedAt: v.optional(v.number()),
    createdAt: v.number(),
    updatedAt: v.number(),
  })
    .index("by_email", ["email"])
    .index("by_role", ["role"])
    .index("by_tokenIdentifier", ["tokenIdentifier"]),

  authConfiguration: defineTable({
    singletonKey: v.literal("authentication"),
    provider: v.literal("workos"),
    state: v.union(
      v.literal("staged"),
      v.literal("verified"),
      v.literal("enforced"),
    ),
    provisioningMode: v.literal("invitationOnly"),
    clientId: v.string(),
    redirectUri: v.string(),
    allowedEmailDomains: v.array(v.string()),
    updatedBy: v.id("users"),
    updatedAt: v.number(),
    verifiedAt: v.optional(v.number()),
    enforcedAt: v.optional(v.number()),
  }).index("by_singletonKey", ["singletonKey"]),

  environmentGrants: defineTable({
    userId: v.id("users"),
    environment: v.union(
      v.literal("development"),
      v.literal("uat"),
      v.literal("production"),
    ),
    status: v.union(v.literal("active"), v.literal("revoked")),
    grantedBy: v.id("users"),
    grantedAt: v.number(),
    revokedAt: v.optional(v.number()),
  })
    .index("by_userId_and_environment", ["userId", "environment"])
    .index("by_environment_and_status", ["environment", "status"]),

  environmentKeyEnvelopes: defineTable({
    userId: v.id("users"),
    environment,
    keyVersion: v.number(),
    wrappedKey: v.string(),
    createdBy: v.id("users"),
    createdAt: v.number(),
  })
    .index("by_userId_and_environment_and_keyVersion", [
      "userId",
      "environment",
      "keyVersion",
    ])
    .index("by_environment_and_keyVersion", ["environment", "keyVersion"]),

  projects: defineTable({
    name: v.string(),
    normalizedName: v.string(),
    status: v.union(v.literal("active"), v.literal("archived")),
    createdBy: v.id("users"),
    createdAt: v.number(),
    updatedAt: v.number(),
    archivedAt: v.optional(v.number()),
  })
    .index("by_normalizedName", ["normalizedName"])
    .index("by_status", ["status"]),

  secretDefinitions: defineTable({
    cryptoId: v.string(),
    name: v.string(),
    projectId: v.id("projects"),
    type: v.union(
      v.literal("login"),
      v.literal("apiKey"),
      v.literal("licenseKey"),
    ),
    status: v.union(v.literal("active"), v.literal("archived")),
    createdBy: v.id("users"),
    createdAt: v.number(),
    updatedAt: v.number(),
    archivedAt: v.optional(v.number()),
  })
    .index("by_status", ["status"])
    .index("by_cryptoId", ["cryptoId"])
    .index("by_projectId_and_status", ["projectId", "status"]),

  secretValues: defineTable({
    secretId: v.id("secretDefinitions"),
    environment,
    ownerUserId: v.union(v.id("users"), v.null()),
    payload: encryptedPayload,
    version: v.number(),
    updatedBy: v.id("users"),
    updatedAt: v.number(),
  })
    .index("by_environment_and_ownerUserId", ["environment", "ownerUserId"])
    .index("by_secretId_and_environment_and_ownerUserId", [
      "secretId",
      "environment",
      "ownerUserId",
    ])
    .index("by_secretId", ["secretId"]),

  secretValueVersions: defineTable({
    secretValueId: v.id("secretValues"),
    payload: encryptedPayload,
    version: v.number(),
    changedBy: v.id("users"),
    changedAt: v.number(),
  }).index("by_secretValueId_and_version", ["secretValueId", "version"]),

  attachments: defineTable({
    secretValueId: v.id("secretValues"),
    cryptoId: v.string(),
    storageId: v.id("_storage"),
    encryptedMetadata: encryptedPayload,
    fileIv: v.string(),
    encryptedSize: v.number(),
    createdBy: v.id("users"),
    createdAt: v.number(),
  }).index("by_secretValueId", ["secretValueId"]),

  auditEvents: defineTable({
    actorUserId: v.id("users"),
    action: v.string(),
    targetType: v.string(),
    targetId: v.optional(v.string()),
    environment: v.optional(environment),
    outcome: v.union(v.literal("success"), v.literal("denied")),
    context: v.optional(v.string()),
    createdAt: v.number(),
  })
    .index("by_actorUserId", ["actorUserId"])
    .index("by_environment", ["environment"]),
});
