import { v } from "convex/values";

export const environmentValidator = v.union(
  v.literal("local"),
  v.literal("development"),
  v.literal("uat"),
  v.literal("production"),
);

export const sharedEnvironmentValidator = v.union(
  v.literal("development"),
  v.literal("uat"),
  v.literal("production"),
);

export const roleValidator = v.union(
  v.literal("developer"),
  v.literal("admin"),
  v.literal("systemAdministrator"),
);

export const authProviderValidator = v.literal("workos");

export const verifiedWorkosIdentityValidator = v.object({
  issuer: v.string(),
  tokenIdentifier: v.string(),
  providerUserId: v.string(),
  email: v.string(),
  emailVerified: v.boolean(),
});

export const authConfigurationStateValidator = v.union(
  v.literal("staged"),
  v.literal("verified"),
  v.literal("enforced"),
);

export const deviceStatusValidator = v.union(
  v.literal("pending"),
  v.literal("active"),
  v.literal("revoked"),
);

export const deviceEnvelopeValidator = v.object({
  environment: environmentValidator,
  keyVersion: v.number(),
  wrappedKey: v.string(),
});

export const secretTypeValidator = v.union(
  v.literal("login"),
  v.literal("apiKey"),
  v.literal("licenseKey"),
);

export const encryptedPayloadValidator = v.object({
  ciphertext: v.string(),
  iv: v.string(),
  wrappedKey: v.string(),
  algorithm: v.literal("AES-256-GCM+AES-KW"),
  aadVersion: v.literal(1),
});

export type Environment = "local" | "development" | "uat" | "production";
export type SharedEnvironment = Exclude<Environment, "local">;
export type UserRole = "developer" | "admin" | "systemAdministrator";
export type AuthProvider = "workos";
export type DeviceStatus = "pending" | "active" | "revoked";
