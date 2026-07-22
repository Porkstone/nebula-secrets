import { ConvexError, v } from "convex/values";
import { internal } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import { action, env, type ActionCtx } from "./_generated/server";
import { isWorkosIssuer } from "./lib/access";
import { environmentValidator } from "./validators";

type VerifiedWorkosIdentity = {
  issuer: string;
  tokenIdentifier: string;
  providerUserId: string;
  email: string;
  emailVerified: boolean;
};

function workosError(code: string, message: string): never {
  throw new ConvexError({ code, message });
}

async function resolveVerifiedWorkosIdentity(
  ctx: ActionCtx,
): Promise<VerifiedWorkosIdentity> {
  const identity = await ctx.auth.getUserIdentity();
  if (!identity) {
    workosError("NOT_AUTHENTICATED", "Not authenticated.");
  }
  if (!isWorkosIssuer(identity.issuer)) {
    workosError(
      "UNSUPPORTED_PROVIDER",
      "The configured authentication provider is not supported.",
    );
  }
  if (!env.WORKOS_API_KEY) {
    workosError(
      "WORKOS_API_KEY_MISSING",
      "The WorkOS API key is not configured on this Convex deployment.",
    );
  }

  let response: Response;
  try {
    response = await fetch(
      `https://api.workos.com/user_management/users/${encodeURIComponent(identity.subject)}`,
      {
        headers: {
          Authorization: `Bearer ${env.WORKOS_API_KEY}`,
        },
      },
    );
  } catch {
    workosError(
      "WORKOS_UNAVAILABLE",
      "WorkOS could not be reached to verify this identity. Try again.",
    );
  }

  if (!response.ok) {
    workosError(
      "WORKOS_PROFILE_LOOKUP_FAILED",
      "WorkOS could not verify this user profile. Contact a System Administrator.",
    );
  }

  let profile: unknown;
  try {
    profile = await response.json();
  } catch {
    workosError(
      "INVALID_WORKOS_RESPONSE",
      "WorkOS returned an invalid user profile.",
    );
  }

  if (
    typeof profile !== "object" ||
    profile === null ||
    !("id" in profile) ||
    typeof profile.id !== "string" ||
    profile.id !== identity.subject ||
    !("email" in profile) ||
    typeof profile.email !== "string" ||
    !("email_verified" in profile) ||
    typeof profile.email_verified !== "boolean"
  ) {
    workosError(
      "INVALID_WORKOS_PROFILE",
      "WorkOS returned an incomplete user profile.",
    );
  }

  return {
    issuer: identity.issuer,
    tokenIdentifier: identity.tokenIdentifier,
    providerUserId: profile.id,
    email: profile.email,
    emailVerified: profile.email_verified,
  };
}

export const linkCurrentIdentity = action({
  args: {},
  handler: async (ctx): Promise<null> => {
    const identity = await resolveVerifiedWorkosIdentity(ctx);
    await ctx.runMutation(
      internal.users.linkVerifiedWorkosIdentity,
      identity,
    );
    return null;
  },
});

export const initializeWorkspace = action({
  args: {
    displayName: v.string(),
    publicKeyJwk: v.string(),
    publicSigningKeyJwk: v.string(),
    deviceLabel: v.string(),
    keyFingerprint: v.string(),
    browserName: v.string(),
    platform: v.string(),
    keyEnvelopes: v.array(
      v.object({
        environment: environmentValidator,
        wrappedKey: v.string(),
      }),
    ),
  },
  handler: async (
    ctx,
    args,
  ): Promise<{ userId: Id<"users">; deviceId: Id<"devices"> }> => {
    const identity = await resolveVerifiedWorkosIdentity(ctx);
    const userId: Id<"users"> = await ctx.runMutation(
      internal.bootstrap.initializeVerifiedWorkos,
      {
      ...identity,
      ...args,
      },
    );
    const deviceId: Id<"devices"> | null = await ctx.runQuery(
      internal.devices.getFirstActiveDeviceIdForUser,
      { userId },
    );
    if (!deviceId) {
      workosError(
        "BOOTSTRAP_DEVICE_NOT_FOUND",
        "The initial device could not be loaded after workspace setup.",
      );
    }
    return { userId, deviceId };
  },
});
