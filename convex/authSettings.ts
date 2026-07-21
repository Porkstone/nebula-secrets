import { env, mutation, query } from "./_generated/server";
import { v } from "convex/values";
import {
  appendAudit,
  isWorkosIssuer,
  requireSystemAdministrator,
} from "./lib/access";
import { authProviderValidator } from "./validators";

const SINGLETON_KEY = "authentication" as const;

function normalizeDomains(domains: string[]) {
  const normalized = Array.from(
    new Set(
      domains.map((domain) => domain.trim().toLowerCase()).filter(Boolean),
    ),
  );
  if (normalized.length > 25) {
    throw new Error("No more than 25 allowed email domains can be configured.");
  }
  for (const domain of normalized) {
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain)) {
      throw new Error(`Invalid email domain: ${domain}`);
    }
  }
  return normalized;
}

function validatePublicWorkosConfiguration(
  clientId: string,
  redirectUri: string,
) {
  const cleanClientId = clientId.trim();
  if (!cleanClientId.startsWith("client_")) {
    throw new Error("WorkOS Client IDs must start with client_.");
  }
  let redirect: URL;
  try {
    redirect = new URL(redirectUri.trim());
  } catch {
    throw new Error("Enter a valid WorkOS redirect URI.");
  }
  const localDevelopment =
    redirect.protocol === "http:" &&
    (redirect.hostname === "127.0.0.1" || redirect.hostname === "localhost");
  if (redirect.protocol !== "https:" && !localDevelopment) {
    throw new Error(
      "WorkOS redirect URIs must use HTTPS outside local development.",
    );
  }
  if (!redirect.pathname.endsWith("/callback")) {
    throw new Error("The WorkOS redirect URI must end with /callback.");
  }
  return { clientId: cleanClientId, redirectUri: redirect.toString() };
}

async function getConfiguration(
  ctx: Parameters<typeof requireSystemAdministrator>[0],
) {
  return await ctx.db
    .query("authConfiguration")
    .withIndex("by_singletonKey", (q) => q.eq("singletonKey", SINGLETON_KEY))
    .unique();
}

export const publicState = query({
  args: {},
  handler: async (ctx) => {
    const configuration = await ctx.db
      .query("authConfiguration")
      .withIndex("by_singletonKey", (q) => q.eq("singletonKey", SINGLETON_KEY))
      .unique();
    return configuration
      ? { provider: configuration.provider, state: configuration.state }
      : { provider: "workos" as const, state: "staged" as const };
  },
});

export const getForSystemAdministrator = query({
  args: {},
  handler: async (ctx) => {
    await requireSystemAdministrator(ctx);
    const configuration = await getConfiguration(ctx);
    return {
      configuration,
      supportedProviders: [
        {
          id: "workos" as const,
          name: "WorkOS AuthKit",
          description:
            "Hosted authentication with enterprise SSO and user management.",
          available: true,
        },
      ],
      deployment: {
        backendClientIdConfigured: Boolean(env.WORKOS_CLIENT_ID),
        backendClientId: env.WORKOS_CLIENT_ID ?? null,
      },
    };
  },
});

export const save = mutation({
  args: {
    provider: authProviderValidator,
    clientId: v.string(),
    redirectUri: v.string(),
    allowedEmailDomains: v.array(v.string()),
  },
  handler: async (ctx, args) => {
    const actor = await requireSystemAdministrator(ctx);
    const workos = validatePublicWorkosConfiguration(
      args.clientId,
      args.redirectUri,
    );
    const allowedEmailDomains = normalizeDomains(args.allowedEmailDomains);
    const existing = await getConfiguration(ctx);
    const now = Date.now();
    const values = {
      singletonKey: SINGLETON_KEY,
      provider: args.provider,
      state: "staged" as const,
      provisioningMode: "invitationOnly" as const,
      clientId: workos.clientId,
      redirectUri: workos.redirectUri,
      allowedEmailDomains,
      updatedBy: actor._id,
      updatedAt: now,
      verifiedAt: undefined,
      enforcedAt: undefined,
    };
    let configurationId;
    if (existing) {
      await ctx.db.replace("authConfiguration", existing._id, values);
      configurationId = existing._id;
    } else {
      configurationId = await ctx.db.insert("authConfiguration", values);
    }
    await appendAudit(ctx, {
      actorUserId: actor._id,
      action: "auth.configurationUpdated",
      targetType: "authConfiguration",
      targetId: configurationId,
      context: args.provider,
    });
    return configurationId;
  },
});

export const verify = mutation({
  args: {},
  handler: async (ctx) => {
    const actor = await requireSystemAdministrator(ctx);
    const identity = await ctx.auth.getUserIdentity();
    if (!identity || !isWorkosIssuer(identity.issuer)) {
      throw new Error("A validated WorkOS session is required.");
    }
    const configuration = await getConfiguration(ctx);
    if (!configuration) throw new Error("Save the WorkOS configuration first.");
    if (!env.WORKOS_CLIENT_ID) {
      throw new Error(
        "WORKOS_CLIENT_ID is not configured on this Convex deployment.",
      );
    }
    if (configuration.clientId !== env.WORKOS_CLIENT_ID) {
      throw new Error(
        "The saved Client ID does not match the Convex deployment.",
      );
    }
    const now = Date.now();
    await ctx.db.patch("authConfiguration", configuration._id, {
      state: "verified",
      verifiedAt: now,
      updatedBy: actor._id,
      updatedAt: now,
    });
    await appendAudit(ctx, {
      actorUserId: actor._id,
      action: "auth.configurationVerified",
      targetType: "authConfiguration",
      targetId: configuration._id,
      context: configuration.provider,
    });
    return null;
  },
});

export const enforce = mutation({
  args: {},
  handler: async (ctx) => {
    const actor = await requireSystemAdministrator(ctx);
    const configuration = await getConfiguration(ctx);
    if (!configuration || configuration.state !== "verified") {
      throw new Error(
        "Verify the authentication configuration before enforcing it.",
      );
    }
    if (
      !env.WORKOS_CLIENT_ID ||
      configuration.clientId !== env.WORKOS_CLIENT_ID
    ) {
      throw new Error(
        "The WorkOS deployment configuration is no longer ready.",
      );
    }
    const now = Date.now();
    await ctx.db.patch("authConfiguration", configuration._id, {
      state: "enforced",
      enforcedAt: now,
      updatedBy: actor._id,
      updatedAt: now,
    });
    await appendAudit(ctx, {
      actorUserId: actor._id,
      action: "auth.enforcementEnabled",
      targetType: "authConfiguration",
      targetId: configuration._id,
      context: configuration.provider,
    });
    return null;
  },
});
