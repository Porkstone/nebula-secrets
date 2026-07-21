# Nebula Secrets

Nebula Secrets is a development-team vault built with React, Vite, and Convex. It stores Login, API Key, and License Key values per environment, with user-private Local values and shared Development, UAT, and Production values.

## Features

- WorkOS AuthKit authentication with token validation in Convex
- Developer, Admin, and System Administrator roles
- System Administrator-managed authentication provider settings
- Invitation-only identity linking by normalized WorkOS email
- Admin-managed environment access
- User-private Local values and shared Development, UAT, and Production values
- Browser-encrypted secrets, notes, and file attachments
- Projects, version history, archive support, and privacy-safe audit events
- Responsive desktop and mobile interface

## Security model

Every protected Convex function derives the current Nebula user from `ctx.auth.getUserIdentity()` and a server-side identity link. Browser-supplied user IDs are never accepted as proof of identity. WorkOS is the only supported provider today; the provider registry and configuration record are designed to accept additional providers later.

Sensitive payloads are encrypted in the browser with AES-256-GCM. Each payload has a random data key wrapped by an environment key using AES-KW. Environment keys are wrapped to browser-generated RSA-OAEP public keys; non-exportable private keys remain in IndexedDB on the enrolled device.

Convex stores ciphertext, wrapped keys, public keys, environment grants, provider metadata, and minimal audit metadata. It does not receive plaintext secret values, notes, filenames, file contents, or the WorkOS API key.

## Configure WorkOS

1. Create or select a WorkOS AuthKit application. For local development, allow the origin `http://127.0.0.1:5173`, set the redirect URI to `http://127.0.0.1:5173/callback`, and set the sign-in endpoint to `http://127.0.0.1:5173/login`.
2. Make the WorkOS API key available only to the provisioning/deployment environment. Never use a `VITE_` prefix for it.
3. Configure the Convex deployment:

```powershell
npx convex env set WORKOS_CLIENT_ID client_...
npx convex env set NEBULA_BOOTSTRAP_ADMIN_EMAIL administrator@example.com
```

4. Configure the public frontend values in `.env.local`:

```text
VITE_WORKOS_CLIENT_ID=client_...
VITE_WORKOS_REDIRECT_URI=http://127.0.0.1:5173/callback
```

The checked-in `convex.json` includes Convex AuthKit provisioning settings for local, preview, and production deployments. `npx convex dev` can provision/update AuthKit when `WORKOS_API_KEY` is available to the command. For hosted deployments, set the public `VITE_WORKOS_*` variables in Vercel and keep `WORKOS_API_KEY` secret.

## Run locally

```powershell
npm install
npm run dev
```

The combined Convex/Vite development command serves the app at [http://127.0.0.1:5173](http://127.0.0.1:5173). The first authenticated user must match `NEBULA_BOOTSTRAP_ADMIN_EMAIL` when that variable is set. That user initializes the vault as the first System Administrator and creates the browser-held encryption keys.

Additional users are invited by email from **Admin > Users & access**. On first sign-in, the exact normalized WorkOS email is linked to the invitation, after which the user enrolls a device key. A System Administrator configures provider metadata and performs staged verification from **Authentication**.

Browser-held private keys are not shared between browsers, profiles, or private windows. If a disposable workspace was initialized elsewhere, only a System Administrator can reset it from the missing-key screen. If the data matters, use the original browser; neither WorkOS nor Convex can recover the private key.

### Existing workspaces

New identity fields are optional so the schema can be deployed before accounts are linked. An existing Admin whose email matches the first WorkOS sign-in is promoted to System Administrator when no System Administrator exists. If the stored email must change, set `NEBULA_BOOTSTRAP_ADMIN_EMAIL` to the approved WorkOS email before linking. Migration inspection helpers are in `convex/migrations.ts`.

## Authentication administration

The database stores only public provider configuration: provider ID, WorkOS Client ID, redirect URI, optional allowed email domains, provisioning mode, and staged/verified/enforced state. Provider credentials remain deployment secrets.

The current provider registry contains WorkOS only. Adding another provider requires extending the provider validator and registry, adding its trusted issuer/JWKS configuration to `convex/auth.config.ts`, implementing its frontend adapter, and adding provider-specific validation. The role and UI boundaries already reserve provider changes for System Administrators.

## Validate

```powershell
npm test
npm run lint
npm run build
npx convex dev --once
```

Tests cover authenticated bootstrap, anonymous-call rejection, invitation linking, role enforcement, System Administrator-only configuration, Local-value isolation, and shared-environment grants.

## Important directories

- `convex/` — schema, authenticated access controls, provider settings, secrets, attachments, bootstrap, migrations, and audit functions
- `src/lib/crypto.ts` — Web Crypto key management and client-side encryption
- `src/App.tsx` — authenticated application screens and workflows
- `src/index.css` — responsive application styling
- `authentication-workos-implementation-plan.html` — implementation plan

## Deployment

Vercel hosts the Vite frontend, while Convex hosts the backend functions, encrypted records, access-control data, audit events, and encrypted attachments. The included `vercel.json` configures the production build and SPA fallback.

Deploy Convex separately with:

```powershell
npx convex deploy
```

Set `VITE_CONVEX_URL`, `VITE_WORKOS_CLIENT_ID`, and `VITE_WORKOS_REDIRECT_URI` in Vercel. Set `WORKOS_CLIENT_ID` and the optional bootstrap email on the production Convex deployment. Keep `WORKOS_API_KEY` and `CONVEX_DEPLOY_KEY` secret and never expose them through Vite variables.

Alternatively, Vercel can deploy both parts during its build using a production `CONVEX_DEPLOY_KEY` and this build command:

```text
npx convex deploy --cmd-url-env-var-name VITE_CONVEX_URL --cmd "npm run build"
```

## License

Nebula Secrets is available under the [MIT License](LICENSE.txt).

## Disclaimer

Use of Nebula Secrets is entirely at your own risk. To the fullest extent permitted by applicable law, the creators and contributors accept no liability for losses or damages arising from use, misuse, compromise, unavailability, or inability to use the system. See the full [project disclaimer](DISCLAIMER.md).
