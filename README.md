# Nebula Secrets

Nebula Secrets is a development-team vault built with React, Vite, and Convex. It stores Login, API Key, and License Key values per environment, with user-private Local values and shared Development, UAT, and Production values.

## MVP features

- Developer and Admin roles
- Admin-managed environment access
- User-private Local values
- Shared Development, UAT, and Production values
- Login, API Key, and License Key forms with encrypted notes
- Required shared Projects for grouping, filtering, and organizing secrets, with a protected General default
- Client-encrypted file attachments (5 MB MVP limit)
- Secret version history and archive support
- Privacy-safe audit events for changes, reveal/copy actions, attachments, and access changes
- Responsive desktop and mobile interface

## Security model

Sensitive payloads are encrypted in the browser with AES-256-GCM. Each payload has a random data key wrapped by an environment key using AES-KW. Environment keys are wrapped to browser-generated RSA-OAEP public keys; non-exportable private keys remain in IndexedDB on the enrolled device.

Convex stores ciphertext, wrapped keys, public keys, environment grants, and minimal metadata. It never receives plaintext secret values, notes, filenames, or file contents.

> **Development limitation:** authentication is intentionally deferred. The identity selector can be spoofed, so the current MVP must contain test data only. Production use requires authentication to bind sessions to user records and public keys.

## Run locally

```powershell
npm install
npm run dev
```

The combined Convex/Vite development command serves the app at [http://127.0.0.1:5173](http://127.0.0.1:5173).

On first use, initialize the workspace to create the first Admin and browser-held encryption keys. Additional users must select their development identity once to enroll a device key before an Admin can grant shared-environment access.

Browser-held private keys are not shared between Chrome, Edge, the Codex in-app browser, browser profiles, or private windows. If a disposable test workspace was initialized in another browser, select its Admin identity and use **Reset test workspace** on the missing-key screen. The reset permanently deletes all development data and lets the current browser initialize fresh keys. If the data matters, use the original browser instead.

## Validate

```powershell
npm test
npm run lint
npm run build
npx convex dev --once
```

The Convex tests cover one-time bootstrap, role enforcement, Local-value isolation, and shared-environment grants.

## Important directories

- `convex/` — schema, access controls, secrets, attachments, bootstrap, and audit functions
- `src/lib/crypto.ts` — Web Crypto key management and client-side encryption
- `src/App.tsx` — MVP screens and workflows
- `src/index.css` — responsive application styling
- `secrets-management-plan.html` — original architecture and delivery plan

## Deployment

Nebula Secrets is designed to use two managed deployment services:

- **Vercel** hosts the Vite-generated frontend and serves the single-page application.
- **Convex** hosts the backend functions, database schema, encrypted records, access-control data, audit events, and encrypted file attachments.

The included `vercel.json` configures the Vite production build, `dist` output directory, and SPA fallback. With its current `npm run build` command, deploy the Convex backend separately using:

```powershell
npx convex deploy
```

Then add `VITE_CONVEX_URL` to the Vercel project's Production environment, using the URL of the production Convex deployment. This URL is included in the browser bundle and is not a secret. Do not use the development deployment URL from `.env.local` in production.

Alternatively, Vercel can deploy both parts during its build. Create a production Convex deploy key, store it in Vercel as the sensitive Production variable `CONVEX_DEPLOY_KEY`, and change the Vercel build command to:

```text
npx convex deploy --cmd-url-env-var-name VITE_CONVEX_URL --cmd "npm run build"
```

In this configuration, Convex deploys the backend and provides `VITE_CONVEX_URL` to the frontend build automatically. Authentication is still intentionally deferred in this MVP, so a deployed instance must contain test data only until authenticated identities replace the development identity selector.

## Authentication (ToDo)

Create Authentication Admin that lets end users configure their auth provider of choice. 
The following providers are expected to be added:
- Google oAuth
- Shoo
- WorkOs
- Clerk

## License

Nebula Secrets is available under the [MIT License](LICENSE.txt).

## Disclaimer

Use of Nebula Secrets is entirely at your own risk. To the fullest extent permitted by applicable law, the creators and contributors accept no liability for losses or damages arising from use, misuse, compromise, unavailability, or inability to use the system. See the full [project disclaimer](DISCLAIMER.md).
