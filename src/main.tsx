import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ConvexReactClient } from "convex/react";
import { ConvexProviderWithAuthKit } from "@convex-dev/workos";
import { AuthKitProvider, useAuth } from "@workos-inc/authkit-react";
import "./index.css";
import App, { ParticleField, ThemeToggle } from "./App.tsx";

const convexUrl = import.meta.env.VITE_CONVEX_URL;
const workosClientId = import.meta.env.VITE_WORKOS_CLIENT_ID;
const workosRedirectUri = import.meta.env.VITE_WORKOS_REDIRECT_URI;

export function MissingAuthenticationConfiguration() {
  return (
    <main className="center-screen padded auth-configuration-required">
      <section className="panel">
        <h1>Authentication configuration required</h1>
        <p>
          Set <code>VITE_WORKOS_CLIENT_ID</code> and{" "}
          <code>VITE_WORKOS_REDIRECT_URI</code>
          in <code>.env.local</code>, then restart the development server.
        </p>
      </section>
    </main>
  );
}

if (!convexUrl || !workosClientId || !workosRedirectUri) {
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <ParticleField />
      <ThemeToggle />
      <MissingAuthenticationConfiguration />
    </StrictMode>,
  );
} else {
  const convex = new ConvexReactClient(convexUrl);
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <AuthKitProvider
        clientId={workosClientId}
        redirectUri={workosRedirectUri}
        onRedirectCallback={() => window.history.replaceState({}, "", "/")}
      >
        <ConvexProviderWithAuthKit client={convex} useAuth={useAuth}>
          <App />
        </ConvexProviderWithAuthKit>
      </AuthKitProvider>
    </StrictMode>,
  );
}
