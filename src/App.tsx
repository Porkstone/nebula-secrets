import {
  Archive,
  ArrowDownToLine,
  BadgeCheck,
  Check,
  ChevronRight,
  CircleAlert,
  Clipboard,
  Clock3,
  Code2,
  Database,
  Eye,
  EyeOff,
  FileKey2,
  FilePlus2,
  Fingerprint,
  Folder,
  FolderPlus,
  KeyRound,
  Laptop,
  LayoutGrid,
  LoaderCircle,
  LockKeyhole,
  LogIn,
  LogOut,
  Menu,
  MoreHorizontal,
  Pencil,
  Plus,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Settings,
  Trash2,
  UserPlus,
  Users,
  X,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  Authenticated,
  AuthLoading,
  Unauthenticated,
  useConvex,
  useMutation,
  useQuery,
} from "convex/react";
import { useAuth } from "@workos-inc/authkit-react";
import type { Doc, Id } from "../convex/_generated/dataModel";
import { api } from "../convex/_generated/api";
import {
  decryptAttachmentFile,
  decryptAttachmentMetadata,
  decryptPayload,
  clearDeviceKeys,
  encryptAttachment,
  encryptPayload,
  generateDeviceKeyMaterial,
  generateEnvironmentKey,
  hasDeviceKey,
  persistDeviceKey,
  secretAad,
  unwrapEnvironmentKey,
  wrapEnvironmentKey,
  type AttachmentMetadata,
  type Environment,
  type SecretPayload,
  type SecretType,
} from "./lib/crypto";

type AppUser = {
  _id: Id<"users">;
  displayName: string;
  email: string;
  role: "developer" | "admin" | "systemAdministrator";
  status: "active" | "suspended";
  hasPublicKey: boolean;
  authProvider: "workos" | null;
  isIdentityLinked: boolean;
  identityLinkedAt: number | null;
};

type SecretRow = {
  definition: Doc<"secretDefinitions">;
  value: Doc<"secretValues"> | null;
};

type DecryptedSecretRow = SecretRow & {
  decrypted: SecretPayload | null;
  decryptionError?: string;
};

const environments: Environment[] = [
  "local",
  "development",
  "uat",
  "production",
];
const environmentLabels: Record<Environment, string> = {
  local: "Local",
  development: "Development",
  uat: "UAT",
  production: "Production",
};
const secretTypeLabels: Record<SecretType, string> = {
  login: "Login",
  apiKey: "API Key",
  licenseKey: "License Key",
};

function LoadingScreen() {
  return (
    <div className="center-screen">
      <div className="loading-mark">
        <LoaderCircle className="spin" size={22} /> Preparing the vault…
      </div>
    </div>
  );
}

function ErrorNotice({ message }: { message: string }) {
  return (
    <div className="notice error">
      <CircleAlert size={17} /> {message}
    </div>
  );
}

export default function App() {
  const { isLoading, user, signIn, signOut } = useAuth();

  useEffect(() => {
    if (!isLoading && !user && window.location.pathname === "/login") {
      void signIn();
    }
  }, [isLoading, signIn, user]);

  if (isLoading) return <LoadingScreen />;
  return (
    <>
      <AuthLoading>
        <LoadingScreen />
      </AuthLoading>
      <Unauthenticated>
        <SignInScreen onSignIn={() => void signIn()} />
      </Unauthenticated>
      <Authenticated>
        <AuthenticatedApplication
          workosEmail={user?.email ?? ""}
          onSignOut={() => void signOut()}
        />
      </Authenticated>
    </>
  );
}

function SignInScreen({ onSignIn }: { onSignIn: () => void }) {
  return (
    <main className="setup-page auth-entry">
      <div className="setup-brand">
        <span className="brand-mark">
          <LockKeyhole size={20} />
        </span>
        <span>Nebula Secrets</span>
      </div>
      <section className="panel auth-card">
        <span className="icon-disc">
          <ShieldCheck size={25} />
        </span>
        <span className="eyebrow">Secure workspace access</span>
        <h1>Sign in to Nebula Secrets</h1>
        <p>
          Continue with the authentication provider configured for this
          deployment.
        </p>
        <button className="button primary" onClick={onSignIn}>
          <LogIn size={17} /> Sign in with WorkOS
        </button>
      </section>
    </main>
  );
}

function AuthenticatedApplication({
  workosEmail,
  onSignOut,
}: {
  workosEmail: string;
  onSignOut: () => void;
}) {
  const bootstrap = useQuery(api.bootstrap.state);
  if (bootstrap === undefined) return <LoadingScreen />;
  if (!bootstrap.initialized)
    return (
      <BootstrapWorkspace workosEmail={workosEmail} onSignOut={onSignOut} />
    );
  return <LinkedWorkspace onSignOut={onSignOut} />;
}

function BootstrapWorkspace({
  workosEmail,
  onSignOut,
}: {
  workosEmail: string;
  onSignOut: () => void;
}) {
  const initialize = useMutation(api.bootstrap.initialize);
  const [displayName, setDisplayName] = useState("System Administrator");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const device = await generateDeviceKeyMaterial();
      const keyEnvelopes = await Promise.all(
        environments.map(async (environment) => {
          const key = await generateEnvironmentKey();
          return {
            environment,
            wrappedKey: await wrapEnvironmentKey(key, device.publicJwk),
          };
        }),
      );
      const adminId = await initialize({
        displayName,
        publicKeyJwk: device.publicJwk,
        keyEnvelopes,
      });
      await persistDeviceKey(adminId, device);
      window.location.reload();
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Workspace setup failed.",
      );
      setBusy(false);
    }
  }

  return (
    <div className="setup-page">
      <div className="setup-brand">
        <span className="brand-mark">
          <LockKeyhole size={20} />
        </span>
        <span>Nebula Secrets</span>
      </div>
      <div className="setup-grid">
        <section className="setup-copy">
          <span className="eyebrow">
            <ShieldCheck size={15} /> End-to-end encrypted by design
          </span>
          <h1>
            Your team’s secrets,
            <br />
            without server-side plaintext.
          </h1>
          <p>
            Initialize the development workspace and its first Admin identity.
            Encryption keys are generated in this browser; Convex receives only
            public keys and encrypted key envelopes.
          </p>
          <div className="security-points">
            <span>
              <Fingerprint size={18} /> Device-held private key
            </span>
            <span>
              <Database size={18} /> Ciphertext-only backend
            </span>
            <span>
              <Shield size={18} /> Environment-scoped access
            </span>
          </div>
        </section>
        <form
          className="panel setup-form"
          onSubmit={(event) => void submit(event)}
        >
          <div>
            <span className="step-label">Workspace setup</span>
            <h2>Create the first System Administrator</h2>
            <p className="muted">
              This privileged identity will be linked to the authenticated
              WorkOS account.
            </p>
          </div>
          <label>
            Display name
            <input
              required
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
            />
          </label>
          <label>
            Authenticated email
            <input readOnly value={workosEmail} />
          </label>
          {error && <ErrorNotice message={error} />}
          <button className="button primary" disabled={busy} type="submit">
            {busy ? (
              <LoaderCircle className="spin" size={17} />
            ) : (
              <KeyRound size={17} />
            )}
            {busy ? "Generating keys…" : "Initialize encrypted vault"}
          </button>
          <button className="button ghost" type="button" onClick={onSignOut}>
            <LogOut size={16} /> Sign out
          </button>
        </form>
      </div>
    </div>
  );
}

function LinkedWorkspace({ onSignOut }: { onSignOut: () => void }) {
  const current = useQuery(api.users.current);
  const users = useQuery(api.users.listVisible, current ? {} : "skip");
  const linkIdentity = useMutation(api.users.linkCurrentIdentity);
  const linkStarted = useRef(false);
  const [linkError, setLinkError] = useState("");

  useEffect(() => {
    if (current !== null || linkStarted.current || linkError) return;
    linkStarted.current = true;
    void linkIdentity({}).catch((cause: unknown) =>
      setLinkError(
        cause instanceof Error
          ? cause.message
          : "Unable to link this identity.",
      ),
    );
  }, [current, linkError, linkIdentity]);

  if (current === undefined || (current === null && !linkError))
    return <LoadingScreen />;
  if (!current) {
    return (
      <main className="center-screen padded">
        <section className="panel access-denied">
          <span className="icon-disc warning">
            <ShieldAlert size={24} />
          </span>
          <h1>Access has not been granted</h1>
          <p>
            {linkError ||
              "Your authenticated email does not match an active Nebula invitation."}
          </p>
          <button className="button" onClick={onSignOut}>
            <LogOut size={16} /> Sign out
          </button>
        </section>
      </main>
    );
  }
  if (!users) return <LoadingScreen />;
  return (
    <DeviceGate
      key={current._id}
      user={current}
      users={users}
      onSignOut={onSignOut}
    />
  );
}

function DeviceGate({
  user,
  users,
  onSignOut,
}: {
  user: AppUser;
  users: AppUser[];
  onSignOut: () => void;
}) {
  const [deviceState, setDeviceState] = useState<
    "checking" | "ready" | "missing"
  >("checking");

  useEffect(() => {
    let cancelled = false;
    void hasDeviceKey(user._id).then((present) => {
      if (!cancelled) setDeviceState(present ? "ready" : "missing");
    });
    return () => {
      cancelled = true;
    };
  }, [user._id]);

  if (deviceState === "checking") return <LoadingScreen />;
  if (!user.hasPublicKey) {
    return <EnrollDevice user={user} onReady={() => setDeviceState("ready")} />;
  }
  if (deviceState === "missing") {
    return <MissingDeviceKey user={user} onSignOut={onSignOut} />;
  }
  return <Dashboard user={user} users={users} onSignOut={onSignOut} />;
}

function MissingDeviceKey({
  user,
  onSignOut,
}: {
  user: AppUser;
  onSignOut: () => void;
}) {
  const resetWorkspace = useMutation(api.devtools.resetWorkspace);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function resetTestWorkspace() {
    const confirmed = window.confirm(
      "Permanently delete every user, encrypted secret, attachment, access grant, and audit event in this TEST workspace? This cannot be undone.",
    );
    if (!confirmed) return;

    setBusy(true);
    setError("");
    try {
      await resetWorkspace({
        confirmation: "RESET NEBULA",
      });
      try {
        await clearDeviceKeys();
      } catch {
        // The deleted user IDs make any browser-local orphaned keys unreachable.
      }
      window.location.reload();
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Workspace reset failed.",
      );
      setBusy(false);
    }
  }

  return (
    <div className="center-screen padded">
      <div className="panel key-missing">
        <span className="icon-disc warning">
          <ShieldAlert size={24} />
        </span>
        <h2>Private key unavailable in this browser</h2>
        <p>
          This usually means the workspace was initialized in a different
          browser or profile. The matching private key never leaves that
          browser, so Convex cannot recover or reveal it.
        </p>
        <button className="button" onClick={onSignOut}>
          <LogOut size={16} /> Sign out and use another account
        </button>
        {error && <ErrorNotice message={error} />}
        {user.role === "systemAdministrator" && (
          <div className="recovery-box">
            <div>
              <strong>Disposable test data?</strong>
              <p>
                Reset the development workspace, then initialize fresh keys in
                this browser.
              </p>
            </div>
            <button
              className="button destructive"
              disabled={busy}
              onClick={() => void resetTestWorkspace()}
            >
              {busy ? (
                <LoaderCircle className="spin" size={17} />
              ) : (
                <Trash2 size={17} />
              )}
              {busy ? "Resetting workspaceâ€¦" : "Reset test workspace"}
            </button>
          </div>
        )}
        <p className="fine-print">
          If the data matters, reopen the browser that initialized this
          identity. Production recovery will require authenticated device
          approval or dual control.
        </p>
      </div>
    </div>
  );
}

function EnrollDevice({
  user,
  onReady,
}: {
  user: AppUser;
  onReady: () => void;
}) {
  const enroll = useMutation(api.users.enrollDevice);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function enrollDevice() {
    setBusy(true);
    setError("");
    try {
      const device = await generateDeviceKeyMaterial();
      const localKey = await generateEnvironmentKey();
      const localKeyEnvelope = await wrapEnvironmentKey(
        localKey,
        device.publicJwk,
      );
      await enroll({ publicKeyJwk: device.publicJwk, localKeyEnvelope });
      await persistDeviceKey(user._id, device);
      onReady();
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Device enrollment failed.",
      );
      setBusy(false);
    }
  }

  return (
    <div className="center-screen padded">
      <div className="panel device-enroll">
        <span className="icon-disc">
          <Laptop size={25} />
        </span>
        <span className="eyebrow">First use on this device</span>
        <h2>Enroll a key for {user.displayName}</h2>
        <p>
          This creates a browser-held private key and a personal Local
          environment key. The private key is stored as a non-exportable Web
          Crypto key.
        </p>
        {error && <ErrorNotice message={error} />}
        <button
          className="button primary"
          onClick={() => void enrollDevice()}
          disabled={busy}
        >
          {busy ? (
            <LoaderCircle className="spin" size={17} />
          ) : (
            <Fingerprint size={17} />
          )}
          {busy ? "Creating secure key…" : "Enroll this device"}
        </button>
      </div>
    </div>
  );
}

function Dashboard({
  user,
  users,
  onSignOut,
}: {
  user: AppUser;
  users: AppUser[];
  onSignOut: () => void;
}) {
  const access = useQuery(api.access.listMine, {});
  const [section, setSection] = useState<
    "vault" | "admin" | "authentication" | "audit"
  >("vault");
  const [environment, setEnvironment] = useState<Environment>("local");
  const [mobileNav, setMobileNav] = useState(false);

  const allowedEnvironments = useMemo(
    () =>
      environments.filter(
        (item) => access?.find((entry) => entry.environment === item)?.granted,
      ),
    [access],
  );

  return (
    <div className="app-shell">
      <aside className={mobileNav ? "sidebar open" : "sidebar"}>
        <div className="brand">
          <span className="brand-mark">
            <LockKeyhole size={18} />
          </span>
          <span>
            Nebula <strong>Secrets</strong>
          </span>
        </div>
        <nav>
          <button
            className={section === "vault" ? "nav-item active" : "nav-item"}
            onClick={() => {
              setSection("vault");
              setMobileNav(false);
            }}
          >
            <LayoutGrid size={18} /> Vault
          </button>
          {user.role !== "developer" && (
            <button
              className={section === "admin" ? "nav-item active" : "nav-item"}
              onClick={() => {
                setSection("admin");
                setMobileNav(false);
              }}
            >
              <Users size={18} /> Admin
            </button>
          )}
          {user.role === "systemAdministrator" && (
            <button
              className={
                section === "authentication" ? "nav-item active" : "nav-item"
              }
              onClick={() => {
                setSection("authentication");
                setMobileNav(false);
              }}
            >
              <Settings size={18} /> Authentication
            </button>
          )}
          <button
            className={section === "audit" ? "nav-item active" : "nav-item"}
            onClick={() => {
              setSection("audit");
              setMobileNav(false);
            }}
          >
            <Clock3 size={18} /> Audit log
          </button>
        </nav>
        <div className="sidebar-security">
          <ShieldCheck size={18} />
          <div>
            <strong>Client encrypted</strong>
            <span>Convex stores ciphertext</span>
          </div>
        </div>
      </aside>

      <div className="main-shell">
        <header className="topbar">
          <button
            className="icon-button mobile-menu"
            aria-label="Open navigation"
            onClick={() => setMobileNav((value) => !value)}
          >
            <Menu size={20} />
          </button>
          <div className="topbar-title">
            <span>
              {section === "vault"
                ? "Secrets vault"
                : section === "admin"
                  ? "Administration"
                  : section === "authentication"
                    ? "Authentication"
                    : "Audit activity"}
            </span>
            {section === "vault" && (
              <small>{environmentLabels[environment]} environment</small>
            )}
          </div>
          <div className="signed-in-user">
            <span className="avatar">
              {user.displayName.slice(0, 2).toUpperCase()}
            </span>
            <span>
              <strong>{user.displayName}</strong>
              <small>
                {user.role === "systemAdministrator"
                  ? "System Administrator"
                  : user.role === "admin"
                    ? "Admin"
                    : "Developer"}
              </small>
            </span>
            <button
              className="icon-button"
              aria-label="Sign out"
              title="Sign out"
              onClick={onSignOut}
            >
              <LogOut size={17} />
            </button>
          </div>
        </header>

        <main className="workspace-main">
          {section === "vault" && (
            <Vault
              user={user}
              environment={environment}
              allowedEnvironments={allowedEnvironments}
              onEnvironmentChange={setEnvironment}
            />
          )}
          {section === "admin" && user.role !== "developer" && (
            <AdminArea user={user} />
          )}
          {section === "authentication" &&
            user.role === "systemAdministrator" && <AuthenticationAdmin />}
          {section === "audit" && <AuditLog user={user} users={users} />}
        </main>
      </div>
    </div>
  );
}

function useEnvironmentKey(
  userId: Id<"users">,
  environment: Environment,
  allowed: boolean,
) {
  const envelope = useQuery(
    api.access.getKeyEnvelope,
    allowed ? { environment } : "skip",
  );
  const [state, setState] = useState<{
    source: string | null;
    key: CryptoKey | null;
    error: string;
  }>(() => ({ source: null, key: null, error: "" }));

  useEffect(() => {
    let cancelled = false;
    if (!envelope)
      return () => {
        cancelled = true;
      };
    void unwrapEnvironmentKey(userId, envelope.wrappedKey)
      .then((key) => {
        if (!cancelled)
          setState({ source: envelope.wrappedKey, key, error: "" });
      })
      .catch((cause: unknown) => {
        if (!cancelled)
          setState({
            source: envelope.wrappedKey,
            key: null,
            error:
              cause instanceof Error
                ? cause.message
                : "Unable to unlock environment.",
          });
      });
    return () => {
      cancelled = true;
    };
  }, [envelope, environment, userId]);

  const current = envelope && state.source === envelope.wrappedKey;
  return {
    environmentKey: current ? state.key : null,
    keyError: current ? state.error : "",
    loading: allowed && envelope === undefined,
  };
}

function Vault({
  user,
  environment,
  allowedEnvironments,
  onEnvironmentChange,
}: {
  user: AppUser;
  environment: Environment;
  allowedEnvironments: Environment[];
  onEnvironmentChange: (environment: Environment) => void;
}) {
  const allowed = allowedEnvironments.includes(environment);
  const { environmentKey, keyError } = useEnvironmentKey(
    user._id,
    environment,
    allowed,
  );
  const rows = useQuery(
    api.secrets.list,
    environmentKey ? { environment } : "skip",
  );
  const projects = useQuery(api.projects.list, {});
  const archiveSecret = useMutation(api.secrets.setArchiveStatus);
  const [decryptedState, setDecryptedState] = useState<{
    token: string;
    rows: DecryptedSecretRow[];
  }>({ token: "", rows: [] });
  const [search, setSearch] = useState("");
  const [projectFilter, setProjectFilter] = useState("all");
  const [showProjects, setShowProjects] = useState(false);
  const [editorRow, setEditorRow] = useState<SecretRow | "new" | null>(null);
  const [detailSecretId, setDetailSecretId] =
    useState<Id<"secretDefinitions"> | null>(null);
  const [message, setMessage] = useState("");

  useEffect(() => {
    let cancelled = false;
    if (!rows || !environmentKey)
      return () => {
        cancelled = true;
      };
    const token = `${environment}:${rows.map((row) => `${row.definition._id}:${row.value?.version ?? 0}`).join("|")}`;
    void Promise.all(
      rows.map(async (row): Promise<DecryptedSecretRow> => {
        if (!row.value) return { ...row, decrypted: null };
        try {
          const decrypted = await decryptPayload<SecretPayload>(
            row.value.payload,
            environmentKey,
            secretAad({
              cryptoId: row.definition.cryptoId,
              environment,
              owner: environment === "local" ? user._id : "shared",
              type: row.definition.type,
              version: row.value.version,
            }),
          );
          return { ...row, decrypted };
        } catch {
          return {
            ...row,
            decrypted: null,
            decryptionError: "Integrity check failed",
          };
        }
      }),
    ).then((result) => {
      if (!cancelled) setDecryptedState({ token, rows: result });
    });
    return () => {
      cancelled = true;
    };
  }, [rows, environmentKey, environment, user._id]);

  const decryptionToken = rows
    ? `${environment}:${rows.map((row) => `${row.definition._id}:${row.value?.version ?? 0}`).join("|")}`
    : "";
  const decryptedRows = useMemo(
    () => (decryptedState.token === decryptionToken ? decryptedState.rows : []),
    [decryptedState, decryptionToken],
  );

  const projectById = useMemo(
    () => new Map((projects ?? []).map((project) => [project._id, project])),
    [projects],
  );
  const generalProjectId = projects?.find(
    (project) => project.normalizedName === "general",
  )?._id;
  const visibleRows = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return decryptedRows.filter((row) => {
      const rowProjectId =
        row.definition.projectId ?? generalProjectId ?? "general";
      if (projectFilter !== "all" && rowProjectId !== projectFilter)
        return false;
      if (!needle) return true;
      const projectName = row.definition.projectId
        ? (projectById.get(row.definition.projectId)?.name ?? "")
        : "General";
      return `${row.definition.name} ${secretTypeLabels[row.definition.type]} ${projectName}`
        .toLowerCase()
        .includes(needle);
    });
  }, [decryptedRows, generalProjectId, projectById, projectFilter, search]);
  const groupedRows = useMemo(() => {
    const groups = new Map<
      string,
      { id: string; name: string; rows: DecryptedSecretRow[] }
    >();
    for (const row of visibleRows) {
      const id = row.definition.projectId ?? generalProjectId ?? "general";
      const name = row.definition.projectId
        ? (projectById.get(row.definition.projectId)?.name ??
          "Archived project")
        : "General";
      const group = groups.get(id) ?? { id, name, rows: [] };
      group.rows.push(row);
      groups.set(id, group);
    }
    return [...groups.values()].sort((left, right) => {
      return left.name.localeCompare(right.name);
    });
  }, [generalProjectId, projectById, visibleRows]);
  const detailRow =
    decryptedRows.find((row) => row.definition._id === detailSecretId) ?? null;

  async function archive(row: DecryptedSecretRow) {
    if (!window.confirm(`Archive “${row.definition.name}”?`)) return;
    await archiveSecret({
      secretId: row.definition._id,
      environment,
      archived: true,
    });
    setDetailSecretId(null);
    setMessage("Secret archived.");
  }

  return (
    <>
      <div className="environment-tabs" aria-label="Environment">
        {environments.map((item) => {
          const enabled = allowedEnvironments.includes(item);
          return (
            <button
              key={item}
              disabled={!enabled}
              className={environment === item ? "active" : ""}
              onClick={() => enabled && onEnvironmentChange(item)}
            >
              {environmentLabels[item]}
              {!enabled && <LockKeyhole size={12} />}
            </button>
          );
        })}
      </div>

      {keyError ? (
        <ErrorNotice message={keyError} />
      ) : !allowed ? (
        <EmptyState
          icon={<ShieldAlert />}
          title="Environment access required"
          body="An Admin must grant this identity access and wrap the environment key to its enrolled public key."
        />
      ) : !environmentKey || !rows || !projects ? (
        <LoadingPanel />
      ) : (
        <>
          <div className="page-actions">
            <div>
              <h1>{environmentLabels[environment]} secrets</h1>
              <p>
                {environment === "local"
                  ? "Private values encrypted for this development identity."
                  : "Shared values for everyone granted this environment."}
              </p>
            </div>
            <div className="page-buttons">
              <button className="button" onClick={() => setShowProjects(true)}>
                <FolderPlus size={17} /> Projects
              </button>
              <button
                className="button primary"
                onClick={() => setEditorRow("new")}
              >
                <Plus size={17} /> New secret
              </button>
            </div>
          </div>
          <div className="toolbar">
            <label className="search-box">
              <Search size={17} />
              <input
                aria-label="Search secrets"
                placeholder="Search secrets…"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
            </label>
            <label className="project-filter">
              <span>Project</span>
              <select
                aria-label="Filter by project"
                value={projectFilter}
                onChange={(event) => setProjectFilter(event.target.value)}
              >
                <option value="all">All projects</option>
                {projects.map((project) => (
                  <option key={project._id} value={project._id}>
                    {project.name}
                  </option>
                ))}
              </select>
            </label>
            <span className="result-count">
              {visibleRows.length}{" "}
              {visibleRows.length === 1 ? "secret" : "secrets"}
            </span>
          </div>
          {message && (
            <div className="notice success">
              <Check size={16} /> {message}
              <button aria-label="Dismiss" onClick={() => setMessage("")}>
                <X size={14} />
              </button>
            </div>
          )}
          {visibleRows.length === 0 ? (
            <EmptyState
              icon={<KeyRound />}
              title={search ? "No matching secrets" : "No secrets here yet"}
              body={
                search
                  ? "Try a different search term."
                  : "Create a typed secret and its encrypted value for this environment."
              }
              action={
                !search ? (
                  <button
                    className="button"
                    onClick={() => setEditorRow("new")}
                  >
                    <Plus size={16} /> Create first secret
                  </button>
                ) : undefined
              }
            />
          ) : (
            <div className="project-groups">
              {groupedRows.map((group) => (
                <section className="project-group" key={group.id}>
                  <header>
                    <span>
                      <Folder size={16} /> {group.name}
                    </span>
                    <small>
                      {group.rows.length}{" "}
                      {group.rows.length === 1 ? "secret" : "secrets"}
                    </small>
                  </header>
                  <div className="secret-list">
                    {group.rows.map((row) => (
                      <button
                        className="secret-row"
                        key={row.definition._id}
                        onClick={() =>
                          row.value
                            ? setDetailSecretId(row.definition._id)
                            : setEditorRow(row)
                        }
                      >
                        <span className={`secret-icon ${row.definition.type}`}>
                          <SecretIcon type={row.definition.type} />
                        </span>
                        <span className="secret-title">
                          <strong>{row.definition.name}</strong>
                          <small>
                            {secretTypeLabels[row.definition.type]} ·{" "}
                            {row.value
                              ? `Version ${row.value.version}`
                              : "No value in this environment"}
                          </small>
                        </span>
                        <span
                          className={
                            row.decryptionError
                              ? "status-chip danger"
                              : row.value
                                ? "status-chip"
                                : "status-chip muted-chip"
                          }
                        >
                          {row.decryptionError
                            ? "Integrity error"
                            : row.value
                              ? "Encrypted"
                              : "Not set"}
                        </span>
                        <ChevronRight size={17} className="row-chevron" />
                      </button>
                    ))}
                  </div>
                </section>
              ))}
            </div>
          )}
        </>
      )}

      {editorRow && environmentKey && (
        <SecretEditor
          user={user}
          environment={environment}
          environmentKey={environmentKey}
          row={editorRow === "new" ? null : editorRow}
          projects={projects ?? []}
          decrypted={
            editorRow === "new"
              ? null
              : (decryptedRows.find(
                  (item) => item.definition._id === editorRow.definition._id,
                )?.decrypted ?? null)
          }
          onClose={() => setEditorRow(null)}
          onSaved={() => {
            setEditorRow(null);
            setMessage("Encrypted secret saved.");
          }}
        />
      )}
      {detailRow && environmentKey && (
        <SecretDetail
          environment={environment}
          environmentKey={environmentKey}
          row={detailRow}
          projectName={
            detailRow.definition.projectId
              ? projectById.get(detailRow.definition.projectId)?.name
              : undefined
          }
          onClose={() => setDetailSecretId(null)}
          onEdit={() => {
            setEditorRow(detailRow);
            setDetailSecretId(null);
          }}
          onArchive={() => void archive(detailRow)}
        />
      )}
      {showProjects && projects && (
        <ProjectManager
          projects={projects}
          onClose={() => setShowProjects(false)}
        />
      )}
    </>
  );
}

function ProjectManager({
  projects,
  onClose,
}: {
  projects: Doc<"projects">[];
  onClose: () => void;
}) {
  const createProject = useMutation(api.projects.create);
  const renameProject = useMutation(api.projects.rename);
  const archiveProject = useMutation(api.projects.archive);
  const [editingId, setEditingId] = useState<Id<"projects"> | null>(null);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  function resetForm() {
    setEditingId(null);
    setName("");
    setError("");
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (editingId) {
        await renameProject({ projectId: editingId, name });
      } else {
        await createProject({ name });
      }
      resetForm();
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Unable to save the project.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function archive(project: Doc<"projects">) {
    if (!window.confirm(`Archive project “${project.name}”?`)) return;
    setError("");
    try {
      await archiveProject({ projectId: project._id });
      if (editingId === project._id) resetForm();
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Unable to archive the project.",
      );
    }
  }

  const sortedProjects = [...projects].sort((left, right) =>
    left.name.localeCompare(right.name),
  );
  return (
    <Modal
      title="Projects"
      subtitle="Organize every secret into a shared project group."
      onClose={onClose}
    >
      <div className="project-manager">
        <form className="project-form" onSubmit={(event) => void submit(event)}>
          <label>
            {editingId ? "Rename project" : "New project"}
            <input
              autoFocus
              required
              maxLength={80}
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="e.g. Customer portal"
            />
          </label>
          <div className="project-form-actions">
            {editingId && (
              <button
                type="button"
                className="button ghost"
                onClick={resetForm}
              >
                Cancel
              </button>
            )}
            <button className="button primary" disabled={busy} type="submit">
              {busy ? (
                <LoaderCircle className="spin" size={16} />
              ) : (
                <FolderPlus size={16} />
              )}
              {editingId ? "Save name" : "Create project"}
            </button>
          </div>
        </form>
        {error && <ErrorNotice message={error} />}
        {sortedProjects.length === 0 ? (
          <p className="project-empty">
            No projects yet. Secrets can remain ungrouped.
          </p>
        ) : (
          <div className="project-list">
            {sortedProjects.map((project) => (
              <div className="project-item" key={project._id}>
                <span className="project-icon">
                  <Folder size={17} />
                </span>
                <strong>{project.name}</strong>
                {project.normalizedName === "general" ? (
                  <span className="status-chip muted-chip">Default</span>
                ) : (
                  <button
                    className="icon-button"
                    aria-label={`Rename ${project.name}`}
                    onClick={() => {
                      setEditingId(project._id);
                      setName(project.name);
                      setError("");
                    }}
                  >
                    <Pencil size={16} />
                  </button>
                )}
                {project.normalizedName === "general" ? (
                  <span />
                ) : (
                  <button
                    className="icon-button danger-button"
                    aria-label={`Archive ${project.name}`}
                    onClick={() => void archive(project)}
                  >
                    <Archive size={16} />
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
        <p className="fine-print">
          General is the protected default project. Project names are
          organizational metadata stored in Convex; secret values and notes
          remain client encrypted.
        </p>
      </div>
    </Modal>
  );
}

function SecretIcon({ type }: { type: SecretType }) {
  if (type === "login") return <LogIn size={19} />;
  if (type === "apiKey") return <Code2 size={19} />;
  return <BadgeCheck size={19} />;
}

function SecretEditor({
  user,
  environment,
  environmentKey,
  row,
  projects,
  decrypted,
  onClose,
  onSaved,
}: {
  user: AppUser;
  environment: Environment;
  environmentKey: CryptoKey;
  row: SecretRow | null;
  projects: Doc<"projects">[];
  decrypted: SecretPayload | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const save = useMutation(api.secrets.save);
  const [name, setName] = useState(row?.definition.name ?? "");
  const [type, setType] = useState<SecretType>(row?.definition.type ?? "login");
  const [projectId, setProjectId] = useState<Id<"projects"> | "">(
    row?.definition.projectId ??
      projects.find((project) => project.normalizedName === "general")?._id ??
      projects[0]?._id ??
      "",
  );
  const [payload, setPayload] = useState<SecretPayload>(
    decrypted ?? { notes: "" },
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const title = row?.value
    ? "Edit secret value"
    : row
      ? `Set ${environmentLabels[environment]} value`
      : "Create secret";

  function field(name: keyof SecretPayload, value: string) {
    setPayload((current) => ({ ...current, [name]: value }));
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const cryptoId = row?.definition.cryptoId ?? crypto.randomUUID();
      const version = (row?.value?.version ?? 0) + 1;
      const encrypted = await encryptPayload(
        payload,
        environmentKey,
        secretAad({
          cryptoId,
          environment,
          owner: environment === "local" ? user._id : "shared",
          type,
          version,
        }),
      );
      await save({
        environment,
        secretId: row?.definition._id,
        projectId: projectId || undefined,
        cryptoId,
        name,
        type,
        payload: encrypted,
        expectedVersion: row?.value?.version,
      });
      onSaved();
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Unable to save the secret.",
      );
      setBusy(false);
    }
  }

  return (
    <Modal
      title={title}
      subtitle={`${environmentLabels[environment]} · encrypted before upload`}
      onClose={onClose}
    >
      <form className="secret-form" onSubmit={(event) => void submit(event)}>
        <div className="form-grid two">
          <label>
            Display name
            <input
              autoFocus
              required
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="e.g. Stripe dashboard"
            />
          </label>
          <label>
            Secret type
            <select
              value={type}
              disabled={Boolean(row)}
              onChange={(event) => {
                setType(event.target.value as SecretType);
                setPayload({ notes: payload.notes });
              }}
            >
              <option value="login">Login</option>
              <option value="apiKey">API Key</option>
              <option value="licenseKey">License Key</option>
            </select>
          </label>
          <label className="wide">
            Project
            <select
              required
              value={projectId}
              onChange={(event) =>
                setProjectId(event.target.value as Id<"projects">)
              }
            >
              {projects.map((project) => (
                <option key={project._id} value={project._id}>
                  {project.name}
                </option>
              ))}
            </select>
          </label>
        </div>
        {type === "login" && (
          <div className="form-grid two">
            <label>
              Username
              <input
                value={payload.username ?? ""}
                onChange={(event) => field("username", event.target.value)}
                autoComplete="off"
              />
            </label>
            <label>
              Password
              <input
                required
                type="password"
                value={payload.password ?? ""}
                onChange={(event) => field("password", event.target.value)}
                autoComplete="new-password"
              />
            </label>
            <label className="wide">
              Sign-in URL
              <input
                type="url"
                value={payload.url ?? ""}
                onChange={(event) => field("url", event.target.value)}
                placeholder="https://"
              />
            </label>
          </div>
        )}
        {type === "apiKey" && (
          <div className="form-grid two">
            <label className="wide">
              API key or token
              <input
                required
                type="password"
                value={payload.apiKey ?? ""}
                onChange={(event) => field("apiKey", event.target.value)}
                autoComplete="off"
              />
            </label>
            <label>
              Endpoint
              <input
                value={payload.endpoint ?? ""}
                onChange={(event) => field("endpoint", event.target.value)}
                placeholder="https://api.example.com"
              />
            </label>
          </div>
        )}
        {type === "licenseKey" && (
          <div className="form-grid two">
            <label className="wide">
              License key
              <input
                required
                type="password"
                value={payload.licenseKey ?? ""}
                onChange={(event) => field("licenseKey", event.target.value)}
                autoComplete="off"
              />
            </label>
            <label>
              Licensee
              <input
                value={payload.licensee ?? ""}
                onChange={(event) => field("licensee", event.target.value)}
              />
            </label>
            <label>
              Expiry date
              <input
                type="date"
                value={payload.expiresAt ?? ""}
                onChange={(event) => field("expiresAt", event.target.value)}
              />
            </label>
          </div>
        )}
        <label>
          Notes
          <textarea
            rows={5}
            value={payload.notes}
            onChange={(event) => field("notes", event.target.value)}
            placeholder="Encrypted notes, setup context, renewal details…"
          />
        </label>
        <div className="encryption-note">
          <ShieldCheck size={17} />
          <span>
            Values and notes are encrypted locally with AES-256-GCM. Convex
            receives ciphertext only.
          </span>
        </div>
        {error && <ErrorNotice message={error} />}
        <div className="modal-actions">
          <button type="button" className="button ghost" onClick={onClose}>
            Cancel
          </button>
          <button className="button primary" type="submit" disabled={busy}>
            {busy ? (
              <LoaderCircle className="spin" size={17} />
            ) : (
              <LockKeyhole size={17} />
            )}
            {busy ? "Encrypting…" : "Encrypt & save"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function SecretDetail({
  environment,
  environmentKey,
  row,
  projectName,
  onClose,
  onEdit,
  onArchive,
}: {
  environment: Environment;
  environmentKey: CryptoKey;
  row: DecryptedSecretRow;
  projectName?: string;
  onClose: () => void;
  onEdit: () => void;
  onArchive: () => void;
}) {
  const recordSecretAction = useMutation(api.audit.recordSecretAction);
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState("");
  const payload = row.decrypted;
  const sensitiveFields =
    row.definition.type === "login"
      ? [
          { label: "Username", value: payload?.username ?? "" },
          {
            label: "Password",
            value: payload?.password ?? "",
            sensitive: true,
          },
          { label: "Sign-in URL", value: payload?.url ?? "" },
        ]
      : row.definition.type === "apiKey"
        ? [
            { label: "API key", value: payload?.apiKey ?? "", sensitive: true },
            { label: "Endpoint", value: payload?.endpoint ?? "" },
          ]
        : [
            {
              label: "License key",
              value: payload?.licenseKey ?? "",
              sensitive: true,
            },
            { label: "Licensee", value: payload?.licensee ?? "" },
            { label: "Expires", value: payload?.expiresAt ?? "" },
          ];

  async function copy(label: string, value: string) {
    await navigator.clipboard.writeText(value);
    if (row.value) {
      await recordSecretAction({
        secretValueId: row.value._id,
        action: "secret.copied",
        context: label,
      });
    }
    setCopied(label);
    window.setTimeout(() => setCopied(""), 1800);
  }

  return (
    <Modal
      title={row.definition.name}
      subtitle={`${projectName ? `${projectName} · ` : ""}${secretTypeLabels[row.definition.type]} · ${environmentLabels[environment]} · v${row.value?.version ?? 0}`}
      onClose={onClose}
      wide
    >
      {row.decryptionError || !payload || !row.value ? (
        <ErrorNotice
          message={
            row.decryptionError ?? "This encrypted value is unavailable."
          }
        />
      ) : (
        <div className="detail-content">
          <div className="detail-toolbar">
            <span className="status-chip">
              <ShieldCheck size={13} /> Integrity verified
            </span>
            <div>
              <button
                className="button ghost small"
                onClick={() => {
                  if (!revealed)
                    void recordSecretAction({
                      secretValueId: row.value!._id,
                      action: "secret.revealed",
                    });
                  setRevealed((value) => !value);
                }}
              >
                {revealed ? <EyeOff size={15} /> : <Eye size={15} />}
                {revealed ? "Hide" : "Reveal"}
              </button>
              <button
                className="icon-button"
                aria-label="Edit secret"
                onClick={onEdit}
              >
                <Pencil size={17} />
              </button>
              <button
                className="icon-button danger-button"
                aria-label="Archive secret"
                onClick={onArchive}
              >
                <Archive size={17} />
              </button>
            </div>
          </div>
          <div className="secret-fields">
            {sensitiveFields
              .filter((item) => item.value)
              .map((item) => (
                <div className="secret-field" key={item.label}>
                  <span>{item.label}</span>
                  <strong>
                    {item.sensitive && !revealed
                      ? "••••••••••••••••"
                      : item.value}
                  </strong>
                  <button
                    className="icon-button"
                    aria-label={`Copy ${item.label}`}
                    onClick={() => void copy(item.label, item.value)}
                  >
                    {copied === item.label ? (
                      <Check size={16} />
                    ) : (
                      <Clipboard size={16} />
                    )}
                  </button>
                </div>
              ))}
          </div>
          <div className="notes-block">
            <span>Notes</span>
            <p>{payload.notes || "No notes added."}</p>
          </div>
          <AttachmentSection
            environmentKey={environmentKey}
            secretValueId={row.value._id}
          />
          <VersionHistory secretValue={row.value} />
        </div>
      )}
    </Modal>
  );
}

function AttachmentSection({
  environmentKey,
  secretValueId,
}: {
  environmentKey: CryptoKey;
  secretValueId: Id<"secretValues">;
}) {
  const convex = useConvex();
  const attachments = useQuery(api.attachments.list, { secretValueId });
  const generateUploadUrl = useMutation(api.attachments.generateUploadUrl);
  const commit = useMutation(api.attachments.commit);
  const remove = useMutation(api.attachments.remove);
  const [metadata, setMetadata] = useState<Record<string, AttachmentMetadata>>(
    {},
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  useEffect(() => {
    let cancelled = false;
    if (!attachments)
      return () => {
        cancelled = true;
      };
    void Promise.all(
      attachments.map(
        async (attachment) =>
          [
            attachment._id,
            await decryptAttachmentMetadata(
              attachment.encryptedMetadata,
              environmentKey,
              attachment.cryptoId,
              secretValueId,
            ),
          ] as const,
      ),
    )
      .then((items) => {
        if (!cancelled) setMetadata(Object.fromEntries(items));
      })
      .catch(() => {
        if (!cancelled)
          setError(
            "One or more attachment metadata records failed integrity checks.",
          );
      });
    return () => {
      cancelled = true;
    };
  }, [attachments, environmentKey, secretValueId]);

  async function upload(file: File) {
    if (file.size > 5 * 1024 * 1024) {
      setError("Attachments are limited to 5 MB in the MVP.");
      return;
    }
    setBusy(true);
    setError("");
    setSuccess("");
    try {
      const cryptoId = crypto.randomUUID();
      const encrypted = await encryptAttachment(
        file,
        environmentKey,
        cryptoId,
        secretValueId,
      );
      const uploadUrl = await generateUploadUrl({ secretValueId });
      const response = await fetch(uploadUrl, {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream" },
        body: encrypted.encryptedBlob,
      });
      if (!response.ok) throw new Error("Encrypted upload failed.");
      const result = (await response.json()) as { storageId: Id<"_storage"> };
      await commit({
        secretValueId,
        cryptoId,
        storageId: result.storageId,
        encryptedMetadata: encrypted.encryptedMetadata,
        fileIv: encrypted.fileIv,
        encryptedSize: encrypted.encryptedBlob.size,
      });
      setSuccess("Encrypted attachment uploaded.");
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Attachment upload failed.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function download(attachmentId: Id<"attachments">) {
    setBusy(true);
    setError("");
    setSuccess("");
    try {
      const attachment = await convex.mutation(api.attachments.getDownload, {
        attachmentId,
      });
      const meta = metadata[attachmentId];
      if (!meta) throw new Error("Attachment metadata is not ready.");
      const response = await fetch(attachment.url);
      const plaintext = await decryptAttachmentFile({
        encryptedBytes: await response.arrayBuffer(),
        encryptedMetadata: attachment.encryptedMetadata,
        fileIv: attachment.fileIv,
        environmentKey,
        cryptoId: attachment.cryptoId,
        secretValueId: attachment.secretValueId,
      });
      const url = URL.createObjectURL(
        new Blob([plaintext], { type: meta.mimeType }),
      );
      const link = document.createElement("a");
      link.href = url;
      link.download = meta.name;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
      setSuccess("Attachment decrypted and download started.");
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Attachment download failed.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="detail-section">
      <div className="section-heading">
        <div>
          <h3>Encrypted attachments</h3>
          <p>File contents and filenames are encrypted before upload.</p>
        </div>
        <label className={busy ? "button small disabled" : "button small"}>
          <FilePlus2 size={15} /> Add file
          <input
            className="sr-only"
            type="file"
            disabled={busy}
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void upload(file);
              event.currentTarget.value = "";
            }}
          />
        </label>
      </div>
      {error && <ErrorNotice message={error} />}
      {success && (
        <div className="notice success">
          <Check size={16} /> {success}
        </div>
      )}
      {!attachments ? (
        <div className="inline-loading">
          <LoaderCircle className="spin" size={15} /> Loading attachments…
        </div>
      ) : attachments.length === 0 ? (
        <p className="muted compact">No files attached.</p>
      ) : (
        <div className="attachment-list">
          {attachments.map((attachment) => {
            const meta = metadata[attachment._id];
            return (
              <div className="attachment-row" key={attachment._id}>
                <span className="file-icon">
                  <FileKey2 size={17} />
                </span>
                <span>
                  <strong>{meta?.name ?? "Decrypting filename…"}</strong>
                  <small>
                    {meta
                      ? formatBytes(meta.originalSize)
                      : "Encrypted attachment"}
                  </small>
                </span>
                <button
                  className="icon-button"
                  disabled={busy || !meta}
                  aria-label="Download attachment"
                  onClick={() => void download(attachment._id)}
                >
                  <ArrowDownToLine size={16} />
                </button>
                <button
                  className="icon-button danger-button"
                  disabled={busy}
                  aria-label="Delete attachment"
                  onClick={() => {
                    if (window.confirm("Delete this encrypted attachment?"))
                      void remove({ attachmentId: attachment._id });
                  }}
                >
                  <Trash2 size={16} />
                </button>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

function VersionHistory({ secretValue }: { secretValue: Doc<"secretValues"> }) {
  const versions = useQuery(api.secrets.listVersions, {
    secretValueId: secretValue._id,
  });
  return (
    <section className="detail-section">
      <div className="section-heading">
        <div>
          <h3>Version history</h3>
          <p>
            Previous encrypted payloads are retained for audit and recovery.
          </p>
        </div>
      </div>
      {!versions ? (
        <div className="inline-loading">
          <LoaderCircle className="spin" size={15} /> Loading versions…
        </div>
      ) : (
        <div className="version-list">
          {versions.map((version) => (
            <div key={`${version.version}-${version.changedAt}`}>
              <span>v{version.version}</span>
              <strong>
                {version.current ? "Current version" : "Previous version"}
              </strong>
              <small>{new Date(version.changedAt).toLocaleString()}</small>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function AuthenticationAdmin() {
  const settings = useQuery(api.authSettings.getForSystemAdministrator, {});
  const saveConfiguration = useMutation(api.authSettings.save);
  const verifyConfiguration = useMutation(api.authSettings.verify);
  const enforceConfiguration = useMutation(api.authSettings.enforce);
  const [draft, setDraft] = useState<{
    provider: "workos";
    clientId: string;
    redirectUri: string;
    domains: string;
  } | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const configuration = settings?.configuration;
  const provider = draft?.provider ?? configuration?.provider ?? "workos";
  const clientId = draft?.clientId ?? configuration?.clientId ?? "";
  const redirectUri =
    draft?.redirectUri ??
    configuration?.redirectUri ??
    import.meta.env.VITE_WORKOS_REDIRECT_URI ??
    "http://127.0.0.1:5173/callback";
  const domains =
    draft?.domains ?? configuration?.allowedEmailDomains.join("\n") ?? "";

  function updateDraft(change: Partial<NonNullable<typeof draft>>) {
    setDraft({ provider, clientId, redirectUri, domains, ...change });
  }

  async function run(action: "save" | "verify" | "enforce") {
    setBusy(action);
    setError("");
    setMessage("");
    try {
      if (action === "save") {
        await saveConfiguration({
          provider,
          clientId,
          redirectUri,
          allowedEmailDomains: domains
            .split(/[\n,]/)
            .map((domain) => domain.trim())
            .filter(Boolean),
        });
        setDraft(null);
        setMessage("Authentication settings saved in staged state.");
      } else if (action === "verify") {
        await verifyConfiguration({});
        setMessage(
          "The WorkOS session and deployment Client ID were verified.",
        );
      } else {
        await enforceConfiguration({});
        setMessage("WorkOS authentication is enforced for this workspace.");
      }
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Authentication configuration failed.",
      );
    } finally {
      setBusy("");
    }
  }

  if (!settings) return <LoadingPanel />;
  const state = settings.configuration?.state ?? "not configured";

  return (
    <>
      <div className="page-actions">
        <div>
          <h1>Authentication provider</h1>
          <p>
            Select and validate the identity provider used to authenticate every
            Nebula request.
          </p>
        </div>
        <span className={`status-chip auth-state ${state}`}>{state}</span>
      </div>

      <div className="auth-settings-grid">
        <form
          className="panel auth-provider-form"
          onSubmit={(event) => {
            event.preventDefault();
            void run("save");
          }}
        >
          <div className="section-heading">
            <div>
              <h2>Provider settings</h2>
              <p>
                Only public provider metadata is stored here. WorkOS API keys
                remain deployment secrets.
              </p>
            </div>
          </div>
          <label>
            Provider
            <select
              value={provider}
              onChange={(event) =>
                updateDraft({ provider: event.target.value as "workos" })
              }
            >
              {settings.supportedProviders.map((candidate) => (
                <option
                  key={candidate.id}
                  value={candidate.id}
                  disabled={!candidate.available}
                >
                  {candidate.name}
                </option>
              ))}
            </select>
          </label>
          <div className="provider-summary">
            <BadgeCheck size={18} />
            <span>
              <strong>WorkOS AuthKit</strong>
              <small>
                Hosted sign-in, directory sync, and enterprise SSO-ready
                authentication.
              </small>
            </span>
          </div>
          <label>
            Client ID
            <input
              required
              value={clientId}
              onChange={(event) =>
                updateDraft({ clientId: event.target.value })
              }
              placeholder="client_01..."
            />
          </label>
          <label>
            Redirect URI
            <input
              required
              type="url"
              value={redirectUri}
              onChange={(event) =>
                updateDraft({ redirectUri: event.target.value })
              }
            />
          </label>
          <label>
            Allowed email domains <span className="optional">optional</span>
            <textarea
              rows={4}
              value={domains}
              onChange={(event) => updateDraft({ domains: event.target.value })}
              placeholder={"example.com\nsubsidiary.example"}
            />
          </label>
          <div className="encryption-note">
            <ShieldCheck size={17} />
            <span>
              Provisioning is invitation-only. An authenticated WorkOS email
              must exactly match a user invitation.
            </span>
          </div>
          {error && <ErrorNotice message={error} />}
          {message && (
            <div className="notice success">
              <Check size={16} /> {message}
            </div>
          )}
          <button className="button primary" disabled={Boolean(busy)}>
            {busy === "save" ? (
              <LoaderCircle className="spin" size={17} />
            ) : (
              <Settings size={17} />
            )}
            Save settings
          </button>
        </form>

        <aside className="panel auth-readiness">
          <h2>Deployment readiness</h2>
          <div className="readiness-row">
            <span>Frontend Client ID</span>
            <strong
              className={
                import.meta.env.VITE_WORKOS_CLIENT_ID ? "ready" : "missing"
              }
            >
              {import.meta.env.VITE_WORKOS_CLIENT_ID ? "Configured" : "Missing"}
            </strong>
          </div>
          <div className="readiness-row">
            <span>Convex Client ID</span>
            <strong
              className={
                settings.deployment.backendClientIdConfigured
                  ? "ready"
                  : "missing"
              }
            >
              {settings.deployment.backendClientIdConfigured
                ? "Configured"
                : "Missing"}
            </strong>
          </div>
          <div className="readiness-row">
            <span>Saved configuration</span>
            <strong>{settings.configuration ? "Present" : "Not saved"}</strong>
          </div>
          <p className="fine-print">
            Set <code>WORKOS_CLIENT_ID</code> in Convex and the matching
            <code>VITE_WORKOS_CLIENT_ID</code> in the frontend environment. Keep
            <code>WORKOS_API_KEY</code> only in the provisioning environment;
            credentials are never persisted in the application database.
          </p>
          <button
            className="button"
            disabled={Boolean(busy) || !settings.configuration}
            onClick={() => void run("verify")}
          >
            {busy === "verify" ? (
              <LoaderCircle className="spin" size={16} />
            ) : (
              <BadgeCheck size={16} />
            )}
            Verify configuration
          </button>
          <button
            className="button primary"
            disabled={
              Boolean(busy) || settings.configuration?.state !== "verified"
            }
            onClick={() => void run("enforce")}
          >
            {busy === "enforce" ? (
              <LoaderCircle className="spin" size={16} />
            ) : (
              <ShieldCheck size={16} />
            )}
            Enforce provider
          </button>
        </aside>
      </div>
    </>
  );
}

function AdminArea({ user }: { user: AppUser }) {
  const convex = useConvex();
  const users = useQuery(api.users.listForAdmin, {});
  const createUser = useMutation(api.users.create);
  const updateUser = useMutation(api.users.update);
  const setGrant = useMutation(api.access.setGrant);
  const [showCreate, setShowCreate] = useState(false);
  const [busyTarget, setBusyTarget] = useState("");
  const [error, setError] = useState("");

  async function changeGrant(
    targetUserId: Id<"users">,
    environment: "development" | "uat" | "production",
    enabled: boolean,
  ) {
    setBusyTarget(`${targetUserId}-${environment}`);
    setError("");
    try {
      if (enabled) {
        const [targetPublicKey, actorEnvelope] = await Promise.all([
          convex.query(api.users.getPublicKey, { targetUserId }),
          convex.query(api.access.getKeyEnvelope, { environment }),
        ]);
        if (!targetPublicKey)
          throw new Error(
            "The target user must enroll a device before receiving environment access.",
          );
        if (!actorEnvelope)
          throw new Error(
            "This Admin does not hold the environment key required to complete the grant.",
          );
        const environmentKey = await unwrapEnvironmentKey(
          user._id,
          actorEnvelope.wrappedKey,
        );
        const wrappedKey = await wrapEnvironmentKey(
          environmentKey,
          targetPublicKey,
        );
        await setGrant({
          targetUserId,
          environment,
          enabled: true,
          wrappedKey,
        });
      } else {
        await setGrant({ targetUserId, environment, enabled: false });
      }
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Access update failed.",
      );
    } finally {
      setBusyTarget("");
    }
  }

  return (
    <>
      <div className="page-actions">
        <div>
          <h1>Users & access</h1>
          <p>
            Roles control operations; environment grants control which shared
            keys a user can decrypt.
          </p>
        </div>
        <button className="button primary" onClick={() => setShowCreate(true)}>
          <UserPlus size={17} /> Add user
        </button>
      </div>
      {error && <ErrorNotice message={error} />}
      {!users ? (
        <LoadingPanel />
      ) : (
        <div className="admin-table-wrap">
          <table className="admin-table">
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Status</th>
                <th>Device key</th>
                <th>Development</th>
                <th>UAT</th>
                <th>Production</th>
              </tr>
            </thead>
            <tbody>
              {users.map((target) => (
                <tr key={target._id}>
                  <td>
                    <div className="user-cell">
                      <span className="avatar">
                        {target.displayName.slice(0, 2).toUpperCase()}
                      </span>
                      <span>
                        <strong>{target.displayName}</strong>
                        <small>{target.email}</small>
                      </span>
                    </div>
                  </td>
                  <td>
                    <select
                      value={target.role}
                      disabled={
                        target.role === "systemAdministrator" &&
                        user.role !== "systemAdministrator"
                      }
                      onChange={(event) =>
                        void updateUser({
                          targetUserId: target._id,
                          role: event.target.value as AppUser["role"],
                          status: target.status,
                        })
                      }
                    >
                      <option value="developer">Developer</option>
                      <option value="admin">Admin</option>
                      {user.role === "systemAdministrator" && (
                        <option value="systemAdministrator">
                          System Administrator
                        </option>
                      )}
                    </select>
                  </td>
                  <td>
                    <select
                      value={target.status}
                      onChange={(event) =>
                        void updateUser({
                          targetUserId: target._id,
                          role: target.role,
                          status: event.target.value as "active" | "suspended",
                        })
                      }
                    >
                      <option value="active">Active</option>
                      <option value="suspended">Suspended</option>
                    </select>
                  </td>
                  <td>
                    <span
                      className={
                        target.hasPublicKey ? "key-state ready" : "key-state"
                      }
                    >
                      {target.hasPublicKey ? (
                        <Check size={13} />
                      ) : (
                        <MoreHorizontal size={13} />
                      )}
                      {target.hasPublicKey ? "Enrolled" : "Pending"}
                    </span>
                  </td>
                  {(["development", "uat", "production"] as const).map(
                    (environment) => {
                      const enabled = Boolean(target.grants[environment]);
                      const busy =
                        busyTarget === `${target._id}-${environment}`;
                      return (
                        <td key={environment}>
                          <button
                            className={
                              enabled ? "access-toggle on" : "access-toggle"
                            }
                            disabled={
                              busy ||
                              target.status !== "active" ||
                              (target._id === user._id && enabled)
                            }
                            aria-pressed={enabled}
                            onClick={() =>
                              void changeGrant(
                                target._id,
                                environment,
                                !enabled,
                              )
                            }
                          >
                            {busy ? (
                              <LoaderCircle className="spin" size={14} />
                            ) : enabled ? (
                              <Check size={14} />
                            ) : (
                              <Plus size={14} />
                            )}
                            {enabled ? "Granted" : "Grant"}
                          </button>
                        </td>
                      );
                    },
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="panel admin-note authenticated-note">
        <ShieldCheck size={20} />
        <div>
          <strong>Authenticated authorization</strong>
          <p>
            Convex derives the current user from the validated WorkOS token.
            Client-supplied user IDs are never accepted as proof of identity.
          </p>
        </div>
      </div>
      {showCreate && (
        <CreateUserModal
          actor={user}
          createUser={createUser}
          onClose={() => setShowCreate(false)}
        />
      )}
    </>
  );
}

function CreateUserModal({
  actor,
  createUser,
  onClose,
}: {
  actor: AppUser;
  createUser: (args: {
    displayName: string;
    email: string;
    role: AppUser["role"];
  }) => Promise<Id<"users">>;
  onClose: () => void;
}) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<AppUser["role"]>("developer");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await createUser({ displayName: name, email, role });
      onClose();
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Unable to create user.",
      );
      setBusy(false);
    }
  }
  return (
    <Modal
      title="Invite user"
      subtitle="Their WorkOS email must exactly match this invitation before device enrollment."
      onClose={onClose}
    >
      <form className="secret-form" onSubmit={(event) => void submit(event)}>
        <label>
          Display name
          <input
            required
            autoFocus
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </label>
        <label>
          WorkOS email
          <input
            required
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
        </label>
        <label>
          Role
          <select
            value={role}
            onChange={(event) => setRole(event.target.value as AppUser["role"])}
          >
            <option value="developer">Developer</option>
            <option value="admin">Admin</option>
            {actor.role === "systemAdministrator" && (
              <option value="systemAdministrator">System Administrator</option>
            )}
          </select>
        </label>
        {error && <ErrorNotice message={error} />}
        <div className="modal-actions">
          <button type="button" className="button ghost" onClick={onClose}>
            Cancel
          </button>
          <button className="button primary" disabled={busy}>
            {busy ? (
              <LoaderCircle className="spin" size={16} />
            ) : (
              <UserPlus size={16} />
            )}
            Invite user
          </button>
        </div>
      </form>
    </Modal>
  );
}

function AuditLog({ user, users }: { user: AppUser; users: AppUser[] }) {
  const adminEvents = useQuery(
    api.audit.listRecent,
    user.role !== "developer" ? {} : "skip",
  );
  const ownEvents = useQuery(
    api.audit.listMine,
    user.role === "developer" ? {} : "skip",
  );
  const events = user.role !== "developer" ? adminEvents : ownEvents;
  const userNames = useMemo(
    () => Object.fromEntries(users.map((item) => [item._id, item.displayName])),
    [users],
  );
  return (
    <>
      <div className="page-actions">
        <div>
          <h1>Audit activity</h1>
          <p>
            Privacy-safe events record sensitive actions without logging secret
            names or values.
          </p>
        </div>
      </div>
      {!events ? (
        <LoadingPanel />
      ) : events.length === 0 ? (
        <EmptyState
          icon={<Clock3 />}
          title="No activity yet"
          body="Vault and access operations will appear here."
        />
      ) : (
        <div className="audit-list">
          {events.map((event) => (
            <div className="audit-row" key={event._id}>
              <span className="audit-icon">
                <AuditIcon action={event.action} />
              </span>
              <span>
                <strong>{event.action.split(".").join(" ")}</strong>
                <small>
                  {userNames[event.actorUserId] ?? "Unknown user"}
                  {event.environment
                    ? ` · ${environmentLabels[event.environment]}`
                    : ""}
                  {event.context ? ` · ${event.context}` : ""}
                </small>
              </span>
              <time>{formatRelativeTime(event.createdAt)}</time>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

function AuditIcon({ action }: { action: string }) {
  if (action.startsWith("environment") || action.startsWith("user"))
    return <Users size={17} />;
  if (action.startsWith("project")) return <Folder size={17} />;
  if (action.startsWith("attachment")) return <FileKey2 size={17} />;
  if (action.startsWith("device")) return <Fingerprint size={17} />;
  return <KeyRound size={17} />;
}

function Modal({
  title,
  subtitle,
  onClose,
  wide = false,
  children,
}: {
  title: string;
  subtitle?: string;
  onClose: () => void;
  wide?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div
      className="modal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        className={wide ? "modal wide" : "modal"}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <header>
          <div>
            <h2>{title}</h2>
            {subtitle && <p>{subtitle}</p>}
          </div>
          <button className="icon-button" aria-label="Close" onClick={onClose}>
            <X size={19} />
          </button>
        </header>
        <div className="modal-body">{children}</div>
      </section>
    </div>
  );
}

function EmptyState({
  icon,
  title,
  body,
  action,
}: {
  icon: React.ReactNode;
  title: string;
  body: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="empty-state">
      <span className="empty-icon">{icon}</span>
      <h2>{title}</h2>
      <p>{body}</p>
      {action}
    </div>
  );
}

function LoadingPanel() {
  return (
    <div className="empty-state compact-state">
      <LoaderCircle className="spin" size={24} />
      <p>Loading encrypted workspace…</p>
    </div>
  );
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatRelativeTime(timestamp: number) {
  const seconds = Math.round((Date.now() - timestamp) / 1000);
  if (seconds < 60) return "Just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return new Date(timestamp).toLocaleDateString();
}
