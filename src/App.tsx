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
  Menu,
  MoreHorizontal,
  Pencil,
  Plus,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  UserPlus,
  Users,
  X,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useConvex, useMutation, useQuery } from "convex/react";
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
  role: "developer" | "admin";
  status: "active" | "suspended";
  hasPublicKey: boolean;
};

type SecretRow = {
  definition: Doc<"secretDefinitions">;
  value: Doc<"secretValues"> | null;
};

type DecryptedSecretRow = SecretRow & {
  decrypted: SecretPayload | null;
  decryptionError?: string;
};

const environments: Environment[] = ["local", "development", "uat", "production"];
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
      <div className="loading-mark"><LoaderCircle className="spin" size={22} /> Preparing the vault…</div>
    </div>
  );
}

function ErrorNotice({ message }: { message: string }) {
  return <div className="notice error"><CircleAlert size={17} /> {message}</div>;
}

export default function App() {
  const bootstrap = useQuery(api.bootstrap.state);
  if (bootstrap === undefined) return <LoadingScreen />;
  if (!bootstrap.initialized) return <BootstrapWorkspace />;
  return <Workspace />;
}

function BootstrapWorkspace() {
  const initialize = useMutation(api.bootstrap.initialize);
  const [displayName, setDisplayName] = useState("System Administrator");
  const [email, setEmail] = useState("admin@nebula.local");
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
        email,
        publicKeyJwk: device.publicJwk,
        keyEnvelopes,
      });
      await persistDeviceKey(adminId, device);
      localStorage.setItem("nebula-selected-user", adminId);
      window.location.reload();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Workspace setup failed.");
      setBusy(false);
    }
  }

  return (
    <div className="setup-page">
      <div className="setup-brand"><span className="brand-mark"><LockKeyhole size={20} /></span><span>Nebula Secrets</span></div>
      <div className="setup-grid">
        <section className="setup-copy">
          <span className="eyebrow"><ShieldCheck size={15} /> End-to-end encrypted by design</span>
          <h1>Your team’s secrets,<br />without server-side plaintext.</h1>
          <p>Initialize the development workspace and its first Admin identity. Encryption keys are generated in this browser; Convex receives only public keys and encrypted key envelopes.</p>
          <div className="security-points">
            <span><Fingerprint size={18} /> Device-held private key</span>
            <span><Database size={18} /> Ciphertext-only backend</span>
            <span><Shield size={18} /> Environment-scoped access</span>
          </div>
        </section>
        <form className="panel setup-form" onSubmit={(event) => void submit(event)}>
          <div>
            <span className="step-label">Workspace setup</span>
            <h2>Create the first Admin</h2>
            <p className="muted">Authentication is intentionally deferred. This identity selector is for development data only.</p>
          </div>
          <label>Display name<input required value={displayName} onChange={(event) => setDisplayName(event.target.value)} /></label>
          <label>Email<input required type="email" value={email} onChange={(event) => setEmail(event.target.value)} /></label>
          {error && <ErrorNotice message={error} />}
          <button className="button primary" disabled={busy} type="submit">
            {busy ? <LoaderCircle className="spin" size={17} /> : <KeyRound size={17} />}
            {busy ? "Generating keys…" : "Initialize encrypted vault"}
          </button>
          <p className="fine-print">Do not use real secrets until authentication binds identities to these device keys.</p>
          <p className="liability-note">Use at your own risk. To the fullest extent permitted by law, the creators and contributors accept no liability for losses arising from use of this system.</p>
        </form>
      </div>
    </div>
  );
}

function Workspace() {
  const users = useQuery(api.users.listSelectable);
  const [selectedUserId, setSelectedUserId] = useState<Id<"users"> | null>(() =>
    localStorage.getItem("nebula-selected-user") as Id<"users"> | null,
  );

  if (!users?.length) return <LoadingScreen />;
  const effectiveSelectedUserId = users.some(
    (candidate) => candidate._id === selectedUserId && candidate.status === "active",
  )
    ? selectedUserId
    : (users.find((candidate) => candidate.status === "active")?._id ?? null);
  if (!effectiveSelectedUserId) return <LoadingScreen />;
  const user = users.find((candidate) => candidate._id === effectiveSelectedUserId);
  if (!user) return <LoadingScreen />;

  function selectUser(userId: Id<"users">) {
    localStorage.setItem("nebula-selected-user", userId);
    setSelectedUserId(userId);
  }

  return <DeviceGate key={user._id} user={user} users={users} onSelectUser={selectUser} />;
}

function DeviceGate({
  user,
  users,
  onSelectUser,
}: {
  user: AppUser;
  users: AppUser[];
  onSelectUser: (userId: Id<"users">) => void;
}) {
  const [deviceState, setDeviceState] = useState<"checking" | "ready" | "missing">("checking");

  useEffect(() => {
    let cancelled = false;
    void hasDeviceKey(user._id).then((present) => {
      if (!cancelled) setDeviceState(present ? "ready" : "missing");
    });
    return () => { cancelled = true; };
  }, [user._id]);

  if (deviceState === "checking") return <LoadingScreen />;
  if (!user.hasPublicKey) {
    return <EnrollDevice user={user} onReady={() => setDeviceState("ready")} />;
  }
  if (deviceState === "missing") {
    return <MissingDeviceKey user={user} users={users} onSelectUser={onSelectUser} />;
  }
  return <Dashboard user={user} users={users} onSelectUser={onSelectUser} />;
}

function MissingDeviceKey({
  user,
  users,
  onSelectUser,
}: {
  user: AppUser;
  users: AppUser[];
  onSelectUser: (userId: Id<"users">) => void;
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
        actorUserId: user._id,
        confirmation: "RESET NEBULA",
      });
      try {
        await clearDeviceKeys();
      } catch {
        // The deleted user IDs make any browser-local orphaned keys unreachable.
      }
      localStorage.removeItem("nebula-selected-user");
      window.location.reload();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Workspace reset failed.");
      setBusy(false);
    }
  }

  return (
    <div className="center-screen padded">
      <div className="panel key-missing">
        <span className="icon-disc warning"><ShieldAlert size={24} /></span>
        <h2>Private key unavailable in this browser</h2>
        <p>This usually means the workspace was initialized in a different browser or profile. The matching private key never leaves that browser, so Convex cannot recover or reveal it.</p>
        <label>Switch development identity
          <select value={user._id} onChange={(event) => onSelectUser(event.target.value as Id<"users">)}>
            {users.filter((item) => item.status === "active").map((item) => <option key={item._id} value={item._id}>{item.displayName}</option>)}
          </select>
        </label>
        {error && <ErrorNotice message={error} />}
        {user.role === "admin" && (
          <div className="recovery-box">
            <div>
              <strong>Disposable test data?</strong>
              <p>Reset the development workspace, then initialize fresh keys in this browser.</p>
            </div>
            <button className="button destructive" disabled={busy} onClick={() => void resetTestWorkspace()}>
              {busy ? <LoaderCircle className="spin" size={17} /> : <Trash2 size={17} />}
              {busy ? "Resetting workspaceâ€¦" : "Reset test workspace"}
            </button>
          </div>
        )}
        <p className="fine-print">If the data matters, reopen the browser that initialized this identity. Production recovery will require authenticated device approval or dual control.</p>
      </div>
    </div>
  );
}

function EnrollDevice({ user, onReady }: { user: AppUser; onReady: () => void }) {
  const enroll = useMutation(api.users.enrollDevice);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function enrollDevice() {
    setBusy(true);
    setError("");
    try {
      const device = await generateDeviceKeyMaterial();
      const localKey = await generateEnvironmentKey();
      const localKeyEnvelope = await wrapEnvironmentKey(localKey, device.publicJwk);
      await enroll({ actorUserId: user._id, publicKeyJwk: device.publicJwk, localKeyEnvelope });
      await persistDeviceKey(user._id, device);
      onReady();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Device enrollment failed.");
      setBusy(false);
    }
  }

  return (
    <div className="center-screen padded">
      <div className="panel device-enroll">
        <span className="icon-disc"><Laptop size={25} /></span>
        <span className="eyebrow">First use on this device</span>
        <h2>Enroll a key for {user.displayName}</h2>
        <p>This creates a browser-held private key and a personal Local environment key. The private key is stored as a non-exportable Web Crypto key.</p>
        {error && <ErrorNotice message={error} />}
        <button className="button primary" onClick={() => void enrollDevice()} disabled={busy}>
          {busy ? <LoaderCircle className="spin" size={17} /> : <Fingerprint size={17} />}
          {busy ? "Creating secure key…" : "Enroll this device"}
        </button>
      </div>
    </div>
  );
}

function Dashboard({
  user,
  users,
  onSelectUser,
}: {
  user: AppUser;
  users: AppUser[];
  onSelectUser: (userId: Id<"users">) => void;
}) {
  const access = useQuery(api.access.listMine, { actorUserId: user._id });
  const [section, setSection] = useState<"vault" | "admin" | "audit">("vault");
  const [environment, setEnvironment] = useState<Environment>("local");
  const [mobileNav, setMobileNav] = useState(false);

  const allowedEnvironments = useMemo(
    () => environments.filter((item) => access?.find((entry) => entry.environment === item)?.granted),
    [access],
  );

  return (
    <div className="app-shell">
      <aside className={mobileNav ? "sidebar open" : "sidebar"}>
        <div className="brand"><span className="brand-mark"><LockKeyhole size={18} /></span><span>Nebula <strong>Secrets</strong></span></div>
        <nav>
          <button className={section === "vault" ? "nav-item active" : "nav-item"} onClick={() => { setSection("vault"); setMobileNav(false); }}><LayoutGrid size={18} /> Vault</button>
          {user.role === "admin" && <button className={section === "admin" ? "nav-item active" : "nav-item"} onClick={() => { setSection("admin"); setMobileNav(false); }}><Users size={18} /> Admin</button>}
          <button className={section === "audit" ? "nav-item active" : "nav-item"} onClick={() => { setSection("audit"); setMobileNav(false); }}><Clock3 size={18} /> Audit log</button>
        </nav>
        <div className="sidebar-security">
          <ShieldCheck size={18} />
          <div><strong>Client encrypted</strong><span>Convex stores ciphertext</span></div>
        </div>
      </aside>

      <div className="main-shell">
        <div className="dev-banner"><ShieldAlert size={14} /><span>Development identity mode — never use real secrets until authentication is connected. Use at your own risk; the creators and contributors accept no liability for losses.</span></div>
        <header className="topbar">
          <button className="icon-button mobile-menu" aria-label="Open navigation" onClick={() => setMobileNav((value) => !value)}><Menu size={20} /></button>
          <div className="topbar-title">
            <span>{section === "vault" ? "Secrets vault" : section === "admin" ? "Administration" : "Audit activity"}</span>
            {section === "vault" && <small>{environmentLabels[environment]} environment</small>}
          </div>
          <div className="identity-select">
            <span className="avatar">{user.displayName.slice(0, 2).toUpperCase()}</span>
            <label className="sr-only" htmlFor="identity">Development identity</label>
            <select id="identity" value={user._id} onChange={(event) => onSelectUser(event.target.value as Id<"users">)}>
              {users.filter((item) => item.status === "active").map((item) => <option key={item._id} value={item._id}>{item.displayName} · {item.role}</option>)}
            </select>
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
          {section === "admin" && user.role === "admin" && <AdminArea user={user} />}
          {section === "audit" && <AuditLog user={user} users={users} />}
        </main>
      </div>
    </div>
  );
}

function useEnvironmentKey(userId: Id<"users">, environment: Environment, allowed: boolean) {
  const envelope = useQuery(
    api.access.getKeyEnvelope,
    allowed ? { actorUserId: userId, environment } : "skip",
  );
  const [state, setState] = useState<{ source: string | null; key: CryptoKey | null; error: string }>(() => ({ source: null, key: null, error: "" }));

  useEffect(() => {
    let cancelled = false;
    if (!envelope) return () => { cancelled = true; };
    void unwrapEnvironmentKey(userId, envelope.wrappedKey)
      .then((key) => { if (!cancelled) setState({ source: envelope.wrappedKey, key, error: "" }); })
      .catch((cause: unknown) => { if (!cancelled) setState({ source: envelope.wrappedKey, key: null, error: cause instanceof Error ? cause.message : "Unable to unlock environment." }); });
    return () => { cancelled = true; };
  }, [envelope, environment, userId]);

  const current = envelope && state.source === envelope.wrappedKey;
  return { environmentKey: current ? state.key : null, keyError: current ? state.error : "", loading: allowed && envelope === undefined };
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
  const { environmentKey, keyError } = useEnvironmentKey(user._id, environment, allowed);
  const rows = useQuery(
    api.secrets.list,
    environmentKey ? { actorUserId: user._id, environment } : "skip",
  );
  const projects = useQuery(api.projects.list, { actorUserId: user._id });
  const archiveSecret = useMutation(api.secrets.setArchiveStatus);
  const [decryptedState, setDecryptedState] = useState<{ token: string; rows: DecryptedSecretRow[] }>({ token: "", rows: [] });
  const [search, setSearch] = useState("");
  const [projectFilter, setProjectFilter] = useState("all");
  const [showProjects, setShowProjects] = useState(false);
  const [editorRow, setEditorRow] = useState<SecretRow | "new" | null>(null);
  const [detailSecretId, setDetailSecretId] = useState<Id<"secretDefinitions"> | null>(null);
  const [message, setMessage] = useState("");

  useEffect(() => {
    let cancelled = false;
    if (!rows || !environmentKey) return () => { cancelled = true; };
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
          return { ...row, decrypted: null, decryptionError: "Integrity check failed" };
        }
      }),
    ).then((result) => { if (!cancelled) setDecryptedState({ token, rows: result }); });
    return () => { cancelled = true; };
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
  const generalProjectId = projects?.find((project) => project.normalizedName === "general")?._id;
  const visibleRows = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return decryptedRows.filter((row) => {
      const rowProjectId = row.definition.projectId ?? generalProjectId ?? "general";
      if (projectFilter !== "all" && rowProjectId !== projectFilter) return false;
      if (!needle) return true;
      const projectName = row.definition.projectId
        ? projectById.get(row.definition.projectId)?.name ?? ""
        : "General";
      return `${row.definition.name} ${secretTypeLabels[row.definition.type]} ${projectName}`
        .toLowerCase()
        .includes(needle);
    });
  }, [decryptedRows, generalProjectId, projectById, projectFilter, search]);
  const groupedRows = useMemo(() => {
    const groups = new Map<string, { id: string; name: string; rows: DecryptedSecretRow[] }>();
    for (const row of visibleRows) {
      const id = row.definition.projectId ?? generalProjectId ?? "general";
      const name = row.definition.projectId
        ? projectById.get(row.definition.projectId)?.name ?? "Archived project"
        : "General";
      const group = groups.get(id) ?? { id, name, rows: [] };
      group.rows.push(row);
      groups.set(id, group);
    }
    return [...groups.values()].sort((left, right) => {
      return left.name.localeCompare(right.name);
    });
  }, [generalProjectId, projectById, visibleRows]);
  const detailRow = decryptedRows.find((row) => row.definition._id === detailSecretId) ?? null;

  async function archive(row: DecryptedSecretRow) {
    if (!window.confirm(`Archive “${row.definition.name}”?`)) return;
    await archiveSecret({ actorUserId: user._id, secretId: row.definition._id, environment, archived: true });
    setDetailSecretId(null);
    setMessage("Secret archived.");
  }

  return (
    <>
      <div className="environment-tabs" aria-label="Environment">
        {environments.map((item) => {
          const enabled = allowedEnvironments.includes(item);
          return <button key={item} disabled={!enabled} className={environment === item ? "active" : ""} onClick={() => enabled && onEnvironmentChange(item)}>{environmentLabels[item]}{!enabled && <LockKeyhole size={12} />}</button>;
        })}
      </div>

      {keyError ? <ErrorNotice message={keyError} /> : !allowed ? (
        <EmptyState icon={<ShieldAlert />} title="Environment access required" body="An Admin must grant this identity access and wrap the environment key to its enrolled public key." />
      ) : !environmentKey || !rows || !projects ? <LoadingPanel /> : (
        <>
          <div className="page-actions">
            <div>
              <h1>{environmentLabels[environment]} secrets</h1>
              <p>{environment === "local" ? "Private values encrypted for this development identity." : "Shared values for everyone granted this environment."}</p>
            </div>
            <div className="page-buttons">
              <button className="button" onClick={() => setShowProjects(true)}><FolderPlus size={17} /> Projects</button>
              <button className="button primary" onClick={() => setEditorRow("new")}><Plus size={17} /> New secret</button>
            </div>
          </div>
          <div className="toolbar">
            <label className="search-box"><Search size={17} /><input aria-label="Search secrets" placeholder="Search secrets…" value={search} onChange={(event) => setSearch(event.target.value)} /></label>
            <label className="project-filter"><span>Project</span><select aria-label="Filter by project" value={projectFilter} onChange={(event) => setProjectFilter(event.target.value)}><option value="all">All projects</option>{projects.map((project) => <option key={project._id} value={project._id}>{project.name}</option>)}</select></label>
            <span className="result-count">{visibleRows.length} {visibleRows.length === 1 ? "secret" : "secrets"}</span>
          </div>
          {message && <div className="notice success"><Check size={16} /> {message}<button aria-label="Dismiss" onClick={() => setMessage("")}><X size={14} /></button></div>}
          {visibleRows.length === 0 ? (
            <EmptyState icon={<KeyRound />} title={search ? "No matching secrets" : "No secrets here yet"} body={search ? "Try a different search term." : "Create a typed secret and its encrypted value for this environment."} action={!search ? <button className="button" onClick={() => setEditorRow("new")}><Plus size={16} /> Create first secret</button> : undefined} />
          ) : (
            <div className="project-groups">
              {groupedRows.map((group) => (
                <section className="project-group" key={group.id}>
                  <header><span><Folder size={16} /> {group.name}</span><small>{group.rows.length} {group.rows.length === 1 ? "secret" : "secrets"}</small></header>
                  <div className="secret-list">
                    {group.rows.map((row) => (
                      <button className="secret-row" key={row.definition._id} onClick={() => row.value ? setDetailSecretId(row.definition._id) : setEditorRow(row)}>
                        <span className={`secret-icon ${row.definition.type}`}><SecretIcon type={row.definition.type} /></span>
                        <span className="secret-title"><strong>{row.definition.name}</strong><small>{secretTypeLabels[row.definition.type]} · {row.value ? `Version ${row.value.version}` : "No value in this environment"}</small></span>
                        <span className={row.decryptionError ? "status-chip danger" : row.value ? "status-chip" : "status-chip muted-chip"}>{row.decryptionError ? "Integrity error" : row.value ? "Encrypted" : "Not set"}</span>
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
          decrypted={editorRow === "new" ? null : decryptedRows.find((item) => item.definition._id === editorRow.definition._id)?.decrypted ?? null}
          onClose={() => setEditorRow(null)}
          onSaved={() => { setEditorRow(null); setMessage("Encrypted secret saved."); }}
        />
      )}
      {detailRow && environmentKey && (
        <SecretDetail
          user={user}
          environment={environment}
          environmentKey={environmentKey}
          row={detailRow}
          projectName={detailRow.definition.projectId ? projectById.get(detailRow.definition.projectId)?.name : undefined}
          onClose={() => setDetailSecretId(null)}
          onEdit={() => { setEditorRow(detailRow); setDetailSecretId(null); }}
          onArchive={() => void archive(detailRow)}
        />
      )}
      {showProjects && projects && (
        <ProjectManager user={user} projects={projects} onClose={() => setShowProjects(false)} />
      )}
    </>
  );
}

function ProjectManager({
  user,
  projects,
  onClose,
}: {
  user: AppUser;
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
        await renameProject({ actorUserId: user._id, projectId: editingId, name });
      } else {
        await createProject({ actorUserId: user._id, name });
      }
      resetForm();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to save the project.");
    } finally {
      setBusy(false);
    }
  }

  async function archive(project: Doc<"projects">) {
    if (!window.confirm(`Archive project “${project.name}”?`)) return;
    setError("");
    try {
      await archiveProject({ actorUserId: user._id, projectId: project._id });
      if (editingId === project._id) resetForm();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to archive the project.");
    }
  }

  const sortedProjects = [...projects].sort((left, right) => left.name.localeCompare(right.name));
  return (
    <Modal title="Projects" subtitle="Organize every secret into a shared project group." onClose={onClose}>
      <div className="project-manager">
        <form className="project-form" onSubmit={(event) => void submit(event)}>
          <label>{editingId ? "Rename project" : "New project"}<input autoFocus required maxLength={80} value={name} onChange={(event) => setName(event.target.value)} placeholder="e.g. Customer portal" /></label>
          <div className="project-form-actions">
            {editingId && <button type="button" className="button ghost" onClick={resetForm}>Cancel</button>}
            <button className="button primary" disabled={busy} type="submit">{busy ? <LoaderCircle className="spin" size={16} /> : <FolderPlus size={16} />}{editingId ? "Save name" : "Create project"}</button>
          </div>
        </form>
        {error && <ErrorNotice message={error} />}
        {sortedProjects.length === 0 ? (
          <p className="project-empty">No projects yet. Secrets can remain ungrouped.</p>
        ) : (
          <div className="project-list">
            {sortedProjects.map((project) => (
              <div className="project-item" key={project._id}>
                <span className="project-icon"><Folder size={17} /></span>
                <strong>{project.name}</strong>
                {project.normalizedName === "general" ? <span className="status-chip muted-chip">Default</span> : <button className="icon-button" aria-label={`Rename ${project.name}`} onClick={() => { setEditingId(project._id); setName(project.name); setError(""); }}><Pencil size={16} /></button>}
                {project.normalizedName === "general" ? <span /> : <button className="icon-button danger-button" aria-label={`Archive ${project.name}`} onClick={() => void archive(project)}><Archive size={16} /></button>}
              </div>
            ))}
          </div>
        )}
        <p className="fine-print">General is the protected default project. Project names are organizational metadata stored in Convex; secret values and notes remain client encrypted.</p>
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
    row?.definition.projectId
      ?? projects.find((project) => project.normalizedName === "general")?._id
      ?? projects[0]?._id
      ?? "",
  );
  const [payload, setPayload] = useState<SecretPayload>(decrypted ?? { notes: "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const title = row?.value ? "Edit secret value" : row ? `Set ${environmentLabels[environment]} value` : "Create secret";

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
        actorUserId: user._id,
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
      setError(cause instanceof Error ? cause.message : "Unable to save the secret.");
      setBusy(false);
    }
  }

  return (
    <Modal title={title} subtitle={`${environmentLabels[environment]} · encrypted before upload`} onClose={onClose}>
      <form className="secret-form" onSubmit={(event) => void submit(event)}>
        <div className="form-grid two">
          <label>Display name<input autoFocus required value={name} onChange={(event) => setName(event.target.value)} placeholder="e.g. Stripe dashboard" /></label>
          <label>Secret type<select value={type} disabled={Boolean(row)} onChange={(event) => { setType(event.target.value as SecretType); setPayload({ notes: payload.notes }); }}><option value="login">Login</option><option value="apiKey">API Key</option><option value="licenseKey">License Key</option></select></label>
          <label className="wide">Project<select required value={projectId} onChange={(event) => setProjectId(event.target.value as Id<"projects">)}>{projects.map((project) => <option key={project._id} value={project._id}>{project.name}</option>)}</select></label>
        </div>
        {type === "login" && <div className="form-grid two"><label>Username<input value={payload.username ?? ""} onChange={(event) => field("username", event.target.value)} autoComplete="off" /></label><label>Password<input required type="password" value={payload.password ?? ""} onChange={(event) => field("password", event.target.value)} autoComplete="new-password" /></label><label className="wide">Sign-in URL<input type="url" value={payload.url ?? ""} onChange={(event) => field("url", event.target.value)} placeholder="https://" /></label></div>}
        {type === "apiKey" && <div className="form-grid two"><label className="wide">API key or token<input required type="password" value={payload.apiKey ?? ""} onChange={(event) => field("apiKey", event.target.value)} autoComplete="off" /></label><label>Endpoint<input value={payload.endpoint ?? ""} onChange={(event) => field("endpoint", event.target.value)} placeholder="https://api.example.com" /></label></div>}
        {type === "licenseKey" && <div className="form-grid two"><label className="wide">License key<input required type="password" value={payload.licenseKey ?? ""} onChange={(event) => field("licenseKey", event.target.value)} autoComplete="off" /></label><label>Licensee<input value={payload.licensee ?? ""} onChange={(event) => field("licensee", event.target.value)} /></label><label>Expiry date<input type="date" value={payload.expiresAt ?? ""} onChange={(event) => field("expiresAt", event.target.value)} /></label></div>}
        <label>Notes<textarea rows={5} value={payload.notes} onChange={(event) => field("notes", event.target.value)} placeholder="Encrypted notes, setup context, renewal details…" /></label>
        <div className="encryption-note"><ShieldCheck size={17} /><span>Values and notes are encrypted locally with AES-256-GCM. Convex receives ciphertext only.</span></div>
        {error && <ErrorNotice message={error} />}
        <div className="modal-actions"><button type="button" className="button ghost" onClick={onClose}>Cancel</button><button className="button primary" type="submit" disabled={busy}>{busy ? <LoaderCircle className="spin" size={17} /> : <LockKeyhole size={17} />}{busy ? "Encrypting…" : "Encrypt & save"}</button></div>
      </form>
    </Modal>
  );
}

function SecretDetail({
  user,
  environment,
  environmentKey,
  row,
  projectName,
  onClose,
  onEdit,
  onArchive,
}: {
  user: AppUser;
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
  const sensitiveFields = row.definition.type === "login"
    ? [{ label: "Username", value: payload?.username ?? "" }, { label: "Password", value: payload?.password ?? "", sensitive: true }, { label: "Sign-in URL", value: payload?.url ?? "" }]
    : row.definition.type === "apiKey"
      ? [{ label: "API key", value: payload?.apiKey ?? "", sensitive: true }, { label: "Endpoint", value: payload?.endpoint ?? "" }]
      : [{ label: "License key", value: payload?.licenseKey ?? "", sensitive: true }, { label: "Licensee", value: payload?.licensee ?? "" }, { label: "Expires", value: payload?.expiresAt ?? "" }];

  async function copy(label: string, value: string) {
    await navigator.clipboard.writeText(value);
    if (row.value) {
      await recordSecretAction({
        actorUserId: user._id,
        secretValueId: row.value._id,
        action: "secret.copied",
        context: label,
      });
    }
    setCopied(label);
    window.setTimeout(() => setCopied(""), 1800);
  }

  return (
    <Modal title={row.definition.name} subtitle={`${projectName ? `${projectName} · ` : ""}${secretTypeLabels[row.definition.type]} · ${environmentLabels[environment]} · v${row.value?.version ?? 0}`} onClose={onClose} wide>
      {row.decryptionError || !payload || !row.value ? <ErrorNotice message={row.decryptionError ?? "This encrypted value is unavailable."} /> : (
        <div className="detail-content">
          <div className="detail-toolbar"><span className="status-chip"><ShieldCheck size={13} /> Integrity verified</span><div><button className="button ghost small" onClick={() => { if (!revealed) void recordSecretAction({ actorUserId: user._id, secretValueId: row.value!._id, action: "secret.revealed" }); setRevealed((value) => !value); }}>{revealed ? <EyeOff size={15} /> : <Eye size={15} />}{revealed ? "Hide" : "Reveal"}</button><button className="icon-button" aria-label="Edit secret" onClick={onEdit}><Pencil size={17} /></button><button className="icon-button danger-button" aria-label="Archive secret" onClick={onArchive}><Archive size={17} /></button></div></div>
          <div className="secret-fields">
            {sensitiveFields.filter((item) => item.value).map((item) => <div className="secret-field" key={item.label}><span>{item.label}</span><strong>{item.sensitive && !revealed ? "••••••••••••••••" : item.value}</strong><button className="icon-button" aria-label={`Copy ${item.label}`} onClick={() => void copy(item.label, item.value)}>{copied === item.label ? <Check size={16} /> : <Clipboard size={16} />}</button></div>)}
          </div>
          <div className="notes-block"><span>Notes</span><p>{payload.notes || "No notes added."}</p></div>
          <AttachmentSection user={user} environmentKey={environmentKey} secretValueId={row.value._id} />
          <VersionHistory user={user} secretValue={row.value} />
        </div>
      )}
    </Modal>
  );
}

function AttachmentSection({ user, environmentKey, secretValueId }: { user: AppUser; environmentKey: CryptoKey; secretValueId: Id<"secretValues"> }) {
  const convex = useConvex();
  const attachments = useQuery(api.attachments.list, { actorUserId: user._id, secretValueId });
  const generateUploadUrl = useMutation(api.attachments.generateUploadUrl);
  const commit = useMutation(api.attachments.commit);
  const remove = useMutation(api.attachments.remove);
  const [metadata, setMetadata] = useState<Record<string, AttachmentMetadata>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  useEffect(() => {
    let cancelled = false;
    if (!attachments) return () => { cancelled = true; };
    void Promise.all(attachments.map(async (attachment) => [attachment._id, await decryptAttachmentMetadata(attachment.encryptedMetadata, environmentKey, attachment.cryptoId, secretValueId)] as const))
      .then((items) => { if (!cancelled) setMetadata(Object.fromEntries(items)); })
      .catch(() => { if (!cancelled) setError("One or more attachment metadata records failed integrity checks."); });
    return () => { cancelled = true; };
  }, [attachments, environmentKey, secretValueId]);

  async function upload(file: File) {
    if (file.size > 5 * 1024 * 1024) { setError("Attachments are limited to 5 MB in the MVP."); return; }
    setBusy(true); setError(""); setSuccess("");
    try {
      const cryptoId = crypto.randomUUID();
      const encrypted = await encryptAttachment(file, environmentKey, cryptoId, secretValueId);
      const uploadUrl = await generateUploadUrl({ actorUserId: user._id, secretValueId });
      const response = await fetch(uploadUrl, { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: encrypted.encryptedBlob });
      if (!response.ok) throw new Error("Encrypted upload failed.");
      const result = await response.json() as { storageId: Id<"_storage"> };
      await commit({ actorUserId: user._id, secretValueId, cryptoId, storageId: result.storageId, encryptedMetadata: encrypted.encryptedMetadata, fileIv: encrypted.fileIv, encryptedSize: encrypted.encryptedBlob.size });
      setSuccess("Encrypted attachment uploaded.");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Attachment upload failed."); }
    finally { setBusy(false); }
  }

  async function download(attachmentId: Id<"attachments">) {
    setBusy(true); setError(""); setSuccess("");
    try {
      const attachment = await convex.mutation(api.attachments.getDownload, { actorUserId: user._id, attachmentId });
      const meta = metadata[attachmentId];
      if (!meta) throw new Error("Attachment metadata is not ready.");
      const response = await fetch(attachment.url);
      const plaintext = await decryptAttachmentFile({ encryptedBytes: await response.arrayBuffer(), encryptedMetadata: attachment.encryptedMetadata, fileIv: attachment.fileIv, environmentKey, cryptoId: attachment.cryptoId, secretValueId: attachment.secretValueId });
      const url = URL.createObjectURL(new Blob([plaintext], { type: meta.mimeType }));
      const link = document.createElement("a"); link.href = url; link.download = meta.name; link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
      setSuccess("Attachment decrypted and download started.");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Attachment download failed."); }
    finally { setBusy(false); }
  }

  return (
    <section className="detail-section">
      <div className="section-heading"><div><h3>Encrypted attachments</h3><p>File contents and filenames are encrypted before upload.</p></div><label className={busy ? "button small disabled" : "button small"}><FilePlus2 size={15} /> Add file<input className="sr-only" type="file" disabled={busy} onChange={(event) => { const file = event.target.files?.[0]; if (file) void upload(file); event.currentTarget.value = ""; }} /></label></div>
      {error && <ErrorNotice message={error} />}
      {success && <div className="notice success"><Check size={16} /> {success}</div>}
      {!attachments ? <div className="inline-loading"><LoaderCircle className="spin" size={15} /> Loading attachments…</div> : attachments.length === 0 ? <p className="muted compact">No files attached.</p> : <div className="attachment-list">{attachments.map((attachment) => { const meta = metadata[attachment._id]; return <div className="attachment-row" key={attachment._id}><span className="file-icon"><FileKey2 size={17} /></span><span><strong>{meta?.name ?? "Decrypting filename…"}</strong><small>{meta ? formatBytes(meta.originalSize) : "Encrypted attachment"}</small></span><button className="icon-button" disabled={busy || !meta} aria-label="Download attachment" onClick={() => void download(attachment._id)}><ArrowDownToLine size={16} /></button><button className="icon-button danger-button" disabled={busy} aria-label="Delete attachment" onClick={() => { if (window.confirm("Delete this encrypted attachment?")) void remove({ actorUserId: user._id, attachmentId: attachment._id }); }}><Trash2 size={16} /></button></div>; })}</div>}
    </section>
  );
}

function VersionHistory({ user, secretValue }: { user: AppUser; secretValue: Doc<"secretValues"> }) {
  const versions = useQuery(api.secrets.listVersions, { actorUserId: user._id, secretValueId: secretValue._id });
  return <section className="detail-section"><div className="section-heading"><div><h3>Version history</h3><p>Previous encrypted payloads are retained for audit and recovery.</p></div></div>{!versions ? <div className="inline-loading"><LoaderCircle className="spin" size={15} /> Loading versions…</div> : <div className="version-list">{versions.map((version) => <div key={`${version.version}-${version.changedAt}`}><span>v{version.version}</span><strong>{version.current ? "Current version" : "Previous version"}</strong><small>{new Date(version.changedAt).toLocaleString()}</small></div>)}</div>}</section>;
}

function AdminArea({ user }: { user: AppUser }) {
  const convex = useConvex();
  const users = useQuery(api.users.listForAdmin, { actorUserId: user._id });
  const createUser = useMutation(api.users.create);
  const updateUser = useMutation(api.users.update);
  const setGrant = useMutation(api.access.setGrant);
  const [showCreate, setShowCreate] = useState(false);
  const [busyTarget, setBusyTarget] = useState("");
  const [error, setError] = useState("");

  async function changeGrant(targetUserId: Id<"users">, environment: "development" | "uat" | "production", enabled: boolean) {
    setBusyTarget(`${targetUserId}-${environment}`); setError("");
    try {
      if (enabled) {
        const [targetPublicKey, actorEnvelope] = await Promise.all([
          convex.query(api.users.getPublicKey, { actorUserId: user._id, targetUserId }),
          convex.query(api.access.getKeyEnvelope, { actorUserId: user._id, environment }),
        ]);
        if (!targetPublicKey) throw new Error("The target user must enroll a device before receiving environment access.");
        if (!actorEnvelope) throw new Error("This Admin does not hold the environment key required to complete the grant.");
        const environmentKey = await unwrapEnvironmentKey(user._id, actorEnvelope.wrappedKey);
        const wrappedKey = await wrapEnvironmentKey(environmentKey, targetPublicKey);
        await setGrant({ actorUserId: user._id, targetUserId, environment, enabled: true, wrappedKey });
      } else {
        await setGrant({ actorUserId: user._id, targetUserId, environment, enabled: false });
      }
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Access update failed."); }
    finally { setBusyTarget(""); }
  }

  return (
    <>
      <div className="page-actions"><div><h1>Users & access</h1><p>Roles control operations; environment grants control which shared keys a user can decrypt.</p></div><button className="button primary" onClick={() => setShowCreate(true)}><UserPlus size={17} /> Add user</button></div>
      {error && <ErrorNotice message={error} />}
      {!users ? <LoadingPanel /> : <div className="admin-table-wrap"><table className="admin-table"><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Device key</th><th>Development</th><th>UAT</th><th>Production</th></tr></thead><tbody>{users.map((target) => <tr key={target._id}><td><div className="user-cell"><span className="avatar">{target.displayName.slice(0, 2).toUpperCase()}</span><span><strong>{target.displayName}</strong><small>{target.email}</small></span></div></td><td><select value={target.role} onChange={(event) => void updateUser({ actorUserId: user._id, targetUserId: target._id, role: event.target.value as "developer" | "admin", status: target.status })}><option value="developer">Developer</option><option value="admin">Admin</option></select></td><td><select value={target.status} onChange={(event) => void updateUser({ actorUserId: user._id, targetUserId: target._id, role: target.role, status: event.target.value as "active" | "suspended" })}><option value="active">Active</option><option value="suspended">Suspended</option></select></td><td><span className={target.hasPublicKey ? "key-state ready" : "key-state"}>{target.hasPublicKey ? <Check size={13} /> : <MoreHorizontal size={13} />}{target.hasPublicKey ? "Enrolled" : "Pending"}</span></td>{(["development", "uat", "production"] as const).map((environment) => { const enabled = Boolean(target.grants[environment]); const busy = busyTarget === `${target._id}-${environment}`; return <td key={environment}><button className={enabled ? "access-toggle on" : "access-toggle"} disabled={busy || target.status !== "active" || (target._id === user._id && enabled)} aria-pressed={enabled} onClick={() => void changeGrant(target._id, environment, !enabled)}>{busy ? <LoaderCircle className="spin" size={14} /> : enabled ? <Check size={14} /> : <Plus size={14} />}{enabled ? "Granted" : "Grant"}</button></td>; })}</tr>)}</tbody></table></div>}
      <div className="panel admin-note"><ShieldAlert size={20} /><div><strong>Development-mode authorization</strong><p>Convex functions enforce the selected user’s role and grants, but the identity ID can be spoofed until authentication is integrated. This workspace must contain test data only.</p></div></div>
      {showCreate && <CreateUserModal actor={user} createUser={createUser} onClose={() => setShowCreate(false)} />}
    </>
  );
}

function CreateUserModal({ actor, createUser, onClose }: { actor: AppUser; createUser: (args: { actorUserId: Id<"users">; displayName: string; email: string; role: "developer" | "admin" }) => Promise<Id<"users">>; onClose: () => void }) {
  const [name, setName] = useState(""); const [email, setEmail] = useState(""); const [role, setRole] = useState<"developer" | "admin">("developer"); const [busy, setBusy] = useState(false); const [error, setError] = useState("");
  async function submit(event: React.FormEvent) { event.preventDefault(); setBusy(true); setError(""); try { await createUser({ actorUserId: actor._id, displayName: name, email, role }); onClose(); } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to create user."); setBusy(false); } }
  return <Modal title="Add development user" subtitle="The user must select their identity once to enroll a device key." onClose={onClose}><form className="secret-form" onSubmit={(event) => void submit(event)}><label>Display name<input required autoFocus value={name} onChange={(event) => setName(event.target.value)} /></label><label>Email<input required type="email" value={email} onChange={(event) => setEmail(event.target.value)} /></label><label>Role<select value={role} onChange={(event) => setRole(event.target.value as "developer" | "admin")}><option value="developer">Developer</option><option value="admin">Admin</option></select></label>{error && <ErrorNotice message={error} />}<div className="modal-actions"><button type="button" className="button ghost" onClick={onClose}>Cancel</button><button className="button primary" disabled={busy}>{busy ? <LoaderCircle className="spin" size={16} /> : <UserPlus size={16} />}Create user</button></div></form></Modal>;
}

function AuditLog({ user, users }: { user: AppUser; users: AppUser[] }) {
  const adminEvents = useQuery(api.audit.listRecent, user.role === "admin" ? { actorUserId: user._id } : "skip");
  const ownEvents = useQuery(api.audit.listMine, user.role === "developer" ? { actorUserId: user._id } : "skip");
  const events = user.role === "admin" ? adminEvents : ownEvents;
  const userNames = useMemo(() => Object.fromEntries(users.map((item) => [item._id, item.displayName])), [users]);
  return <><div className="page-actions"><div><h1>Audit activity</h1><p>Privacy-safe events record sensitive actions without logging secret names or values.</p></div></div>{!events ? <LoadingPanel /> : events.length === 0 ? <EmptyState icon={<Clock3 />} title="No activity yet" body="Vault and access operations will appear here." /> : <div className="audit-list">{events.map((event) => <div className="audit-row" key={event._id}><span className="audit-icon"><AuditIcon action={event.action} /></span><span><strong>{event.action.split(".").join(" ")}</strong><small>{userNames[event.actorUserId] ?? "Unknown user"}{event.environment ? ` · ${environmentLabels[event.environment]}` : ""}{event.context ? ` · ${event.context}` : ""}</small></span><time>{formatRelativeTime(event.createdAt)}</time></div>)}</div>}</>;
}

function AuditIcon({ action }: { action: string }) {
  if (action.startsWith("environment") || action.startsWith("user")) return <Users size={17} />;
  if (action.startsWith("project")) return <Folder size={17} />;
  if (action.startsWith("attachment")) return <FileKey2 size={17} />;
  if (action.startsWith("device")) return <Fingerprint size={17} />;
  return <KeyRound size={17} />;
}

function Modal({ title, subtitle, onClose, wide = false, children }: { title: string; subtitle?: string; onClose: () => void; wide?: boolean; children: React.ReactNode }) {
  return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><section className={wide ? "modal wide" : "modal"} role="dialog" aria-modal="true" aria-label={title}><header><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div><button className="icon-button" aria-label="Close" onClick={onClose}><X size={19} /></button></header><div className="modal-body">{children}</div></section></div>;
}

function EmptyState({ icon, title, body, action }: { icon: React.ReactNode; title: string; body: string; action?: React.ReactNode }) {
  return <div className="empty-state"><span className="empty-icon">{icon}</span><h2>{title}</h2><p>{body}</p>{action}</div>;
}

function LoadingPanel() {
  return <div className="empty-state compact-state"><LoaderCircle className="spin" size={24} /><p>Loading encrypted workspace…</p></div>;
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatRelativeTime(timestamp: number) {
  const seconds = Math.round((Date.now() - timestamp) / 1000);
  if (seconds < 60) return "Just now";
  const minutes = Math.round(seconds / 60); if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60); if (hours < 24) return `${hours}h ago`;
  return new Date(timestamp).toLocaleDateString();
}
