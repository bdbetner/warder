import { invoke } from "@tauri-apps/api/core";
import { useEffect, useMemo, useState } from "react";
import { Dashboard } from "./components/Dashboard";
import { ProtectedZones } from "./components/ProtectedZones";
import { ReadinessPanel } from "./components/ReadinessPanel";
import { SessionLauncher } from "./components/SessionLauncher";
import { SessionLogs } from "./components/SessionLogs";
import { SetupWizard } from "./components/SetupWizard";
import type {
  AppPolicyState,
  DesktopPaths,
  GuiConfigDraft,
  ProfileProtectedPathTemplate,
  ProfileTemplateCatalogEntry,
  ProtectedPathSelection,
  RecommendedProtection,
} from "./types";

const DEFAULT_PROFILE_ID = "codex-cli";
const APP_STATE_KEY = "warder.desktop.state.v1";
const DEFAULT_RECEIPT_KEY_PATH = "/run/warder-key";

function toSelection(item: RecommendedProtection): ProtectedPathSelection {
  return {
    ...item,
    selected: item.enabled_by_default,
    readProtected: item.access === "read-write" && item.enabled_by_default,
    writeProtected: item.enabled_by_default,
    snapshotProtected: false,
  };
}

function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

function templatePathSelection(
  templateId: string,
  templatePath: ProfileProtectedPathTemplate,
  snapshotProtected: boolean,
): ProtectedPathSelection {
  return {
    id: `template-${templateId}-${slug(templatePath.resolved_path)}`,
    label: templatePath.label,
    path: templatePath.resolved_path,
    kind: "sensitive-user",
    access: templatePath.read && templatePath.write ? "read-write" : "write-only",
    reason: `Recommended by the ${templateId} setup template.`,
    exists: true,
    enabled_by_default: true,
    selected: true,
    readProtected: templatePath.read,
    writeProtected: templatePath.write,
    snapshotProtected,
  };
}

function loadPersistedState(): AppPolicyState | null {
  try {
    const raw = window.localStorage.getItem(APP_STATE_KEY);
    return raw ? (JSON.parse(raw) as AppPolicyState) : null;
  } catch {
    return null;
  }
}

function persistState(state: AppPolicyState) {
  window.localStorage.setItem(APP_STATE_KEY, JSON.stringify(state));
}

function mergePersistedPaths(
  defaults: ProtectedPathSelection[],
  persisted: ProtectedPathSelection[] | undefined,
): ProtectedPathSelection[] {
  if (!persisted?.length) {
    return defaults;
  }

  const defaultPaths = new Map(defaults.map((path) => [path.path, path]));
  const merged = defaults.map((path) => {
    const saved = persisted.find((item) => item.path === path.path);
    return saved ? { ...path, ...saved, exists: path.exists } : path;
  });
  const custom = persisted.filter((path) => !defaultPaths.has(path.path));

  return [...merged, ...custom];
}

export default function App() {
  const [setupOpen, setSetupOpen] = useState(true);
  const [paths, setPaths] = useState<ProtectedPathSelection[]>([]);
  const [profileTemplates, setProfileTemplates] = useState<
    ProfileTemplateCatalogEntry[]
  >([]);
  const [selectedProfileId, setSelectedProfileId] = useState(DEFAULT_PROFILE_ID);
  const [agentCommand, setAgentCommand] = useState("codex");
  const [networkJournal, setNetworkJournal] = useState(false);
  const [requireEnforcement, setRequireEnforcement] = useState(true);
  const [receiptKeyPath, setReceiptKeyPath] = useState(DEFAULT_RECEIPT_KEY_PATH);
  const [configPath, setConfigPath] = useState("");
  const [dbPath, setDbPath] = useState("");
  const [setupError, setSetupError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    Promise.all([
      invoke<DesktopPaths>("desktop_default_paths"),
      invoke<RecommendedProtection[]>("load_recommended_protections"),
      invoke<ProfileTemplateCatalogEntry[]>("load_profile_template_catalog"),
    ])
      .then(([desktopPaths, recommendedProtections, templates]) => {
        const persisted = loadPersistedState();
        setConfigPath(persisted?.configPath ?? desktopPaths.config_path);
        setDbPath(persisted?.dbPath ?? desktopPaths.db_path);
        setProfileTemplates(templates);
        const defaultProfile =
          templates.find((item) => item.id === DEFAULT_PROFILE_ID) ?? templates[0];
        if (!defaultProfile) {
          setPaths(
            mergePersistedPaths(
              recommendedProtections.map(toSelection),
              persisted?.protectedPaths,
            ),
          );
          setSetupOpen(!persisted?.setupComplete);
          setLoaded(true);
          return;
        }

        const selections = recommendedProtections.map(toSelection);
        const existingPaths = new Set(selections.map((path) => path.path));
        const additions = defaultProfile.template.recommended_protected_paths
          .filter((path) => !existingPaths.has(path.resolved_path))
          .map((path) =>
            templatePathSelection(
              defaultProfile.id,
              path,
              defaultProfile.template.snapshot === "best-effort",
            ),
          );
        const defaultAgentCommand =
          defaultProfile.declared_command === "<command>"
            ? "sh"
            : defaultProfile.declared_command;
        setSelectedProfileId(persisted?.selectedProfileId ?? defaultProfile.id);
        setAgentCommand(persisted?.agentCommand ?? defaultAgentCommand);
        setNetworkJournal(
          persisted?.networkJournal ?? defaultProfile.template.network_journal,
        );
        setRequireEnforcement(persisted?.requireEnforcement ?? true);
        setReceiptKeyPath(persisted?.receiptKeyPath ?? DEFAULT_RECEIPT_KEY_PATH);
        setPaths(
          mergePersistedPaths([...selections, ...additions], persisted?.protectedPaths),
        );
        setSetupOpen(!persisted?.setupComplete);
        setLoaded(true);
      })
      .catch((reason) => setError(String(reason)));
  }, []);

  useEffect(() => {
    if (!loaded) {
      return;
    }

    persistState({
      setupComplete: !setupOpen,
      selectedProfileId,
      agentCommand,
      networkJournal,
      requireEnforcement,
      receiptKeyPath,
      configPath,
      dbPath,
      protectedPaths: paths,
    });
  }, [
    agentCommand,
    configPath,
    dbPath,
    loaded,
    networkJournal,
    paths,
    receiptKeyPath,
    requireEnforcement,
    selectedProfileId,
    setupOpen,
  ]);

  const selectedCount = useMemo(
    () => paths.filter((path) => path.selected).length,
    [paths],
  );

  function focusLauncher() {
    const launcher = document.getElementById("session-launcher");
    launcher?.scrollIntoView({ behavior: "smooth", block: "start" });
    launcher?.focus({ preventScroll: true });
  }

  function togglePath(id: string) {
    setPaths((current) =>
      current.map((path) =>
        path.id === id
          ? {
              ...path,
              selected: !path.selected,
              readProtected: !path.selected && path.access === "read-write",
              writeProtected: !path.selected,
            }
          : path,
      ),
    );
  }

  function toggleRead(id: string) {
    setPaths((current) =>
      current.map((path) =>
        path.id === id ? { ...path, readProtected: !path.readProtected } : path,
      ),
    );
  }

  function toggleSnapshot(id: string) {
    setPaths((current) =>
      current.map((path) =>
        path.id === id
          ? { ...path, snapshotProtected: !path.snapshotProtected }
          : path,
      ),
    );
  }

  function updatePath(id: string, patch: Partial<ProtectedPathSelection>) {
    setPaths((current) =>
      current.map((path) => (path.id === id ? { ...path, ...patch } : path)),
    );
  }

  function addCustomPath(path: string, label: string) {
    const cleanPath = path.trim();
    if (!cleanPath) {
      return;
    }
    const id = `custom-${slug(cleanPath) || Date.now().toString(36)}`;
    setPaths((current) => [
      ...current,
      {
        id,
        label: label.trim() || cleanPath,
        path: cleanPath,
        kind: "sensitive-user",
        access: "read-write",
        reason: "Custom protected path.",
        exists: true,
        enabled_by_default: true,
        selected: true,
        readProtected: false,
        writeProtected: true,
        snapshotProtected: false,
      },
    ]);
  }

  function removePath(id: string) {
    setPaths((current) => current.filter((path) => path.id !== id));
  }

  function applyProfileTemplate(profileId: string) {
    const profile = profileTemplates.find((item) => item.id === profileId);
    if (!profile) {
      return;
    }
    setSelectedProfileId(profile.id);
    setAgentCommand(
      profile.declared_command === "<command>" ? "sh" : profile.declared_command,
    );
    setNetworkJournal(profile.template.network_journal);
    setPaths((current) => {
      const existingPaths = new Set(current.map((path) => path.path));
      const additions = profile.template.recommended_protected_paths
        .filter((path) => !existingPaths.has(path.resolved_path))
        .map((path) =>
          templatePathSelection(
            profile.id,
            path,
            profile.template.snapshot === "best-effort",
          ),
        );
      return [...current, ...additions];
    });
  }

  async function saveSetup() {
    setSetupError(null);
    const draft: GuiConfigDraft = {
      agent: {
        id: "local-agent",
        label: "Local Agent",
        command: agentCommand,
        profile: selectedProfileId,
      },
      protected_paths: paths
        .filter((path) => path.selected)
        .map((path) => ({
          id: path.id,
          label: path.label,
          path: path.path,
          read_protected: path.readProtected,
          write_protected: path.writeProtected,
          snapshot: path.snapshotProtected,
        })),
      network_journal: networkJournal,
    };

    if (draft.protected_paths.length === 0) {
      setSetupError("Select at least one protected path before saving setup.");
      return;
    }

    await invoke("save_gui_config", {
      configPath,
      draft,
    });
    setSetupOpen(false);
  }

  if (error) {
    return (
      <main className="app-shell">
        <section className="panel error">{error}</section>
      </main>
    );
  }

  return (
    <main className="app-shell">
      <header className="app-header">
        <div className="brand-mark" aria-hidden="true" />
        <div>
          <strong>Warder</strong>
          <span>Local safety controls for agent sessions</span>
        </div>
      </header>
      {setupOpen ? (
        <SetupWizard
          paths={paths}
          profileTemplates={profileTemplates}
          selectedProfileId={selectedProfileId}
          networkJournal={networkJournal}
          onTogglePath={togglePath}
          onToggleRead={toggleRead}
          onToggleSnapshot={toggleSnapshot}
          onUpdatePath={updatePath}
          onAddCustomPath={addCustomPath}
          onRemovePath={removePath}
          onApplyProfileTemplate={applyProfileTemplate}
          onNetworkJournalChange={setNetworkJournal}
          configPath={configPath}
          dbPath={dbPath}
          agentCommand={agentCommand}
          requireEnforcement={requireEnforcement}
          onConfigPathChange={setConfigPath}
          onDbPathChange={setDbPath}
          onAgentCommandChange={setAgentCommand}
          onRequireEnforcementChange={setRequireEnforcement}
          error={setupError}
          onComplete={saveSetup}
        />
      ) : (
        <>
          <Dashboard
            paths={paths}
            onRunSetup={() => setSetupOpen(true)}
            onStartSession={focusLauncher}
          />
          <ReadinessPanel />
          <div className="dashboard-grid">
            <SessionLauncher
              configPath={configPath}
              dbPath={dbPath}
              hasProtectedPaths={selectedCount > 0}
              requireEnforcement={requireEnforcement}
              receiptKeyPath={receiptKeyPath}
              onReceiptKeyPathChange={setReceiptKeyPath}
            />
            <SessionLogs dbPath={dbPath} />
          </div>
          <ProtectedZones paths={paths} />
          <p className="footer-note">
            {selectedCount} path{selectedCount === 1 ? "" : "s"} selected.
            Protection applies to Warder-launched sessions.
          </p>
        </>
      )}
    </main>
  );
}
