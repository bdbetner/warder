import { useMemo, useState } from "react";
import { protectionGroupCounts } from "../protectionGroups";
import type { ProfileTemplateCatalogEntry, ProtectedPathSelection } from "../types";

const PRIMARY_PROFILE_IDS = ["codex-cli", "claude-code", "openclaw-agent"];

const PROFILE_COPY: Record<string, { name: string; subtitle: string; command: string }> = {
  "codex-cli": {
    name: "Codex",
    subtitle: "Local Codex shell sessions",
    command: "codex",
  },
  "claude-code": {
    name: "Claude",
    subtitle: "Claude Code in a local workspace",
    command: "claude",
  },
  "openclaw-agent": {
    name: "OpenClaw",
    subtitle: "OpenClaw agent runs with host-side Warder controls",
    command: "openclaw agent",
  },
};

interface SetupWizardProps {
  paths: ProtectedPathSelection[];
  profileTemplates: ProfileTemplateCatalogEntry[];
  selectedProfileId: string;
  networkJournal: boolean;
  configPath: string;
  dbPath: string;
  agentCommand: string;
  requireEnforcement: boolean;
  onTogglePath: (id: string) => void;
  onToggleRead: (id: string) => void;
  onToggleSnapshot: (id: string) => void;
  onUpdatePath: (id: string, patch: Partial<ProtectedPathSelection>) => void;
  onAddCustomPath: (path: string, label: string) => void;
  onRemovePath: (id: string) => void;
  onApplyProfileTemplate: (profileId: string) => void;
  onNetworkJournalChange: (enabled: boolean) => void;
  onConfigPathChange: (path: string) => void;
  onDbPathChange: (path: string) => void;
  onAgentCommandChange: (command: string) => void;
  onRequireEnforcementChange: (enabled: boolean) => void;
  error: string | null;
  onComplete: () => Promise<void>;
}

function profileName(profile: ProfileTemplateCatalogEntry): string {
  return PROFILE_COPY[profile.id]?.name ?? profile.declared_command;
}

function profileSubtitle(profile: ProfileTemplateCatalogEntry): string {
  return PROFILE_COPY[profile.id]?.subtitle ?? profile.summary;
}

function orderedPrimaryProfiles(profileTemplates: ProfileTemplateCatalogEntry[]) {
  const byId = new Map(profileTemplates.map((profile) => [profile.id, profile]));
  const primary = PRIMARY_PROFILE_IDS.flatMap((id) => {
    const profile = byId.get(id);
    return profile ? [profile] : [];
  });

  if (primary.length > 0) {
    return primary;
  }

  return profileTemplates.slice(0, 3);
}

function protectionSummary(paths: ProtectedPathSelection[]) {
  const selected = paths.filter((path) => path.selected);
  const missing = paths.filter((path) => !path.exists);
  return { selected, missing, buckets: protectionGroupCounts(selected) };
}

export function SetupWizard({
  paths,
  profileTemplates,
  selectedProfileId,
  networkJournal,
  configPath,
  dbPath,
  agentCommand,
  requireEnforcement,
  onTogglePath,
  onToggleRead,
  onToggleSnapshot,
  onUpdatePath,
  onAddCustomPath,
  onRemovePath,
  onApplyProfileTemplate,
  onNetworkJournalChange,
  onConfigPathChange,
  onDbPathChange,
  onAgentCommandChange,
  onRequireEnforcementChange,
  error,
  onComplete,
}: SetupWizardProps) {
  const [step, setStep] = useState(0);
  const [customPath, setCustomPath] = useState("");
  const [customLabel, setCustomLabel] = useState("");
  const [showAllPaths, setShowAllPaths] = useState(false);

  const selectedTemplate = profileTemplates.find(
    (template) => template.id === selectedProfileId,
  );
  const primaryProfiles = useMemo(
    () => orderedPrimaryProfiles(profileTemplates),
    [profileTemplates],
  );
  const { selected, missing, buckets } = protectionSummary(paths);
  const visiblePaths = showAllPaths
    ? paths
    : paths.filter((path) => path.selected || !path.exists).slice(0, 8);
  const canContinue = selected.length > 0;
  const selectedProfileLabel = selectedTemplate
    ? profileName(selectedTemplate)
    : "Custom agent";

  return (
    <section className="onboarding">
      <aside className="onboarding-rail" aria-label="Setup steps">
        <strong>Setup</strong>
        {["Choose agent", "Protect folders", "Save profile"].map((label, index) => (
          <button
            key={label}
            type="button"
            className={step === index ? "step-link active" : "step-link"}
            onClick={() => setStep(index)}
          >
            <span>{index + 1}</span>
            {label}
          </button>
        ))}
      </aside>

      <div className="panel setup-panel simple-setup">
        <p className="eyebrow">First run</p>
        <h1>Set up your first protected agent</h1>
        <p className="lead">
          Warder launches an agent for you, blocks protected-folder writes when
          Linux supports it, and saves a receipt so you can review what happened.
        </p>

        {step === 0 && (
          <div className="setup-step">
            <div className="section-heading">
              <div>
                <h2>What are you running?</h2>
                <p>
                  Pick the agent you use most. You can change this later without
                  rebuilding your protection list.
                </p>
              </div>
            </div>
            <div className="agent-choice-grid">
              {primaryProfiles.map((profile) => (
                <button
                  key={profile.id}
                  type="button"
                  className={
                    profile.id === selectedProfileId
                      ? "agent-choice selected"
                      : "agent-choice"
                  }
                  onClick={() => onApplyProfileTemplate(profile.id)}
                >
                  <strong>{profileName(profile)}</strong>
                  <span>{profileSubtitle(profile)}</span>
                  <small>{PROFILE_COPY[profile.id]?.command ?? profile.declared_command}</small>
                </button>
              ))}
            </div>
            <label className="field setup-command">
              Agent command
              <input
                value={agentCommand}
                onChange={(event) => onAgentCommandChange(event.target.value)}
              />
            </label>
            <details className="advanced-details">
              <summary>Advanced agent profiles</summary>
              <label className="field compact-field">
                Agent profile
                <select
                  value={selectedProfileId}
                  onChange={(event) => onApplyProfileTemplate(event.target.value)}
                >
                  {profileTemplates.map((template) => (
                    <option key={template.id} value={template.id}>
                      {profileName(template)} - {template.summary}
                    </option>
                  ))}
                </select>
              </label>
              {selectedTemplate ? (
                <p className="muted">{selectedTemplate.preflight}</p>
              ) : null}
            </details>
            <div className="setup-actions">
              <button className="primary" type="button" onClick={() => setStep(1)}>
                Continue
              </button>
            </div>
          </div>
        )}

        {step === 1 && (
          <div className="setup-step">
            <div className="section-heading">
              <div>
                <h2>What should Warder protect?</h2>
                <p>
                  Start with the recommended sensitive folders. Most users can
                  keep these defaults and add only project-specific secrets.
                </p>
              </div>
              <span className="badge">{selected.length} selected</span>
            </div>
            <div className="protection-buckets">
              {Object.entries(buckets).map(([bucket, count]) => (
                <div key={bucket} className="bucket-card">
                  <strong>{bucket}</strong>
                  <span>
                    {count} folder{count === 1 ? "" : "s"} protected
                  </span>
                </div>
              ))}
              {selected.length === 0 && (
                <div className="bucket-card warning-card">
                  <strong>No folders selected</strong>
                  <span>Choose at least one folder before saving.</span>
                </div>
              )}
            </div>
            <div className="custom-path-form simple-custom-path">
              <label className="field compact-field">
                Add folder
                <input
                  value={customPath}
                  placeholder="/absolute/path"
                  onChange={(event) => setCustomPath(event.target.value)}
                />
              </label>
              <label className="field compact-field">
                Label
                <input
                  value={customLabel}
                  placeholder="Project secrets"
                  onChange={(event) => setCustomLabel(event.target.value)}
                />
              </label>
              <button
                type="button"
                onClick={() => {
                  onAddCustomPath(customPath, customLabel);
                  setCustomPath("");
                  setCustomLabel("");
                }}
              >
                Add folder
              </button>
            </div>
            <div className="simple-path-list">
              {visiblePaths.map((path) => (
                <article
                  className={`simple-path-row ${path.selected ? "selected" : ""}`}
                  key={path.id}
                >
                  <label>
                    <input
                      type="checkbox"
                      checked={path.selected}
                      disabled={!path.exists}
                      onChange={() => onTogglePath(path.id)}
                    />
                    <span>
                      <strong>{path.label}</strong>
                      <small>{path.path}</small>
                    </span>
                  </label>
                  <div className="row-actions">
                    {!path.exists && <span className="signal off">Missing</span>}
                    {path.exists && <span className="signal on">Write-block</span>}
                    <button type="button" onClick={() => onRemovePath(path.id)}>
                      Remove
                    </button>
                  </div>
                </article>
              ))}
            </div>
            {paths.length > visiblePaths.length && (
              <button type="button" onClick={() => setShowAllPaths(true)}>
                Show all folders
              </button>
            )}
            <details className="advanced-details">
              <summary>Advanced protection options</summary>
              <p className="muted">
                Read blocking is experimental. Write blocking is the stable
                default for protected folders.
              </p>
              <div className="path-list">
                {paths.map((path) => (
                  <article
                    className={`path-row setup-path ${path.selected ? "selected" : ""}`}
                    key={path.id}
                  >
                    <div className="path-main">
                      <label>
                        <input
                          type="checkbox"
                          checked={path.selected}
                          disabled={!path.exists}
                          onChange={() => onTogglePath(path.id)}
                        />
                        <span>
                          <input
                            className="inline-input strong-input"
                            value={path.label}
                            onChange={(event) =>
                              onUpdatePath(path.id, { label: event.target.value })
                            }
                          />
                          <input
                            className="inline-input"
                            value={path.path}
                            onChange={(event) =>
                              onUpdatePath(path.id, {
                                path: event.target.value,
                                exists: true,
                              })
                            }
                          />
                        </span>
                      </label>
                      <div className="protection-matrix">
                        <label className="inline-check">
                          <input
                            type="checkbox"
                            checked={path.readProtected}
                            disabled={!path.selected || path.access === "write-only"}
                            onChange={() => onToggleRead(path.id)}
                          />
                          Read
                        </label>
                        <span
                          className={path.writeProtected ? "signal on" : "signal muted"}
                        >
                          Write
                        </span>
                        <button
                          type="button"
                          className={
                            path.snapshotProtected ? "signal on" : "signal muted"
                          }
                          onClick={() => onToggleSnapshot(path.id)}
                        >
                          Snapshot
                        </button>
                        <button type="button" onClick={() => onRemovePath(path.id)}>
                          Remove
                        </button>
                      </div>
                    </div>
                  </article>
                ))}
              </div>
            </details>
            <div className="setup-actions">
              <button type="button" onClick={() => setStep(0)}>
                Back
              </button>
              <button
                className="primary"
                type="button"
                disabled={!canContinue}
                onClick={() => setStep(2)}
              >
                Continue
              </button>
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="setup-step">
            <div className="section-heading">
              <div>
                <h2>Save your protected profile</h2>
                <p>
                  Warder will use this setup when you start a protected session
                  from the desktop app.
                </p>
              </div>
            </div>
            <div className="plain-summary-grid">
              <div>
                <strong>{selectedProfileLabel}</strong>
                <span>Agent profile</span>
              </div>
              <div>
                <strong>{selected.length}</strong>
                <span>Folders protected from writes</span>
              </div>
              <div>
                <strong>{requireEnforcement ? "Strict" : "Best effort"}</strong>
                <span>Launch mode</span>
              </div>
            </div>
            {missing.length > 0 && (
              <p className="notice">
                {missing.length} recommended folder{missing.length === 1 ? "" : "s"} are
                missing on this machine and will be skipped.
              </p>
            )}
            <div className="toggle-row simple-toggles">
              <label className="inline-check">
                <input
                  type="checkbox"
                  checked={requireEnforcement}
                  onChange={(event) => onRequireEnforcementChange(event.target.checked)}
                />
                Refuse launch if write blocking is unavailable
              </label>
              <label className="inline-check">
                <input
                  type="checkbox"
                  checked={networkJournal}
                  onChange={(event) => onNetworkJournalChange(event.target.checked)}
                />
                Record network journal when supported
              </label>
            </div>
            <details className="advanced-details">
              <summary>Advanced storage paths</summary>
              <div className="settings-grid">
                <label className="field compact-field">
                  Config path
                  <input
                    value={configPath}
                    onChange={(event) => onConfigPathChange(event.target.value)}
                  />
                </label>
                <label className="field compact-field">
                  Database path
                  <input
                    value={dbPath}
                    onChange={(event) => onDbPathChange(event.target.value)}
                  />
                </label>
              </div>
            </details>
            {error && <pre className="output error">{error}</pre>}
            <div className="setup-actions">
              <button type="button" onClick={() => setStep(1)}>
                Back
              </button>
              <button className="primary" onClick={() => void onComplete()}>
                Save profile
              </button>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
