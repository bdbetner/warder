import { useState } from "react";
import type { ProfileTemplateCatalogEntry, ProtectedPathSelection } from "../types";

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
  const [customPath, setCustomPath] = useState("");
  const [customLabel, setCustomLabel] = useState("");
  const selectedTemplate = profileTemplates.find(
    (template) => template.id === selectedProfileId,
  );
  const selectedCount = paths.filter((path) => path.selected).length;
  const readableCount = paths.filter((path) => path.selected && path.readProtected).length;
  const skippedCount = paths.filter((path) => !path.exists).length;

  return (
    <section className="workspace">
      <aside className="steps">
        <strong>Setup</strong>
        <span className="active">1. Agent profile</span>
        <span>2. Protected folders</span>
        <span>3. Logging</span>
        <span>4. Test run</span>
      </aside>
      <div className="panel setup-panel">
        <p className="eyebrow">First run</p>
        <h1>Choose an agent profile</h1>
        <p className="lead">
          Start from a known profile, confirm the sensitive folders, then save a
          policy Warder can use for protected launches.
        </p>
        <div className="template-panel">
          <label className="field compact-field">
            Agent profile
            <select
              value={selectedProfileId}
              onChange={(event) => onApplyProfileTemplate(event.target.value)}
            >
              {profileTemplates.map((template) => (
                <option key={template.id} value={template.id}>
                  {template.declared_command} - {template.summary}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            onClick={() => onApplyProfileTemplate(selectedProfileId)}
            disabled={!selectedTemplate}
          >
            Reapply template
          </button>
        </div>
        <div className="settings-grid">
          <label className="field compact-field">
            Agent command
            <input
              value={agentCommand}
              onChange={(event) => onAgentCommandChange(event.target.value)}
            />
          </label>
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
        <div className="toggle-row">
          <label className="inline-check">
            <input
              type="checkbox"
              checked={networkJournal}
              onChange={(event) => onNetworkJournalChange(event.target.checked)}
            />
            Network journal
          </label>
          <label className="inline-check">
            <input
              type="checkbox"
              checked={requireEnforcement}
              onChange={(event) => onRequireEnforcementChange(event.target.checked)}
            />
            Strict write-block launch
          </label>
        </div>
        {selectedTemplate ? (
          <div className="template-summary">
            <div>
              <span className="badge">{selectedTemplate.effect}</span>
              <span className="badge">
                {networkJournal ? "Network journal on" : "Network journal off"}
              </span>
              <span className="badge">
                Snapshot {selectedTemplate.template.snapshot}
              </span>
            </div>
            <p>{selectedTemplate.preflight}</p>
            <small>
              Writable roots:{" "}
              {selectedTemplate.template.writable_roots.join(", ") || "none"}
            </small>
          </div>
        ) : null}
        <div className="setup-review">
          <div>
            <strong>{selectedCount}</strong>
            <span>protected paths</span>
          </div>
          <div>
            <strong>{readableCount}</strong>
            <span>read-aware selections</span>
          </div>
          <div>
            <strong>{skippedCount}</strong>
            <span>missing folders</span>
          </div>
        </div>
        <h2>Protected paths</h2>
        <p className="notice">
          Write protection is the v1 enforced control. Read selections are
          visible policy notes only; Warder does not block reads in v1.
        </p>
        <div className="custom-path-form">
          <label className="field compact-field">
            Custom path
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
            Add path
          </button>
        </div>
        <div className="path-list">
          {paths.map((path) => (
            <article className={`path-row setup-path ${path.selected ? "selected" : ""}`} key={path.id}>
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
                  <span className={path.exists ? "badge" : "badge muted-badge"}>
                    {path.exists ? "Present" : "Skipped"}
                  </span>
                  <label className="inline-check">
                    <input
                      type="checkbox"
                      checked={path.readProtected}
                      disabled={!path.selected || path.access === "write-only"}
                      onChange={() => onToggleRead(path.id)}
                    />
                    Read
                  </label>
                  <span className={path.writeProtected ? "signal on" : "signal muted"}>
                    Write
                  </span>
                  <button
                    type="button"
                    className={path.snapshotProtected ? "signal on" : "signal muted"}
                    onClick={() => onToggleSnapshot(path.id)}
                  >
                    Snapshot
                  </button>
                  <button type="button" onClick={() => onRemovePath(path.id)}>
                    Remove
                  </button>
                </div>
              </div>
              <p>{path.reason}</p>
            </article>
          ))}
        </div>
        {error && <pre className="output error">{error}</pre>}
        <button className="primary" onClick={() => void onComplete()}>
          Save setup
        </button>
      </div>
    </section>
  );
}
