import type { ProfileTemplateCatalogEntry, ProtectedPathSelection } from "../types";

interface SetupWizardProps {
  paths: ProtectedPathSelection[];
  profileTemplates: ProfileTemplateCatalogEntry[];
  selectedProfileId: string;
  networkJournal: boolean;
  onTogglePath: (id: string) => void;
  onToggleRead: (id: string) => void;
  onApplyProfileTemplate: (profileId: string) => void;
  onComplete: () => Promise<void>;
}

export function SetupWizard({
  paths,
  profileTemplates,
  selectedProfileId,
  networkJournal,
  onTogglePath,
  onToggleRead,
  onApplyProfileTemplate,
  onComplete,
}: SetupWizardProps) {
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
          Write protection is the v1 enforced control. Read selections are kept
          visible in the generated policy description until Warder grows a
          dedicated read-deny policy field.
        </p>
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
                    <strong>{path.label}</strong>
                    <small>{path.path}</small>
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
                  <span
                    className={path.snapshotProtected ? "signal on" : "signal muted"}
                  >
                    Snapshot
                  </span>
                </div>
              </div>
              <p>{path.reason}</p>
            </article>
          ))}
        </div>
        <button className="primary" onClick={() => void onComplete()}>
          Save setup
        </button>
      </div>
    </section>
  );
}
