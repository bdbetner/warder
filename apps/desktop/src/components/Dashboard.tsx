import type { ProtectedPathSelection } from "../types";

interface DashboardProps {
  paths: ProtectedPathSelection[];
  onRunSetup: () => void;
  onStartSession: () => void;
}

export function Dashboard({ paths, onRunSetup, onStartSession }: DashboardProps) {
  const enabled = paths.filter((path) => path.selected);
  const readAware = enabled.filter((path) => path.readProtected).length;
  const missing = paths.filter((path) => !path.exists).length;

  return (
    <section className="workspace">
      <aside className="steps">
        <strong>Warder</strong>
        <span className="active">Dashboard</span>
        <span>Protected Zones</span>
        <span>Sessions & Logs</span>
        <span>Settings</span>
      </aside>
      <div className="panel hero-panel">
        <div className="hero-copy">
          <p className="eyebrow">Overview</p>
          <h1>Protected sessions for local agent work</h1>
          <p className="lead">
            Warder keeps sensitive folders visible, launch controls close at
            hand, and receipts easy to review after every supervised session.
          </p>
        </div>
        <div className="status-card protected">
          <span className="status-dot" aria-hidden="true" />
          <div>
            <strong>{enabled.length > 0 ? "Policy ready" : "Setup needed"}</strong>
            <span>
              {enabled.length > 0
                ? `${enabled.length} protected path${
                    enabled.length === 1 ? "" : "s"
                  } active`
                : "Choose at least one protected path before launch"}
            </span>
          </div>
        </div>
        <div className="stat-grid">
          <div>
            <strong>{enabled.length}</strong>
            <span>protected paths</span>
          </div>
          <div>
            <strong>{readAware}</strong>
            <span>read-aware selections</span>
          </div>
          <div>
            <strong>{missing}</strong>
            <span>missing recommended paths</span>
          </div>
        </div>
        <div className="toolbar">
          <button className="primary" onClick={onStartSession}>
            Start protected session
          </button>
          <button onClick={onRunSetup}>Run setup wizard</button>
        </div>
      </div>
    </section>
  );
}
