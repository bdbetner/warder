import type { ProtectedPathSelection } from "../types";

export function ProtectedZones({ paths }: { paths: ProtectedPathSelection[] }) {
  const selected = paths.filter((path) => path.selected);
  const available = paths.filter((path) => path.exists).length;

  return (
    <section className="panel protected-zones-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Protected zones</p>
          <h2>Configured paths</h2>
        </div>
        <span className="badge">{selected.length} of {available} active</span>
      </div>
      {selected.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon" aria-hidden="true">Z</div>
          <strong>No protected paths selected</strong>
          <p>
            Run setup and choose the folders Warder should protect before
            launching an agent session.
          </p>
        </div>
      ) : (
        <div className="path-list">
          {selected.map((path) => (
            <article className="path-row protected-card" key={path.id}>
              <div className="path-card-top">
                <div>
                  <strong>{path.label}</strong>
                  <small>{path.path}</small>
                </div>
                <span className={`zone-kind ${path.kind}`}>
                  {path.kind === "vital-system" ? "System" : "User"}
                </span>
              </div>
              <div className="protection-matrix">
                <span className={path.exists ? "signal on" : "signal off"}>
                  {path.exists ? "Present" : "Missing"}
                </span>
                <span className={path.readProtected ? "signal on" : "signal muted"}>
                  Read
                </span>
                <span className={path.writeProtected ? "signal on" : "signal muted"}>
                  Write
                </span>
                <span
                  className={path.snapshotProtected ? "signal on" : "signal muted"}
                >
                  Snapshot
                </span>
              </div>
              <p>
                {path.readProtected
                  ? "Read request noted; write protection requested."
                  : "Write protection requested."}
              </p>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
