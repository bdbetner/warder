import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { HostReadinessSummary } from "../types";

export function ReadinessPanel() {
  const [readiness, setReadiness] = useState<HostReadinessSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function loadReadiness() {
    try {
      setError(null);
      const result = await invoke<HostReadinessSummary>("host_readiness_summary");
      setReadiness(result);
    } catch (reason) {
      setError(String(reason));
      setReadiness(null);
    }
  }

  useEffect(() => {
    loadReadiness();
  }, []);

  const hasReasons =
    Boolean(readiness?.blocked_reasons.length) ||
    Boolean(readiness?.degraded_reasons.length);
  const summaryText = readiness
    ? readiness.level === "strong"
      ? "This host has the core controls Warder checks before launch."
      : "Review these limits before starting a session that needs strong protection."
    : "Checking host support...";

  return (
    <section className="panel readiness-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Host readiness</p>
          <h2>{readiness ? readiness.level : "Checking host"}</h2>
        </div>
        <button className="icon-button" onClick={loadReadiness} aria-label="Refresh host readiness">
          Refresh
        </button>
      </div>
      {error ? (
        <p className="error-text">{error}</p>
      ) : (
        <>
          <div className="readiness-summary">
            {readiness && (
              <span className={`readiness-badge ${readiness.level}`}>
                {readiness.level}
              </span>
            )}
            <p className="muted">{summaryText}</p>
          </div>
          {readiness && hasReasons ? (
            <div className="readiness-reasons">
              {readiness.blocked_reasons.length > 0 && (
                <div>
                  <h3>Blocked reasons</h3>
                  <ul className="reason-list">
                    {readiness.blocked_reasons.map((reason) => (
                      <li key={reason}>{reason}</li>
                    ))}
                  </ul>
                </div>
              )}
              {readiness.degraded_reasons.length > 0 && (
                <div>
                  <h3>Degraded reasons</h3>
                  <ul className="reason-list">
                    {readiness.degraded_reasons.map((reason) => (
                      <li key={reason}>{reason}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : (
            <div className="empty-state compact">
              <strong>No host limits reported</strong>
              <p>No blocked or degraded host checks are currently visible.</p>
            </div>
          )}
        </>
      )}
    </section>
  );
}
