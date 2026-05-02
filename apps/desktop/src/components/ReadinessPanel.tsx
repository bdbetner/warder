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
  const checks = readiness ? readinessChecks(readiness) : [];

  return (
    <section className="panel readiness-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Host readiness</p>
          <h2>{readiness ? readiness.level : "Checking host"}</h2>
        </div>
        <button className="icon-button" onClick={loadReadiness} aria-label="Run Warder doctor">
          Warder doctor
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
          {readiness && (
            <>
              <div className="readiness-checklist">
                {checks.map((check) => (
                  <div key={check.label} className="check-row">
                    <span className={`readiness-badge ${check.level}`}>
                      {check.level}
                    </span>
                    <div>
                      <strong>{check.label}</strong>
                      <p>{check.message}</p>
                    </div>
                  </div>
                ))}
              </div>
              <details className="advanced-details">
                <summary>Show raw doctor output</summary>
                <pre
                  className="output readiness-doctor-output"
                  aria-label="Warder doctor summary"
                >
                  {readiness.summary}
                </pre>
              </details>
            </>
          )}
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

function readinessChecks(readiness: HostReadinessSummary) {
  const allReasons = [...readiness.blocked_reasons, ...readiness.degraded_reasons].join(
    "\n",
  );
  const statusFor = (pattern: RegExp) => {
    if (readiness.blocked_reasons.some((reason) => pattern.test(reason))) {
      return "blocked" as const;
    }
    if (readiness.degraded_reasons.some((reason) => pattern.test(reason))) {
      return "degraded" as const;
    }
    return readiness.level === "strong" ? ("strong" as const) : ("degraded" as const);
  };
  const journalStatus = /ebpf|journal/i.test(allReasons)
    ? statusFor(/ebpf|journal/i)
    : readiness.level === "strong"
      ? "strong"
      : "degraded";

  return [
    {
      label: "Write blocking",
      level: statusFor(/landlock|write/i),
      message:
        readiness.level === "strong"
          ? "Host checks show Warder can apply core write-blocking controls."
          : "Review Landlock/write-blocking readiness before relying on strict protection.",
    },
    {
      label: "Session attribution",
      level: statusFor(/cgroup/i),
      message: "Warder uses session attribution to connect launch, journals, and receipts.",
    },
    {
      label: "Snapshots",
      level: statusFor(/btrfs|snapshot/i),
      message: "Snapshots are optional recovery support for project work.",
    },
    {
      label: "Journals",
      level: journalStatus,
      message: "File and network journals are review evidence, not enforcement.",
    },
  ];
}
