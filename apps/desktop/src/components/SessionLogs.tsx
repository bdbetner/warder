import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import type { RecentSessionSummary, StructuredReceipt } from "../types";

const SESSION_ID_STATE_KEY = "warder.desktop.sessionId.v1";
type ReceiptTab = "summary" | "file" | "network" | "snapshot" | "degraded" | "raw";

const receiptTabs: { id: ReceiptTab; label: string }[] = [
  { id: "summary", label: "Summary" },
  { id: "file", label: "File Activity" },
  { id: "network", label: "Network Activity" },
  { id: "snapshot", label: "Snapshot/Recovery" },
  { id: "degraded", label: "Degraded Coverage" },
  { id: "raw", label: "Raw Receipt" },
];

export function SessionLogs({ dbPath }: { dbPath: string }) {
  const [sessionId, setSessionId] = useState(
    () => window.localStorage.getItem(SESSION_ID_STATE_KEY) ?? "",
  );
  const [sessions, setSessions] = useState<RecentSessionSummary[]>([]);
  const [receipt, setReceipt] = useState("");
  const [structuredReceipt, setStructuredReceipt] = useState<StructuredReceipt | null>(null);
  const [journals, setJournals] = useState("");
  const [receiptTab, setReceiptTab] = useState<ReceiptTab>("summary");
  const [recoveryOutput, setRecoveryOutput] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void refreshSessions();
  }, [dbPath]);

  useEffect(() => {
    window.localStorage.setItem(SESSION_ID_STATE_KEY, sessionId);
  }, [sessionId]);

  async function refreshSessions() {
    setError(null);
    try {
      const items = await invoke<RecentSessionSummary[]>("recent_sessions", {
        dbPath,
        limit: 20,
      });
      setSessions(items);
    } catch (reason) {
      setError(String(reason));
    }
  }

  async function loadReceipt(id = sessionId) {
    setError(null);
    setReceipt("");
    setStructuredReceipt(null);
    setJournals("");
    setRecoveryOutput("");
    try {
      const [output, structured] = await Promise.all([
        invoke<string>("session_receipt_text", {
          dbPath,
          sessionId: id,
        }),
        invoke<string>("session_receipt_json", {
          dbPath,
          sessionId: id,
        }),
      ]);
      const parsed = JSON.parse(structured) as StructuredReceipt;
      setSessionId(id);
      setReceipt(output);
      setStructuredReceipt(parsed);
      setReceiptTab("summary");
    } catch (reason) {
      setError(String(reason));
    }
  }

  async function previewSnapshotRestore() {
    const snapshot = structuredReceipt?.enforcement.snapshot;
    if (!snapshot?.snapshot_id || !snapshot.path) {
      setError("receipt does not expose a snapshot restore preview");
      return;
    }
    setError(null);
    setRecoveryOutput("");
    try {
      const output = await invoke<string>("snapshot_revert_preview", {
        snapshotRoot: snapshot.path,
        snapshotId: snapshot.snapshot_id,
      });
      setRecoveryOutput(output);
    } catch (reason) {
      setError(String(reason));
    }
  }

  async function restoreSnapshot() {
    const snapshot = structuredReceipt?.enforcement.snapshot;
    if (!snapshot?.snapshot_id || !snapshot.path) {
      setError("receipt does not expose a guarded snapshot restore");
      return;
    }
    setError(null);
    setRecoveryOutput("");
    try {
      const output = await invoke<string>("snapshot_revert_session", {
        dbPath,
        sessionId,
        snapshotRoot: snapshot.path,
        snapshotId: snapshot.snapshot_id,
      });
      await refreshSessions();
      await loadReceipt(sessionId);
      setReceiptTab("snapshot");
      setRecoveryOutput(output);
    } catch (reason) {
      setError(String(reason));
    }
  }

  async function loadJournals(id = sessionId) {
    setError(null);
    setReceipt("");
    setStructuredReceipt(null);
    setJournals("");
    setRecoveryOutput("");
    try {
      const output = await invoke<string>("session_journals_text", {
        dbPath,
        sessionId: id,
      });
      setSessionId(id);
      setJournals(output);
    } catch (reason) {
      setError(String(reason));
    }
  }

  return (
    <section className="panel">
      <p className="eyebrow">Receipts and logs</p>
      <h2>Session history</h2>
      <p className="muted">
        Receipts remain the primary log surface. File and network journal
        details appear inside each session receipt when Warder recorded them.
      </p>
      <div className="session-list">
        <div className="toolbar">
          <strong>Recent sessions</strong>
          <button onClick={refreshSessions}>Refresh</button>
        </div>
        {sessions.length === 0 ? (
          <div className="empty-state compact">
            <strong>No sessions recorded</strong>
            <p>Run a protected session and its receipt will appear here.</p>
          </div>
        ) : (
          sessions.map((session) => (
            <button
              className="session-row"
              key={session.id}
              onClick={() => loadReceipt(session.id)}
            >
              <span>
                <strong>{session.id}</strong>
                <small>{session.command}</small>
                <span className="session-meta">
                  <small>file {session.file_journal_events}</small>
                  <small>network {session.network_journal_events}</small>
                  <small>degraded {session.degraded_reasons}</small>
                </span>
              </span>
              <span className={`badge status-${session.status}`}>
                {session.status}
              </span>
            </button>
          ))
        )}
      </div>
      <label className="field">
        Session ID
        <input value={sessionId} onChange={(event) => setSessionId(event.target.value)} />
      </label>
      <div className="toolbar">
        <button onClick={() => loadReceipt()}>Load receipt</button>
        <button onClick={() => loadJournals()}>Load journals</button>
      </div>
      {error && <pre className="output error">{error}</pre>}
      {structuredReceipt && receipt && (
        <div className="result-card">
          <div className="result-header">
            <strong>Receipt</strong>
            <span className="badge">{sessionId || "manual"}</span>
          </div>
          <div className="tabs">
            {receiptTabs.map((tab) => (
              <button
                className={receiptTab === tab.id ? "active" : ""}
                key={tab.id}
                onClick={() => setReceiptTab(tab.id)}
              >
                {tab.label}
              </button>
            ))}
          </div>
          <ReceiptTabPanel
            dbPath={dbPath}
            receipt={structuredReceipt}
            rawReceipt={receipt}
            tab={receiptTab}
            onPreviewSnapshotRestore={previewSnapshotRestore}
            onRestoreSnapshot={restoreSnapshot}
          />
          {recoveryOutput && <pre className="output">{recoveryOutput}</pre>}
        </div>
      )}
      {journals && (
        <div className="result-card">
          <div className="result-header">
            <strong>Journals</strong>
            <span className="badge">{sessionId || "manual"}</span>
          </div>
          <pre className="output">{journals}</pre>
        </div>
      )}
    </section>
  );
}

function ReceiptTabPanel({
  dbPath,
  receipt,
  rawReceipt,
  tab,
  onPreviewSnapshotRestore,
  onRestoreSnapshot,
}: {
  dbPath: string;
  receipt: StructuredReceipt;
  rawReceipt: string;
  tab: ReceiptTab;
  onPreviewSnapshotRestore: () => void;
  onRestoreSnapshot: () => void;
}) {
  if (tab === "raw") {
    return <pre className="output">{rawReceipt}</pre>;
  }
  if (tab === "file") {
    return (
      <div className="receipt-grid">
        <Metric label="Events" value={receipt.file_activity.total_events} />
        <KeyValueList title="Zones" values={receipt.file_activity.zones} />
        <KeyValueList title="Sources" values={receipt.file_activity.sources} />
        <KeyValueList title="Attribution" values={receipt.file_activity.attribution} />
      </div>
    );
  }
  if (tab === "network") {
    return (
      <div className="receipt-grid">
        <Metric label="Events" value={receipt.network_activity.total_events} />
        <KeyValueList title="Destinations" values={receipt.network_activity.destinations} />
        <KeyValueList title="Protocols" values={receipt.network_activity.protocols} />
        <KeyValueList title="Sources" values={receipt.network_activity.sources} />
        <KeyValueList title="Attribution" values={receipt.network_activity.attribution} />
      </div>
    );
  }
  if (tab === "snapshot") {
    const snapshot = receipt.enforcement.snapshot;
    const canPreview = Boolean(snapshot.snapshot_id && snapshot.path);
    const canRestore = receipt.recovery_actions.some(
      (action) => action.kind === "restore_snapshot_guarded" && action.mutates,
    );
    return (
      <div className="receipt-detail">
        <dl>
          <div>
            <dt>Status</dt>
            <dd>{snapshot.status}</dd>
          </div>
          <div>
            <dt>Backend</dt>
            <dd>{snapshot.backend ?? "none"}</dd>
          </div>
          <div>
            <dt>Snapshot ID</dt>
            <dd>{snapshot.snapshot_id ?? "none"}</dd>
          </div>
          <div>
            <dt>Snapshot root</dt>
            <dd>{snapshot.path ?? "none"}</dd>
          </div>
        </dl>
        <div className="toolbar">
          <button disabled={!canPreview} onClick={onPreviewSnapshotRestore}>
            Preview revert
          </button>
          <button className="danger" disabled={!canRestore} onClick={onRestoreSnapshot}>
            Guarded revert
          </button>
        </div>
        <ActionList actions={receipt.recovery_actions} dbPath={dbPath} />
      </div>
    );
  }
  if (tab === "degraded") {
    return (
      <div className="receipt-detail">
        <Metric label="Reasons" value={receipt.degraded_coverage.total_reasons} />
        <TextList items={receipt.degraded_reasons} empty="No degraded coverage reported." />
        <TextList
          items={receipt.readiness.blocked_reasons}
          title="Blocked reasons"
          empty="No blocked readiness reasons."
        />
        <TextList
          items={receipt.readiness.degraded_reasons}
          title="Readiness degradation"
          empty="No readiness degradation."
        />
        <TextList
          items={receipt.limitations}
          title="Receipt limitations"
          empty="No receipt limitations reported."
        />
      </div>
    );
  }
  return (
    <div className="receipt-grid">
      <Metric label="Status" value={receipt.status} />
      <Metric label="Readiness" value={receipt.readiness.level} />
      <Metric label="Exit code" value={receipt.exit_code ?? "none"} />
      <Metric label="Protected zones" value={receipt.protected_zones.length} />
      <div className="receipt-detail wide">
        <h3>Command</h3>
        <code>{receipt.command.join(" ")}</code>
      </div>
      <div className="receipt-detail wide">
        <h3>Enforcement</h3>
        <dl>
          <StatusRow label="Cgroup" status={receipt.enforcement.cgroup.status} />
          <StatusRow label="Landlock" status={receipt.enforcement.landlock.status} />
          <StatusRow label="Snapshot" status={receipt.enforcement.snapshot.status} />
        </dl>
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function KeyValueList({ title, values }: { title: string; values: Record<string, number> }) {
  const entries = Object.entries(values);
  return (
    <div className="receipt-detail">
      <h3>{title}</h3>
      {entries.length === 0 ? (
        <p className="muted">No entries.</p>
      ) : (
        <dl>
          {entries.map(([key, value]) => (
            <StatusRow key={key} label={key} status={String(value)} />
          ))}
        </dl>
      )}
    </div>
  );
}

function ActionList({ actions, dbPath }: { actions: StructuredReceipt["recovery_actions"]; dbPath: string }) {
  return (
    <div className="receipt-detail wide">
      <h3>Recovery actions</h3>
      {actions.length === 0 ? (
        <p className="muted">No recovery action exposed by this receipt.</p>
      ) : (
        <ul>
          {actions.map((action) => (
            <li key={`${action.kind}-${action.command}`}>
              <strong>{action.label}</strong>
              {action.reason && <span>{action.reason}</span>}
              <code>{action.command.replace(dbPath, "<selected db>")}</code>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function TextList({
  items,
  title,
  empty,
}: {
  items: string[];
  title?: string;
  empty: string;
}) {
  return (
    <div className="receipt-detail wide">
      {title && <h3>{title}</h3>}
      {items.length === 0 ? (
        <p className="muted">{empty}</p>
      ) : (
        <ul>
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

function StatusRow({ label, status }: { label: string; status: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{status}</dd>
    </div>
  );
}
