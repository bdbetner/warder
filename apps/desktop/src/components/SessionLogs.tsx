import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import type { RecentSessionSummary } from "../types";

const DB_PATH = ".warder/warder.sqlite3";
const SESSION_ID_STATE_KEY = "warder.desktop.sessionId.v1";

export function SessionLogs() {
  const [sessionId, setSessionId] = useState(
    () => window.localStorage.getItem(SESSION_ID_STATE_KEY) ?? "",
  );
  const [sessions, setSessions] = useState<RecentSessionSummary[]>([]);
  const [receipt, setReceipt] = useState("");
  const [journals, setJournals] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void refreshSessions();
  }, []);

  useEffect(() => {
    window.localStorage.setItem(SESSION_ID_STATE_KEY, sessionId);
  }, [sessionId]);

  async function refreshSessions() {
    setError(null);
    try {
      const items = await invoke<RecentSessionSummary[]>("recent_sessions", {
        dbPath: DB_PATH,
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
    setJournals("");
    try {
      const output = await invoke<string>("session_receipt_text", {
        dbPath: DB_PATH,
        sessionId: id,
      });
      setSessionId(id);
      setReceipt(output);
    } catch (reason) {
      setError(String(reason));
    }
  }

  async function loadJournals(id = sessionId) {
    setError(null);
    setReceipt("");
    setJournals("");
    try {
      const output = await invoke<string>("session_journals_text", {
        dbPath: DB_PATH,
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
      {receipt && (
        <div className="result-card">
          <div className="result-header">
            <strong>Receipt</strong>
            <span className="badge">{sessionId || "manual"}</span>
          </div>
          <pre className="output">{receipt}</pre>
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
