import type { ProtectedPathSelection } from "../types";
import { ProtectionContract } from "./ProtectionContract";

interface DashboardProps {
  paths: ProtectedPathSelection[];
  requireEnforcement: boolean;
  networkJournal: boolean;
  onRunSetup: () => void;
  onStartSession: () => void;
}

export function Dashboard({
  paths,
  requireEnforcement,
  networkJournal,
  onRunSetup,
  onStartSession,
}: DashboardProps) {
  const enabled = paths.filter((path) => path.selected);
  const secretCount = enabled.filter((path) => path.kind === "sensitive-user").length;
  const systemCount = enabled.filter((path) => path.kind === "vital-system").length;

  return (
    <section className="panel clean-dashboard">
      <div className="dashboard-intro">
        <p className="eyebrow">Home</p>
        <h1>Run an agent without giving it the whole machine.</h1>
        <p className="lead">
          Warder starts the agent, protects the folders you choose, and gives
          you a receipt when the session is done.
        </p>
      </div>

      <div className="status-card protected">
        <span className="status-dot" aria-hidden="true" />
        <div>
          <strong>{enabled.length > 0 ? "Ready to launch" : "Setup needed"}</strong>
          <span>
            {enabled.length > 0
              ? `${enabled.length} folder${enabled.length === 1 ? "" : "s"} protected`
              : "Choose protected folders before starting a session"}
          </span>
        </div>
      </div>

      <ProtectionContract
        protectedPathCount={enabled.length}
        requireEnforcement={requireEnforcement}
        networkJournal={networkJournal}
      />

      <div className="action-grid">
        <button
          className="primary action-card"
          disabled={enabled.length === 0}
          onClick={onStartSession}
        >
          <strong>Start protected session</strong>
          <span>Review readiness, then launch your agent.</span>
        </button>
        <button className="action-card" onClick={onRunSetup}>
          <strong>Edit protected folders</strong>
          <span>Change agent profile or protection defaults.</span>
        </button>
        <a className="action-card" href="#session-history">
          <strong>Review last run</strong>
          <span>Open receipts and journals from recent sessions.</span>
        </a>
      </div>

      <div className="plain-summary-grid dashboard-summary">
        <div>
          <strong>{secretCount}</strong>
          <span>credential or user folders</span>
        </div>
        <div>
          <strong>{systemCount}</strong>
          <span>system safeguards</span>
        </div>
        <div>
          <strong>Session only</strong>
          <span>direct launches are not supervised</span>
        </div>
      </div>
    </section>
  );
}
