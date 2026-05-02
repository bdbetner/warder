interface ProtectionContractProps {
  protectedPathCount: number;
  requireEnforcement: boolean;
  networkJournal: boolean;
  compact?: boolean;
}

export function ProtectionContract({
  protectedPathCount,
  requireEnforcement,
  networkJournal,
  compact = false,
}: ProtectionContractProps) {
  return (
    <section className={compact ? "protection-contract compact" : "protection-contract"}>
      <div>
        <p className="eyebrow">Protection contract</p>
        <h2>What Warder will do</h2>
      </div>
      <div className="contract-grid">
        <div>
          <strong>Protected this session</strong>
          <ul>
            <li>
              {protectedPathCount} saved folder
              {protectedPathCount === 1 ? "" : "s"} protected from writes
            </li>
            <li>
              {requireEnforcement
                ? "Strict launch stops if write blocking is unavailable"
                : "Best-effort launch can continue with degraded protection"}
            </li>
          </ul>
        </div>
        <div>
          <strong>Observed, not blocked</strong>
          <ul>
            <li>
              {networkJournal
                ? "Network activity is recorded when host support is available"
                : "Network journal is off for this profile"}
            </li>
            <li>Receipts summarize file, network, and degraded coverage</li>
          </ul>
        </div>
        <div>
          <strong>Not covered</strong>
          <ul>
            <li>Direct launches outside Warder are not supervised</li>
            <li>Read blocking is experimental and off unless explicitly configured</li>
          </ul>
        </div>
      </div>
    </section>
  );
}
