import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import { formatShellCommand, splitCommand } from "../command";
import type { LaunchRequest, LaunchSessionResult } from "../types";
import { ProtectionContract } from "./ProtectionContract";

const COMMAND_STATE_KEY = "warder.desktop.launchCommand.v1";

function launchRequest(
  commandText: string,
  configPath: string,
  dbPath: string,
  requireEnforcement: boolean,
  receiptKeyPath: string,
  readinessReviewed: boolean,
): LaunchRequest {
  const cleanReceiptKeyPath = receiptKeyPath.trim();
  return {
    config_path: configPath,
    db_path: dbPath,
    agent_id: "local-agent",
    command: splitCommand(commandText),
    require_enforcement: requireEnforcement,
    receipt_key_path: cleanReceiptKeyPath ? cleanReceiptKeyPath : null,
    accept_degraded: !requireEnforcement,
    readiness_reviewed: readinessReviewed,
  };
}

interface SessionLauncherProps {
  configPath: string;
  dbPath: string;
  hasProtectedPaths: boolean;
  requireEnforcement: boolean;
  networkJournal: boolean;
  protectedPathCount: number;
  receiptKeyPath: string;
  showSupervisionScopeBanner: boolean;
  onReceiptKeyPathChange: (value: string) => void;
  onProtectedLaunchComplete: () => void;
}

export function SessionLauncher({
  configPath,
  dbPath,
  hasProtectedPaths,
  requireEnforcement,
  networkJournal,
  protectedPathCount,
  receiptKeyPath,
  showSupervisionScopeBanner,
  onReceiptKeyPathChange,
  onProtectedLaunchComplete,
}: SessionLauncherProps) {
  const [command, setCommand] = useState(
    () => window.localStorage.getItem(COMMAND_STATE_KEY) ?? "true",
  );
  const [dryRun, setDryRun] = useState("");
  const [launchResult, setLaunchResult] = useState<LaunchSessionResult | null>(
    null,
  );
  const [launchReadiness, setLaunchReadiness] = useState("");
  const [cliCommand, setCliCommand] = useState("");
  const [readinessReviewed, setReadinessReviewed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    window.localStorage.setItem(COMMAND_STATE_KEY, command);
  }, [command]);

  useEffect(() => {
    setReadinessReviewed(false);
  }, [command, configPath, dbPath, receiptKeyPath, requireEnforcement]);

  async function reviewLaunchReadiness() {
    setError(null);
    setLaunchResult(null);
    if (!hasProtectedPaths) {
      setError("select at least one protected path before launching a session");
      return;
    }
    try {
      const request = launchRequest(
        command,
        configPath,
        dbPath,
        requireEnforcement,
        receiptKeyPath,
        false,
      );
      const [readiness, cli] = await Promise.all([
        invoke<string>("launch_readiness_text", { request }),
        invoke<string[]>("build_launch_command", { request }),
      ]);
      setLaunchReadiness(readiness);
      setCliCommand(formatShellCommand(cli));
      setReadinessReviewed(true);
    } catch (reason) {
      setReadinessReviewed(false);
      setError(String(reason));
    }
  }

  async function runDryRun() {
    setError(null);
    setLaunchResult(null);
    if (!hasProtectedPaths) {
      setError("select at least one protected path before launching a session");
      return;
    }
    try {
      const request = launchRequest(
        command,
        configPath,
        dbPath,
        requireEnforcement,
        receiptKeyPath,
        false,
      );
      const [readiness, output, cli] = await Promise.all([
        invoke<string>("launch_readiness_text", { request }),
        invoke<string>("dry_run_text", {
          configPath,
          agentId: request.agent_id,
          command: request.command,
        }),
        invoke<string[]>("build_launch_command", { request }),
      ]);
      setLaunchReadiness(readiness);
      setDryRun(output);
      setCliCommand(formatShellCommand(cli));
      setReadinessReviewed(true);
    } catch (reason) {
      setReadinessReviewed(false);
      setError(String(reason));
    }
  }

  async function runProtectedSession() {
    setError(null);
    if (!hasProtectedPaths) {
      setError("select at least one protected path before launching a session");
      return;
    }
    if (!readinessReviewed) {
      setError("review launch readiness before starting this session");
      return;
    }
    setRunning(true);
    try {
      const request = launchRequest(
        command,
        configPath,
        dbPath,
        requireEnforcement,
        receiptKeyPath,
        true,
      );
      const readiness = await invoke<string>("launch_readiness_text", {
        request,
      });
      setLaunchReadiness(readiness);
      setReadinessReviewed(true);
      const result = await invoke<LaunchSessionResult>("launch_session_command", {
        request,
      });
      setLaunchResult(result);
      onProtectedLaunchComplete();
      setDryRun("");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setRunning(false);
    }
  }

  return (
    <section className="panel" id="session-launcher" tabIndex={-1}>
      <p className="eyebrow">Protected session</p>
      <h2>Launch through Warder</h2>
      <p className="muted">
        Commands run through Warder using the saved setup policy. Review dry-run
        warnings before starting a protected session.
      </p>
      <ProtectionContract
        compact
        protectedPathCount={protectedPathCount}
        requireEnforcement={requireEnforcement}
        networkJournal={networkJournal}
      />
      {showSupervisionScopeBanner && (
        <p className="notice strong-notice">
          Warder only supervises processes launched via warder run or this
          desktop launcher. Direct launches or processes started by malware are
          completely unsupervised.
        </p>
      )}
      {requireEnforcement && (
        <p className="notice">
          Strict launch is enabled. Warder will refuse to start if protected
          writes cannot be blocked or the external receipt key is unavailable.
        </p>
      )}
      {!requireEnforcement && (
        <p className="notice">
          Best-effort launch is enabled. Warder will pass the explicit degraded
          acknowledgement required by the CLI.
        </p>
      )}
      {!hasProtectedPaths && (
        <p className="notice">
          Select at least one protected path in setup before launching.
        </p>
      )}
      {hasProtectedPaths && !readinessReviewed && (
        <p className="notice">
          Review launch readiness before starting this session.
        </p>
      )}
      <label className="field">
        Command
        <input
          value={command}
          placeholder="true"
          onChange={(event) => setCommand(event.target.value)}
        />
      </label>
      <label className="field">
        Receipt key
        <input
          value={receiptKeyPath}
          placeholder="/run/user/<uid>/warder/receipt.key"
          onChange={(event) => onReceiptKeyPathChange(event.target.value)}
        />
      </label>
      <div className="toolbar">
        <button disabled={!hasProtectedPaths} onClick={reviewLaunchReadiness}>
          Review readiness
        </button>
        <button disabled={!hasProtectedPaths} onClick={runDryRun}>
          Dry run
        </button>
        <button
          className="primary"
          disabled={running || !hasProtectedPaths || !readinessReviewed}
          onClick={runProtectedSession}
        >
          {running ? "Running..." : "Run protected session"}
        </button>
      </div>
      {cliCommand && (
        <div className="command-copy">
          <strong>Equivalent CLI</strong>
          <code>{cliCommand}</code>
        </div>
      )}
      {error && <pre className="output error">{error}</pre>}
      {launchReadiness && (
        <div className="result-card">
          <div className="result-header">
            <strong>Launch readiness</strong>
            <span className="badge">Doctor</span>
          </div>
          <pre className="output">{launchReadiness}</pre>
        </div>
      )}
      {dryRun && (
        <div className="result-card">
          <div className="result-header">
            <strong>Dry-run result</strong>
            <span className="badge">Review</span>
          </div>
          <pre className="output">{dryRun}</pre>
        </div>
      )}
      {launchResult && (
        <div className="result-card">
          <div className="result-header">
            <strong>{launchResult.session_id} finished</strong>
            <span className="badge">
              exit {launchResult.exit_code ?? "unknown"}
            </span>
          </div>
          <pre className="output">{launchResult.receipt}</pre>
        </div>
      )}
    </section>
  );
}
