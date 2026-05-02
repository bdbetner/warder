import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import { formatShellCommand, splitCommand } from "../command";
import type { LaunchRequest, LaunchSessionResult } from "../types";

const COMMAND_STATE_KEY = "warder.desktop.launchCommand.v1";

function launchRequest(
  commandText: string,
  configPath: string,
  dbPath: string,
  requireEnforcement: boolean,
): LaunchRequest {
  return {
    config_path: configPath,
    db_path: dbPath,
    agent_id: "local-agent",
    command: splitCommand(commandText),
    require_enforcement: requireEnforcement,
    accept_degraded: !requireEnforcement,
  };
}

interface SessionLauncherProps {
  configPath: string;
  dbPath: string;
  hasProtectedPaths: boolean;
  requireEnforcement: boolean;
}

export function SessionLauncher({
  configPath,
  dbPath,
  hasProtectedPaths,
  requireEnforcement,
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
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    window.localStorage.setItem(COMMAND_STATE_KEY, command);
  }, [command]);

  async function runDryRun() {
    setError(null);
    setLaunchResult(null);
    if (!hasProtectedPaths) {
      setError("select at least one protected path before launching a session");
      return;
    }
    try {
      const request = launchRequest(command, configPath, dbPath, requireEnforcement);
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
    } catch (reason) {
      setError(String(reason));
    }
  }

  async function runProtectedSession() {
    setError(null);
    if (!hasProtectedPaths) {
      setError("select at least one protected path before launching a session");
      return;
    }
    setRunning(true);
    try {
      const request = launchRequest(command, configPath, dbPath, requireEnforcement);
      const readiness = await invoke<string>("launch_readiness_text", {
        request,
      });
      setLaunchReadiness(readiness);
      const result = await invoke<LaunchSessionResult>("launch_session_command", {
        request,
      });
      setLaunchResult(result);
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
      {requireEnforcement && (
        <p className="notice">
          Strict write-block launch is enabled. Warder will refuse to start if
          protected writes cannot be blocked.
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
      <label className="field">
        Command
        <input
          value={command}
          placeholder="true"
          onChange={(event) => setCommand(event.target.value)}
        />
      </label>
      <div className="toolbar">
        <button disabled={!hasProtectedPaths} onClick={runDryRun}>
          Dry run
        </button>
        <button
          className="primary"
          disabled={running || !hasProtectedPaths}
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
