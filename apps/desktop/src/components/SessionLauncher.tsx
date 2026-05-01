import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import type { LaunchRequest, LaunchSessionResult } from "../types";

const CONFIG_PATH = ".warder/gui.toml";
const DB_PATH = ".warder/warder.sqlite3";
const COMMAND_STATE_KEY = "warder.desktop.launchCommand.v1";

function splitCommand(input: string): string[] {
  return input.split(" ").map((part) => part.trim()).filter(Boolean);
}

function launchRequest(commandText: string): LaunchRequest {
  return {
    config_path: CONFIG_PATH,
    db_path: DB_PATH,
    agent_id: "local-agent",
    command: splitCommand(commandText),
  };
}

export function SessionLauncher() {
  const [command, setCommand] = useState(
    () => window.localStorage.getItem(COMMAND_STATE_KEY) ?? "true",
  );
  const [dryRun, setDryRun] = useState("");
  const [launchResult, setLaunchResult] = useState<LaunchSessionResult | null>(
    null,
  );
  const [cliCommand, setCliCommand] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    window.localStorage.setItem(COMMAND_STATE_KEY, command);
  }, [command]);

  async function runDryRun() {
    setError(null);
    setLaunchResult(null);
    const request = launchRequest(command);
    try {
      const [output, cli] = await Promise.all([
        invoke<string>("dry_run_text", {
          configPath: CONFIG_PATH,
          agentId: request.agent_id,
          command: request.command,
        }),
        invoke<string[]>("build_launch_command", { request }),
      ]);
      setDryRun(output);
      setCliCommand(cli.join(" "));
    } catch (reason) {
      setError(String(reason));
    }
  }

  async function runProtectedSession() {
    setError(null);
    setRunning(true);
    const request = launchRequest(command);
    try {
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
      <label className="field">
        Command
        <input
          value={command}
          placeholder="true"
          onChange={(event) => setCommand(event.target.value)}
        />
      </label>
      <div className="toolbar">
        <button onClick={runDryRun}>Dry run</button>
        <button className="primary" disabled={running} onClick={runProtectedSession}>
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
