import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import type { LaunchRequest, LaunchSessionResult } from "../types";

const COMMAND_STATE_KEY = "warder.desktop.launchCommand.v1";

function splitCommand(input: string): string[] {
  const args: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;
  let escaped = false;

  for (const char of input) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if (quote) {
      if (char === quote) {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (/\s/.test(char)) {
      if (current) {
        args.push(current);
        current = "";
      }
      continue;
    }
    current += char;
  }

  if (escaped) {
    current += "\\";
  }
  if (quote) {
    throw new Error(`unterminated ${quote} quote in command`);
  }
  if (current) {
    args.push(current);
  }
  return args;
}

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
  };
}

interface SessionLauncherProps {
  configPath: string;
  dbPath: string;
  requireEnforcement: boolean;
}

export function SessionLauncher({
  configPath,
  dbPath,
  requireEnforcement,
}: SessionLauncherProps) {
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
    try {
      const request = launchRequest(command, configPath, dbPath, requireEnforcement);
      const [output, cli] = await Promise.all([
        invoke<string>("dry_run_text", {
          configPath,
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
    try {
      const request = launchRequest(command, configPath, dbPath, requireEnforcement);
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
