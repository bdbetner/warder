import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import App from "./App";

const { invokeMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: invokeMock,
}));

const recommendedProtections = [
  {
    id: "system-etc",
    label: "System config",
    path: "/etc",
    kind: "vital-system",
    access: "write-only",
    reason: "Core OS configuration.",
    exists: true,
    enabled_by_default: true,
  },
];

const profileTemplates = [
  {
    id: "codex-cli",
    declared_command: "codex",
    summary: "known local CLI agent",
    preflight: "confirm Codex workspace settings",
    effect: "transparent preset only",
    template: {
      recommended_protected_paths: [
        {
          label: "SSH keys",
          path: "$HOME/.ssh",
          resolved_path: "/home/alex/.ssh",
          read: true,
          write: true,
        },
      ],
      writable_roots: ["/home/alex/project"],
      network_journal: true,
      snapshot: "best-effort",
    },
  },
];

const recentSessions = [
  {
    id: "session-smoke",
    status: "completed",
    command: "true",
    started_at_unix_seconds: 1_777_400_000,
    file_journal_events: 2,
    network_journal_events: 0,
    degraded_reasons: 1,
  },
];

function installInvokeMock() {
  invokeMock.mockImplementation((command: string) => {
    switch (command) {
      case "load_recommended_protections":
        return Promise.resolve(recommendedProtections);
      case "load_profile_template_catalog":
        return Promise.resolve(profileTemplates);
      case "desktop_default_paths":
        return Promise.resolve({
          project_root: "/home/alex/project",
          config_path: "/home/alex/project/.warder/gui.toml",
          db_path: "/home/alex/project/.warder/warder.sqlite3",
        });
      case "save_gui_config":
        return Promise.resolve(undefined);
      case "host_readiness_summary":
        return Promise.resolve({
          level: "degraded",
          summary:
            "host readiness: degraded\nblocked reasons: none\ndegraded reasons:\n- Btrfs snapshots unavailable",
          blocked_reasons: [],
          degraded_reasons: ["Btrfs snapshots unavailable"],
        });
      case "dry_run_text":
        return Promise.resolve("dry run\nvalidation: ok");
      case "build_launch_command":
        return Promise.resolve(["warder", "run", "--launch", "--", "true"]);
      case "launch_readiness_text":
        return Promise.resolve(
          "host readiness: degraded\nlaunch readiness: degraded\nlaunch decision: degraded launch accepted by --accept-degraded",
        );
      case "launch_session_command":
        return Promise.resolve({
          session_id: "session-smoke",
          exit_code: 0,
          validation_warnings: [],
          receipt: "session: session-smoke\nstatus: completed",
        });
      case "recent_sessions":
        return Promise.resolve(recentSessions);
      case "session_receipt_text":
        return Promise.resolve("session: session-smoke\nstatus: completed");
      case "session_receipt_json":
        return Promise.resolve(
          JSON.stringify({
            session_id: "session-smoke",
            status: "completed",
            exit_code: 0,
            command: ["true"],
            protected_zones: ["protected"],
            limitations: [
              "Protected-path reads are not blocked in this alpha.",
              "Receipts are accountability records, not tamper-proof forensics.",
            ],
            enforcement: {
              cgroup: { status: "degraded", message: null, path: null, backend: null, snapshot_id: null },
              landlock: { status: "degraded", message: null, path: null, backend: null, snapshot_id: null },
              snapshot: { status: "not_requested", message: null, path: null, backend: null, snapshot_id: null },
            },
            file_activity: { total_events: 2, zones: { protected: 2 }, sources: { inotify: 2 }, attribution: {} },
            network_activity: { total_events: 0, destinations: {}, protocols: {}, sources: {}, attribution: {} },
            readiness: { level: "degraded", blocked_reasons: [], degraded_reasons: ["Landlock unavailable"] },
            degraded_coverage: { total_reasons: 1 },
            degraded_reasons: ["Landlock unavailable"],
            recovery_actions: [],
          }),
        );
      case "session_journals_text":
        return Promise.resolve("file journal: 2 event(s)");
      default:
        throw new Error(`unexpected invoke: ${command}`);
    }
  });
}

describe("Warder desktop smoke flow", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    window.localStorage.clear();
    installInvokeMock();
  });

  afterEach(() => {
    cleanup();
  });

  test("drives setup, dry-run, launch, receipt, and journal readback from the app surface", async () => {
    const user = userEvent.setup();
    render(<App />);

    await screen.findByRole("heading", { name: "Choose an agent profile" });
    expect(screen.getByDisplayValue("/home/alex/.ssh")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Save setup" }));

    await screen.findByRole("heading", {
      name: "Protected sessions for local agent work",
    });
    const readinessPanel = screen
      .getByText("Host readiness")
      .closest("section");
    expect(readinessPanel).not.toBeNull();
    expect(
      within(readinessPanel as HTMLElement).getByRole("heading", {
        name: "degraded",
      }),
    ).toBeInTheDocument();
    expect(
      within(readinessPanel as HTMLElement).getByLabelText(
        "Warder doctor summary",
      ),
    ).toHaveTextContent("Btrfs snapshots unavailable");
    expect(
      screen.getByRole("button", { name: "Run protected session" }),
    ).toBeDisabled();

    await user.click(screen.getByRole("button", { name: "Dry run" }));
    expect(await screen.findByText(/launch readiness: degraded/)).toBeInTheDocument();
    expect(await screen.findByText(/validation: ok/)).toBeInTheDocument();
    expect(screen.getByText(/warder run --launch/)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Run protected session" }),
    ).toBeEnabled();

    await user.click(screen.getByRole("button", { name: "Run protected session" }));
    expect(await screen.findByText(/session-smoke finished/)).toBeInTheDocument();

    const logViewer = screen
      .getByRole("heading", { name: "Session history" })
      .closest("section");
    expect(logViewer).not.toBeNull();
    const logs = within(logViewer as HTMLElement);

    await user.click(await logs.findByRole("button", { name: /session-smoke/ }));
    await user.click(await logs.findByRole("button", { name: "Raw Receipt" }));
    expect(await logs.findByText(/status: completed/)).toBeInTheDocument();

    await user.click(logs.getByRole("button", { name: "Load journals" }));
    expect(await logs.findByText(/file journal: 2 event/)).toBeInTheDocument();
  });

  test("restores completed setup state on launch", async () => {
    window.localStorage.setItem(
      "warder.desktop.state.v1",
      JSON.stringify({
        setupComplete: true,
        selectedProfileId: "codex-cli",
        agentCommand: "codex",
        networkJournal: true,
        requireEnforcement: false,
        configPath: "/home/alex/project/.warder/gui.toml",
        dbPath: "/home/alex/project/.warder/warder.sqlite3",
        protectedPaths: [
          {
            ...recommendedProtections[0],
            selected: false,
            readProtected: false,
            writeProtected: false,
            snapshotProtected: false,
          },
          {
            id: "template-codex-cli-home-alex-ssh",
            label: "SSH keys",
            path: "/home/alex/.ssh",
            kind: "sensitive-user",
            access: "read-write",
            reason: "Recommended by the codex-cli setup template.",
            exists: true,
            enabled_by_default: true,
            selected: false,
            readProtected: false,
            writeProtected: false,
            snapshotProtected: true,
          },
        ],
      }),
    );

    render(<App />);

    await screen.findByRole("heading", {
      name: "Protected sessions for local agent work",
    });
    expect(
      screen.queryByRole("heading", { name: "Choose an agent profile" }),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/0 paths selected/)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Start protected session" }),
    ).toBeDisabled();
    expect(screen.getByRole("button", { name: "Review readiness" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Dry run" })).toBeDisabled();
  });

  test("does not save setup without a protected path", async () => {
    const user = userEvent.setup();
    render(<App />);

    await screen.findByRole("heading", { name: "Choose an agent profile" });
    const systemRow = screen.getByDisplayValue("/etc").closest("article");
    const sshRow = screen.getByDisplayValue("/home/alex/.ssh").closest("article");
    expect(systemRow).not.toBeNull();
    expect(sshRow).not.toBeNull();
    await user.click(within(systemRow as HTMLElement).getAllByRole("checkbox")[0]);
    await user.click(within(sshRow as HTMLElement).getAllByRole("checkbox")[0]);
    await user.click(screen.getByRole("button", { name: "Save setup" }));

    expect(
      await screen.findByText(/Select at least one protected path/),
    ).toBeInTheDocument();
    expect(invokeMock).not.toHaveBeenCalledWith(
      "save_gui_config",
      expect.anything(),
    );
  });
});
