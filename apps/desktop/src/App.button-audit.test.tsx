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

type InvokeHandler = (args: Record<string, unknown>) => unknown;

const defaultPaths = {
  project_root: "/tmp/warder-gui-audit/project",
  config_path: "/tmp/warder-gui-audit/project/.warder/gui.toml",
  db_path: "/tmp/warder-gui-audit/project/.warder/warder.sqlite3",
  receipt_key_path: "/run/user/1000/warder/receipt.key",
};

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
  {
    id: "missing-browser",
    label: "Missing browser profile",
    path: "/home/alex/.config/missing-browser",
    kind: "sensitive-user",
    access: "read-write",
    reason: "Optional browser state.",
    exists: false,
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
  {
    id: "claude-code",
    declared_command: "claude",
    summary: "known local CLI agent for Claude Code",
    preflight: "confirm Claude workspace settings",
    effect: "transparent preset only",
    template: {
      recommended_protected_paths: [],
      writable_roots: ["/home/alex/project"],
      network_journal: true,
      snapshot: "best-effort",
    },
  },
  {
    id: "openclaw-agent",
    declared_command: "openclaw agent",
    summary: "OpenClaw agent run",
    preflight: "confirm OpenClaw policy",
    effect: "transparent preset only",
    template: {
      recommended_protected_paths: [],
      writable_roots: ["/home/alex/project"],
      network_journal: true,
      snapshot: "best-effort",
    },
  },
  {
    id: "generic-cli",
    declared_command: "<command>",
    summary: "generic local CLI command",
    preflight: "confirm declared command",
    effect: "transparent preset only",
    template: {
      recommended_protected_paths: [
        {
          label: "Netrc credentials",
          path: "$HOME/.netrc",
          resolved_path: "/home/alex/.netrc",
          read: true,
          write: true,
        },
      ],
      writable_roots: [],
      network_journal: false,
      snapshot: "disabled",
    },
  },
];

const recentSessions = [
  {
    id: "session-audit",
    status: "completed",
    command: "true",
    started_at_unix_seconds: 1_777_400_000,
    file_journal_events: 2,
    network_journal_events: 1,
    degraded_reasons: 1,
  },
];

function structuredReceipt(snapshot = true) {
  return {
    session_id: "session-audit",
    status: "completed",
    exit_code: 0,
    command: ["true"],
    protected_zones: ["system-etc"],
    limitations: [
      "Warder only supervises processes launched via warder run or this desktop launcher.",
    ],
    enforcement: {
      cgroup: {
        status: "applied",
        message: null,
        path: "/sys/fs/cgroup/warder/session-audit",
        backend: null,
        snapshot_id: null,
      },
      landlock: {
        status: "applied",
        message: null,
        path: null,
        backend: null,
        snapshot_id: null,
      },
      snapshot: {
        status: snapshot ? "created" : "not_requested",
        message: null,
        path: snapshot ? "/tmp/warder-gui-audit/snapshots" : null,
        backend: snapshot ? "btrfs" : null,
        snapshot_id: snapshot ? "snap-session-audit" : null,
      },
    },
    file_activity: {
      total_events: 2,
      zones: { "system-etc": 2 },
      sources: { inotify: 2 },
      attribution: { "session-window": 2 },
    },
    network_activity: {
      total_events: 1,
      destinations: { "127.0.0.1:443": 1 },
      protocols: { tcp: 1 },
      sources: { procfs: 1 },
      attribution: { "session-window": 1 },
    },
    readiness: {
      level: "degraded",
      blocked_reasons: [],
      degraded_reasons: ["Btrfs snapshots unavailable"],
    },
    degraded_coverage: { total_reasons: 1 },
    degraded_reasons: ["Btrfs snapshots unavailable"],
    recovery_actions: snapshot
      ? [
          {
            kind: "restore_snapshot_guarded",
            label: "Guarded revert",
            command:
              "warder revert --db /tmp/warder-gui-audit/project/.warder/warder.sqlite3 --session session-audit",
            command_argv: ["warder", "revert"],
            mutates: true,
            reason: "snapshot available",
          },
        ]
      : [],
  };
}

function installInvokeMock(overrides: Record<string, InvokeHandler> = {}) {
  invokeMock.mockImplementation(
    (command: string, args: Record<string, unknown> = {}) => {
      if (overrides[command]) {
        return Promise.resolve(overrides[command](args));
      }
      switch (command) {
        case "desktop_default_paths":
          return Promise.resolve(defaultPaths);
        case "load_recommended_protections":
          return Promise.resolve(recommendedProtections);
        case "load_profile_template_catalog":
          return Promise.resolve(profileTemplates);
        case "save_gui_config":
          return Promise.resolve(undefined);
        case "host_readiness_summary":
          return Promise.resolve({
            level: "degraded",
            summary:
              "host readiness: degraded\nsupervision scope: Warder-launched sessions only",
            blocked_reasons: [],
            degraded_reasons: ["Btrfs snapshots unavailable"],
          });
        case "launch_readiness_text":
          return Promise.resolve(
            "host readiness: degraded\nlaunch readiness: degraded",
          );
        case "build_launch_command":
          return Promise.resolve(["warder", "run", "--launch", "--", "true"]);
        case "dry_run_text":
          return Promise.resolve("dry run\nvalidation: ok");
        case "launch_session_command":
          return Promise.resolve({
            session_id: "session-audit",
            exit_code: 0,
            validation_warnings: [],
            receipt: "session: session-audit\nstatus: completed",
          });
        case "recent_sessions":
          return Promise.resolve(recentSessions);
        case "session_receipt_text":
          return Promise.resolve("session: session-audit\nstatus: completed");
        case "session_receipt_json":
          return Promise.resolve(JSON.stringify(structuredReceipt()));
        case "session_journals_text":
          return Promise.resolve("file journal: 2 event(s)\nnetwork journal: 1 event(s)");
        case "snapshot_revert_preview":
          return Promise.resolve("revert preview: would restore 1 root");
        case "snapshot_revert_session":
          return Promise.resolve("guarded revert completed");
        default:
          throw new Error(`unexpected invoke: ${command}`);
      }
    },
  );
}

function persistCompletedSetup(protectedLaunchCount = 3) {
  window.localStorage.setItem(
    "warder.desktop.state.v1",
    JSON.stringify({
      setupComplete: true,
      selectedProfileId: "codex-cli",
      agentCommand: "codex",
      networkJournal: true,
      requireEnforcement: false,
      receiptKeyPath: "/run/user/1000/warder/receipt.key",
      protectedLaunchCount,
      configPath: defaultPaths.config_path,
      dbPath: defaultPaths.db_path,
      protectedPaths: [
        {
          ...recommendedProtections[0],
          selected: true,
          readProtected: false,
          writeProtected: true,
          snapshotProtected: false,
        },
      ],
    }),
  );
}

describe("Warder closed GUI button audit", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    window.localStorage.clear();
    installInvokeMock();
  });

  afterEach(() => {
    cleanup();
  });

  test("setup wizard buttons update policy state and save only through mocked IPC", async () => {
    const user = userEvent.setup();
    render(<App />);

    await screen.findByRole("heading", { name: "Set up your first protected agent" });
    expect(screen.getByRole("button", { name: /Codex/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Claude/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /OpenClaw/ })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Claude/ }));
    expect(screen.getByLabelText("Agent command")).toHaveValue("claude");
    await user.click(screen.getByRole("button", { name: /OpenClaw/ }));
    expect(screen.getByLabelText("Agent command")).toHaveValue("openclaw agent");
    await user.click(screen.getByRole("button", { name: /Codex/ }));
    expect(screen.getByLabelText("Agent command")).toHaveValue("codex");

    await user.click(screen.getByText("Advanced agent profiles"));
    await user.selectOptions(screen.getByLabelText("Agent profile"), "generic-cli");
    expect(screen.getByLabelText("Agent command")).toHaveValue("sh");

    await user.click(screen.getByRole("button", { name: "Continue" }));
    const missingRow = screen.getByText("Missing browser profile").closest("article");
    expect(missingRow).not.toBeNull();
    expect(within(missingRow as HTMLElement).getAllByRole("checkbox")[0]).not.toBeChecked();
    expect(within(missingRow as HTMLElement).getAllByRole("checkbox")[0]).toBeDisabled();

    expect(screen.getByText("Netrc credentials")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Save profile/ }));
    expect(screen.getByRole("heading", { name: "Save your protected profile" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Back" }));
    expect(screen.getByRole("heading", { name: "What should Warder protect?" })).toBeInTheDocument();
    await user.clear(screen.getByLabelText("Add folder"));
    await user.type(screen.getByLabelText("Add folder"), "/tmp/warder gui/custom secrets");
    await user.type(screen.getByLabelText("Label"), "Custom secrets");
    await user.click(screen.getByRole("button", { name: "Add folder" }));
    const customRow = screen.getByText("Custom secrets").closest("article");
    expect(customRow).not.toBeNull();

    await user.click(screen.getByText("Advanced protection options"));
    const customAdvancedRow = screen
      .getByDisplayValue("/tmp/warder gui/custom secrets")
      .closest("article");
    expect(customAdvancedRow).not.toBeNull();
    await user.click(
      within(customAdvancedRow as HTMLElement).getByRole("button", { name: "Snapshot" }),
    );
    await user.click(
      within(customAdvancedRow as HTMLElement).getByRole("button", { name: "Remove" }),
    );
    expect(
      screen.queryByDisplayValue("/tmp/warder gui/custom secrets"),
    ).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.click(
      screen.getByRole("checkbox", {
        name: "Refuse launch if write blocking is unavailable",
      }),
    );
    await user.click(
      screen.getByRole("checkbox", { name: "Record network journal when supported" }),
    );
    await user.click(screen.getByText("Advanced storage paths"));
    await user.clear(screen.getByLabelText("Config path"));
    await user.type(screen.getByLabelText("Config path"), "/tmp/warder gui/config.toml");
    await user.click(screen.getByRole("button", { name: "Save profile" }));

    expect(invokeMock).toHaveBeenCalledWith("save_gui_config", {
      configPath: "/tmp/warder gui/config.toml",
      draft: expect.objectContaining({
        network_journal: true,
        agent: expect.objectContaining({
          command: "sh",
          profile: "generic-cli",
        }),
        protected_paths: expect.not.arrayContaining([
          expect.objectContaining({ id: "missing-browser" }),
        ]),
      }),
    });
    expect(
      await screen.findByRole("heading", {
        name: "Run an agent without giving it the whole machine.",
      }),
    ).toBeInTheDocument();
  });

  test("launcher buttons require readiness review and reset when inputs change", async () => {
    persistCompletedSetup();
    const user = userEvent.setup();
    render(<App />);

    await screen.findByRole("heading", {
      name: "Run an agent without giving it the whole machine.",
    });
    await user.click(screen.getByRole("button", { name: /Start protected session/ }));
    expect(document.activeElement).toHaveAttribute("id", "session-launcher");
    expect(
      screen.getByRole("button", { name: "Run protected session" }),
    ).toBeDisabled();

    await user.click(screen.getByRole("button", { name: "Review readiness" }));
    expect(await screen.findByText(/launch readiness: degraded/)).toBeInTheDocument();
    expect(screen.getByText(/warder run --launch/)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Run protected session" }),
    ).toBeEnabled();

    await user.clear(screen.getByLabelText("Command"));
    await user.type(screen.getByLabelText("Command"), "sh -c 'echo closed'");
    expect(
      screen.getByRole("button", { name: "Run protected session" }),
    ).toBeDisabled();

    await user.click(screen.getByRole("button", { name: "Dry run" }));
    expect(await screen.findByText(/validation: ok/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Run protected session" }));
    expect(await screen.findByText(/session-audit finished/)).toBeInTheDocument();

    const launchCall = [...invokeMock.mock.calls]
      .reverse()
      .find((call) => call[0] === "launch_session_command");
    expect(launchCall?.[1]).toEqual({
      request: expect.objectContaining({
        command: ["sh", "-c", "echo closed"],
        accept_degraded: true,
        readiness_reviewed: true,
      }),
    });
  });

  test("dashboard action buttons open launch, setup, and receipt-review surfaces", async () => {
    persistCompletedSetup();
    const user = userEvent.setup();
    render(<App />);

    await screen.findByRole("heading", {
      name: "Run an agent without giving it the whole machine.",
    });
    await user.click(screen.getByRole("button", { name: /Edit protected folders/ }));
    expect(
      await screen.findByRole("heading", { name: "Set up your first protected agent" }),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Save profile/ }));
    await user.click(screen.getByRole("button", { name: "Save profile" }));
    await screen.findByRole("heading", {
      name: "Run an agent without giving it the whole machine.",
    });
    const reviewLink = screen.getByRole("link", { name: /Review last run/ });
    await user.click(reviewLink);
    expect(window.location.hash).toBe("#session-history");
  });

  test("doctor button retries after a closed-environment backend error", async () => {
    persistCompletedSetup();
    let doctorAttempts = 0;
    installInvokeMock({
      host_readiness_summary: () => {
        doctorAttempts += 1;
        if (doctorAttempts === 1) {
          throw new Error("closed doctor failure");
        }
        return {
          level: "strong",
          summary: "host readiness: strong",
          blocked_reasons: [],
          degraded_reasons: [],
        };
      },
    });
    const user = userEvent.setup();
    render(<App />);

    expect(await screen.findByText(/closed doctor failure/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Run Warder doctor" }));
    await user.click(await screen.findByText("Show raw doctor output"));
    expect(await screen.findByLabelText("Warder doctor summary")).toHaveTextContent(
      "host readiness: strong",
    );
  });

  test("session-history buttons cover receipt tabs, journals, and guarded restore", async () => {
    persistCompletedSetup();
    const user = userEvent.setup();
    render(<App />);

    const logs = within(
      (await screen.findByRole("heading", { name: "Session history" })).closest(
        "section",
      ) as HTMLElement,
    );
    await user.click(logs.getByRole("button", { name: "Refresh" }));
    await user.click(await logs.findByRole("button", { name: /session-audit/ }));

    for (const tab of [
      "Summary",
      "File Activity",
      "Network Activity",
      "Snapshot/Recovery",
      "Degraded Coverage",
      "Raw Receipt",
    ]) {
      await user.click(await logs.findByRole("button", { name: tab }));
    }
    expect(await logs.findByText(/status: completed/)).toBeInTheDocument();

    await user.click(logs.getByRole("button", { name: "Snapshot/Recovery" }));
    await user.click(logs.getByRole("button", { name: "Preview revert" }));
    expect(await logs.findByText(/would restore 1 root/)).toBeInTheDocument();
    await user.click(logs.getByRole("button", { name: "Guarded revert" }));
    expect(await logs.findByText(/guarded revert completed/)).toBeInTheDocument();

    await user.click(logs.getByRole("button", { name: "Load journals" }));
    expect(await logs.findByText(/network journal: 1 event/)).toBeInTheDocument();
    expect(invokeMock).toHaveBeenCalledWith("snapshot_revert_preview", {
      snapshotRoot: "/tmp/warder-gui-audit/snapshots",
      snapshotId: "snap-session-audit",
    });
    expect(invokeMock).toHaveBeenCalledWith("snapshot_revert_session", {
      dbPath: defaultPaths.db_path,
      sessionId: "session-audit",
      snapshotRoot: "/tmp/warder-gui-audit/snapshots",
      snapshotId: "snap-session-audit",
    });
  });

  test("manual receipt and journal buttons surface backend errors without crashing", async () => {
    persistCompletedSetup();
    installInvokeMock({
      session_receipt_text: () => {
        throw new Error("missing closed receipt");
      },
      session_journals_text: () => {
        throw new Error("missing closed journals");
      },
    });
    const user = userEvent.setup();
    render(<App />);

    const logs = within(
      (await screen.findByRole("heading", { name: "Session history" })).closest(
        "section",
      ) as HTMLElement,
    );
    await user.clear(logs.getByLabelText("Session ID"));
    await user.type(logs.getByLabelText("Session ID"), "missing-session");
    await user.click(logs.getByRole("button", { name: "Load receipt" }));
    expect(await logs.findByText(/missing closed receipt/)).toBeInTheDocument();
    await user.click(logs.getByRole("button", { name: "Load journals" }));
    expect(await logs.findByText(/missing closed journals/)).toBeInTheDocument();
  });
});
