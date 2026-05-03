# How Warder Fits

Warder is best understood as a tool-agnostic supervised-session layer for Linux desktops and workstations. It is not trying to replace every sandbox, VM, firewall, agent permission system, or host security policy.

## Comparison At A Glance

| Need | Warder v1.0 public beta | Containers or microVMs | Host MAC policy such as AppArmor or SELinux | Simple command wrappers |
| --- | --- | --- | --- | --- |
| Run a specific local agent session with guardrails | Strong fit | Possible, but heavier workflow | Possible, but requires policy authoring | Possible, depending on wrapper |
| Keep daily-driver files and projects visible while blocking protected writes | Strong fit with Landlock support | Requires mounts, bind rules, or shared folders | Possible with careful profiles | Usually limited |
| See a readable receipt after the run | Core feature | Usually custom logging | Usually audit-log oriented | Usually limited |
| Snapshot and revert risky work | Core feature on supported Btrfs roots | Possible through VM or filesystem tooling | Outside the policy system | Usually outside scope |
| Desktop pre-launch review | Core feature | Usually not desktop-first | Outside the policy system | Usually CLI-only |
| Host-wide always-on protection | Not in v1.0 beta; planned for v1.1 | Possible for workloads inside the VM/container | Strong fit when configured globally | Usually not |
| Network blocking | Not enforced in v1.0 beta | Possible with VM/container networking | Possible with separate network policy | Usually limited |
| Lowest isolation boundary | Process/session-level host controls | Container or VM boundary | Host policy boundary | Depends on wrapper |

## Where Warder Fits Next To Agent Permissions

Agent-native permission systems are still valuable. Codex, Claude Code, OpenClaw, and other tools can decide which tool calls or shell commands they are willing to attempt. Warder sits outside those apps: it launches the command under host-side controls where Linux supports them, records what coverage actually applied, and produces a local receipt.

That means Warder should not copy model-mediated approval systems or market itself as a replacement for them. Its job is the cross-tool host record: one protected-zone policy, one launch-readiness report, one receipt model, and one recovery story for explicit local sessions.

## When Warder Is The Right Tool

Use Warder when you want to run an explicit local session and get three things in one place:

- protected-zone policy
- host-backed controls where Linux supports them
- a receipt that explains active coverage, degraded coverage, observed activity, and snapshot state

That makes Warder useful for coding agents, shell-based automation, local research agents, or other commands that should be allowed to work in a project without freely modifying credentials, notes, or system paths.

## When To Add Another Layer

Use Warder with another security layer when you need protection outside Warder-launched sessions.

- Use a firewall, VPN policy, or host network policy when egress blocking matters.
- Use AppArmor, SELinux, or another host MAC system for always-on rules.
- Use containers or microVMs when you need a stronger isolation boundary than a supervised host process.
- Use separate Linux users or throwaway environments for work that should not share the same home directory.

Warder is deliberately honest about this boundary: if a process is not launched through Warder, Warder does not supervise it.
