# Threat Model

Warder exists because local AI agents can damage or leak user data when they run with broad local permissions. Its job is to make supervised sessions easier to bound, inspect, and recover from.

This document explains the risks Warder is designed around and the limits users should keep in mind.

## Main Risks

### Malicious Or Compromised Agent

An agent may try to write protected files, overwrite project history, change config files, or make unexpected network calls. Warder tags agent processes, applies policy, and records session activity.

### Permissive Agent Modes

Permissive modes reduce approval friction and let agents run more commands without interruption. Warder's purpose is to make that workflow safer, not magically safe. If a permissive session is not launched through Warder, or if required kernel/filesystem features are missing, the agent may still have the user's normal access. Warder must make that degraded state obvious before launch and in the session receipt.

### Profile Misconfiguration

Agent profiles are convenience presets, not trust boundaries by themselves. A profile can be too broad, stale, or wrong for a user's machine. Warder must make profiles explainable before launch, show the exact paths and policies they configure, and let users override them with explicit local policy.

### App-Specific Sandbox Drift

Different local agent tools may ship different sandbox, permission, or approval systems. Those controls can change between versions and may not expose comparable logs. Warder should not assume an app's built-in sandbox is present or sufficient. A supervised Warder session should record Warder's own policy, enforcement state, and degraded modes so users can compare sessions consistently across tools.

### Untagged Process Escape

If a child process escapes the tagged cgroup, enforcement and journaling may miss it. Warder must make cgroup tagging explicit, test process-tree behavior, and report when a process cannot be tagged.

### Landlock Availability

Landlock support depends on kernel version and process setup. If Landlock is unavailable, Warder must clearly report that enforcement is degraded rather than pretending writes are blocked.

### Path Traversal And Symlink Escape

Protected path matching must canonicalize paths where possible and deny traversal attempts. Symlinks pointing outside or into protected zones must be handled deliberately and tested.

### Snapshot Failure

Snapshots can fail because the filesystem is not Btrfs, OverlayFS is unavailable, or permissions are insufficient. Warder must fail closed for sessions that require snapshots, or clearly mark sessions as unsnapshotted.

### Journal Blind Spots

eBPF file and network journals are observability tools, not a complete security boundary. Lost events, kernel limitations, and permission failures must be surfaced in the session receipt.

### Receipt Misinterpretation

Receipts are accountability tools, not proof of complete containment. A receipt can only summarize events Warder observed, policy Warder loaded, and degraded states Warder detected. Missing kernel support, untagged processes, unsupported filesystems, event loss, or tools launched outside Warder can make a receipt incomplete. Receipts must distinguish enforced controls, observed activity, inferred summaries, and unknowns.

### Dry-Run Limits

Dry-run and explain output can show policy intent, host capability checks, planned snapshots, and likely degraded protections. They cannot prove what an agent will do after launch. Treat preflight output as a launch preview rather than a complete simulator.

### Network Egress

Unexpected egress can leak data. Warder can store and read network-egress events, and optional eBPF collection can observe selected TCP and UDP attempts where host support allows it. That is visibility, not network enforcement, and it is not complete socket forensics.

### Containerized Execution

Agents may run inside Docker or another container runtime, especially for OpenClaw-style management workflows. Container boundaries can hide process trees, remap cgroups, expose protected host paths through bind mounts, block Landlock or eBPF setup, and make snapshot backends unavailable. Warder should report container-based runs as degraded unless the active protections are verified.

### Secrets Exposure

Common secret paths remain high risk: `.ssh/`, `.gnupg/`, `.aws/`, `.azure/`, `.kube/`, `.env`, key files, wallet files, browser profiles, and credential stores. These should be denied or called out in default policies.

### Policy Misconfiguration

Users can define zones that are too broad, too narrow, or contradictory. Config validation should warn about whole-home protection, missing snapshot backends, overlapping zones, and unsupported enforcement.

### Audit Tampering

Local logs can be modified by a user or malware with filesystem access. Warder provides useful local accountability, not tamper-proof forensics.

## Out Of Scope

- Full containment of every Linux action.
- Protection for commands not launched through Warder.
- Tamper-proof forensic logging.
- Complete network forensics.
- Cloud security scanning.
- Vulnerability scanning for dependencies.
- Proof that an agent, MCP server, or external tool is safe.

Future dependency, command-policy, and tool-inventory features should report uncertainty plainly and attach findings to supervised session receipts.
