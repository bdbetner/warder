# Security Policy

Warder is an alpha Linux safety tool for supervised local agent sessions. It is designed to reduce risk with protected zones, host controls where available, and readable session receipts. It is not a guarantee that arbitrary permissive execution is safe.

## Current Posture

Warder's strongest current protection is filesystem write denial for supervised processes where Linux Landlock is available. Its strongest accountability feature is the session receipt, which records the command, policy, active protections, degraded protections, observed file activity, network-journal coverage, and snapshot state.

Warder only supervises commands launched through `warder run`. It does not protect against processes started outside Warder.

Several security-hardening items are still open in the alpha: snapshot ids need stricter validation before restore path construction, local SQLite state needs stronger permissions and concurrency settings, session ids are not yet random, cgroup tagging can lag process spawn, and path canonicalization must be made consistent across config, policy, and enforcement planning.

## What Warder Uses

- cgroups to identify agent sessions
- Landlock for filesystem write restrictions where supported
- inotify to watch protected paths
- snapshots to make supported sessions reversible
- optional eBPF collectors for file and network observation where built and permitted
- local SQLite metadata for sessions, zones, snapshots, and journal summaries

## Honest Degradation

If a required kernel feature, filesystem capability, or permission is missing, Warder must say so plainly. It should not claim enforcement that it cannot actually provide.

Expected degraded cases include missing cgroup delegation, unavailable Landlock support, unsupported snapshot backends, missing BPF privileges, and commands launched outside Warder.

## Local Storage

Warder stores local metadata in SQLite. Warder should not upload session data or call external services as part of the core supervision path.

Local receipts and journals are accountability records, not tamper-proof forensics. A local user or malware with filesystem access can modify local files.

Until receipt signing and stronger state-file controls are implemented, do not use Warder receipts as forensic evidence against a process that could also modify Warder's local state directory.

## Before Relying On Warder

Check these items for the specific machine and session:

- Are agent processes tagged in the expected cgroup?
- Are protected paths canonicalized before policy decisions?
- Does Landlock enforcement apply before the agent starts?
- Does the CLI report degraded enforcement clearly?
- Does a session snapshot exist before a protected run starts?
- Does revert work on the chosen snapshot backend?
- Does the journal show file activity in readable form?
- Does network journal output explain its coverage limits?
- Are common secret paths denied or warned about by default?

## Reporting Security Issues

This project does not yet publish a dedicated security contact. Until that exists, open a private report through GitHub security advisories if the repository has advisories enabled, or contact the repository owner directly.
