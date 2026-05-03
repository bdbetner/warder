# Security Policy

Warder is a public beta Linux tool for supervised local agent sessions. It is designed to reduce risk with protected zones, host controls where available, readable session receipts, and recovery paths where supported. It is not a guarantee that arbitrary permissive execution is safe, and it is not a host-wide sandbox.

## Current Posture

Warder's strongest current protection is filesystem write denial for supervised processes where Linux Landlock is available. Its strongest accountability feature is the session receipt, which records the command, policy, active protections, degraded protections, observed file activity, network-journal coverage, and snapshot state.

Warder only supervises commands launched through `warder run` or the desktop launcher. It does not protect against processes started outside Warder.

Several security-hardening limits remain in the public beta: global always-on supervision is not implemented, receipt signing uses local or external shared-secret keys rather than public-key signatures, network destination allowlists are not enforced, file and network journals have known coverage gaps, and the desktop app must keep its IPC surface narrow as the UI grows.

## What Warder Uses

- cgroups to identify agent sessions before the supervised command executes and apply best-effort resource limits when the cgroup root permits it
- Landlock for filesystem write restrictions where supported
- seccomp for a small escape-syscall filter around supervised commands
- inotify to watch protected paths
- snapshots to make supported sessions reversible
- optional eBPF collectors for file and network observation where built and permitted
- local SQLite metadata for sessions, zones, snapshots, and journal summaries

## Honest Degradation

If a required kernel feature, filesystem capability, or permission is missing, Warder must say so plainly. It should not claim enforcement that it cannot actually provide.

Expected degraded cases include missing cgroup delegation, unavailable Landlock support, unsupported snapshot backends, missing BPF privileges, and commands launched outside Warder.

## Local Storage

Warder stores local metadata in SQLite. Warder should not upload session data or call external services as part of the core supervision path.

Local receipts and journals are accountability records, not tamper-proof forensics. Warder keeps a local SQLite hash chain for session records and `warder verify-receipts` fails closed when that chain is missing or inconsistent, but a local user or malware with write access to Warder's state can still modify both records and integrity metadata.

Receipt signing can add local HMAC integrity checks for exported receipts when the signing key is kept outside the supervised session's write access. It does not make Warder state tamper-proof, and it is not a public-key non-repudiation mechanism. Until stronger state-file controls and external key management are implemented, do not use Warder receipts as forensic evidence against a process that could also modify Warder's local state directory or receipt signing key.

Warder refuses launches when the configured SQLite database path or strict-mode receipt key path is inside a configured protected zone or agent writable root. Warder also requires the parent directory for those state files to be private on Unix (`0700` or stricter) when the directory already exists, and rejects group/world-writable ancestor directories unless they use the sticky bit convention of shared temp directories. Keep Warder state in the default XDG state directory or another private directory outside every zone path and every `enforcement.writable_roots` entry. This reduces straightforward self-tampering by Warder-launched agents and accidental shared-temp placement, but it does not make local state tamper-proof against unrelated same-user processes or malware.

Do not run supervised agents as root. If Warder itself is started through `sudo`, `warder run --launch` refuses by default. Passing `--allow-root` is an explicit acknowledgement for sudo-based cgroup setup; Warder then requires `SUDO_UID` and `SUDO_GID`, enables `no_new_privs`, disables dumpability, clears ambient capabilities and supplementary groups, drops the child capability bounding set, and drops the child back to that non-root user before installing seccomp and Landlock. Direct root shells without a non-root sudo target are refused.

## Before Relying On Warder

Check these items for the specific machine and session:

- Are agent processes tagged in the expected cgroup?
- Did Warder apply or clearly degrade the expected cgroup resource limits?
- Are protected paths canonicalized before policy decisions?
- Does Landlock enforcement apply before the agent starts?
- Does the CLI report degraded enforcement clearly?
- Does a session snapshot exist before a protected run starts?
- Does revert work on the chosen snapshot backend?
- Does the journal show file activity in readable form?
- Does network journal output explain its coverage limits?
- Are receipt signing keys stored outside any path the supervised command can write?
- Is Warder's SQLite database outside every configured zone path and writable root?
- Is Warder's state directory private (`0700` or stricter) and outside writable shared ancestors unless those ancestors are sticky temp directories?
- Is the session being launched without root privileges, or with `--allow-root` only when sudo provides a non-root drop target?
- Are common secret paths denied or warned about by default?

## Reporting Security Issues

Use GitHub private vulnerability reporting or GitHub Security Advisories for vulnerabilities that could affect Warder users. If private reporting is unavailable, contact the repository owner before publishing details.

Useful reports include bypasses for Warder-launched sessions, incorrect enforcement claims, receipt-integrity failures, unsafe desktop IPC paths, unsafe snapshot or restore behavior, or cases where degraded protection is hidden from the user. Reports about processes launched outside Warder are still useful, but global always-on supervision is currently out of scope for v1.0.
