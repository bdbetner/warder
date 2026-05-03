# Protection Matrix

Use this matrix to set expectations before a Warder run. `warder test-host`
is the source of truth for a specific machine; this page explains common host
profiles and what users should expect.

Status words match `warder test-host`:

- `proven working`: Warder ran a local probe and observed the control working.
- `configured/planned`: the host exposes the required surface, but a specific
  delegated root, snapshot root, privileged runner, or live session is still
  needed to prove the whole workflow.
- `degraded`: Warder can still run, but coverage is weaker than the preferred
  path.
- `unsupported`: Warder does not provide that control on the current host or in
  the current public beta.

## Common Hosts

| Host | Write deny | Read deny | Cgroup attribution | Seccomp escape filter | Snapshot/revert | File/network journals | Network blocking |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Modern Ubuntu/Debian on ext4 | proven working when Landlock is enabled | experimental; prove with `warder test-host` and strict config | configured/planned with delegated cgroup v2 root | proven working on Linux seccomp hosts | unsupported without Btrfs | inotify baseline; eBPF depends on BPF permissions/object paths | unsupported |
| Modern Ubuntu/Debian on Btrfs | proven working when Landlock is enabled | experimental; prove with `warder test-host` and strict config | configured/planned with delegated cgroup v2 root | proven working on Linux seccomp hosts | configured/planned with a Btrfs snapshot root | inotify baseline; eBPF depends on BPF permissions/object paths | unsupported |
| Fedora or other systemd desktop on Btrfs | proven working when Landlock is enabled | experimental; prove with `warder test-host` and strict config | configured/planned with delegated cgroup v2 root | proven working on Linux seccomp hosts | configured/planned with a Btrfs snapshot root | inotify baseline; eBPF depends on BPF permissions/object paths | unsupported |
| Linux host without Landlock ABI | unsupported | unsupported | configured/planned or unsupported depending on cgroup v2 | proven working if seccomp is available | depends on filesystem | observation only; receipts must show degraded enforcement | unsupported |
| Docker/containerized shell | degraded or unsupported unless host Landlock/cgroups are delegated and visible | degraded or unsupported | degraded; process trees and cgroups may be remapped | may work inside the container but does not prove host containment | usually unsupported | limited by namespaces, bind mounts, and permissions | unsupported |
| OpenClaw with Docker/remote sandbox backends | host OpenClaw process only unless sandboxed tool execution is verified | host OpenClaw process only unless sandboxed tool execution is verified | degraded when OpenClaw moves work into Docker, SSH, or OpenShell | applies to the Warder-launched host process | depends on host paths, not remote/container paths | degraded for sandboxed or remote work unless host visibility is proven | unsupported |
| macOS alpha candidate | not part of Linux v1.0 beta | not part of Linux v1.0 beta | not applicable | not applicable | future design | future design | future design |

## How To Use This Matrix

1. Run `warder test-host`.
2. Compare the output with the nearest row above.
3. Run `warder dry-run --config <path> --agent <id> -- <command>` for the
   actual session.
4. Use strict mode with `--require-enforcement --receipt-key <path>` when
   sensitive work requires enforced write blocking and strong receipt integrity.
5. Treat `--accept-degraded` as an explicit decision to run with weaker coverage.

Network destination policy is not enforced in the public beta. If egress
blocking matters, use a host firewall, VPN policy, proxy, container, VM, or MAC
policy alongside Warder.
