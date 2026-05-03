# Linux Compatibility

Warder v1.0 public beta targets Linux x86_64 systems. The release artifacts are built for Linux and published as a CLI binary, GUI binary, Ubuntu/Debian `.deb`, RPM package, and portable GUI AppImage.

Warder is intentionally runtime-checked rather than pretending every Linux host has the same security features. Run `warder test-host` and `warder doctor` on the target machine before trusting a session. For common host expectations, see [Protection Matrix](protection-matrix.md).

## Recommended Baseline

Use a current, supported Linux distribution with:

- x86_64 CPU architecture
- systemd or another setup that can provide a writable cgroup v2 subtree for the current user
- Linux Landlock enabled for filesystem write blocking
- Btrfs for snapshot and revert workflows
- BPF and bpffs support if you want live eBPF journal coverage
- GTK 3 and WebKitGTK 4.1 runtime libraries for the desktop app

The easiest review path is a `.deb` on an Ubuntu/Debian-family desktop or an RPM on an RPM-family desktop. Other distributions can use the raw binaries or AppImage, but Warder does not yet publish distro-specific compatibility claims beyond the packaged release formats.

## Feature Support By Host Capability

| Warder feature | Linux requirement | What happens when unavailable |
| --- | --- | --- |
| CLI, config, receipts, and basic launch flow | Linux x86_64 userland | Unsupported architectures are outside the current beta target. |
| Landlock write blocking | Kernel with Landlock enabled, commonly Linux 5.13 or newer plus distro support | Warder reports degraded enforcement or refuses launch when strict mode requires enforcement. |
| Experimental read blocking | Landlock host support plus explicit `read_deny = true` or `read_policy = "deny"` and disjoint `enforcement.readable_roots` | Disabled by default; unsupported or invalid read policy is reported during readiness checks. |
| Session cgroup tagging | cgroup v2 and a writable delegated subtree | Warder reports degraded cgroup coverage unless the launch requires enforcement. |
| Seccomp deny-list hardening | Linux seccomp support on x86_64 or aarch64 | Warder reports setup failure or degraded readiness instead of silently claiming containment. This blocks namespace/mount escapes and selected process/kernel observation syscalls; it is not a default-deny sandbox. |
| File journal | inotify for protected-zone watches; optional eBPF for expanded observation | Receipts describe which journal sources were active and which events may be missing. |
| Network journal | procfs and optional eBPF/BPF permissions | Network data is visibility-only in v1.0 beta and must not be treated as network enforcement. |
| Btrfs snapshot and revert | Protected root on Btrfs plus configured snapshot root | Snapshot-required sessions fail closed; optional snapshots are reported as unavailable. |
| Desktop app | Linux desktop with GTK 3 and WebKitGTK 4.1 runtime libraries | Use the CLI if the desktop runtime is unavailable. |

## eBPF Build Tooling

The eBPF object build scripts require a system Clang with BPF target support. The scripts prefer `/usr/bin/clang` and intentionally reject Swift toolchain Clang wrappers because those wrappers have failed BPF builds on some developer workstations. If your system Clang is installed somewhere else, run the scripts with an explicit working compiler:

```bash
CLANG=/usr/bin/clang scripts/build-ebpf-file-journal.sh
CLANG=/usr/bin/clang scripts/build-ebpf-network-journal.sh
```

## Kernel Guidance

Warder should be usable as a supervised launcher on mainstream modern Linux systems, but stronger protection depends on kernel and distro configuration.

- Linux 5.13 or newer is the practical minimum for Landlock-backed protected-write enforcement.
- Linux 5.15 LTS or newer is the expected baseline for common eBPF tracepoint availability.
- Linux 6.x kernels are preferred for the broadest journal validation surface.

These are guidance points, not guarantees. Distro kernels may disable or restrict features, and hardened systems may require extra BPF, cgroup, or filesystem setup.

## Check A Machine

After installing Warder, run:

```bash
warder test-host
warder doctor
```

Then run a readiness check for the actual config you plan to use:

```bash
warder dry-run --config warder.toml --agent <agent-id> -- <agent command>
```

Use `--require-enforcement --receipt-key <path>` for strict sessions. Use `--accept-degraded` only when you have read the degraded reasons and are comfortable with the reduced coverage.

Avoid running agents through `sudo`. If a privileged launcher is needed for host setup, `warder run --launch` requires `--allow-root` and a sudo environment with `SUDO_UID`/`SUDO_GID`; the child enables `no_new_privs`, disables dumpability, clears ambient capabilities and supplementary groups, drops its capability bounding set, and is dropped back to that non-root user before exec. Direct root launches are refused.

## Current Beta Limits

- Release packages are checksummed and attested where available, but they are not package-manager signed.
- The AppImage is GUI-only; keep the separate `warder` CLI binary nearby when using the portable artifact folder.
- Non-Ubuntu package names and distro-specific desktop dependencies remain unverified until Warder adds distro-specific CI.
- Warder does not provide host-wide supervision in v1.0 beta. Processes launched outside `warder run` or the desktop launcher are unsupervised.
