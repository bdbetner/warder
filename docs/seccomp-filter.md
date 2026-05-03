# Seccomp Escape Filter

Warder-launched sessions install a small Linux seccomp filter before the supervised command is executed. This filter is a hardening layer for common namespace and mount escapes. It is not a complete syscall sandbox.

## Architecture Scope

The current public beta supports the supervised seccomp filter on Linux `x86_64` and `aarch64`. The filter checks the seccomp audit architecture before matching syscall numbers because syscall numbers are architecture-specific. If Warder is built for an unsupported Linux architecture, seccomp setup fails instead of silently installing a misleading filter.

## Denied Syscalls

The filter returns `EPERM` for these syscalls:

| Syscall | Why Warder Denies It |
| --- | --- |
| `unshare` | Blocks creating new namespaces such as a mount namespace from the supervised process. |
| `mount` | Blocks mounting or remounting filesystems from the supervised process. |
| `umount2` | Blocks unmounting paths that could hide or change the reviewed filesystem view. |
| `pivot_root` | Blocks replacing the process root filesystem. |
| `setns` | Blocks joining another namespace after launch. |
| `ptrace` | Blocks ptrace-style process inspection and tampering from the supervised process. |
| `process_vm_readv` / `process_vm_writev` | Blocks cross-process memory reads and writes from the supervised process. |
| `perf_event_open` | Blocks perf event access that can expose process or kernel-side information. |
| `keyctl` | Blocks Linux keyring operations from the supervised process. |
| `fanotify_init` / `fanotify_mark` | Blocks setting up broad filesystem observation from inside the supervised process. |
| `bpf` | Blocks loading or manipulating BPF programs from inside the supervised process. |
| `open_by_handle_at` | Blocks file-handle based opens that can bypass normal path review assumptions on capable hosts. |
| `userfaultfd` | Blocks userfaultfd setup from the supervised process. |
| `clone3` | Blocks the newer clone entrypoint so namespace creation cannot bypass the `unshare` deny. |
| `init_module` / `finit_module` / `delete_module` | Blocks kernel module load/unload attempts. |
| `kexec_load` / `kexec_file_load` / `reboot` | Blocks reboot and kexec paths from the supervised process. |

All other syscalls are allowed by this filter. This is a deliberate deny-list hardening layer, not a default-deny application sandbox. Filesystem policy remains Landlock's job, and network policy remains visibility-only in v1.0 beta.

## Verification

Run:

```bash
warder test-host
```

The `seccomp_escape_filter` row is `proven working` only when a child process installs the filter and proves `unshare(CLONE_NEWNS)` is denied with `EPERM`.
