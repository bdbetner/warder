# Seccomp Escape Filter

Warder-launched sessions install a small Linux seccomp filter before the supervised command is executed. This filter is a hardening layer for common namespace and mount escapes. It is not a complete syscall sandbox.

## Architecture Scope

The current public beta supports the supervised seccomp filter on Linux `x86_64`. The filter checks the seccomp audit architecture before matching syscall numbers because syscall numbers are architecture-specific. If Warder is built for an unsupported Linux architecture, seccomp setup fails instead of silently installing a misleading filter.

## Denied Syscalls

The filter returns `EPERM` for these syscalls:

| Syscall | Why Warder Denies It |
| --- | --- |
| `unshare` | Blocks creating new namespaces such as a mount namespace from the supervised process. |
| `mount` | Blocks mounting or remounting filesystems from the supervised process. |
| `umount2` | Blocks unmounting paths that could hide or change the reviewed filesystem view. |
| `pivot_root` | Blocks replacing the process root filesystem. |
| `setns` | Blocks joining another namespace after launch. |

All other syscalls are allowed by this filter. Filesystem policy remains Landlock's job, and network policy remains visibility-only in v1.0 beta.

## Verification

Run:

```bash
warder test-host
```

The `seccomp_escape_filter` row is `proven working` only when a child process installs the filter and proves `unshare(CLONE_NEWNS)` is denied with `EPERM`.
