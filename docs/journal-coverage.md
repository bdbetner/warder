# Journal Coverage

Warder journals are visibility records, not enforcement evidence. Landlock is the write-blocking path when it applies; file and network journals help review what Warder observed during a supervised session.

## Kernel Compatibility

| Kernel family | Expected behavior | Notes |
| --- | --- | --- |
| 5.15 LTS | Core tracepoints used by Warder are expected to exist on mainstream distro kernels; attach can still fail if BPF, bpffs, or capabilities are unavailable. | `warder doctor` reports an eBPF tracepoint status table. Hooks show `attach-planned` when live attach is available and `degraded` when the hook family cannot attach. |
| 6.x | Preferred validation target for the expanded fd-write, mmap, sendfile, splice, and cgroup-id fields. | Newer distro kernels are still visibility-only; failed tracepoint attach must be treated as degraded coverage. |
| Older or restricted kernels | Degraded or unavailable eBPF journals are expected. | Landlock/write enforcement and inotify may still work independently. |

## File Journal Surfaces

| Surface | Source | Coverage | Limits |
| --- | --- | --- | --- |
| Protected-path creates, writes, deletes, moves | inotify | Watches configured protected-zone roots during a supervised run. | Observational only. Events are session-window attributed, not proof of the exact process or syscall. |
| Path-based file syscalls | eBPF tracepoints | `open`, `openat`, `openat2`, `creat`, `truncate`, `rename*`, `link*`, `symlink*`, `unlink*`, `mkdir*`, `mknod*`. | Records path strings seen at syscall entry. Namespace, bind-mount, and path-race effects can still make review incomplete. |
| Already-open descriptor writes | eBPF tracepoints | `write`, `writev`, `pwrite64`, `pwritev`, `pwritev2`, `ftruncate`. | Records synthetic `fd:<hex>` labels because syscall tracepoints do not resolve the descriptor back to a stable path. |
| Writable memory mappings | eBPF tracepoints | `mmap` and `mprotect` when `PROT_WRITE` is requested. | `mmap` records the source fd; `mprotect` records a synthetic virtual-address label. These are warning signals, not path-complete evidence. |
| Kernel-assisted file copy/write paths | eBPF tracepoints | `sendfile`, `splice`, `copy_file_range`. | Records destination fd labels. It may not identify the protected file path without separate fd/path attribution. |
| Cgroup attribution | eBPF record field | Every live eBPF file record includes the current kernel cgroup id when the helper is available. | The default filter allows all cgroups until userspace configures a target cgroup id. Receipts must still treat attribution as best-effort. |

## Network Journal Surfaces

| Surface | Source | Coverage | Limits |
| --- | --- | --- | --- |
| Connect attempts | eBPF tracepoints | TCP `connect(2)` with IPv4/IPv6 destination and port. | Observational only, no network blocking. |
| Datagram sends | eBPF tracepoints | UDP `sendto(2)`, `sendmsg(2)`, and `sendmmsg(2)` where a destination address is present. | Connected UDP writes without an address can still be incomplete. |
| Socket fd sends | eBPF tracepoints | `send(2)`, `sendfile(2)`, and `splice(2)` as synthetic `fd:<hex>` destinations. | Does not prove the fd is a network socket or resolve the peer by itself. Procfs snapshots may add connected peer detail when available. |
| Connected sockets | procfs snapshot | Reads process fd and network tables during supervised runs. | Containers, namespaces, permissions, short-lived sockets, and direct processes outside Warder can hide sockets. |
| Cgroup attribution | eBPF record field | Every live eBPF network record includes the current kernel cgroup id when the helper is available. | The default filter allows all cgroups until userspace configures a target cgroup id. Receipts must still treat attribution as best-effort. |

## Receipt Rule

Every receipt must keep stating the visibility limits. A quiet file or network journal means "nothing was observed through these surfaces," not "nothing happened." Warder does not publish a numeric coverage percentage because local kernel signals cannot make that estimate reliable across kernels, load, containers, namespaces, and BPF attach states; receipts instead include a concrete blind-spot list.
