# eBPF File Journal

Warder keeps live eBPF file journaling opt-in. The default build reports exact host blockers and continues to use inotify-backed file observation.

Build Warder's bundled file-access object:

```bash
scripts/build-ebpf-file-journal.sh
```

A privileged validation host can then require a live protected-path event:

```bash
WARDER_REQUIRE_LIVE_EBPF=1 scripts/ebpf-file-journal-smoke.sh
```

The same validation is available as the manual GitHub Actions workflow `eBPF live smoke`. It defaults to a self-hosted privileged Linux runner:

```text
runner_labels: ["self-hosted","linux","x64","ebpf"]
```

Use that workflow only on a runner where `/sys/fs/bpf` is readable/writable and the job has effective BPF privileges. GitHub-hosted runners are not expected to pass the live attach check.

For busy hosts, the live reader defaults to larger per-CPU perf buffers. Override the page count with `WARDER_EBPF_FILE_PERF_PAGES` if a validation host still reports lost perf events.

Warder filters observed live eBPF file events before persistence: protected-zone matches are kept, unmatched observed events are dropped to avoid system-wide `openat` noise, and denied events are kept even when unmatched.

## Current Coverage Limits

The current eBPF file journal is an observation aid, not an enforcement boundary. The bundled object traces common path-based file syscalls by default, including `open`, `openat`, `openat2`, `creat`, `truncate`, `rename*`, `link*`, `symlink*`, `unlink*`, `mkdir*`, and `mknod*`. It also observes fd-write, `ftruncate(2)`, writable `mmap(2)`/`mprotect(2)`, `sendfile(2)`, `splice(2)`, and `copy_file_range(2)` surfaces. Those fd and mmap events may only produce synthetic `fd:<hex>` or `va:<hex>` labels, so they can still fail to prove which protected path was affected. Bind mounts, namespace changes, unsupported syscall families, or any activity that happens before Warder can attribute the process tree can also hide file activity.

Because of those limits, receipts must treat live eBPF as degraded or incomplete visibility unless a privileged validation host has explicitly tested the required hooks for that release. Landlock write denial remains the v1 write-blocking path; eBPF journals should not be described as write enforcement, read blocking, or complete file forensics.

The bundled object provides:

- tracepoint programs for the default path-based syscall set, or one override program selected with `WARDER_EBPF_FILE_PROGRAM`;
- a perf event array map named `EVENTS`, or `WARDER_EBPF_FILE_MAP`;
- fixed-size event payloads using Warder's raw file-access ABI: native-endian `u32 pid`, `u8 operation`, `u8 denied`, `u64 unix_timestamp_nanos`, and a 256-byte NUL-terminated path.

The default tracepoint target is `syscalls:sys_enter_openat`. Override it with `WARDER_EBPF_FILE_OBJECT`, `WARDER_EBPF_FILE_TRACEPOINT_CATEGORY`, and `WARDER_EBPF_FILE_TRACEPOINT_NAME` when testing a different kernel program.
