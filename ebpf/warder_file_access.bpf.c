// SPDX-License-Identifier: MIT OR GPL-2.0-only
//
// Minimal Warder file-access tracepoint program.
//
// This intentionally avoids kernel headers so CI and fresh checkouts can build
// the object with only clang's BPF target available.

#define SEC(NAME) __attribute__((section(NAME), used))

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

enum {
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_F_CURRENT_CPU = 0xffffffffULL,
};

enum {
    WARDER_FILE_OPERATION_READ = 1,
    WARDER_FILE_OPERATION_WRITE = 2,
    WARDER_FILE_OPERATION_CREATE = 3,
    WARDER_FILE_OPERATION_DELETE = 4,
    WARDER_FILE_OPERATION_RENAME = 5,
};

enum {
    WARDER_PROT_WRITE = 0x2,
};

enum {
    WARDER_O_WRONLY = 01,
    WARDER_O_RDWR = 02,
    WARDER_O_CREAT = 0100,
    WARDER_O_TRUNC = 01000,
};

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

struct warder_file_access_record {
    __u32 pid;
    __u8 operation;
    __u8 denied;
    __u64 timestamp_nanos;
    __u64 cgroup_id;
    char path[256];
} __attribute__((packed));

struct sys_enter_openat_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    long dfd;
    const char *filename;
    int flags;
};

struct sys_enter_open_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    const char *filename;
    int flags;
    long mode;
};

struct sys_enter_openat2_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    long dfd;
    const char *filename;
    const void *how;
    long size;
};

struct sys_enter_one_path_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    const char *pathname;
};

struct sys_enter_two_path_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    const char *oldname;
    const char *newname;
};

struct sys_enter_renameat_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    long olddfd;
    const char *oldname;
    long newdfd;
    const char *newname;
};

struct sys_enter_renameat2_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    long olddfd;
    const char *oldname;
    long newdfd;
    const char *newname;
    unsigned int flags;
};

struct sys_enter_linkat_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    long olddfd;
    const char *oldname;
    long newdfd;
    const char *newname;
    int flags;
};

struct sys_enter_symlinkat_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    const char *oldname;
    long newdfd;
    const char *newname;
};

struct sys_enter_path_dfd_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    long dfd;
    const char *pathname;
};

struct sys_enter_mknodat_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    long dfd;
    const char *filename;
    long mode;
    long dev;
};

struct sys_enter_fd_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    long fd;
};

struct sys_enter_pwrite_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    long fd;
    const void *buf;
    long count;
    long pos;
};

struct sys_enter_pwritev2_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    long fd;
    const void *vec;
    long vlen;
    long pos_l;
    long pos_h;
    int flags;
};

struct sys_enter_mmap_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long off;
};

struct sys_enter_mprotect_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    unsigned long start;
    unsigned long len;
    unsigned long prot;
};

struct sys_enter_sendfile_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    long out_fd;
    long in_fd;
    const void *offset;
    long count;
};

struct sys_enter_splice_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    long fd_in;
    const void *off_in;
    long fd_out;
    const void *off_out;
    long len;
    unsigned int flags;
};

struct sys_enter_copy_file_range_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    long fd_in;
    const void *off_in;
    long fd_out;
    const void *off_out;
    long len;
    unsigned int flags;
};

struct warder_open_how {
    __u64 flags;
    __u64 mode;
    __u64 resolve;
};

SEC("maps")
struct bpf_map_def EVENTS = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 0,
    .map_flags = 0,
};

SEC("maps")
struct bpf_map_def CGROUP_FILTER = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
    .map_flags = 0,
};

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)112;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)114;
static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *)25;

static __u8 warder_operation_from_flags(int flags)
{
    if (flags & WARDER_O_CREAT) {
        return WARDER_FILE_OPERATION_CREATE;
    }
    if ((flags & WARDER_O_WRONLY) || (flags & WARDER_O_RDWR) || (flags & WARDER_O_TRUNC)) {
        return WARDER_FILE_OPERATION_WRITE;
    }
    return WARDER_FILE_OPERATION_READ;
}

static int warder_cgroup_allowed(__u64 cgroup_id)
{
    __u32 key = 0;
    __u64 *target = bpf_map_lookup_elem(&CGROUP_FILTER, &key);

    if (!target || *target == 0) {
        return 1;
    }
    return *target == cgroup_id;
}

static char warder_hex_nibble(__u8 value)
{
    value &= 0x0f;
    return value < 10 ? (char)('0' + value) : (char)('a' + value - 10);
}

static void warder_write_u64_hex(char *dst, __u64 value)
{
#pragma unroll
    for (int pos = 0; pos < 16; pos++) {
        int shift = 60 - (pos * 4);
        dst[pos] = warder_hex_nibble((__u8)(value >> shift));
    }
    dst[16] = '\0';
}

static int warder_emit_synthetic_fd_record(void *ctx, const char *prefix, long fd, __u8 operation)
{
    struct warder_file_access_record record = {};
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!warder_cgroup_allowed(cgroup_id)) {
        return 0;
    }

    record.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    record.operation = operation;
    record.denied = 0;
    record.timestamp_nanos = bpf_ktime_get_ns();
    record.cgroup_id = cgroup_id;

    record.path[0] = prefix[0];
    record.path[1] = prefix[1];
    record.path[2] = ':';
    warder_write_u64_hex(&record.path[3], (__u64)fd);

    bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, &record, sizeof(record));
    return 0;
}

static int warder_emit_path_record(void *ctx, const char *path, __u8 operation)
{
    struct warder_file_access_record record = {};
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!warder_cgroup_allowed(cgroup_id)) {
        return 0;
    }

    record.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    record.operation = operation;
    record.denied = 0;
    record.timestamp_nanos = bpf_ktime_get_ns();
    record.cgroup_id = cgroup_id;

    if (path) {
        bpf_probe_read_user_str(record.path, sizeof(record.path), path);
    }

    bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, &record, sizeof(record));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int warder_file_access(struct sys_enter_openat_ctx *ctx)
{
    return warder_emit_path_record(ctx, ctx->filename, warder_operation_from_flags(ctx->flags));
}

SEC("tracepoint/syscalls/sys_enter_open")
int warder_file_open(struct sys_enter_open_ctx *ctx)
{
    return warder_emit_path_record(ctx, ctx->filename, warder_operation_from_flags(ctx->flags));
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int warder_file_openat2(struct sys_enter_openat2_ctx *ctx)
{
    struct warder_open_how how = {};

    if (ctx->how) {
        bpf_probe_read_user(&how, sizeof(how), ctx->how);
    }
    return warder_emit_path_record(ctx, ctx->filename, warder_operation_from_flags((int)how.flags));
}

SEC("tracepoint/syscalls/sys_enter_creat")
int warder_file_creat(struct sys_enter_one_path_ctx *ctx)
{
    return warder_emit_path_record(ctx, ctx->pathname, WARDER_FILE_OPERATION_CREATE);
}

SEC("tracepoint/syscalls/sys_enter_truncate")
int warder_file_truncate(struct sys_enter_one_path_ctx *ctx)
{
    return warder_emit_path_record(ctx, ctx->pathname, WARDER_FILE_OPERATION_WRITE);
}

SEC("tracepoint/syscalls/sys_enter_ftruncate")
int warder_file_ftruncate(struct sys_enter_fd_ctx *ctx)
{
    return warder_emit_synthetic_fd_record(ctx, "fd", ctx->fd, WARDER_FILE_OPERATION_WRITE);
}

SEC("tracepoint/syscalls/sys_enter_write")
int warder_file_write(struct sys_enter_fd_ctx *ctx)
{
    return warder_emit_synthetic_fd_record(ctx, "fd", ctx->fd, WARDER_FILE_OPERATION_WRITE);
}

SEC("tracepoint/syscalls/sys_enter_writev")
int warder_file_writev(struct sys_enter_fd_ctx *ctx)
{
    return warder_emit_synthetic_fd_record(ctx, "fd", ctx->fd, WARDER_FILE_OPERATION_WRITE);
}

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int warder_file_pwrite64(struct sys_enter_pwrite_ctx *ctx)
{
    return warder_emit_synthetic_fd_record(ctx, "fd", ctx->fd, WARDER_FILE_OPERATION_WRITE);
}

SEC("tracepoint/syscalls/sys_enter_pwritev")
int warder_file_pwritev(struct sys_enter_pwrite_ctx *ctx)
{
    return warder_emit_synthetic_fd_record(ctx, "fd", ctx->fd, WARDER_FILE_OPERATION_WRITE);
}

SEC("tracepoint/syscalls/sys_enter_pwritev2")
int warder_file_pwritev2(struct sys_enter_pwritev2_ctx *ctx)
{
    return warder_emit_synthetic_fd_record(ctx, "fd", ctx->fd, WARDER_FILE_OPERATION_WRITE);
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int warder_file_mmap(struct sys_enter_mmap_ctx *ctx)
{
    if (!(ctx->prot & WARDER_PROT_WRITE)) {
        return 0;
    }
    return warder_emit_synthetic_fd_record(ctx, "fd", (long)ctx->fd, WARDER_FILE_OPERATION_WRITE);
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int warder_file_mprotect(struct sys_enter_mprotect_ctx *ctx)
{
    if (!(ctx->prot & WARDER_PROT_WRITE)) {
        return 0;
    }
    return warder_emit_synthetic_fd_record(ctx, "va", (long)ctx->start, WARDER_FILE_OPERATION_WRITE);
}

SEC("tracepoint/syscalls/sys_enter_sendfile")
int warder_file_sendfile(struct sys_enter_sendfile_ctx *ctx)
{
    return warder_emit_synthetic_fd_record(ctx, "fd", ctx->out_fd, WARDER_FILE_OPERATION_WRITE);
}

SEC("tracepoint/syscalls/sys_enter_splice")
int warder_file_splice(struct sys_enter_splice_ctx *ctx)
{
    return warder_emit_synthetic_fd_record(ctx, "fd", ctx->fd_out, WARDER_FILE_OPERATION_WRITE);
}

SEC("tracepoint/syscalls/sys_enter_copy_file_range")
int warder_file_copy_file_range(struct sys_enter_copy_file_range_ctx *ctx)
{
    return warder_emit_synthetic_fd_record(ctx, "fd", ctx->fd_out, WARDER_FILE_OPERATION_WRITE);
}

SEC("tracepoint/syscalls/sys_enter_rename")
int warder_file_rename(struct sys_enter_two_path_ctx *ctx)
{
    warder_emit_path_record(ctx, ctx->oldname, WARDER_FILE_OPERATION_RENAME);
    return warder_emit_path_record(ctx, ctx->newname, WARDER_FILE_OPERATION_CREATE);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int warder_file_renameat(struct sys_enter_renameat_ctx *ctx)
{
    warder_emit_path_record(ctx, ctx->oldname, WARDER_FILE_OPERATION_RENAME);
    return warder_emit_path_record(ctx, ctx->newname, WARDER_FILE_OPERATION_CREATE);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int warder_file_renameat2(struct sys_enter_renameat2_ctx *ctx)
{
    warder_emit_path_record(ctx, ctx->oldname, WARDER_FILE_OPERATION_RENAME);
    return warder_emit_path_record(ctx, ctx->newname, WARDER_FILE_OPERATION_CREATE);
}

SEC("tracepoint/syscalls/sys_enter_link")
int warder_file_link(struct sys_enter_two_path_ctx *ctx)
{
    return warder_emit_path_record(ctx, ctx->newname, WARDER_FILE_OPERATION_CREATE);
}

SEC("tracepoint/syscalls/sys_enter_linkat")
int warder_file_linkat(struct sys_enter_linkat_ctx *ctx)
{
    return warder_emit_path_record(ctx, ctx->newname, WARDER_FILE_OPERATION_CREATE);
}

SEC("tracepoint/syscalls/sys_enter_symlink")
int warder_file_symlink(struct sys_enter_two_path_ctx *ctx)
{
    return warder_emit_path_record(ctx, ctx->newname, WARDER_FILE_OPERATION_CREATE);
}

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int warder_file_symlinkat(struct sys_enter_symlinkat_ctx *ctx)
{
    return warder_emit_path_record(ctx, ctx->newname, WARDER_FILE_OPERATION_CREATE);
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int warder_file_unlink(struct sys_enter_one_path_ctx *ctx)
{
    return warder_emit_path_record(ctx, ctx->pathname, WARDER_FILE_OPERATION_DELETE);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int warder_file_unlinkat(struct sys_enter_path_dfd_ctx *ctx)
{
    return warder_emit_path_record(ctx, ctx->pathname, WARDER_FILE_OPERATION_DELETE);
}

SEC("tracepoint/syscalls/sys_enter_mkdir")
int warder_file_mkdir(struct sys_enter_one_path_ctx *ctx)
{
    return warder_emit_path_record(ctx, ctx->pathname, WARDER_FILE_OPERATION_CREATE);
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int warder_file_mkdirat(struct sys_enter_path_dfd_ctx *ctx)
{
    return warder_emit_path_record(ctx, ctx->pathname, WARDER_FILE_OPERATION_CREATE);
}

SEC("tracepoint/syscalls/sys_enter_mknod")
int warder_file_mknod(struct sys_enter_one_path_ctx *ctx)
{
    return warder_emit_path_record(ctx, ctx->pathname, WARDER_FILE_OPERATION_CREATE);
}

SEC("tracepoint/syscalls/sys_enter_mknodat")
int warder_file_mknodat(struct sys_enter_mknodat_ctx *ctx)
{
    return warder_emit_path_record(ctx, ctx->filename, WARDER_FILE_OPERATION_CREATE);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
