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
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_F_CURRENT_CPU = 0xffffffffULL,
};

enum {
    WARDER_FILE_OPERATION_READ = 1,
    WARDER_FILE_OPERATION_WRITE = 2,
    WARDER_FILE_OPERATION_CREATE = 3,
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

static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
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

static int warder_emit_path_record(void *ctx, const char *path, __u8 operation)
{
    struct warder_file_access_record record = {};

    record.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    record.operation = operation;
    record.denied = 0;
    record.timestamp_nanos = bpf_ktime_get_ns();

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

SEC("tracepoint/syscalls/sys_enter_rename")
int warder_file_rename(struct sys_enter_two_path_ctx *ctx)
{
    warder_emit_path_record(ctx, ctx->oldname, WARDER_FILE_OPERATION_WRITE);
    return warder_emit_path_record(ctx, ctx->newname, WARDER_FILE_OPERATION_CREATE);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int warder_file_renameat(struct sys_enter_renameat_ctx *ctx)
{
    warder_emit_path_record(ctx, ctx->oldname, WARDER_FILE_OPERATION_WRITE);
    return warder_emit_path_record(ctx, ctx->newname, WARDER_FILE_OPERATION_CREATE);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int warder_file_renameat2(struct sys_enter_renameat2_ctx *ctx)
{
    warder_emit_path_record(ctx, ctx->oldname, WARDER_FILE_OPERATION_WRITE);
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
    return warder_emit_path_record(ctx, ctx->pathname, WARDER_FILE_OPERATION_WRITE);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int warder_file_unlinkat(struct sys_enter_path_dfd_ctx *ctx)
{
    return warder_emit_path_record(ctx, ctx->pathname, WARDER_FILE_OPERATION_WRITE);
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
