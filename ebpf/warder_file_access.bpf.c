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

SEC("tracepoint/syscalls/sys_enter_openat")
int warder_file_access(struct sys_enter_openat_ctx *ctx)
{
    struct warder_file_access_record record = {};

    record.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    record.operation = warder_operation_from_flags(ctx->flags);
    record.denied = 0;
    record.timestamp_nanos = bpf_ktime_get_ns();

    if (ctx->filename) {
        bpf_probe_read_user_str(record.path, sizeof(record.path), ctx->filename);
    }

    bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, &record, sizeof(record));
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
