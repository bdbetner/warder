// SPDX-License-Identifier: MIT OR GPL-2.0-only
//
// Minimal Warder network-egress tracepoint program.
//
// This starts with connect(2) plus UDP sendto(2)/sendmsg(2)/sendmmsg(2)
// coverage so the live journal has a small, reviewable kernel surface before
// broader socket coverage lands.

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
    WARDER_NETWORK_PROTOCOL_TCP = 1,
    WARDER_NETWORK_PROTOCOL_UDP = 2,
};

enum {
    WARDER_AF_INET = 2,
    WARDER_AF_INET6 = 10,
};

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

struct warder_network_egress_record {
    __u32 pid;
    __u8 protocol;
    __u8 denied;
    __u16 destination_port;
    __u64 timestamp_nanos;
    char destination[64];
} __attribute__((packed));

struct sys_enter_connect_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    long fd;
    const void *uservaddr;
    long addrlen;
};

struct sys_enter_sendto_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    long fd;
    const void *buff;
    long len;
    long flags;
    const void *addr;
    long addr_len;
};

struct sys_enter_sendmsg_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    long fd;
    const void *msg;
    long flags;
};

struct sys_enter_sendmmsg_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    int syscall_nr;
    long fd;
    const void *msgvec;
    long vlen;
    long flags;
};

struct warder_sockaddr_in {
    __u16 family;
    __u16 port;
    __u32 addr;
};

struct warder_sockaddr_in6 {
    __u16 family;
    __u16 port;
    __u32 flowinfo;
    __u8 addr[16];
    __u32 scope_id;
};

struct warder_msghdr {
    void *msg_name;
    int msg_namelen;
    void *msg_iov;
    __u64 msg_iovlen;
    void *msg_control;
    __u64 msg_controllen;
    unsigned int msg_flags;
};

struct warder_mmsghdr {
    struct warder_msghdr msg_hdr;
    unsigned int msg_len;
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
static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *)25;

static __u16 warder_bswap16(__u16 value)
{
    return (__u16)((value << 8) | (value >> 8));
}

static char warder_hex_nibble(__u8 value)
{
    value &= 0x0f;
    return value < 10 ? (char)('0' + value) : (char)('a' + value - 10);
}

static void warder_write_hex_byte(char *dst, __u8 value)
{
    dst[0] = warder_hex_nibble(value >> 4);
    dst[1] = warder_hex_nibble(value);
}

static void warder_write_ipv4_hex(char *dst, __u32 address)
{
    dst[0] = 'i';
    dst[1] = 'p';
    dst[2] = 'v';
    dst[3] = '4';
    dst[4] = ':';
    warder_write_hex_byte(&dst[5], (__u8)(address & 0xff));
    warder_write_hex_byte(&dst[7], (__u8)((address >> 8) & 0xff));
    warder_write_hex_byte(&dst[9], (__u8)((address >> 16) & 0xff));
    warder_write_hex_byte(&dst[11], (__u8)((address >> 24) & 0xff));
    dst[13] = '\0';
}

static void warder_write_ipv6_hex(char *dst, const __u8 *address)
{
    dst[0] = 'i';
    dst[1] = 'p';
    dst[2] = 'v';
    dst[3] = '6';
    dst[4] = ':';
#pragma unroll
    for (int index = 0; index < 16; index++) {
        warder_write_hex_byte(&dst[5 + (index * 2)], address[index]);
    }
    dst[37] = '\0';
}

static int warder_emit_sockaddr_record(void *ctx, const void *uservaddr, __u8 protocol)
{
    struct warder_network_egress_record record = {};
    __u16 family = 0;

    if (!uservaddr) {
        return 0;
    }
    if (bpf_probe_read_user(&family, sizeof(family), uservaddr) < 0) {
        return 0;
    }

    record.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    record.protocol = protocol;
    record.denied = 0;
    record.timestamp_nanos = bpf_ktime_get_ns();

    if (family == WARDER_AF_INET) {
        struct warder_sockaddr_in addr = {};
        if (bpf_probe_read_user(&addr, sizeof(addr), uservaddr) < 0) {
            return 0;
        }
        record.destination_port = warder_bswap16(addr.port);
        warder_write_ipv4_hex(record.destination, addr.addr);
    } else if (family == WARDER_AF_INET6) {
        struct warder_sockaddr_in6 addr6 = {};
        if (bpf_probe_read_user(&addr6, sizeof(addr6), uservaddr) < 0) {
            return 0;
        }
        record.destination_port = warder_bswap16(addr6.port);
        warder_write_ipv6_hex(record.destination, addr6.addr);
    } else {
        return 0;
    }

    bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, &record, sizeof(record));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int warder_network_egress(struct sys_enter_connect_ctx *ctx)
{
    return warder_emit_sockaddr_record(ctx, ctx->uservaddr, WARDER_NETWORK_PROTOCOL_TCP);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int warder_network_sendto(struct sys_enter_sendto_ctx *ctx)
{
    return warder_emit_sockaddr_record(ctx, ctx->addr, WARDER_NETWORK_PROTOCOL_UDP);
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int warder_network_sendmsg(struct sys_enter_sendmsg_ctx *ctx)
{
    struct warder_msghdr msg = {};

    if (!ctx->msg) {
        return 0;
    }
    if (bpf_probe_read_user(&msg, sizeof(msg), ctx->msg) < 0) {
        return 0;
    }
    return warder_emit_sockaddr_record(ctx, msg.msg_name, WARDER_NETWORK_PROTOCOL_UDP);
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int warder_network_sendmmsg(struct sys_enter_sendmmsg_ctx *ctx)
{
    struct warder_mmsghdr msg = {};

    if (!ctx->msgvec || ctx->vlen <= 0) {
        return 0;
    }
    if (bpf_probe_read_user(&msg, sizeof(msg), ctx->msgvec) < 0) {
        return 0;
    }
    return warder_emit_sockaddr_record(ctx, msg.msg_hdr.msg_name, WARDER_NETWORK_PROTOCOL_UDP);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
