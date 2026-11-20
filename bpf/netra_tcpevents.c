// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// TCP event sensors — four classic tracepoints, passive and fail-open (they
// only count; they never influence a packet or a socket):
//
//   tcp:tcp_retransmit_skb     a segment was retransmitted
//   tcp:tcp_send_reset         this host sent a RST
//   tcp:tcp_receive_reset      this host received a RST
//   sock:inet_sock_set_state   a socket changed TCP state
//
// What this adds over bpf/netra_tc.c's sockops: per-tuple retransmit and RST
// attribution in both directions, and the full state-transition matrix, where
// sockops only counts TCP_CLOSE. See docs/tcp-events.md.
//
// A standalone object with its own verifier budget, like netra_edge_intel.c,
// netra_capture.c and netra_tlsfp.c.
//
// No BTF / CO-RE. A classic tracepoint's record layout is defined by the kernel
// that built it and differs between versions and even between sibling
// tracepoints of one kernel (Linux 6.8: tcp_send_reset has `sport` at 28,
// tcp_receive_reset at 16). The agent therefore reads each tracepoint's own
// /sys/kernel/tracing/events/<group>/<name>/format (internal/tpformat) and
// passes the offsets in through the read-only globals below before load.
// Fields are fetched with bpf_probe_read_kernel: arrays such as saddr[4] sit at
// offsets a direct context load would refuse as misaligned.

#include <linux/bpf.h>
#include <linux/in.h>

// No libbpf headers — same self-contained prelude as the other objects.
#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)BPF_FUNC_probe_read_kernel;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;

#define TCPEV_AF_INET  2
#define TCPEV_AF_INET6 10

// Offset value meaning "this field does not exist on the running kernel".
#define TPL_ABSENT 0xFFFFu

// Where the fields of one tracepoint record live. Filled by the agent from the
// kernel's format file. valid == 0 means the layout could not be established,
// and the program then does nothing.
//
// Two record shapes exist for the flow tracepoints. The classic one has
// separate sport/dport/family/saddr/daddr fields (Linux 6.8). Newer kernels
// (seen on 6.17) give tcp_send_reset a pair of 28-byte struct sockaddr_in6-sized
// blobs instead: sa_src / sa_dst are then the offsets of those blobs and the
// classic fields are absent. The agent sets exactly one of the two.
struct tp_layout {
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 saddr;
    __u16 daddr;
    __u16 saddr6;
    __u16 daddr6;
    __u16 oldstate;
    __u16 newstate;
    __u16 protocol;
    __u16 sa_src; // sockaddr-style source blob, or TPL_ABSENT
    __u16 sa_dst; // sockaddr-style destination blob, or TPL_ABSENT
    __u8 valid;
    __u8 pad;
};

const volatile struct tp_layout L_retrans;
const volatile struct tp_layout L_send_reset;
const volatile struct tp_layout L_recv_reset;
const volatile struct tp_layout L_set_state;

// tcp_ev_stats slots.
#define TCPEV_STAT_RETRANS      0
#define TCPEV_STAT_RST_SENT     1
#define TCPEV_STAT_RST_RECV     2
#define TCPEV_STAT_TRANSITIONS  3
#define TCPEV_STAT_READ_ERR     4
#define TCPEV_STAT_BAD_FAMILY   5
#define TCPEV_STAT_MAP_FULL     6
#define TCPEV_STAT_SLOTS        8

// Per-tuple counters. Ports are host order (the tracepoints convert them);
// IPv4 addresses occupy the first four bytes of the 16-byte fields.
struct tcpev_flow_key {
    __u8 family;
    __u8 pad[3];
    __u8 saddr[16];
    __u8 daddr[16];
    __u16 sport;
    __u16 dport;
};

struct tcpev_flow_value {
    __u64 retrans;
    __u64 rst_sent;
    __u64 rst_recv;
    __u64 last_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct tcpev_flow_key);
    __type(value, struct tcpev_flow_value);
} tcp_ev_flows SEC(".maps");

// Transition counters indexed (oldstate << 4) | newstate. TCP states are 1..12.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} tcp_ev_transitions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, TCPEV_STAT_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} tcp_ev_stats SEC(".maps");

static __always_inline void stat_inc(__u32 slot)
{
    __u64 *v = bpf_map_lookup_elem(&tcp_ev_stats, &slot);
    if (v)
        *v += 1; // per-CPU slot: no atomic needed
}

// Reads len bytes at record offset off. Returns 0 on success.
static __always_inline int rd(const void *ctx, __u16 off, void *dst, __u32 len)
{
    if (off == TPL_ABSENT)
        return -1;
    return bpf_probe_read_kernel(dst, len, (const char *)ctx + off);
}

// Builds the flow key from sockaddr-style blobs: a struct sockaddr_in (family @0,
// port @2 big endian, address @4) or sockaddr_in6 (port @2, flowinfo @4, address
// @8). Returns 0 on success.
static __always_inline int read_flow_sockaddr(const void *ctx, const volatile struct tp_layout *l, struct tcpev_flow_key *k)
{
    __u16 family = 0, sp = 0, dp = 0;
    __u16 src = l->sa_src, dst = l->sa_dst;
    if (rd(ctx, src, &family, sizeof(family)) || rd(ctx, (__u16)(src + 2), &sp, sizeof(sp)) ||
        rd(ctx, (__u16)(dst + 2), &dp, sizeof(dp))) {
        stat_inc(TCPEV_STAT_READ_ERR);
        return -1;
    }
    k->sport = __builtin_bswap16(sp);
    k->dport = __builtin_bswap16(dp);
    if (family == TCPEV_AF_INET) {
        k->family = 4;
        if (rd(ctx, (__u16)(src + 4), k->saddr, 4) || rd(ctx, (__u16)(dst + 4), k->daddr, 4)) {
            stat_inc(TCPEV_STAT_READ_ERR);
            return -1;
        }
    } else if (family == TCPEV_AF_INET6) {
        k->family = 6;
        if (rd(ctx, (__u16)(src + 8), k->saddr, 16) || rd(ctx, (__u16)(dst + 8), k->daddr, 16)) {
            stat_inc(TCPEV_STAT_READ_ERR);
            return -1;
        }
    } else {
        stat_inc(TCPEV_STAT_BAD_FAMILY);
        return -1;
    }
    return 0;
}

// Builds the flow key from a tracepoint record. Returns 0 on success.
static __always_inline int read_flow(const void *ctx, const volatile struct tp_layout *l, struct tcpev_flow_key *k)
{
    if (l->sa_src != TPL_ABSENT && l->sa_dst != TPL_ABSENT)
        return read_flow_sockaddr(ctx, l, k);
    __u16 family = 0;
    if (rd(ctx, l->family, &family, sizeof(family))) {
        stat_inc(TCPEV_STAT_READ_ERR);
        return -1;
    }
    if (rd(ctx, l->sport, &k->sport, sizeof(k->sport)) || rd(ctx, l->dport, &k->dport, sizeof(k->dport))) {
        stat_inc(TCPEV_STAT_READ_ERR);
        return -1;
    }
    if (family == TCPEV_AF_INET) {
        k->family = 4;
        if (rd(ctx, l->saddr, k->saddr, 4) || rd(ctx, l->daddr, k->daddr, 4)) {
            stat_inc(TCPEV_STAT_READ_ERR);
            return -1;
        }
    } else if (family == TCPEV_AF_INET6) {
        k->family = 6;
        if (rd(ctx, l->saddr6, k->saddr, 16) || rd(ctx, l->daddr6, k->daddr, 16)) {
            stat_inc(TCPEV_STAT_READ_ERR);
            return -1;
        }
    } else {
        stat_inc(TCPEV_STAT_BAD_FAMILY);
        return -1;
    }
    return 0;
}

// kind: 0 retransmit, 1 RST sent, 2 RST received.
static __always_inline int on_flow_event(const void *ctx, const volatile struct tp_layout *l, __u32 kind)
{
    if (!l->valid)
        return 0;
    struct tcpev_flow_key key = {};
    if (read_flow(ctx, l, &key))
        return 0;

    struct tcpev_flow_value *v = bpf_map_lookup_elem(&tcp_ev_flows, &key);
    if (!v) {
        // First sighting. An LRU map evicts to make room, so a failure here
        // means another CPU won the insert race or the kernel refused; look
        // again before counting it as lost.
        struct tcpev_flow_value zero = {};
        bpf_map_update_elem(&tcp_ev_flows, &key, &zero, 1 /* BPF_NOEXIST */);
        v = bpf_map_lookup_elem(&tcp_ev_flows, &key);
        if (!v) {
            stat_inc(TCPEV_STAT_MAP_FULL);
            return 0;
        }
    }
    if (kind == 0)
        __sync_fetch_and_add(&v->retrans, 1);
    else if (kind == 1)
        __sync_fetch_and_add(&v->rst_sent, 1);
    else
        __sync_fetch_and_add(&v->rst_recv, 1);
    v->last_ns = bpf_ktime_get_ns();
    stat_inc(kind == 0 ? TCPEV_STAT_RETRANS : kind == 1 ? TCPEV_STAT_RST_SENT : TCPEV_STAT_RST_RECV);
    return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_skb")
int netra_tp_retransmit(void *ctx)
{
    return on_flow_event(ctx, &L_retrans, 0);
}

SEC("tracepoint/tcp/tcp_send_reset")
int netra_tp_send_reset(void *ctx)
{
    return on_flow_event(ctx, &L_send_reset, 1);
}

SEC("tracepoint/tcp/tcp_receive_reset")
int netra_tp_receive_reset(void *ctx)
{
    return on_flow_event(ctx, &L_recv_reset, 2);
}

SEC("tracepoint/sock/inet_sock_set_state")
int netra_tp_state(void *ctx)
{
    const volatile struct tp_layout *l = &L_set_state;
    if (!l->valid)
        return 0;
    // inet_sock_set_state also fires for DCCP, SCTP and MPTCP; where the kernel
    // reports the protocol, keep TCP only.
    if (l->protocol != TPL_ABSENT) {
        __u16 proto = 0;
        if (rd(ctx, l->protocol, &proto, sizeof(proto)))
            return 0;
        if (proto != IPPROTO_TCP)
            return 0;
    }
    int oldstate = 0, newstate = 0;
    if (rd(ctx, l->oldstate, &oldstate, sizeof(oldstate)) || rd(ctx, l->newstate, &newstate, sizeof(newstate))) {
        stat_inc(TCPEV_STAT_READ_ERR);
        return 0;
    }
    __u32 idx = (((__u32)oldstate & 15u) << 4) | ((__u32)newstate & 15u);
    __u64 *v = bpf_map_lookup_elem(&tcp_ev_transitions, &idx);
    if (v)
        *v += 1;
    stat_inc(TCPEV_STAT_TRANSITIONS);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
