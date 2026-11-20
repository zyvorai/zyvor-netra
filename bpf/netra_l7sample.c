// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Sampled plaintext application-protocol observer (Redis, PostgreSQL, MySQL,
// Kafka, HTTP/2 + gRPC). A standalone cgroup_skb object with its own verifier
// budget, like netra_tlsfp.c: it is deliberately NOT part of netra_tc.c, whose L7
// programs already sit at a verifier jump-history ceiling on some kernels (see
// docs/l7-metadata.md).
//
// Observe-only: always allows the packet. For a TCP segment that carries payload
// and has a configured service port as its source or destination, it copies at
// most L7S_COPY bytes of the payload into a ring buffer, rate-limited per flow
// and direction. Userspace (internal/l7sample) classifies the bytes into a
// bounded set of operation names and discards them; nothing is stored.
//
// Fail-open and cheap on the hot path: the port check comes before any copy, and
// a packet that is not to or from a configured port costs a parse and two hash
// lookups. Counters (l7s_stats) say how many segments were eligible, sent,
// rate-limited or lost, so userspace can scale sampled counts back to estimates.
//
// The ports and their protocol ids are configuration, written by the agent into
// l7s_ports; the object has no built-in port list.

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_submit;
static __u64 (*bpf_skb_cgroup_id)(const void *skb) = (void *)BPF_FUNC_skb_cgroup_id;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)BPF_FUNC_skb_load_bytes;

#define L7S_COPY 128

// Bounds check the compiler cannot delete. After a helper call clobbers the
// registers, clang recomputes an offset from an unbounded value and drops a guard
// it can prove always true from the C source (o = n - 8 with n < 16), while the
// verifier, which only sees the recomputed register, cannot. The empty asm makes
// the value opaque so the comparison stays in the bytecode where the verifier can
// use it.
#define BOUND(v, max)                 \
    do {                              \
        asm volatile("" : "+r"(v));   \
        if ((v) > (max))              \
            return 0;                 \
    } while (0)

#define DIR_EGRESS  0
#define DIR_INGRESS 1

// l7s_stats slots.
#define L7S_STAT_ELIGIBLE     0 // payload-bearing TCP segments on a configured port
#define L7S_STAT_EMITTED      1 // sent to userspace
#define L7S_STAT_RATE_LIMITED 2 // skipped by the per-flow limiter
#define L7S_STAT_RINGBUF_FULL 3 // userspace was not keeping up
#define L7S_STAT_LOAD_FAIL    4 // the payload could not be read
#define L7S_STAT_SLOTS        8

struct l7s_event {
    __u64 ts_ns;
    __u64 cgroup_id;
    __u8 family;    // 4 or 6
    __u8 dir;       // DIR_EGRESS / DIR_INGRESS, relative to this host
    __u8 proto;     // protocol id from l7s_ports
    __u8 to_server; // 1: the destination port is the service port (a request)
    __u16 sport;    // host order
    __u16 dport;
    __u8 saddr[16]; // IPv4 in the first four bytes
    __u8 daddr[16];
    __u16 len;      // payload bytes copied into data
    __u16 pad;
    __u8 data[L7S_COPY];
} __attribute__((packed));

// Service port (host order) -> protocol id. Written by the agent.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u16);
    __type(value, __u8);
} l7s_ports SEC(".maps");

// Config slot 0: minimum nanoseconds between samples of one flow and direction.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} l7s_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} l7s_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, __u64);
} l7s_rate SEC(".maps");

struct l7s_scratch {
    __u8 data[L7S_COPY];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct l7s_scratch);
} l7s_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, L7S_STAT_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} l7s_stats SEC(".maps");

static __always_inline void stat_inc(__u32 slot)
{
    __u64 *v = bpf_map_lookup_elem(&l7s_stats, &slot);
    if (v)
        *v += 1; // per-CPU slot: no atomic needed
}

// Copies min(avail, L7S_COPY) payload bytes into the scratch buffer and returns
// the count, or 0 on failure. bpf_skb_load_bytes needs a constant length, so the
// copy is done in fixed-size chunks with the last chunk overlapping the one before
// it: a 14-byte Redis PING is captured whole, not truncated to a power of two.
// Destination offsets are bounded explicitly so the verifier can prove each
// access stays inside the buffer.
static __always_inline __u16 load_payload(struct __sk_buff *skb, __u32 off, __u32 avail, struct l7s_scratch *sc)
{
    __u32 n = avail > L7S_COPY ? L7S_COPY : avail;
    if (n == 0)
        return 0;
    __builtin_memset(sc->data, 0, L7S_COPY);

    if (n >= 16) {
#pragma unroll
        for (int k = 0; k < L7S_COPY / 16; k++) {
            __u32 o = (__u32)k * 16;
            if (o >= n)
                break;
            if (o + 16 > n)
                o = n - 16;
            BOUND(o, L7S_COPY - 16);
            if (bpf_skb_load_bytes(skb, off + o, sc->data + o, 16))
                return 0;
        }
        return (__u16)n;
    }
    if (n >= 8) {
        if (bpf_skb_load_bytes(skb, off, sc->data, 8))
            return 0;
        __u32 o = n - 8; // 0..7
        BOUND(o, 8);
        if (bpf_skb_load_bytes(skb, off + o, sc->data + o, 8))
            return 0;
        return (__u16)n;
    }
    if (n >= 4) {
        if (bpf_skb_load_bytes(skb, off, sc->data, 4))
            return 0;
        __u32 o = n - 4; // 0..3
        BOUND(o, 4);
        if (bpf_skb_load_bytes(skb, off + o, sc->data + o, 4))
            return 0;
        return (__u16)n;
    }
    if (n >= 2) {
        if (bpf_skb_load_bytes(skb, off, sc->data, 2))
            return 0;
        __u32 o = n - 2; // 0..1
        BOUND(o, 2);
        if (bpf_skb_load_bytes(skb, off + o, sc->data + o, 2))
            return 0;
        return (__u16)n;
    }
    if (bpf_skb_load_bytes(skb, off, sc->data, 1))
        return 0;
    return 1;
}

// Rate limit and emit one sample. flow is a hash of the directional tuple.
static __always_inline void emit(struct __sk_buff *skb, __u8 family, __u8 dir, __u8 proto, __u8 to_server,
                                 __u16 sport, __u16 dport, const __u8 *saddr, const __u8 *daddr,
                                 __u64 flow, __u32 payload_off, __u32 avail)
{
    __u32 zero = 0;
    __u64 *gap = bpf_map_lookup_elem(&l7s_cfg, &zero);
    __u64 now = bpf_ktime_get_ns();
    if (gap && *gap) {
        __u64 *last = bpf_map_lookup_elem(&l7s_rate, &flow);
        if (last && now - *last < *gap) {
            stat_inc(L7S_STAT_RATE_LIMITED);
            return;
        }
        bpf_map_update_elem(&l7s_rate, &flow, &now, BPF_ANY);
    }

    struct l7s_scratch *sc = bpf_map_lookup_elem(&l7s_scratch, &zero);
    if (!sc)
        return;
    __u16 n = load_payload(skb, payload_off, avail, sc);
    if (n == 0) {
        stat_inc(L7S_STAT_LOAD_FAIL);
        return;
    }

    struct l7s_event *e = bpf_ringbuf_reserve(&l7s_events, sizeof(*e), 0);
    if (!e) {
        stat_inc(L7S_STAT_RINGBUF_FULL);
        return;
    }
    e->ts_ns = now;
    e->cgroup_id = bpf_skb_cgroup_id(skb);
    e->family = family;
    e->dir = dir;
    e->proto = proto;
    e->to_server = to_server;
    e->sport = sport;
    e->dport = dport;
    __builtin_memcpy(e->saddr, saddr, 16);
    __builtin_memcpy(e->daddr, daddr, 16);
    e->len = n;
    e->pad = 0;
    __builtin_memcpy(e->data, sc->data, L7S_COPY);
    bpf_ringbuf_submit(e, 0);
    stat_inc(L7S_STAT_EMITTED);
}

// Decide whether the segment is to or from a configured service port.
static __always_inline int match(__u16 sport, __u16 dport, __u8 *proto, __u8 *to_server)
{
    __u8 *p = bpf_map_lookup_elem(&l7s_ports, &dport);
    if (p) {
        *proto = *p;
        *to_server = 1;
        return 1;
    }
    p = bpf_map_lookup_elem(&l7s_ports, &sport);
    if (p) {
        *proto = *p;
        *to_server = 0;
        return 1;
    }
    return 0;
}

static __always_inline int sample(struct __sk_buff *skb, __u8 dir)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if ((void *)((__u8 *)data + 1) > data_end)
        return 1;
    __u8 version = (*(__u8 *)data) >> 4;

    __u8 saddr[16] = {}, daddr[16] = {};
    struct tcphdr *tcp;
    __u32 l3len;
    __u8 family;

    if (version == 4) {
        struct iphdr *ip = data;
        if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_TCP || ip->ihl < 5)
            return 1;
        l3len = ip->ihl * 4;
        tcp = (void *)ip + l3len;
        if ((void *)(tcp + 1) > data_end || tcp->doff < 5)
            return 1;
        family = 4;
        __builtin_memcpy(saddr, &ip->saddr, 4);
        __builtin_memcpy(daddr, &ip->daddr, 4);
    } else if (version == 6) {
        struct ipv6hdr *ip6 = data;
        if ((void *)(ip6 + 1) > data_end || ip6->nexthdr != IPPROTO_TCP)
            return 1;
        l3len = sizeof(*ip6);
        tcp = (void *)(ip6 + 1);
        if ((void *)(tcp + 1) > data_end || tcp->doff < 5)
            return 1;
        family = 6;
        __builtin_memcpy(saddr, &ip6->saddr, 16);
        __builtin_memcpy(daddr, &ip6->daddr, 16);
    } else {
        return 1;
    }

    __u16 sport = __builtin_bswap16(tcp->source);
    __u16 dport = __builtin_bswap16(tcp->dest);
    __u8 proto = 0, to_server = 0;
    if (!match(sport, dport, &proto, &to_server))
        return 1;

    __u32 payload_off = l3len + tcp->doff * 4;
    // skb->len counts from the IP header here, and unlike ip->tot_len it is right
    // for GSO/TSO segments (where tot_len is 0).
    if (skb->len <= payload_off)
        return 1; // no payload
    __u32 avail = skb->len - payload_off;
    stat_inc(L7S_STAT_ELIGIBLE);
    // Directional flow hash: distinct per direction so each side is limited on its own.
    __u64 flow = ((__u64)saddr[0] << 56) | ((__u64)saddr[3] << 48) | ((__u64)daddr[0] << 40) | ((__u64)daddr[3] << 32) |
                 ((__u64)sport << 16) | dport;
    flow ^= ((__u64)saddr[12] << 24) ^ ((__u64)daddr[12] << 8) ^ ((__u64)dir << 63);
    emit(skb, family, dir, proto, to_server, sport, dport, saddr, daddr, flow, payload_off, avail);
    return 1;
}

SEC("cgroup_skb/egress")
int netra_l7s_egress(struct __sk_buff *skb)
{
    return sample(skb, DIR_EGRESS);
}

SEC("cgroup_skb/ingress")
int netra_l7s_ingress(struct __sk_buff *skb)
{
    return sample(skb, DIR_INGRESS);
}

char _license[] SEC("license") = "Dual BSD/GPL";
