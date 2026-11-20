// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Edge TCP intelligence — a standalone, passive, fail-open TCX observer.
// It never touches a packet's verdict (always returns TC_ACT_UNSPEC) and
// is attached as a *second* TCX program alongside netra_ingress/egress
// (bpf/netra_tc.c), not folded into that program — see
// docs/fluxvm-borrow-backlog.md and docs/edge-tcp-intel.md for why this
// stays a separate object with its own verifier budget.
//
// This is deliberately not redundant with sockops-derived srtt/handshake
// data (bpf/netra_tc.c's BPF_SOCK_OPS_RTT_CB / track_tcp_signal): sockops
// only fires for a socket this host is itself an endpoint of, after NAT
// resolution. This program sits on the TC/TCX edge and can see SYN/SYN-ACK
// timing for forwarded/NAT'd flows the local socket layer never attaches
// to. Ported from fluxvm_tcp_intel.bpf.c's design (handshake/RTT
// histograms, packet-level retransmit/RST/FIN counters) with its
// VM-tenant-specific config/event plumbing dropped — Netra has no
// per-tenant keying to do here, just per-node aggregation reported
// upward like every other agent stat (see internal/agent's
// readEdgeIntel).

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>

// No libbpf headers (bpf/bpf_helpers.h, bpf/bpf_endian.h) — this build
// environment only installs clang/llvm/linux-libc-dev, not libbpf-dev,
// matching bpf/netra_tc.c's own self-contained prelude exactly (same
// SEC/__uint/__type macros, same raw BPF_FUNC_* helper-pointer
// declarations, __builtin_bswap16/32 instead of bpf_ntohs/bpf_ntohl).
#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;

#define EDGE_AF_INET  4u
#define EDGE_AF_INET6 6u
#define EDGE_HIST_HANDSHAKE 1u
#define EDGE_HIST_RTT       2u
#define EDGE_COUNT_SYN         1u
#define EDGE_COUNT_ESTABLISHED 2u
#define EDGE_COUNT_RETRANSMIT  3u
#define EDGE_COUNT_RST         4u
#define EDGE_COUNT_FIN         5u
#define EDGE_COUNT_FLOW_MISS   6u

struct edge_flow_key {
    __u8 family;
    __u8 reserved0[3];
    __u8 local[16];
    __u8 remote[16];
    __u16 local_port;
    __u16 remote_port;
};

struct edge_flow_value {
    __u64 syn_ns;
    __u64 handshake_ns;
    __u64 last_out_ns;
    __u64 last_in_ns;
    __u64 rtt_total_ns;
    __u64 rtt_max_ns;
    __u64 rtt_min_ns;
    __u64 last_seen_ns;
    __u32 last_out_seq;
    __u32 last_out_end;
    __u32 last_in_seq;
    __u32 last_in_end;
    __u32 last_ack_from_remote;
    __u32 last_ack_from_local;
    __u32 retransmits;
    __u32 syn_retransmits;
    __u32 rtt_samples;
    __u32 rst_count;
    __u32 fin_count;
    __u32 established;
    __u32 syn_origin; /* 1 = local, 2 = remote */
    __u32 reserved0;
};

struct edge_hist_key { __u32 kind; __u32 bucket; };
struct edge_hist_value { __u64 count; __u64 total_ns; __u64 max_ns; };
struct edge_count_key { __u32 kind; };

struct edge_vlan_hdr { __be16 tci; __be16 encap_proto; };

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct edge_flow_key);
    __type(value, struct edge_flow_value);
} edge_tcp_flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct edge_hist_key);
    __type(value, struct edge_hist_value);
} edge_tcp_hist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, struct edge_count_key);
    __type(value, __u64);
} edge_tcp_counts SEC(".maps");

static __always_inline void edge_count(__u32 kind)
{
    struct edge_count_key key = {.kind = kind};
    __u64 *value = bpf_map_lookup_elem(&edge_tcp_counts, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
        return;
    }
    __u64 one = 1;
    bpf_map_update_elem(&edge_tcp_counts, &key, &one, BPF_NOEXIST);
}

// log2-of-microseconds bucketing, 25 buckets (0..24) — same scheme
// fluxvm_tcp_intel.bpf.c uses, proven on real kernels there.
static __always_inline __u32 edge_bucket_for(__u64 ns)
{
    __u64 us = (ns + 999) / 1000;
    __u32 bucket = 0;
    #pragma unroll
    for (int i = 0; i < 24; i++) {
        if (us > 1) {
            us >>= 1;
            bucket++;
        }
    }
    return bucket > 24 ? 24 : bucket;
}

static __always_inline void edge_histogram(__u32 kind, __u64 ns)
{
    struct edge_hist_key key = {.kind = kind, .bucket = edge_bucket_for(ns)};
    struct edge_hist_value *value = bpf_map_lookup_elem(&edge_tcp_hist, &key);
    if (value) {
        __sync_fetch_and_add(&value->count, 1);
        __sync_fetch_and_add(&value->total_ns, ns);
        if (ns > value->max_ns)
            value->max_ns = ns;
        return;
    }
    struct edge_hist_value initial = {.count = 1, .total_ns = ns, .max_ns = ns};
    bpf_map_update_elem(&edge_tcp_hist, &key, &initial, BPF_NOEXIST);
}

static __always_inline int edge_parse_l2(struct __sk_buff *skb, void **cursor_out, void **end_out, __u16 *proto_out)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    void *cursor = eth + 1;
    __u16 proto = __builtin_bswap16(eth->h_proto);
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto != 0x8100 && proto != 0x88a8)
            break;
        struct edge_vlan_hdr *vlan = cursor;
        if ((void *)(vlan + 1) > data_end)
            return 0;
        proto = __builtin_bswap16(vlan->encap_proto);
        cursor = vlan + 1;
    }
    *cursor_out = cursor;
    *end_out = data_end;
    *proto_out = proto;
    return 1;
}

static __always_inline int edge_parse4(struct __sk_buff *skb, int inbound,
                                       struct edge_flow_key *key,
                                       struct tcphdr **tcp_out, __u32 *payload_len)
{
    void *cursor = 0, *data_end = 0;
    __u16 proto = 0;
    if (!edge_parse_l2(skb, &cursor, &data_end, &proto) || proto != ETH_P_IP)
        return 0;
    struct iphdr *ip = cursor;
    if ((void *)(ip + 1) > data_end || ip->ihl < 5 || ip->protocol != IPPROTO_TCP)
        return 0;
    __u32 ihl = (__u32)ip->ihl * 4;
    if ((void *)ip + ihl > data_end)
        return 0;
    __u16 frag = __builtin_bswap16(ip->frag_off);
    if ((frag & 0x1fff) != 0)
        return 0;
    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)(tcp + 1) > data_end || tcp->doff < 5)
        return 0;
    __u32 thl = (__u32)tcp->doff * 4;
    if ((void *)tcp + thl > data_end)
        return 0;
    __u32 total = __builtin_bswap16(ip->tot_len);
    *payload_len = total > ihl + thl ? total - ihl - thl : 0;
    key->family = EDGE_AF_INET;
    if (!inbound) {
        __builtin_memcpy(key->local, &ip->saddr, 4);
        __builtin_memcpy(key->remote, &ip->daddr, 4);
        key->local_port = __builtin_bswap16(tcp->source);
        key->remote_port = __builtin_bswap16(tcp->dest);
    } else {
        __builtin_memcpy(key->local, &ip->daddr, 4);
        __builtin_memcpy(key->remote, &ip->saddr, 4);
        key->local_port = __builtin_bswap16(tcp->dest);
        key->remote_port = __builtin_bswap16(tcp->source);
    }
    *tcp_out = tcp;
    return 1;
}

static __always_inline int edge_parse6(struct __sk_buff *skb, int inbound,
                                       struct edge_flow_key *key,
                                       struct tcphdr **tcp_out, __u32 *payload_len)
{
    void *cursor = 0, *data_end = 0;
    __u16 proto = 0;
    if (!edge_parse_l2(skb, &cursor, &data_end, &proto) || proto != ETH_P_IPV6)
        return 0;
    struct ipv6hdr *ip6 = cursor;
    if ((void *)(ip6 + 1) > data_end || ip6->nexthdr != IPPROTO_TCP)
        return 0;
    struct tcphdr *tcp = (void *)(ip6 + 1);
    if ((void *)(tcp + 1) > data_end || tcp->doff < 5)
        return 0;
    __u32 thl = (__u32)tcp->doff * 4;
    if ((void *)tcp + thl > data_end)
        return 0;
    __u32 plen = __builtin_bswap16(ip6->payload_len);
    *payload_len = plen > thl ? plen - thl : 0;
    key->family = EDGE_AF_INET6;
    if (!inbound) {
        __builtin_memcpy(key->local, ip6->saddr.in6_u.u6_addr8, 16);
        __builtin_memcpy(key->remote, ip6->daddr.in6_u.u6_addr8, 16);
        key->local_port = __builtin_bswap16(tcp->source);
        key->remote_port = __builtin_bswap16(tcp->dest);
    } else {
        __builtin_memcpy(key->local, ip6->daddr.in6_u.u6_addr8, 16);
        __builtin_memcpy(key->remote, ip6->saddr.in6_u.u6_addr8, 16);
        key->local_port = __builtin_bswap16(tcp->dest);
        key->remote_port = __builtin_bswap16(tcp->source);
    }
    *tcp_out = tcp;
    return 1;
}

static __always_inline int edge_parse_tcp(struct __sk_buff *skb, int inbound,
                                          struct edge_flow_key *key,
                                          struct tcphdr **tcp_out, __u32 *payload_len)
{
    __builtin_memset(key, 0, sizeof(*key));
    if (edge_parse4(skb, inbound, key, tcp_out, payload_len))
        return 1;
    __builtin_memset(key, 0, sizeof(*key));
    return edge_parse6(skb, inbound, key, tcp_out, payload_len);
}

static __always_inline struct edge_flow_value *edge_flow_get_or_create(const struct edge_flow_key *key, __u64 now)
{
    struct edge_flow_value *value = bpf_map_lookup_elem(&edge_tcp_flows, key);
    if (value)
        return value;
    struct edge_flow_value initial = {.rtt_min_ns = ~0ULL, .last_seen_ns = now};
    bpf_map_update_elem(&edge_tcp_flows, key, &initial, BPF_NOEXIST);
    value = bpf_map_lookup_elem(&edge_tcp_flows, key);
    if (!value)
        edge_count(EDGE_COUNT_FLOW_MISS);
    return value;
}

static __always_inline void edge_rtt_sample(struct edge_flow_value *value, __u32 ack,
                                            __u64 sent_ns, __u32 *last_ack)
{
    if (!sent_ns || ack == *last_ack)
        return;
    __u64 now = bpf_ktime_get_ns();
    __u64 rtt = now - sent_ns;
    *last_ack = ack;
    value->rtt_samples++;
    value->rtt_total_ns += rtt;
    if (rtt > value->rtt_max_ns)
        value->rtt_max_ns = rtt;
    if (rtt < value->rtt_min_ns)
        value->rtt_min_ns = rtt;
    edge_histogram(EDGE_HIST_RTT, rtt);
}

static __always_inline void edge_handshake_sample(struct edge_flow_value *value)
{
    if (!value->syn_ns || value->established)
        return;
    __u64 hs = bpf_ktime_get_ns() - value->syn_ns;
    value->handshake_ns = hs;
    value->established = 1;
    edge_count(EDGE_COUNT_ESTABLISHED);
    edge_histogram(EDGE_HIST_HANDSHAKE, hs);
}

static __always_inline void edge_observe_out(struct __sk_buff *skb)
{
    struct edge_flow_key key;
    struct tcphdr *tcp = 0;
    __u32 payload_len = 0;
    if (!edge_parse_tcp(skb, 0, &key, &tcp, &payload_len))
        return;
    __u64 now = bpf_ktime_get_ns();
    __u32 seq = __builtin_bswap32(tcp->seq);
    __u32 ack = __builtin_bswap32(tcp->ack_seq);
    struct edge_flow_value *value = edge_flow_get_or_create(&key, now);
    if (!value)
        return;
    value->last_seen_ns = now;

    if (tcp->syn && !tcp->ack) {
        edge_count(EDGE_COUNT_SYN);
        if (value->syn_ns && !value->established && value->syn_origin == 1) {
            value->syn_retransmits++;
            value->retransmits++;
            edge_count(EDGE_COUNT_RETRANSMIT);
        } else if (!value->syn_ns || value->established) {
            value->syn_ns = now;
            value->syn_origin = 1;
            value->established = 0;
        }
    } else if (tcp->syn && tcp->ack && value->syn_origin == 2) {
        edge_handshake_sample(value);
    }

    if (payload_len > 0) {
        __u32 end = seq + payload_len;
        if (value->last_out_seq == seq && value->last_out_end == end) {
            value->retransmits++;
            edge_count(EDGE_COUNT_RETRANSMIT);
        }
        value->last_out_seq = seq;
        value->last_out_end = end;
        value->last_out_ns = now;
    }
    if (tcp->ack && value->last_in_ns && value->last_in_end && ack >= value->last_in_end)
        edge_rtt_sample(value, ack, value->last_in_ns, &value->last_ack_from_local);
    if (tcp->rst) { value->rst_count++; edge_count(EDGE_COUNT_RST); }
    if (tcp->fin) { value->fin_count++; edge_count(EDGE_COUNT_FIN); }
}

static __always_inline void edge_observe_in(struct __sk_buff *skb)
{
    struct edge_flow_key key;
    struct tcphdr *tcp = 0;
    __u32 payload_len = 0;
    if (!edge_parse_tcp(skb, 1, &key, &tcp, &payload_len))
        return;
    __u64 now = bpf_ktime_get_ns();
    __u32 seq = __builtin_bswap32(tcp->seq);
    __u32 ack = __builtin_bswap32(tcp->ack_seq);
    struct edge_flow_value *value = edge_flow_get_or_create(&key, now);
    if (!value)
        return;
    value->last_seen_ns = now;

    if (tcp->syn && !tcp->ack) {
        edge_count(EDGE_COUNT_SYN);
        if (value->syn_ns && !value->established && value->syn_origin == 2) {
            value->syn_retransmits++;
            value->retransmits++;
            edge_count(EDGE_COUNT_RETRANSMIT);
        } else if (!value->syn_ns || value->established) {
            value->syn_ns = now;
            value->syn_origin = 2;
            value->established = 0;
        }
    } else if (tcp->syn && tcp->ack && value->syn_origin == 1) {
        edge_handshake_sample(value);
    }

    if (payload_len > 0) {
        __u32 end = seq + payload_len;
        if (value->last_in_seq == seq && value->last_in_end == end) {
            value->retransmits++;
            edge_count(EDGE_COUNT_RETRANSMIT);
        }
        value->last_in_seq = seq;
        value->last_in_end = end;
        value->last_in_ns = now;
    }
    if (tcp->ack && value->last_out_ns && value->last_out_end && ack >= value->last_out_end)
        edge_rtt_sample(value, ack, value->last_out_ns, &value->last_ack_from_remote);
    if (tcp->rst) { value->rst_count++; edge_count(EDGE_COUNT_RST); }
    if (tcp->fin) { value->fin_count++; edge_count(EDGE_COUNT_FIN); }
}

// Always TC_ACT_UNSPEC: this program never has a verdict opinion, so a
// TCX chain running it alongside netra_ingress/egress (bpf/netra_tc.c)
// always falls through to whatever that program (or the default) decides.
SEC("tc")
int netra_edge_egress(struct __sk_buff *skb)
{
    edge_observe_out(skb);
    return TC_ACT_UNSPEC;
}

SEC("tc")
int netra_edge_ingress(struct __sk_buff *skb)
{
    edge_observe_in(skb);
    return TC_ACT_UNSPEC;
}

char LICENSE[] SEC("license") = "GPL";
