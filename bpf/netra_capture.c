// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Packet capture streaming — a standalone, passive, fail-open TCX observer.
// It never touches a packet's verdict (always returns TC_ACT_UNSPEC) and is
// attached as a *second* TCX program alongside netra_ingress/egress
// (bpf/netra_tc.c) and netra_edge_intel.c's own pair, not folded into
// either — see bpf/netra_edge_intel.c's header comment for why new sensors
// stay separate objects with their own verifier budget rather than
// branches inside the hot path.
//
// Capture is opt-in and off by default: the single-entry capture_spec map
// starts zeroed (enabled=0), so this program is a single map lookup and an
// early return on every packet until an operator explicitly starts a
// capture (see internal/api/capture.go). When enabled, it matches packets
// against the operator-supplied filter (protocol/host/port) and pushes the
// full frame (capped at NETRA_CAP_MAX_LEN, jumbo-frame-safe) into a ringbuf
// for internal/capture to stream out. A packet that fails the match, or
// exceeds the per-second rate cap, is simply not captured — it is never
// dropped or delayed, matching every other observe-only sensor in this
// repo.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

// No libbpf headers, same self-contained prelude as netra_tc.c/
// netra_edge_intel.c (this build environment only installs clang/llvm/
// linux-libc-dev, not libbpf-dev).
#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_submit;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_discard;
static long (*bpf_skb_load_bytes)(void *skb, __u32 offset, void *to, __u32 len) = (void *)BPF_FUNC_skb_load_bytes;

#define DIR_INGRESS 1
#define DIR_EGRESS  2
#define CAP_FAMILY_V4 4
#define CAP_FAMILY_V6 6

// Full L2 frame, capped well above common MTUs so jumbo frames are still
// captured whole; the operator-chosen snap length (spec.snap_len) further
// clamps this down per session, but the ringbuf reservation itself is
// always this fixed size — bpf_ringbuf_reserve's size argument must be a
// compile-time constant, so a fixed-max reservation (rather than a
// variable one sized to the real capture length) is what the verifier
// accepts, same tradeoff already made for every other fixed-layout event
// in this codebase (see netra_tc.c's struct obs_event).
#define NETRA_CAP_MAX_LEN 9000

// capture_spec is a single-entry desired-state map: internal/agent writes
// it (via the ordinary Go map.Put the same way config_map/blocked_v4/etc.
// are already written from applyConfig) whenever the controller reports a
// desired capture for this node, and clears it (enabled=0) on stop or
// expiry. Kernel-side expires_ns is a belt-and-suspenders backstop in case
// the agent itself is slow to clear it — the primary duration enforcement
// happens in userspace (internal/agent reconciling on its existing 3s
// tick), not here.
struct capture_spec {
    __u8 enabled;
    __u8 family;   // 0 = any, else CAP_FAMILY_V4/V6
    __u8 protocol; // 0 = any, else IPPROTO_TCP/UDP/ICMP/ICMPV6
    __u8 pad0;
    __u8 host[16]; // all-zero = wildcard; matched against src OR dst address
    __u16 port;    // 0 = wildcard; matched against src OR dst port
    __u16 snap_len;
    __u64 expires_ns;
    __u32 max_pps; // 0 = no cap
    __u32 pad1;
} __attribute__((packed));
_Static_assert(sizeof(struct capture_spec) == 40, "capture_spec ABI");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct capture_spec);
} capture_spec SEC(".maps");

// capture_rate is separate from capture_spec (rather than folded into it)
// so the agent can blind-write a fresh spec on every reconcile tick
// without clobbering the in-kernel rate-limit window counters.
struct capture_rate {
    __u32 window_start_sec;
    __u32 window_count;
    __u64 captured_packets;
    __u64 captured_bytes;
    __u64 dropped_by_rate_cap;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct capture_rate);
} capture_rate SEC(".maps");

struct capture_event {
    __u64 ts_ns;
    __u32 ifindex;
    __u32 orig_len;
    __u32 cap_len;
    __u8 direction;
    __u8 family;
    __u8 protocol;
    __u8 pad0;
    __u8 data[NETRA_CAP_MAX_LEN];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB, generously sized for capture bursts
} capture_events SEC(".maps");

static __always_inline int addr_matches(const __u8 *want, const __u8 *got, int len)
{
    for (int i = 0; i < len; i++) {
        if (want[i] != 0)
            goto nonzero;
    }
    return 1; // all-zero want = wildcard
nonzero:
    for (int i = 0; i < len; i++) {
        if (want[i] != got[i])
            return 0;
    }
    return 1;
}

struct parsed {
    __u8 family;
    __u8 protocol;
    __u8 src[16];
    __u8 dst[16];
    __u16 src_port;
    __u16 dst_port;
};

// parse_headers reads only what's needed for filter matching, directly off
// the skb's linear data (same bounds-checked pointer style as netra_tc.c's
// handle_v4/handle_v6) — it never touches the ringbuf or the rate map, so a
// packet that fails to parse simply fails every filter and is skipped, it
// is never treated as a match.
static __always_inline int parse_headers(struct __sk_buff *skb, struct parsed *p)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    if (eth->h_proto == __builtin_bswap16(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end || ip->version != 4 || ip->ihl < 5)
            return 0;
        p->family = CAP_FAMILY_V4;
        p->protocol = ip->protocol;
        __builtin_memset(p->src, 0, 16);
        __builtin_memset(p->dst, 0, 16);
        __builtin_memcpy(p->src, &ip->saddr, 4);
        __builtin_memcpy(p->dst, &ip->daddr, 4);
        void *l4 = (void *)ip + (ip->ihl * 4);
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = l4;
            if ((void *)(tcp + 1) > data_end)
                return 1;
            p->src_port = tcp->source;
            p->dst_port = tcp->dest;
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = l4;
            if ((void *)(udp + 1) > data_end)
                return 1;
            p->src_port = udp->source;
            p->dst_port = udp->dest;
        }
        return 1;
    }
    if (eth->h_proto == __builtin_bswap16(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return 0;
        p->family = CAP_FAMILY_V6;
        p->protocol = ip6->nexthdr;
        __builtin_memcpy(p->src, &ip6->saddr, 16);
        __builtin_memcpy(p->dst, &ip6->daddr, 16);
        void *l4 = (void *)(ip6 + 1);
        if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = l4;
            if ((void *)(tcp + 1) > data_end)
                return 1;
            p->src_port = tcp->source;
            p->dst_port = tcp->dest;
        } else if (ip6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = l4;
            if ((void *)(udp + 1) > data_end)
                return 1;
            p->src_port = udp->source;
            p->dst_port = udp->dest;
        }
        return 1;
    }
    return 0;
}

static __always_inline int spec_matches(const struct capture_spec *s, const struct parsed *p)
{
    if (s->family != 0 && s->family != p->family)
        return 0;
    if (s->protocol != 0 && s->protocol != p->protocol)
        return 0;
    int addr_len = (p->family == CAP_FAMILY_V6) ? 16 : 4;
    if (!addr_matches(s->host, p->src, addr_len) && !addr_matches(s->host, p->dst, addr_len))
        return 0;
    __u16 want_port = __builtin_bswap16(s->port);
    if (s->port != 0 && p->src_port != want_port && p->dst_port != want_port)
        return 0;
    return 1;
}

// rate_allow enforces spec.max_pps with a coarse one-second sliding bucket.
// capture_rate is a single BPF_MAP_TYPE_ARRAY entry (not per-CPU), so under
// concurrent traffic across cores this is an approximate, racy counter —
// acceptable for a debugging aid whose only consequence of a missed race is
// capturing a few extra/fewer packets in one window, never a dropped or
// delayed packet on the actual datapath.
static __always_inline int rate_allow(struct capture_rate *r, __u32 max_pps, __u64 now_ns)
{
    if (max_pps == 0)
        return 1;
    __u32 now_sec = (__u32)(now_ns / 1000000000ULL);
    if (r->window_start_sec != now_sec) {
        r->window_start_sec = now_sec;
        r->window_count = 0;
    }
    if (r->window_count >= max_pps) {
        r->dropped_by_rate_cap++;
        return 0;
    }
    r->window_count++;
    return 1;
}

static __always_inline int handle_capture(struct __sk_buff *skb, __u8 direction)
{
    __u32 key = 0;
    struct capture_spec *spec = bpf_map_lookup_elem(&capture_spec, &key);
    if (!spec || !spec->enabled)
        return TC_ACT_UNSPEC;
    __u64 now_ns = bpf_ktime_get_ns();
    if (spec->expires_ns != 0 && now_ns >= spec->expires_ns)
        return TC_ACT_UNSPEC;

    struct parsed p;
    __builtin_memset(&p, 0, sizeof(p));
    if (!parse_headers(skb, &p))
        return TC_ACT_UNSPEC;
    if (!spec_matches(spec, &p))
        return TC_ACT_UNSPEC;

    struct capture_rate *rate = bpf_map_lookup_elem(&capture_rate, &key);
    if (!rate)
        return TC_ACT_UNSPEC;
    if (!rate_allow(rate, spec->max_pps, now_ns))
        return TC_ACT_UNSPEC;

    struct capture_event *e = bpf_ringbuf_reserve(&capture_events, sizeof(*e), 0);
    if (!e) {
        rate->dropped_by_rate_cap++; // ringbuf full counts the same as a rate drop for status purposes
        return TC_ACT_UNSPEC;
    }
    __u32 orig_len = skb->len;
    __u32 snap = spec->snap_len;
    if (snap == 0 || snap > NETRA_CAP_MAX_LEN)
        snap = NETRA_CAP_MAX_LEN;
    __u32 cap_len = orig_len < snap ? orig_len : snap;
    if (cap_len > NETRA_CAP_MAX_LEN)
        cap_len = NETRA_CAP_MAX_LEN; // re-clamp for the verifier's own bounds tracking
    if (cap_len == 0) {
        // bpf_skb_load_bytes' len arg must be provably non-zero to the
        // verifier; without this branch its tracked range is [0, MAX],
        // which the verifier rejects as an "invalid zero-sized read".
        bpf_ringbuf_discard(e, 0);
        return TC_ACT_UNSPEC;
    }

    e->ts_ns = now_ns;
    e->ifindex = skb->ifindex;
    e->orig_len = orig_len;
    e->direction = direction;
    e->family = p.family;
    e->protocol = p.protocol;
    e->pad0 = 0;
    if (bpf_skb_load_bytes(skb, 0, e->data, cap_len) != 0) {
        bpf_ringbuf_discard(e, 0);
        return TC_ACT_UNSPEC;
    }
    e->cap_len = cap_len;
    bpf_ringbuf_submit(e, 0);
    rate->captured_packets++;
    rate->captured_bytes += cap_len;
    return TC_ACT_UNSPEC;
}

SEC("tc") int netra_capture_ingress(struct __sk_buff *skb) { return handle_capture(skb, DIR_INGRESS); }
SEC("tc") int netra_capture_egress(struct __sk_buff *skb) { return handle_capture(skb, DIR_EGRESS); }

char LICENSE[] SEC("license") = "GPL";
