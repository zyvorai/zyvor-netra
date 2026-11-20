// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Node isolation — a standalone, allow-only egress filter for one node,
// attached at the head of the TCX egress chain of the agent's interfaces.
// See docs/node-isolation.md.
//
// Unlike the rest of the firewall (bpf/netra_tc.c, where allowed_* maps are
// only exceptions to deny rules and default-deny exists only per workload),
// this program answers one question: "is this new outbound flow inside the
// node's allow-list?" Its mode is independent of config_map:
//
//   off      no policy for this node; everything passes (TCX_NEXT)
//   shadow   evaluate and count would-block packets, never drop
//   enforce  drop what the allow-list does not cover
//
// Ported from FluxVM (docs/fluxvm-borrow-backlog.md):
//   - the tuple rule shape and branch-free prefix compare of
//     fluxvm_pod_policy.bpf.h (CIDR + protocol + port range, at most 64);
//   - fluxvm_xdp_shield.bpf.c's generation-keyed policy maps with the config
//     generation published last, so a policy replacement is atomic: a packet
//     sees either the whole old rule set or the whole new one;
//   - fluxvm_tc.bpf.c's DHCP / IPv6 neighbor-discovery passthrough.
//
// What is evaluated, deliberately stateless:
//   - TCP: only a SYN without ACK (a new outbound connection). Replies to
//     inbound connections (SYN-ACK and later) and flows established before
//     the policy always pass, so an operator's SSH session survives enforce.
//   - UDP and other IP protocols: every packet, unless its local source port
//     is exempt (replies from a local UDP service).
//   - ICMP / ICMPv6, DHCP, DHCPv6 and non-first fragments always pass.
//
// Fail-open by construction: any parse failure, missing map entry or zero
// generation is TCX_NEXT. The agent demotes enforce to shadow when its lease
// expires or the controller goes stale (internal/agent, internal/nodeiso).

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// Same self-contained prelude as the other objects (no libbpf headers).
#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;

// 64 operator rules plus up to 16 the agent adds (controller reachability).
#define NODEISO_MAX_RULES 80
#define NODEISO_MODE_OFF 0u
#define NODEISO_MODE_SHADOW 1u
#define NODEISO_MODE_ENFORCE 2u
#define NODEISO_AF_INET 4u
#define NODEISO_AF_INET6 6u

#define NODEISO_STAT_ALLOWED 0u
#define NODEISO_STAT_WOULD_BLOCK 1u
#define NODEISO_STAT_BLOCKED 2u
#define NODEISO_STAT_EXEMPT 3u
#define NODEISO_STAT_WOULD_BLOCK_BYTES 4u
#define NODEISO_STAT_BLOCKED_BYTES 5u
#define NODEISO_STAT_SLOTS 6u

// TCX: "no opinion, run the next program". Numerically TC_ACT_UNSPEC.
#define NODEISO_NEXT TC_ACT_UNSPEC

struct nodeiso_config {
    __u32 generation; // 0 = no policy
    __u32 mode;
    __u32 rule_count;
    __u32 reserved;
};

struct nodeiso_rule_key {
    __u32 generation;
    __u32 index;
};

// Same field set as struct fluxvm_pod_rule minus pod_id/direction: a node
// has one egress allow-list. protocol 0 = any; port_start == port_end == 0 =
// any port. A non-zero port range only matches TCP/UDP, whatever protocol says.
struct nodeiso_rule {
    __u8 family;
    __u8 protocol;
    __u8 prefix_len;
    __u8 reserved;
    __u16 port_start;
    __u16 port_end;
    __u8 address[16];
};

struct nodeiso_exempt_key {
    __u32 generation;
    __u8 protocol;
    __u8 reserved;
    __u16 port; // local (source) port, host order
};

struct nodeiso_dest_key {
    __u8 family;
    __u8 protocol;
    __u16 port;
    __u8 address[16];
};

struct nodeiso_dest_value {
    __u64 packets;
    __u64 bytes;
};

struct nodeiso_vlan_hdr {
    __be16 tci;
    __be16 encap_proto;
};

_Static_assert(sizeof(struct nodeiso_config) == 16, "nodeiso config ABI");
_Static_assert(sizeof(struct nodeiso_rule_key) == 8, "nodeiso rule key ABI");
_Static_assert(sizeof(struct nodeiso_rule) == 24, "nodeiso rule ABI");
_Static_assert(sizeof(struct nodeiso_exempt_key) == 8, "nodeiso exempt key ABI");
_Static_assert(sizeof(struct nodeiso_dest_key) == 20, "nodeiso dest key ABI");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct nodeiso_config);
} nodeiso_cfg SEC(".maps");

// Two generations (old + new) of at most NODEISO_MAX_RULES each, plus headroom.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 3 * NODEISO_MAX_RULES);
    __type(key, struct nodeiso_rule_key);
    __type(value, struct nodeiso_rule);
} nodeiso_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct nodeiso_exempt_key);
    __type(value, __u8);
} nodeiso_exempt SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, NODEISO_STAT_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} nodeiso_stats SEC(".maps");

// Destinations outside the allow-list (would-block in shadow, blocked in
// enforce). LRU, so a scan cannot grow it without bound.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct nodeiso_dest_key);
    __type(value, struct nodeiso_dest_value);
} nodeiso_dests SEC(".maps");

static __always_inline void nodeiso_count(__u32 slot, __u64 n)
{
    __u64 *v = bpf_map_lookup_elem(&nodeiso_stats, &slot);
    if (v)
        *v += n;
}

static __always_inline void nodeiso_record_dest(const struct nodeiso_dest_key *key, __u32 bytes)
{
    struct nodeiso_dest_value *v = bpf_map_lookup_elem(&nodeiso_dests, key);
    if (v) {
        __sync_fetch_and_add(&v->packets, 1);
        __sync_fetch_and_add(&v->bytes, bytes);
        return;
    }
    struct nodeiso_dest_value initial = {.packets = 1, .bytes = bytes};
    bpf_map_update_elem(&nodeiso_dests, key, &initial, BPF_NOEXIST);
}

// fluxvm_prefix_match: compare the leading `full` bytes with pure ALU ops
// and one branch, then the partial byte. `peer` is always a stack copy.
static __always_inline int nodeiso_prefix_match(const __u8 *peer, const __u8 *network, __u8 bits, __u8 family)
{
    __u8 max_bits = family == NODEISO_AF_INET ? 32 : 128;
    if (bits > max_bits)
        return 0;
    __u32 full = bits >> 3;
    __u8 rem = bits & 7;
    __u8 diff = 0;
#pragma unroll
    for (int i = 0; i < 16; i++) {
        __u32 in_prefix = (__u32)((i - (int)full) >> 31);
        __asm__ volatile("" : "+r"(in_prefix));
        diff |= (__u8)((peer[i] ^ network[i]) & in_prefix);
    }
    if (diff)
        return 0;
    if (!rem)
        return 1;
    full &= 0x0f;
    __u8 mask = (__u8)(0xffu << (8 - rem));
    return (peer[full] & mask) == (network[full] & mask);
}

static __always_inline int nodeiso_rule_matches(const struct nodeiso_rule *r, __u8 family, const __u8 *peer,
                                                __u8 protocol, __u16 dport, int has_ports)
{
    if (r->family != family)
        return 0;
    if (!nodeiso_prefix_match(peer, r->address, r->prefix_len, family))
        return 0;
    if (r->protocol && r->protocol != protocol)
        return 0;
    if (r->port_start == 0 && r->port_end == 0)
        return 1;
    return has_ports && dport >= r->port_start && dport <= r->port_end;
}

struct nodeiso_flow {
    __u8 family;
    __u8 protocol;
    __u8 evaluate; // 0 = always passes (exempt class)
    __u8 has_ports;
    __u16 sport;
    __u16 dport;
    __u8 daddr[16];
};

static __always_inline int nodeiso_l4(void *l4, void *data_end, __u8 protocol, struct nodeiso_flow *f)
{
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return 0;
        f->sport = __builtin_bswap16(tcp->source);
        f->dport = __builtin_bswap16(tcp->dest);
        f->has_ports = 1;
        f->evaluate = tcp->syn && !tcp->ack;
        return 1;
    }
    if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return 0;
        f->sport = __builtin_bswap16(udp->source);
        f->dport = __builtin_bswap16(udp->dest);
        f->has_ports = 1;
        // DHCP / DHCPv6 client traffic.
        if ((f->sport == 68 && f->dport == 67) || (f->sport == 546 && f->dport == 547))
            f->evaluate = 0;
        return 1;
    }
    return 1;
}

// Returns 0 when the packet cannot be classified (it then passes).
static __always_inline int nodeiso_parse(struct __sk_buff *skb, struct nodeiso_flow *f)
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
        struct nodeiso_vlan_hdr *vlan = cursor;
        if ((void *)(vlan + 1) > data_end)
            return 0;
        proto = __builtin_bswap16(vlan->encap_proto);
        cursor = vlan + 1;
    }
    f->evaluate = 1;
    if (proto == ETH_P_IP) {
        struct iphdr *ip = cursor;
        if ((void *)(ip + 1) > data_end || ip->ihl < 5)
            return 0;
        f->family = NODEISO_AF_INET;
        f->protocol = ip->protocol;
        __builtin_memcpy(f->daddr, &ip->daddr, 4);
        if (ip->protocol == IPPROTO_ICMP) {
            f->evaluate = 0;
            return 1;
        }
        __u16 frag = __builtin_bswap16(ip->frag_off);
        if (frag & 0x1fff) { // non-first fragment: no ports to judge
            f->evaluate = 0;
            return 1;
        }
        return nodeiso_l4((void *)ip + (__u32)ip->ihl * 4, data_end, ip->protocol, f);
    }
    if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = cursor;
        if ((void *)(ip6 + 1) > data_end)
            return 0;
        f->family = NODEISO_AF_INET6;
        f->protocol = ip6->nexthdr;
        __builtin_memcpy(f->daddr, ip6->daddr.in6_u.u6_addr8, 16);
        // ICMPv6 carries neighbor discovery and PMTU; never filtered.
        if (ip6->nexthdr == IPPROTO_ICMPV6) {
            f->evaluate = 0;
            return 1;
        }
        return nodeiso_l4(ip6 + 1, data_end, ip6->nexthdr, f);
    }
    return 0;
}

// A fixed-size address, so it can cross a BPF-to-BPF call as typed memory.
struct nodeiso_peer {
    __u8 b[16];
};

// Match ONE rule. Deliberately a global (non-static, noinline) function, as
// in fluxvm_rule_match_idx: the verifier checks a global function once, on
// its own, whereas the same body inlined into the rule scan is re-walked for
// every iteration, which exceeds the 1,000,000-insn limit on Linux 7.x.
// At most five arguments: meta = family | protocol << 8 | has_ports << 16.
__attribute__((noinline)) int nodeiso_rule_match_idx(__u32 generation, __u32 index, __u32 meta, __u32 dport,
                                                     const struct nodeiso_peer *peer)
{
    // Newer verifiers treat a global function's pointer argument as nullable.
    if (!peer)
        return 0;
    struct nodeiso_rule_key key = {.generation = generation, .index = index};
    struct nodeiso_rule *r = bpf_map_lookup_elem(&nodeiso_rules, &key);
    if (!r)
        return 0;
    return nodeiso_rule_matches(r, (__u8)meta, peer->b, (__u8)(meta >> 8), (__u16)dport, (meta >> 16) & 1);
}

static __always_inline int nodeiso_allowed(const struct nodeiso_config *cfg, const struct nodeiso_flow *f)
{
    __u32 count = cfg->rule_count;
    if (count > NODEISO_MAX_RULES)
        count = NODEISO_MAX_RULES;
    struct nodeiso_peer peer;
    __builtin_memcpy(peer.b, f->daddr, 16);
    __u32 meta = (__u32)f->family | ((__u32)f->protocol << 8) | ((__u32)f->has_ports << 16);
#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < NODEISO_MAX_RULES; i++) {
        if (i >= count)
            break;
        if (nodeiso_rule_match_idx(cfg->generation, i, meta, f->dport, &peer))
            return 1;
    }
    return 0;
}

SEC("tc")
int netra_nodeiso_egress(struct __sk_buff *skb)
{
    __u32 zero = 0;
    struct nodeiso_config *cfg = bpf_map_lookup_elem(&nodeiso_cfg, &zero);
    if (!cfg || cfg->generation == 0 || cfg->mode == NODEISO_MODE_OFF)
        return NODEISO_NEXT;
    // Snapshot: the agent may publish a new generation while this runs.
    struct nodeiso_config c = *cfg;

    struct nodeiso_flow f = {};
    if (!nodeiso_parse(skb, &f) || !f.evaluate)
        return NODEISO_NEXT;
    if (f.has_ports) {
        struct nodeiso_exempt_key ek = {.generation = c.generation, .protocol = f.protocol, .port = f.sport};
        if (bpf_map_lookup_elem(&nodeiso_exempt, &ek)) {
            nodeiso_count(NODEISO_STAT_EXEMPT, 1);
            return NODEISO_NEXT;
        }
    }
    if (nodeiso_allowed(&c, &f)) {
        nodeiso_count(NODEISO_STAT_ALLOWED, 1);
        return NODEISO_NEXT;
    }
    struct nodeiso_dest_key dk = {.family = f.family, .protocol = f.protocol, .port = f.dport};
    __builtin_memcpy(dk.address, f.daddr, 16);
    nodeiso_record_dest(&dk, skb->len);
    if (c.mode == NODEISO_MODE_ENFORCE) {
        nodeiso_count(NODEISO_STAT_BLOCKED, 1);
        nodeiso_count(NODEISO_STAT_BLOCKED_BYTES, skb->len);
        return TC_ACT_SHOT;
    }
    nodeiso_count(NODEISO_STAT_WOULD_BLOCK, 1);
    nodeiso_count(NODEISO_STAT_WOULD_BLOCK_BYTES, skb->len);
    return NODEISO_NEXT;
}

char LICENSE[] SEC("license") = "GPL";
