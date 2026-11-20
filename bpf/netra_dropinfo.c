// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Drop attribution — the classic skb:kfree_skb tracepoint, passive and
// fail-open (it only counts; it never influences a packet).
//
// bpf/netra_tc.c already counts kernel drop *reasons*, but a count with no
// packet in it cannot say which connection is being dropped or by what code.
// This program adds, for every dropped skb:
//
//   - the IP 5-tuple (family, protocol, addresses, ports), and
//   - `location`, the address of the kernel code that freed it
//     (resolved to a symbol such as nf_hook_slow or tcp_v4_rcv in Go).
//
// Aggregation is in-kernel (an LRU map per tuple+reason and a small map per
// reason+location): a drop storm costs a few map updates, not a ring buffer
// flood, and userspace reads bounded tables.
//
// BTF. The tracepoint record gives the skb *pointer*; reading the packet out of
// it needs the offsets of sk_buff->head and ->network_header, which differ
// between kernels. Those three fields are read with CO-RE (preserve_access_index)
// and relocated by the loader against /sys/kernel/btf/vmlinux, so this object
// is the one place that depends on kernel BTF. It is a standalone object: a
// kernel without BTF costs only this feature, never the core datapath. The
// tracepoint record's own layout (skbaddr, location, protocol, reason) is
// patched in from the kernel's format file, as in netra_tcpevents.c.
//
// A tuple is trusted only when the tracepoint's own `protocol` field (the
// skb's ethertype) and the IP version nibble agree, so an skb whose network
// header was never set produces an "unattributed" drop, not a garbage tuple.

#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define __core __attribute__((preserve_access_index))

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)BPF_FUNC_probe_read_kernel;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;

// Only the members this program reads; the loader relocates each against the
// running kernel's sk_buff.
struct sk_buff {
    unsigned char *head;
    __u16 network_header;
} __core;

// Reads one member of a kernel struct through a CO-RE-relocated address.
#define CORE_READ(dst, ptr, field) bpf_probe_read_kernel(&(dst), sizeof(dst), &((ptr)->field))

#define ETH_P_IP_HOST   0x0800
#define ETH_P_IPV6_HOST 0x86DD
#define IPPROTO_TCP_    6
#define IPPROTO_UDP_    17
#define NH_UNSET        0xFFFFu

// Offset value meaning "this field does not exist on the running kernel".
#define TPL_ABSENT 0xFFFFu

// Where the fields of the skb:kfree_skb record live. Filled by the agent from
// the kernel's format file. valid == 0 means it could not be established and the
// program does nothing.
struct dropinfo_layout {
    __u16 skbaddr;
    __u16 location;
    __u16 protocol;
    __u16 reason;
    __u8 valid;
    __u8 pad;
};

const volatile struct dropinfo_layout L_kfree;

// dropinfo_stats slots.
#define DROP_STAT_TOTAL      0 // every kfree_skb seen
#define DROP_STAT_TUPLE      1 // ... with an IP tuple
#define DROP_STAT_NO_TUPLE   2 // ... not IP, or headers disagree
#define DROP_STAT_NO_HEADER  3 // ... network header not set yet
#define DROP_STAT_READ_ERR   4 // a kernel read failed
#define DROP_STAT_MAP_FULL   5 // an aggregation slot could not be created
#define DROP_STAT_SLOTS      8

// Ports are host order; IPv4 addresses occupy the first four bytes. family is
// 4, 6, or 0 for "no tuple" (all address/port bytes then zero).
struct drop_key {
    __u32 reason;
    __u8 family;
    __u8 proto;
    __u16 pad;
    __u8 saddr[16];
    __u8 daddr[16];
    __u16 sport;
    __u16 dport;
};

struct drop_val {
    __u64 count;
    __u64 location; // most recent
    __u64 last_ns;
};

struct site_key {
    __u32 reason;
    __u32 pad;
    __u64 location;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct drop_key);
    __type(value, struct drop_val);
} drop_flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, struct site_key);
    __type(value, __u64);
} drop_sites SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, DROP_STAT_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} drop_stats SEC(".maps");

static __always_inline void stat_inc(__u32 slot)
{
    __u64 *v = bpf_map_lookup_elem(&drop_stats, &slot);
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

#define FILL_NO_HEADER 1
#define FILL_NO_TUPLE  2
#define FILL_READ_ERR  3

// Fills the tuple of k from the skb. Returns 0, or a FILL_* reason it could not;
// k's tuple fields are written only on success.
static __always_inline int fill_tuple(struct sk_buff *skb, __u16 ethertype, struct drop_key *k)
{
    unsigned char *head = 0;
    __u16 nh = 0;
    if (CORE_READ(head, skb, head) || CORE_READ(nh, skb, network_header))
        return FILL_READ_ERR;
    if (!head || nh == NH_UNSET)
        return FILL_NO_HEADER;
    const unsigned char *ip = head + nh;

    __u8 proto = 0;
    __u32 l4off = 0;
    __u8 sa[16] = {}, da[16] = {};
    __u8 family = 0;
    int frag = 0;

    if (ethertype == ETH_P_IP_HOST) {
        __u8 h[20];
        if (bpf_probe_read_kernel(h, sizeof(h), ip))
            return FILL_READ_ERR;
        if ((h[0] >> 4) != 4)
            return FILL_NO_TUPLE;
        __u32 ihl = (h[0] & 0x0F) * 4;
        if (ihl < 20)
            return FILL_NO_TUPLE;
        family = 4;
        proto = h[9];
        __builtin_memcpy(sa, h + 12, 4);
        __builtin_memcpy(da, h + 16, 4);
        frag = (((h[6] & 0x1F) << 8) | h[7]) != 0; // non-first fragment: no L4 header
        l4off = ihl;
    } else if (ethertype == ETH_P_IPV6_HOST) {
        __u8 h[40];
        if (bpf_probe_read_kernel(h, sizeof(h), ip))
            return FILL_READ_ERR;
        if ((h[0] >> 4) != 6)
            return FILL_NO_TUPLE;
        family = 6;
        proto = h[6]; // next header; an extension header leaves ports at zero
        __builtin_memcpy(sa, h + 8, 16);
        __builtin_memcpy(da, h + 24, 16);
        l4off = 40;
    } else {
        return FILL_NO_TUPLE;
    }

    __u16 sport = 0, dport = 0;
    if (!frag && (proto == IPPROTO_TCP_ || proto == IPPROTO_UDP_)) {
        __u8 p[4];
        if (bpf_probe_read_kernel(p, sizeof(p), ip + l4off) == 0) {
            sport = ((__u16)p[0] << 8) | p[1];
            dport = ((__u16)p[2] << 8) | p[3];
        }
    }

    k->family = family;
    k->proto = proto;
    __builtin_memcpy(k->saddr, sa, 16);
    __builtin_memcpy(k->daddr, da, 16);
    k->sport = sport;
    k->dport = dport;
    return 0;
}

SEC("tracepoint/skb/kfree_skb")
int netra_drop_info(void *ctx)
{
    const volatile struct dropinfo_layout *l = &L_kfree;
    if (!l->valid)
        return 0;

    __u64 skbaddr = 0, location = 0;
    __u16 ethertype = 0;
    __u32 reason = 0;
    if (rd(ctx, l->skbaddr, &skbaddr, sizeof(skbaddr)) || !skbaddr) {
        stat_inc(DROP_STAT_READ_ERR);
        return 0;
    }
    // Optional on older kernels: absent means unknown, not an error.
    rd(ctx, l->location, &location, sizeof(location));
    rd(ctx, l->reason, &reason, sizeof(reason));
    if (rd(ctx, l->protocol, &ethertype, sizeof(ethertype)))
        ethertype = 0;

    stat_inc(DROP_STAT_TOTAL);

    struct drop_key key = {};
    key.reason = reason;
    switch (fill_tuple((struct sk_buff *)skbaddr, ethertype, &key)) {
    case 0:
        stat_inc(DROP_STAT_TUPLE);
        break;
    case FILL_NO_HEADER:
        stat_inc(DROP_STAT_NO_HEADER);
        break;
    case FILL_READ_ERR:
        stat_inc(DROP_STAT_READ_ERR);
        break;
    default:
        stat_inc(DROP_STAT_NO_TUPLE);
        break;
    }

    __u64 now = bpf_ktime_get_ns();
    struct drop_val *v = bpf_map_lookup_elem(&drop_flows, &key);
    if (!v) {
        struct drop_val zero = {};
        bpf_map_update_elem(&drop_flows, &key, &zero, 1 /* BPF_NOEXIST */);
        v = bpf_map_lookup_elem(&drop_flows, &key);
    }
    if (v) {
        __sync_fetch_and_add(&v->count, 1);
        v->location = location;
        v->last_ns = now;
    } else {
        stat_inc(DROP_STAT_MAP_FULL);
    }

    struct site_key sk = {};
    sk.reason = reason;
    sk.location = location;
    __u64 *c = bpf_map_lookup_elem(&drop_sites, &sk);
    if (!c) {
        __u64 zero = 0;
        bpf_map_update_elem(&drop_sites, &sk, &zero, 1 /* BPF_NOEXIST */);
        c = bpf_map_lookup_elem(&drop_sites, &sk);
    }
    if (c)
        __sync_fetch_and_add(c, 1);
    else
        stat_inc(DROP_STAT_MAP_FULL);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
