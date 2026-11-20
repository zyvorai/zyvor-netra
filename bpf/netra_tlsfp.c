// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Continuous TLS ClientHello sampling for JA3/JA4 — standalone cgroup_skb
// egress observer with its own verifier budget. Intentionally NOT folded
// into bpf/netra_tc.c's L7 programs (those already hit a fixed jump-history
// ceiling on some kernels; see docs/l7-metadata.md).
//
// Observe-only: always returns 1 (allow). Rate-limited truncated handshake
// samples (≤256 bytes) go to tls_hello_events; userspace parses JA3/JA4.
// No decryption, no application payload export.
//
// Payload is read from linear data when present, else via bpf_skb_load_bytes
// into a per-CPU scratch map (stack alone cannot hold a 256-byte sample under
// the 512-byte combined-frame limit). load_bytes size must be constant, so we
// try 256→128→64→6. Rate-limit key is destination tuple (cgroup_id may be 0).

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
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)BPF_FUNC_get_current_cgroup_id;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)BPF_FUNC_skb_load_bytes;

#define TLS_HELLO_COPY 256
#define TLS_HELLO_RATE_NS (2ULL * 1000000000ULL)

struct tls_hello_event {
	__u64 cgroup_id;
	__u64 ts_ns;
	__u16 copy_len;
	__u16 pad;
	__u8 data[TLS_HELLO_COPY];
} __attribute__((packed));

struct tls_hello_scratch {
	__u8 data[TLS_HELLO_COPY];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} tls_hello_events SEC(".maps");

struct tls_hello_rate_value {
	__u64 last_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct tls_hello_rate_value);
} tls_hello_rate SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tls_hello_scratch);
} tls_hello_scratch SEC(".maps");

static __always_inline __u16
load_hello(struct __sk_buff *skb, __u32 payload_off, struct tls_hello_scratch *sc)
{
	/* Constant sizes only — variable len is rejected by the verifier. */
	if (bpf_skb_load_bytes(skb, payload_off, sc->data, 256) == 0)
		return 256;
	if (bpf_skb_load_bytes(skb, payload_off, sc->data, 128) == 0)
		return 128;
	if (bpf_skb_load_bytes(skb, payload_off, sc->data, 64) == 0)
		return 64;
	if (bpf_skb_load_bytes(skb, payload_off, sc->data, 6) == 0)
		return 6;
	return 0;
}

/* Prefer linear skb bytes when the ClientHello is already in data/data_end
 * (BPF_PROG_TEST_RUN and some short packets). Fall back to load_bytes when
 * the linear window only covers headers — the common live cgroup_skb case. */
static __always_inline __u16
fill_hello(struct __sk_buff *skb, __u32 payload_off, unsigned char *payload, void *data_end,
	   struct tls_hello_scratch *sc)
{
	if (payload && (void *)(payload + 6) <= data_end &&
	    payload[0] == 0x16 && payload[5] == 0x01) {
		__u16 n = 0;
#pragma unroll
		for (int i = 0; i < TLS_HELLO_COPY; i++) {
			if ((void *)(payload + i + 1) > data_end)
				break;
			sc->data[i] = payload[i];
			n = (__u16)(i + 1);
		}
		if (n >= 6)
			return n;
	}
	return load_hello(skb, payload_off, sc);
}

static __always_inline int
emit_from_scratch(struct tls_hello_scratch *sc, __u16 n, __u64 rate_key)
{
	if (n < 6)
		return 1;
	if (sc->data[0] != 0x16 || sc->data[5] != 0x01)
		return 1;

	__u64 now = bpf_ktime_get_ns();
	struct tls_hello_rate_value *rv = bpf_map_lookup_elem(&tls_hello_rate, &rate_key);
	if (rv && (now - rv->last_ns) < TLS_HELLO_RATE_NS)
		return 1;
	struct tls_hello_rate_value nv = {};
	nv.last_ns = now;
	bpf_map_update_elem(&tls_hello_rate, &rate_key, &nv, BPF_ANY);

	struct tls_hello_event *e = bpf_ringbuf_reserve(&tls_hello_events, sizeof(*e), 0);
	if (!e)
		return 1;
	__builtin_memset(e, 0, sizeof(*e));
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->ts_ns = now;
	e->copy_len = n;
	__builtin_memcpy(e->data, sc->data, TLS_HELLO_COPY);
	bpf_ringbuf_submit(e, 0);
	return 1;
}

static __always_inline int sample_v4(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *ip = data;
	if ((void *)(ip + 1) > data_end)
		return 1;
	if (ip->protocol != IPPROTO_TCP)
		return 1;
	__u32 ihl = ip->ihl;
	if (ihl < 5)
		return 1;
	struct tcphdr *tcp = (void *)ip + ihl * 4;
	if ((void *)(tcp + 1) > data_end)
		return 1;
	if (tcp->doff < 5)
		return 1;
	__u32 payload_off = ihl * 4 + ((__u32)tcp->doff * 4);
	unsigned char *payload = (unsigned char *)tcp + ((__u32)tcp->doff * 4);
	if ((void *)payload > data_end)
		payload = 0;

	__u32 zero = 0;
	struct tls_hello_scratch *sc = bpf_map_lookup_elem(&tls_hello_scratch, &zero);
	if (!sc)
		return 1;
	__u16 n = fill_hello(skb, payload_off, payload, data_end, sc);
	__u64 rate_key = ((__u64)ip->daddr << 16) | (__u64)tcp->dest;
	return emit_from_scratch(sc, n, rate_key);
}

static __always_inline int sample_v6(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ipv6hdr *ip6 = data;
	if ((void *)(ip6 + 1) > data_end)
		return 1;
	if (ip6->nexthdr != IPPROTO_TCP)
		return 1;
	struct tcphdr *tcp = (void *)(ip6 + 1);
	if ((void *)(tcp + 1) > data_end)
		return 1;
	if (tcp->doff < 5)
		return 1;
	__u32 payload_off = sizeof(struct ipv6hdr) + ((__u32)tcp->doff * 4);
	unsigned char *payload = (unsigned char *)tcp + ((__u32)tcp->doff * 4);
	if ((void *)payload > data_end)
		payload = 0;

	__u32 zero = 0;
	struct tls_hello_scratch *sc = bpf_map_lookup_elem(&tls_hello_scratch, &zero);
	if (!sc)
		return 1;
	__u16 n = fill_hello(skb, payload_off, payload, data_end, sc);
	__u64 rate_key = ((__u64)ip6->daddr.s6_addr32[3] << 16) | (__u64)tcp->dest;
	return emit_from_scratch(sc, n, rate_key);
}

SEC("cgroup_skb/egress")
int netra_tlsfp_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	if ((void *)((__u8 *)data + 1) > data_end)
		return 1;
	__u8 version = (*(__u8 *)data) >> 4;
	if (version == 4)
		return sample_v4(skb);
	if (version == 6)
		return sample_v6(skb);
	return 1;
}

char _license[] SEC("license") = "Dual BSD/GPL";
