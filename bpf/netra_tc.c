// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
// Netra standalone eBPF network observability/security datapath.
// It owns only Netra maps and does not depend on Cilium maps or programs.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#define NETRA_BPF 1
#include "netra_ipv6.h"
#include "netra_l7.h"
#include "netra_icmp.h"

/* Force full inlining — clang BPF rejects non-inlined helpers with >5 args. */
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

#define DIR_INGRESS 1
#define DIR_EGRESS  2
#define HOOK_TC      1
#define HOOK_CGROUP  2
#define HOOK_XDP     3
#define HOOK_SOCKET  4
#define HOOK_SOCKOPS 5
#define ACT_ALLOW    0
#define ACT_BLOCK    1
#define EVT_FLOW     1
#define EVT_DNS      2
#define EVT_CONNECT  3
#define EVT_BLOCK    4
#define EVT_DNS_RESPONSE 5
#define EVT_TCP_HEALTH 6
#define REASON_NONE  0
#define REASON_EXACT 1
#define REASON_CIDR  2
#define REASON_PORT  3
#define REASON_UID   4
#define REASON_RATE  5
#define REASON_DNS   6
#define REASON_PROCESS 7
#define REASON_SNI 8
#define REASON_NETPOL 9
#define REASON_NETPOL_RULE 10         /* explicit netpol_rules4 deny match (v2) */
#define REASON_NETPOL_DEFAULT_DENY 11 /* v2 default-deny posture, no matching allow rule */
#define REASON_CONN_RATE 12           /* per-cgroup new-TCP-connection-rate cap (conn_rate_limits) */
#define REASON_BPS 13                 /* per-destination byte-rate cap (rate_bps_v4/v6) */
#define REASON_CAPABILITY 14          /* agent-sourced capability-gated socket deny (capgate_pids) */
#define FAMILY_V4    4
#define FAMILY_V6    6

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_delete_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_submit;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)BPF_FUNC_get_current_uid_gid;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)BPF_FUNC_get_current_comm;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)BPF_FUNC_get_current_cgroup_id;
static __u64 (*bpf_get_socket_cookie)(void *ctx) = (void *)BPF_FUNC_get_socket_cookie;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)BPF_FUNC_skb_load_bytes;
static int (*bpf_sock_ops_cb_flags_set)(struct bpf_sock_ops *skops, int flags) = (void *)BPF_FUNC_sock_ops_cb_flags_set;

// Additive ABI: node/interface-scoped TC observations, never workload attribution.
struct icmp_error_key {
    __u32 ifindex;
    __u8 family, type, code, direction;
};
struct icmp_error_value {
    __u64 packets;
    __u32 advertised_mtu;
    __u32 pad;
    __u64 last_ns;
};
_Static_assert(sizeof(struct icmp_error_key) == 8, "icmp key ABI");
_Static_assert(sizeof(struct icmp_error_value) == 24, "icmp value ABI");
_Static_assert(__builtin_offsetof(struct icmp_error_key, family) == 4, "icmp family offset");
_Static_assert(__builtin_offsetof(struct icmp_error_value, advertised_mtu) == 8, "icmp MTU offset");
_Static_assert(__builtin_offsetof(struct icmp_error_value, last_ns) == 16, "icmp time offset");
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct icmp_error_key);
    __type(value, struct icmp_error_value);
} icmp_errors SEC(".maps");

static __always_inline void record_icmp_error(__u32 ifindex, __u8 family,
        __u8 direction, const struct netra_icmp_error *error)
{
    if (!error->valid) return;
    struct icmp_error_key k = { .ifindex = ifindex, .family = family,
        .type = error->type, .code = error->code, .direction = direction };
    struct icmp_error_value *v = bpf_map_lookup_elem(&icmp_errors, &k);
    if (!v) {
        struct icmp_error_value initial = {};
        bpf_map_update_elem(&icmp_errors, &k, &initial, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&icmp_errors, &k);
    }
    if (v) {
        __sync_fetch_and_add(&v->packets, 1);
        v->advertised_mtu = error->mtu;
        v->last_ns = bpf_ktime_get_ns();
    }
}

// Legacy v0.6 destination stats are retained so existing pinned maps can be reused.
struct dest_key {
    __u32 dst_ip;
    __u16 dst_port;
    __u8 protocol;
    __u8 pad;
};
struct dest_value {
    __u64 packets;
    __u64 bytes;
    __u64 blocked;
    __u64 last_ns;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dest_key);
    __type(value, struct dest_value);
} dest_stats SEC(".maps");

struct flow_key {
    __u8 family;
    __u8 direction;
    __u8 hook;
    __u8 protocol;
    __u16 src_port;
    __u16 dst_port;
    __u8 src_addr[16];
    __u8 dst_addr[16];
};
struct flow_value {
    __u64 packets;
    __u64 bytes;
    __u64 blocked;
    __u64 last_ns;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} flow_stats SEC(".maps");

struct workload_flow_key {
    __u64 cgroup_id;
    struct flow_key flow;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct workload_flow_key);
    __type(value, struct flow_value);
} workload_flow_stats SEC(".maps");

// Per-interface flow attribution — same pattern as workload_flow_key
// above: wraps flow_key verbatim instead of resizing it, so the existing
// flow_stats/workload_flow_stats pinned ABIs remain untouched. Populated
// only from the two HOOK_TC branches of handle_v4/handle_v6 (tc/egress,
// tc/ingress, TCX): that's the only place skb->ifindex reflects a
// specific, Netra-attached NIC. cgroup_skb hooks run at a pre-routing/
// socket-layer point where ifindex isn't a trustworthy "which NIC"
// signal, and the early-deny XDP program only ever calls update_flow on
// its blocked path, which would make this counter inconsistently
// blocked-only if included — so both are deliberately excluded.
struct iface_flow_key {
    __u32 ifindex;
    struct flow_key flow;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct iface_flow_key);
    __type(value, struct flow_value);
} iface_flow_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} blocked_v4 SEC(".maps");

struct ip6_key { __u8 addr[16]; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ip6_key);
    __type(value, __u8);
} blocked_v6 SEC(".maps");

// allowed_v4/v6 are exact-IP exceptions evaluated before any deny/rate.
// Presence means "never block this peer" for this packet. Observe mode
// still records the flow. Empty maps = no exceptions (fail-open elsewhere).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} allowed_v4 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ip6_key);
    __type(value, __u8);
} allowed_v6 SEC(".maps");

struct lpm4_key { __u32 prefixlen; __u8 data[5]; } __attribute__((packed));
struct lpm6_key { __u32 prefixlen; __u8 data[17]; } __attribute__((packed));
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 8192);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm4_key);
    __type(value, __u8);
} blocked_cidr_v4 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 8192);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm6_key);
    __type(value, __u8);
} blocked_cidr_v6 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 8192);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm4_key);
    __type(value, __u8);
} allowed_cidr_v4 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 8192);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm6_key);
    __type(value, __u8);
} allowed_cidr_v6 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} blocked_ingress_v4 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ip6_key);
    __type(value, __u8);
} blocked_ingress_v6 SEC(".maps");

struct port_key { __u8 direction; __u8 protocol; __u16 port; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct port_key);
    __type(value, __u8);
} blocked_ports SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct port_key);
    __type(value, __u8);
} allowed_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} blocked_uids SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} allowed_uids SEC(".maps");

struct dns_key { char name[96]; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct dns_key);
    __type(value, __u8);
} blocked_dns SEC(".maps");

struct comm_key { char name[16]; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct comm_key);
    __type(value, __u8);
} blocked_comms SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct comm_key);
    __type(value, __u8);
} allowed_comms SEC(".maps");

// Capability-gated socket deny: an agent-sourced, TOCTOU-caveated signal,
// not a kernel credential read. Reading task_struct->real_cred->cap_effective
// directly from cgroup/connect4|6 would require an unstable CO-RE
// struct-offset read into unexported kernel internals — a new class of
// fragility this project has avoided everywhere else in this file. Instead
// the agent periodically scans /proc (internal/procmeta), decides per-PID
// whether any currently-configured denied capability is effective, and
// only writes PIDs that currently match into capgate_pids as a plain
// presence flag (not the raw bitmask) — keeping the BPF-side check a
// single O(1) lookup, same shape as blocked_uids/blocked_comms. Because
// this is populated between agent sync intervals, a process's capability
// can legitimately change (drop or gain one) in the window between the
// last scan and this socket() call — this is a real, accepted limitation,
// not a bug; see docs/capability-gated-deny.md.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32); /* pid */
    __type(value, __u8);
} capgate_pids SEC(".maps");

struct rate_state { __u64 second; __u64 count; __u64 dropped; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} rate_v4 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct rate_state);
} rate_state_v4 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ip6_key);
    __type(value, __u32);
} rate_v6 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ip6_key);
    __type(value, struct rate_state);
} rate_state_v6 SEC(".maps");

// Byte-rate (bps) cap per destination — parallel to rate_v4/v6 above, not a
// replacement: a destination can have a PPS cap, a BPS cap, or both
// independently. Reuses struct rate_state verbatim; its `count` field holds
// cumulative bytes this second here, not a packet count.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} rate_bps_v4 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct rate_state);
} rate_byte_state_v4 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ip6_key);
    __type(value, __u32);
} rate_bps_v6 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ip6_key);
    __type(value, struct rate_state);
} rate_byte_state_v6 SEC(".maps");

// Per-cgroup new-TCP-connection-rate cap. Unlike rate_v4/v6 (keyed by
// destination address, checked in the TC packet path), this is keyed by
// cgroup_id and checked in socket4/socket6 (cgroup/connect4|connect6) —
// once per TCP connect() attempt, not once per packet. Family-agnostic
// (cgroup_id has no address family), so a single map pair covers both.
// Reuses the existing rate_state token-bucket shape verbatim.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64); /* cgroup_id */
    __type(value, __u32); /* connections-per-second ceiling */
} conn_rate_limits SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64); /* cgroup_id */
    __type(value, struct rate_state);
} conn_rate_state SEC(".maps");

// icmp_type_stats: observe-only ICMPv4 type histogram (key = ICMP type 0-255).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u8);
    __type(value, __u64);
} icmp_type_stats SEC(".maps");
// icmp6_type_stats: observe-only ICMPv6 type histogram (key = ICMPv6 type 0-255).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u8);
    __type(value, __u64);
} icmp6_type_stats SEC(".maps");

// key 0: 0=observe, 1=enforce.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

// scope_config key 0: 0=all cgroups, 1=selected cgroups only.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} scope_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u8);
} enforced_cgroups SEC(".maps");


// Socket owner identity is captured at connect() time and joined to sockops
// callbacks by socket cookie. This avoids attributing sockops callbacks to the
// kthread/softirq that happened to execute them.
struct socket_owner_value {
    __u64 cgroup_id;
    __u32 pid;
    __u32 uid;
    char comm[16];
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct socket_owner_value);
} socket_owner SEC(".maps");

struct tcp_health_key {
    __u64 cgroup_id;
    __u8 family;
    __u8 pad[3];
    __u32 local_ip4;
    __u32 remote_ip4;
    __u8 local_ip6[16];
    __u8 remote_ip6[16];
    __u16 local_port;
    __u16 remote_port;
};
struct tcp_health_value {
    __u64 active_established;
    __u64 passive_established;
    __u64 closes;
    __u64 retrans;
    __u64 rto;
    __u64 rtt_samples;
    __u64 srtt_us;
    __u64 rtt_min_us;
    __u64 snd_cwnd;
    __u64 bytes_acked;
    __u64 bytes_received;
    __u64 segs_in;
    __u64 segs_out;
    __u64 last_ns;
    __u32 pid;
    __u32 uid;
    char comm[16];
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct tcp_health_key);
    __type(value, struct tcp_health_value);
} tcp_health SEC(".maps");

struct tcp_signal_value {
    __u64 syn;
    __u64 syn_ack;
    __u64 fin;
    __u64 rst;
    __u64 packets;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct tcp_signal_value);
} tcp_signals SEC(".maps");

// UDP flow health beyond DNS: packets/bytes per cgroup+remote-endpoint UDP
// flow, mirroring tcp_health_key's shape so the two are easy to reason about
// together. No send_errors/failure field: unlike DNS (which pairs its own
// query/response and can therefore call a query "failed"), a bare UDP
// sendmsg() has no in-kernel signal available to any hook Netra attaches —
// cgroup/sendmsg4/6 runs before the packet is even queued, so it can't see a
// later ICMP port-unreachable, and the interface-level icmp_errors map
// (docs/icmp-diagnostics.md) isn't keyed per-flow. Documented honestly in
// docs/udp-flow-health.md rather than inventing a counter with no real
// signal behind it — same standard as the QUIC-observed reframe.
struct udp_flow_key {
    __u64 cgroup_id;
    __u8 family;
    __u8 pad[3];
    __u32 local_ip4;
    __u32 remote_ip4;
    __u8 local_ip6[16];
    __u8 remote_ip6[16];
    __u16 local_port;
    __u16 remote_port;
};
struct udp_flow_value {
    __u64 packets;
    __u64 bytes;
    __u64 last_ns;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct udp_flow_key);
    __type(value, struct udp_flow_value);
} udp_flow_health SEC(".maps");

// QUIC-observed: NOT SNI extraction. Full QUIC SNI parsing is infeasible in
// BPF — RFC 9001 mandatorily applies header protection to Initial packets,
// requiring HKDF-SHA256 + AES-128/ChaCha20, none of which exist as BPF
// helpers. This instead counts UDP/443 packets whose first payload byte
// matches RFC 9000's long-header form (top bit set, second-highest "fixed"
// bit set) — a traffic-observation heuristic, not a parser. See
// docs/quic-observed.md.
struct quic_observed_key {
    __u64 cgroup_id;
    __u8 family;
    __u8 pad[3];
    __u8 remote_addr[16];
    __u16 remote_port; // always 443 today; kept explicit for schema stability
    __u16 pad2;
};
struct quic_observed_value {
    __u64 packets;             // all UDP/443 packets observed for this cgroup+remote
    __u64 long_header_packets; // subset matching the long-header heuristic
    __u64 last_ns;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct quic_observed_key);
    __type(value, struct quic_observed_value);
} quic_observed SEC(".maps");

struct dns_pending_key {
    __u64 cgroup_id;
    __u8 family;
    __u8 pad0;
    __u16 client_port;
    __u16 txid;
    __u16 pad1;
    __u8 server[16];
};
struct dns_pending_value {
    __u64 start_ns;
    char name[96];
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dns_pending_key);
    __type(value, struct dns_pending_value);
} dns_pending SEC(".maps");

struct dns_health_key {
    __u64 cgroup_id;
    char name[96];
};
struct dns_health_value {
    __u64 queries;
    __u64 responses;
    __u64 failures;
    __u64 total_latency_us;
    __u64 max_latency_us;
    __u64 last_ns;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dns_health_key);
    __type(value, struct dns_health_value);
} dns_health SEC(".maps");

struct tls_meta_key { __u64 cgroup_id; char sni[96]; };
struct tls_meta_value { __u64 handshakes; __u64 blocked; __u64 last_ns; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct tls_meta_key);
    __type(value, struct tls_meta_value);
} tls_sni_stats SEC(".maps");

struct http_meta_key { __u64 cgroup_id; char host[96]; char method[8]; };
struct http_meta_value { __u64 requests; __u64 last_ns; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct http_meta_key);
    __type(value, struct http_meta_value);
} http_host_stats SEC(".maps");

struct http_status_key { __u64 cgroup_id; __u16 status; __u16 pad; };
struct http_status_value { __u64 count; __u64 last_ns; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct http_status_key);
    __type(value, struct http_status_value);
} http_status_stats SEC(".maps");

struct connect_attempt_key {
    __u64 cgroup_id;
    __u8 family;
    __u8 protocol;
    __u16 remote_port;
    __u8 remote[16];
} __attribute__((packed));
struct connect_attempt_value { __u64 attempts; __u64 blocked; __u64 last_ns; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct connect_attempt_key);
    __type(value, struct connect_attempt_value);
} connect_attempts SEC(".maps");


// v0.13 path diagnostics use new maps so existing pinned map ABIs remain valid.
struct connect_start_value {
    __u64 start_ns;
    struct connect_attempt_key key;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u64);
    __type(value, struct connect_start_value);
} connect_start SEC(".maps");

struct connect_health_value {
    __u64 established;
    __u64 total_latency_us;
    __u64 max_latency_us;
    __u64 last_ns;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct connect_attempt_key);
    __type(value, struct connect_health_value);
} connect_health SEC(".maps");

struct tcp_pressure_value {
    __u64 callbacks;
    __u64 snd_cwnd;
    __u64 snd_ssthresh;
    __u64 packets_out;
    __u64 retrans_out;
    __u64 total_retrans;
    __u64 lost_out;
    __u64 sacked_out;
    __u64 rate_delivered;
    __u64 rate_interval_us;
    __u64 mss_cache;
    __u64 state;
    __u64 last_ns;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct tcp_health_key);
    __type(value, struct tcp_pressure_value);
} tcp_pressure SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct dns_key);
    __type(value, __u8);
} blocked_sni SEC(".maps");

// v0.14 node-level kernel skb drop diagnostics. The raw kfree_skb
// tracepoint keeps the drop reason as args[2] across kernels that expose the
// reason argument, avoiding formatted-tracepoint layout dependencies.
struct kernel_drop_key {
    __u32 reason;
    __u32 pad;
};
struct kernel_drop_value {
    __u64 count;
    __u64 last_ns;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct kernel_drop_key);
    __type(value, struct kernel_drop_value);
} kernel_drops SEC(".maps");

// Node-level IPv6 extension-header/fragmentation metrics. The
// netra_ipv6_walk() helper already computes ext_headers/fragmented/
// nonfirst_fragment/more_fragments/chain_truncated for every IPv6 packet
// purely to decide whether L4 parsing is safe; this map is the first place
// any of that is counted rather than discarded. Keyed by (direction, hook)
// only — cgroup identity is not reliably available at all three call sites
// (handle_v6's HOOK_TC branch and netra_xdp_ingress have none), so this
// stays node-level for a consistent, comparable signal, matching the same
// reasoning kernel_drops already uses for the kfree_skb tracepoint.
struct ipv6_ext_key {
    __u8 direction;
    __u8 hook;
    __u16 pad;
};
struct ipv6_ext_value {
    __u64 packets;
    __u64 ext_header_packets;
    __u64 total_ext_headers;
    __u64 fragmented;
    __u64 nonfirst_fragments;
    __u64 more_fragments;
    __u64 chain_truncated;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, struct ipv6_ext_key);
    __type(value, struct ipv6_ext_value);
} ipv6_ext_stats SEC(".maps");

#include "netra_event.h"
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

// Conntrack + policy-drop ABI (v0.17). New maps only — existing pinned ABIs unchanged.
#define NETRA_CT_TCP_TIMEOUT_NS  (3600ULL * 1000000000ULL)
#define NETRA_CT_UDP_TIMEOUT_NS  (180ULL * 1000000000ULL)
#define NETRA_CT_OTHER_TIMEOUT_NS (60ULL * 1000000000ULL)

struct ct_key {
    __u8 family;
    __u8 protocol;
    __u16 pad;
    __u16 src_port;
    __u16 dst_port;
    __u8 src_addr[16];
    __u8 dst_addr[16];
};
struct ct_state {
    __u64 last_seen_ns;
    __u64 packets;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct ct_key);
    __type(value, struct ct_state);
} conntrack SEC(".maps");

// SYN-drop mode: an exact-IP deny rule (blocked_v4/blocked_ingress_v4,
// REASON_EXACT) can be additionally flagged here so only a genuinely new
// TCP connection attempt (SYN set, ACK clear) is actually dropped for that
// address+direction — any other TCP packet (including traffic on a
// connection Netra's own `conntrack` never saw the handshake for, e.g. one
// open before this rule was added, or before the agent attached) is
// allowed through instead of unconditionally dropped. Deliberately a
// separate side-map rather than widening blocked_v4/blocked_ingress_v4's
// pinned __u8 value ABI. CIDR-matched deny (REASON_CIDR) is not covered —
// see docs/syn-drop.md. UDP/other protocols are unaffected (there is no
// "new connection" concept for them); the deny rule behaves exactly as
// before for non-TCP traffic even when flagged here.
struct syndrop_key4 { __u32 addr; __u8 direction; __u8 pad[3]; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct syndrop_key4);
    __type(value, __u8);
} syndrop_v4 SEC(".maps");
struct syndrop_key6 { __u8 addr[16]; __u8 direction; __u8 pad[3]; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct syndrop_key6);
    __type(value, __u8);
} syndrop_v6 SEC(".maps");

// SYN-drop mode, CIDR extension: syndrop_v4/v6 above only cover exact-IP
// deny entries (REASON_EXACT) because their hash key is a precise
// {addr,direction} pair. blocked_cidr_v4/v6 (the LPM tries a CIDR deny
// rule lives in) return only a boolean match with no rule identity, so a
// per-CIDR SYN-drop flag can't be looked up the same way — it needs its
// own LPM trie, keyed identically to blocked_cidr_v4/v6 (direction packed
// into data[0], address in the remaining bytes), checked only when the
// blocking reason is REASON_CIDR. Side-maps, same discipline as the
// exact-IP pair above: blocked_cidr_v4/v6's pinned value type is untouched.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 8192);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm4_key);
    __type(value, __u8);
} syndrop_cidr_v4 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 8192);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm6_key);
    __type(value, __u8);
} syndrop_cidr_v6 SEC(".maps");

struct policy_drop_key {
    __u8 family;
    __u8 protocol;
    __u8 direction;
    __u8 reason;
    __u16 src_port;
    __u16 dst_port;
    __u8 src_addr[16];
    __u8 dst_addr[16];
};
struct policy_drop_value {
    __u64 packets;
    __u64 bytes;
    __u64 last_ns;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct policy_drop_key);
    __type(value, struct policy_drop_value);
} policy_drops SEC(".maps");

// Optional XDP Shield (v0.18) — generation-published, opt-in interfaces only.
struct shield_config {
    __u32 generation;
    __u32 mode; /* 0=off 1=audit 2=enforce */
    __u32 protect_all;
    __u32 syn_pps;
    __u32 udp_pps;
    __u32 icmp_pps;
    __u32 other_pps;
    __u32 burst_seconds;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct shield_config);
} shield_cfg SEC(".maps");
struct shield_ip4_key { __u32 generation; __u32 addr; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct shield_ip4_key);
    __type(value, __u8);
} shield_protected4 SEC(".maps");
struct shield_ip6_key { __u32 generation; __u8 addr[16]; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct shield_ip6_key);
    __type(value, __u8);
} shield_protected6 SEC(".maps");
struct shield_src_key { __u8 family; __u8 class_id; __u16 pad; __u8 addr[16]; };
struct shield_src_state {
    __u64 last_refill_ns;
    __u64 tokens;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct shield_src_key);
    __type(value, struct shield_src_state);
} shield_sources SEC(".maps");
struct shield_stat_value { __u64 allowed; __u64 dropped; __u64 audited; };
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct shield_stat_value);
} shield_stats SEC(".maps");

// Per-class breakdown of shield_stats (never resize shield_stats itself —
// it's an already-pinned map; index 0 is unused, 1=syn 2=udp 3=icmp 4=other,
// matching netra_xdp_shield's existing class_id values).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, struct shield_stat_value);
} shield_class_stats SEC(".maps");

// Per-source "would-be-denied" hit counter, reusing shield_src_key verbatim
// so an operator can preview which sources Shield would drop before
// switching from audit to enforce mode. Recorded identically in both modes.
// attempts is a separate, unconditional new-connection-attempt counter
// (SYN packets only, class_id==1) recorded regardless of pass/drop verdict
// — distinct from denied, which only counts packets the token bucket was
// empty for.
struct shield_source_hit_value { __u64 denied; __u64 last_ns; __u64 attempts; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct shield_src_key);
    __type(value, struct shield_source_hit_value);
} shield_source_hits SEC(".maps");

// Optional NetworkPolicy-shaped deny maps (v0.19) — identity = cgroup_id hash bucket.
struct netpol_peer4_key {
    __u64 cgroup_id;
    __u32 peer;
    __u16 port;
    __u8 protocol;
    __u8 direction; /* DIR_* */
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct netpol_peer4_key);
    __type(value, __u8); /* 1=deny */
} netpol_deny4 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32); /* 0=off 1=on */
} netpol_enabled SEC(".maps");

// v2: allow-list / default-deny per-workload engine (Phase 3). Additive —
// netpol_deny4/netpol_enabled above are untouched, so the legacy deny-only
// engine keeps working unmodified for existing users. Independent of
// config_map (the global observe/enforce flag), following the same
// decoupled-mode precedent as netra_xdp_shield's shield_cfg.mode.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct netpol_peer4_key);
    __type(value, __u8); /* 0=allow 1=deny */
} netpol_rules4 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64); /* cgroup_id */
    __type(value, __u8); /* 0=default-allow(fail-open, absent==same) 1=default-deny-this-workload */
} netpol_default4 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32); /* 0=off 1=on */
} netpol_v2_enabled SEC(".maps");

/* Per-CPU scratch keeps large buffers off the 512-byte BPF stack. */
struct netra_pkt_scratch {
    char dns_name[96];
    char sni[96];
    char http_m[8];
    char http_h[96];
    __u8 src[16];
    __u8 dst[16];
    struct ct_key ct;
    struct ct_state cts;
    struct policy_drop_key pdk;
    struct policy_drop_value pdv;
    struct dns_key name_key;
    struct dest_key destk;
    struct dest_value destv;
    struct flow_key flowk;
    struct flow_value flowv;
    struct workload_flow_key wflowk;
    struct iface_flow_key ifk;
    struct udp_flow_key ufk;
    struct udp_flow_value ufv;
    struct quic_observed_key qok;
    struct quic_observed_value qov;
    struct tls_meta_key tlsk;
    struct tls_meta_value tlsv;
    struct http_meta_key httpk;
    struct http_meta_value httpv;
    struct http_status_key httpsk;
    struct http_status_value httpsv;
    struct dns_health_key dnshk;
    struct dns_health_value dnshv;
    struct dns_pending_key dnspk;
    struct dns_pending_value dnspv;
    struct connect_attempt_key cak;
    struct connect_attempt_value cav;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct netra_pkt_scratch);
} pkt_scratch SEC(".maps");

static __always_inline struct netra_pkt_scratch *netra_scratch(void)
{
    __u32 z = 0;
    return bpf_map_lookup_elem(&pkt_scratch, &z);
}

static __always_inline __u64 ct_timeout_ns(__u8 protocol)
{
    if (protocol == IPPROTO_TCP) return NETRA_CT_TCP_TIMEOUT_NS;
    if (protocol == IPPROTO_UDP) return NETRA_CT_UDP_TIMEOUT_NS;
    return NETRA_CT_OTHER_TIMEOUT_NS;
}

static __always_inline void ct_fill(__u8 family, __u8 proto, __u16 sport, __u16 dport,
                                   const __u8 src[16], const __u8 dst[16], struct ct_key *k)
{
    __builtin_memset(k, 0, sizeof(*k));
    k->family = family; k->protocol = proto; k->src_port = sport; k->dst_port = dport;
    __builtin_memcpy(k->src_addr, src, 16); __builtin_memcpy(k->dst_addr, dst, 16);
}

static __always_inline int ct_hit(struct ct_key *k)
{
    struct ct_state *st = bpf_map_lookup_elem(&conntrack, k);
    if (!st) return 0;
    __u64 now = bpf_ktime_get_ns();
    if (st->last_seen_ns == 0 || now - st->last_seen_ns > ct_timeout_ns(k->protocol)) {
        bpf_map_delete_elem(&conntrack, k);
        return 0;
    }
    st->last_seen_ns = now;
    __sync_fetch_and_add(&st->packets, 1);
    return 1;
}

static __always_inline void ct_learn_pair(__u8 family, __u8 proto, __u16 sport, __u16 dport,
                                         const __u8 src[16], const __u8 dst[16])
{
    struct netra_pkt_scratch *sc = netra_scratch();
    if (!sc) return;
    sc->cts.last_seen_ns = bpf_ktime_get_ns();
    sc->cts.packets = 1;
    ct_fill(family, proto, sport, dport, src, dst, &sc->ct);
    bpf_map_update_elem(&conntrack, &sc->ct, &sc->cts, BPF_ANY);
    ct_fill(family, proto, dport, sport, dst, src, &sc->ct);
    bpf_map_update_elem(&conntrack, &sc->ct, &sc->cts, BPF_ANY);
}

static __always_inline void record_policy_drop(__u8 family, __u8 proto, __u8 direction, __u8 reason,
                                               __u16 sport, __u16 dport, const __u8 src[16], const __u8 dst[16],
                                               __u32 len)
{
    if (!reason) return;
    struct netra_pkt_scratch *sc = netra_scratch();
    if (!sc) return;
    __builtin_memset(&sc->pdk, 0, sizeof(sc->pdk));
    sc->pdk.family = family; sc->pdk.protocol = proto; sc->pdk.direction = direction; sc->pdk.reason = reason;
    sc->pdk.src_port = sport; sc->pdk.dst_port = dport;
    __builtin_memcpy(sc->pdk.src_addr, src, 16); __builtin_memcpy(sc->pdk.dst_addr, dst, 16);
    __builtin_memset(&sc->pdv, 0, sizeof(sc->pdv));
    struct policy_drop_value *v = bpf_map_lookup_elem(&policy_drops, &sc->pdk);
    if (!v) {
        bpf_map_update_elem(&policy_drops, &sc->pdk, &sc->pdv, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&policy_drops, &sc->pdk);
    }
    if (v) {
        __sync_fetch_and_add(&v->packets, 1);
        __sync_fetch_and_add(&v->bytes, len);
        v->last_ns = bpf_ktime_get_ns();
    }
}

static __always_inline int netpol_denies4(__u64 cgroup_id, __u8 direction, __u32 peer, __u8 proto, __u16 dport)
{
    __u32 z = 0; __u32 *en = bpf_map_lookup_elem(&netpol_enabled, &z);
    if (!en || !*en || !cgroup_id) return 0;
    struct netpol_peer4_key k = {.cgroup_id=cgroup_id,.peer=peer,.port=dport,.protocol=proto,.direction=direction};
    if (bpf_map_lookup_elem(&netpol_deny4, &k)) return 1;
    k.port = 0; /* any-port deny */
    return bpf_map_lookup_elem(&netpol_deny4, &k) != 0;
}

// netpol_v2_lookup4: explicit allow/deny lookup for the v2 engine. Returns 1
// and sets *verdict (0=allow 1=deny) if an explicit rule matches; returns 0
// (no opinion) if v2 is off, this isn't a cgroup context, or no rule
// matches — callers must fall through to the flat deny-list/legacy/default
// posture checks in that case. An explicit allow here is deliberately able
// to override every check below it, including the flat global emergency
// deny-list — see docs/native-netpol.md for the safety tradeoff this
// represents; it is not a bug that a v2 allow can un-block an address an
// operator staged in the flat deny-list.
//
// Three-step fallback, cheapest/most-specific first: (1) exact peer + exact
// port, (2) exact peer + any-port, (3) any-peer (peer=0) + exact port — a
// port-only rule, mirroring the v1 flat engine's allowed_ports two-step
// fallback (allowed_port()) into this hash-keyed v2 engine. peer=0 is safe
// as a wildcard sentinel: 0.0.0.0 is never a real peer address on this
// path. There is no "any-peer + any-port" fourth step — a rule with
// neither an exact peer nor an exact port has no real discriminator and is
// rejected at the API layer (see ebpfNetPolRuleAdd), so no such row can
// exist in netpol_rules4 to look up.
static __always_inline int netpol_v2_lookup4(__u64 cgroup_id, __u8 direction, __u32 peer, __u8 proto, __u16 dport, __u8 *verdict)
{
    __u32 z = 0; __u32 *en = bpf_map_lookup_elem(&netpol_v2_enabled, &z);
    if (!en || !*en || !cgroup_id) return 0;
    struct netpol_peer4_key k = {.cgroup_id=cgroup_id,.peer=peer,.port=dport,.protocol=proto,.direction=direction};
    __u8 *v = bpf_map_lookup_elem(&netpol_rules4, &k);
    if (!v) {
        k.port = 0; /* any-port rule */
        v = bpf_map_lookup_elem(&netpol_rules4, &k);
    }
    if (!v) {
        k.peer = 0; k.port = dport; /* port-only rule: any peer, exact port */
        v = bpf_map_lookup_elem(&netpol_rules4, &k);
        if (!v) return 0;
    }
    *verdict = *v;
    return 1;
}

// netpol_v2_default_deny4: is this cgroup in default-deny posture? Absence
// of an entry means fail-open (default-allow) — a workload is only ever
// subject to default-deny once the control plane explicitly puts it there
// (see PUT /api/v1/ebpf/netpol/default-deny), mirroring real Kubernetes
// NetworkPolicy semantics and every other fail-open boundary in this file.
static __always_inline int netpol_v2_default_deny4(__u64 cgroup_id)
{
    if (!cgroup_id) return 0;
    __u8 *posture = bpf_map_lookup_elem(&netpol_default4, &cgroup_id);
    return posture && *posture;
}

static __always_inline void track_ipv6_ext(__u8 direction, __u8 hook, const struct netra_ipv6_l4 *w)
{
    struct ipv6_ext_key k = {.direction = direction, .hook = hook};
    struct ipv6_ext_value zero = {};
    struct ipv6_ext_value *v = bpf_map_lookup_elem(&ipv6_ext_stats, &k);
    if (!v) {
        bpf_map_update_elem(&ipv6_ext_stats, &k, &zero, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&ipv6_ext_stats, &k);
    }
    if (!v) return;
    __sync_fetch_and_add(&v->packets, 1);
    if (w->ext_headers) {
        __sync_fetch_and_add(&v->ext_header_packets, 1);
        __sync_fetch_and_add(&v->total_ext_headers, w->ext_headers);
    }
    if (w->fragmented) __sync_fetch_and_add(&v->fragmented, 1);
    if (w->nonfirst_fragment) __sync_fetch_and_add(&v->nonfirst_fragments, 1);
    if (w->more_fragments) __sync_fetch_and_add(&v->more_fragments, 1);
    if (w->chain_truncated) __sync_fetch_and_add(&v->chain_truncated, 1);
}

static __always_inline void track_shield_source_hit(const struct shield_src_key *k)
{
    struct shield_source_hit_value zero = {};
    struct shield_source_hit_value *v = bpf_map_lookup_elem(&shield_source_hits, k);
    if (!v) {
        bpf_map_update_elem(&shield_source_hits, k, &zero, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&shield_source_hits, k);
    }
    if (!v) return;
    __sync_fetch_and_add(&v->denied, 1);
    v->last_ns = bpf_ktime_get_ns();
}

static __always_inline void track_shield_source_attempt(const struct shield_src_key *k)
{
    struct shield_source_hit_value zero = {};
    struct shield_source_hit_value *v = bpf_map_lookup_elem(&shield_source_hits, k);
    if (!v) {
        bpf_map_update_elem(&shield_source_hits, k, &zero, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&shield_source_hits, k);
    }
    if (!v) return;
    __sync_fetch_and_add(&v->attempts, 1);
}

static __always_inline int shield_rate_ok(__u8 family, __u8 class_id, const __u8 addr[16], __u32 pps, __u32 burst)
{
    if (class_id == 1) {
        struct shield_src_key ak = {.family=family,.class_id=class_id};
        __builtin_memcpy(ak.addr, addr, 16);
        track_shield_source_attempt(&ak);
    }
    if (!pps) return 1;
    if (!burst) burst = 1;
    struct shield_src_key k = {.family=family,.class_id=class_id};
    __builtin_memcpy(k.addr, addr, 16);
    struct shield_src_state *st = bpf_map_lookup_elem(&shield_sources, &k);
    __u64 now = bpf_ktime_get_ns();
    __u64 capacity = (__u64)pps * burst;
    if (!st) {
        struct shield_src_state init = {.last_refill_ns=now,.tokens=capacity ? capacity-1 : 0};
        bpf_map_update_elem(&shield_sources, &k, &init, BPF_NOEXIST);
        return 1;
    }
    __u64 elapsed = now - st->last_refill_ns;
    if (elapsed > 0 && pps) {
        __u64 add = (elapsed * pps) / 1000000000ULL;
        if (add) {
            st->tokens += add;
            if (st->tokens > capacity) st->tokens = capacity;
            st->last_refill_ns = now;
        }
    }
    if (st->tokens == 0) {
        track_shield_source_hit(&k);
        return 0;
    }
    st->tokens -= 1;
    return 1;
}

static __always_inline int enforcing(void)
{
    __u32 key = 0;
    __u32 *mode = bpf_map_lookup_elem(&config_map, &key);
    return mode && *mode == 1;
}

static __always_inline int scope_allows(__u64 cgroup_id)
{
    __u32 key = 0;
    __u32 *mode = bpf_map_lookup_elem(&scope_config, &key);
    if (!mode || *mode == 0) return 1;
    if (!cgroup_id) return 0;
    return bpf_map_lookup_elem(&enforced_cgroups, &cgroup_id) != 0;
}

static __always_inline void copy4(__u8 out[16], __u32 addr)
{
    __builtin_memset(out, 0, 16);
    __builtin_memcpy(out, &addr, 4);
}
static __always_inline void copy16(__u8 out[16], const void *addr)
{
    __builtin_memcpy(out, addr, 16);
}

static __always_inline int blocked_port(__u8 direction, __u8 proto, __u16 port)
{
    struct port_key k = {.direction = direction, .protocol = proto, .port = port};
    if (bpf_map_lookup_elem(&blocked_ports, &k)) return 1;
    k.protocol = 0;
    return bpf_map_lookup_elem(&blocked_ports, &k) != 0;
}
static __always_inline int allowed_port(__u8 direction, __u8 proto, __u16 port)
{
    if (!port) return 0;
    struct port_key k = {.direction = direction, .protocol = proto, .port = port};
    if (bpf_map_lookup_elem(&allowed_ports, &k)) return 1;
    k.protocol = 0;
    return bpf_map_lookup_elem(&allowed_ports, &k) != 0;
}

static __always_inline int blocked_cidr4(__u8 direction, __u32 addr)
{
    struct lpm4_key k = {.prefixlen = 40};
    k.data[0] = direction;
    __builtin_memcpy(&k.data[1], &addr, 4);
    return bpf_map_lookup_elem(&blocked_cidr_v4, &k) != 0;
}
static __always_inline int blocked_cidr6(__u8 direction, const __u8 addr[16])
{
    struct lpm6_key k = {.prefixlen = 136};
    k.data[0] = direction;
    __builtin_memcpy(&k.data[1], addr, 16);
    return bpf_map_lookup_elem(&blocked_cidr_v6, &k) != 0;
}

static __always_inline int rate_limited6(const __u8 addr[16])
{
    struct ip6_key k = {};
    __builtin_memcpy(k.addr, addr, 16);
    __u32 *pps = bpf_map_lookup_elem(&rate_v6, &k);
    if (!pps || !*pps) return 0;
    __u64 sec = bpf_ktime_get_ns() / 1000000000ULL;
    struct rate_state zero = {.second = sec, .count = 0, .dropped = 0};
    struct rate_state *st = bpf_map_lookup_elem(&rate_state_v6, &k);
    if (!st) {
        bpf_map_update_elem(&rate_state_v6, &k, &zero, BPF_NOEXIST);
        st = bpf_map_lookup_elem(&rate_state_v6, &k);
        if (!st) return 0;
    }
    if (st->second != sec) {
        st->second = sec;
        st->count = 1;
        return 0;
    }
    __u64 old = __sync_fetch_and_add(&st->count, 1);
    if (old >= *pps) {
        __sync_fetch_and_add(&st->dropped, 1);
        return 1;
    }
    return 0;
}

// Byte-rate cap counterpart to rate_limited6 — same fixed-one-second-window
// logic, but accumulates len (bytes) instead of a fixed 1 per call. A
// packet that pushes the cumulative total over the cap is still admitted
// (checked against the pre-add total, same tolerance as the PPS version);
// only later packets in the same second are dropped.
static __always_inline int bps_limited6(const __u8 addr[16], __u32 len)
{
    struct ip6_key k = {};
    __builtin_memcpy(k.addr, addr, 16);
    __u32 *bps = bpf_map_lookup_elem(&rate_bps_v6, &k);
    if (!bps || !*bps) return 0;
    __u64 sec = bpf_ktime_get_ns() / 1000000000ULL;
    struct rate_state zero = {.second = sec, .count = len, .dropped = 0};
    struct rate_state *st = bpf_map_lookup_elem(&rate_byte_state_v6, &k);
    if (!st) {
        bpf_map_update_elem(&rate_byte_state_v6, &k, &zero, BPF_NOEXIST);
        st = bpf_map_lookup_elem(&rate_byte_state_v6, &k);
        if (!st) return 0;
    }
    if (st->second != sec) {
        st->second = sec;
        st->count = len;
        return 0;
    }
    __u64 old = __sync_fetch_and_add(&st->count, len);
    if (old >= *bps) {
        __sync_fetch_and_add(&st->dropped, 1);
        return 1;
    }
    return 0;
}

static __always_inline void bump_icmp_map(void *map, __u8 typ)
{
    __u64 *n = bpf_map_lookup_elem(map, &typ);
    if (n) {
        __sync_fetch_and_add(n, 1);
        return;
    }
    __u64 one = 1;
    bpf_map_update_elem(map, &typ, &one, BPF_NOEXIST);
}
static __always_inline void bump_icmp_type(__u8 typ) { bump_icmp_map(&icmp_type_stats, typ); }
static __always_inline void bump_icmp6_type(__u8 typ) { bump_icmp_map(&icmp6_type_stats, typ); }

static __always_inline int allowed_cidr4(__u8 direction, __u32 addr)
{
    struct lpm4_key k = {.prefixlen = 40};
    k.data[0] = direction;
    __builtin_memcpy(&k.data[1], &addr, 4);
    return bpf_map_lookup_elem(&allowed_cidr_v4, &k) != 0;
}
static __always_inline int allowed_cidr6(__u8 direction, const __u8 addr[16])
{
    struct lpm6_key k = {.prefixlen = 136};
    k.data[0] = direction;
    __builtin_memcpy(&k.data[1], addr, 16);
    return bpf_map_lookup_elem(&allowed_cidr_v6, &k) != 0;
}

static __always_inline int rate_limited4(__u32 dst)
{
    __u32 *pps = bpf_map_lookup_elem(&rate_v4, &dst);
    if (!pps || !*pps) return 0;
    __u64 sec = bpf_ktime_get_ns() / 1000000000ULL;
    struct rate_state zero = {.second = sec, .count = 0, .dropped = 0};
    struct rate_state *st = bpf_map_lookup_elem(&rate_state_v4, &dst);
    if (!st) {
        bpf_map_update_elem(&rate_state_v4, &dst, &zero, BPF_NOEXIST);
        st = bpf_map_lookup_elem(&rate_state_v4, &dst);
        if (!st) return 0;
    }
    if (st->second != sec) {
        st->second = sec;
        st->count = 1;
        return 0;
    }
    __u64 old = __sync_fetch_and_add(&st->count, 1);
    if (old >= *pps) {
        __sync_fetch_and_add(&st->dropped, 1);
        return 1;
    }
    return 0;
}

// Byte-rate cap counterpart to rate_limited4 — see bps_limited6's comment.
static __always_inline int bps_limited4(__u32 dst, __u32 len)
{
    __u32 *bps = bpf_map_lookup_elem(&rate_bps_v4, &dst);
    if (!bps || !*bps) return 0;
    __u64 sec = bpf_ktime_get_ns() / 1000000000ULL;
    struct rate_state zero = {.second = sec, .count = len, .dropped = 0};
    struct rate_state *st = bpf_map_lookup_elem(&rate_byte_state_v4, &dst);
    if (!st) {
        bpf_map_update_elem(&rate_byte_state_v4, &dst, &zero, BPF_NOEXIST);
        st = bpf_map_lookup_elem(&rate_byte_state_v4, &dst);
        if (!st) return 0;
    }
    if (st->second != sec) {
        st->second = sec;
        st->count = len;
        return 0;
    }
    __u64 old = __sync_fetch_and_add(&st->count, len);
    if (old >= *bps) {
        __sync_fetch_and_add(&st->dropped, 1);
        return 1;
    }
    return 0;
}

// Per-cgroup new-TCP-connection-rate cap — same token-bucket-per-second
// logic as rate_limited4/6, keyed by cgroup_id instead of destination
// address. Only called from socket4/socket6 for proto==IPPROTO_TCP (see
// their call sites): cgroup/sendmsg4|6 (UDP) never reaches this, since a
// UDP sendmsg() isn't a new connection.
static __always_inline int conn_rate_limited(__u64 cgroup_id)
{
    if (!cgroup_id) return 0;
    __u32 *pps = bpf_map_lookup_elem(&conn_rate_limits, &cgroup_id);
    if (!pps || !*pps) return 0;
    __u64 sec = bpf_ktime_get_ns() / 1000000000ULL;
    struct rate_state zero = {.second = sec, .count = 0, .dropped = 0};
    struct rate_state *st = bpf_map_lookup_elem(&conn_rate_state, &cgroup_id);
    if (!st) {
        bpf_map_update_elem(&conn_rate_state, &cgroup_id, &zero, BPF_NOEXIST);
        st = bpf_map_lookup_elem(&conn_rate_state, &cgroup_id);
        if (!st) return 0;
    }
    if (st->second != sec) {
        st->second = sec;
        st->count = 1;
        return 0;
    }
    __u64 old = __sync_fetch_and_add(&st->count, 1);
    if (old >= *pps) {
        __sync_fetch_and_add(&st->dropped, 1);
        return 1;
    }
    return 0;
}

static __always_inline void update_flow(__u8 family, __u8 direction, __u8 hook, __u8 proto,
                                        __u16 sport, __u16 dport, const __u8 src[16], const __u8 dst[16],
                                        __u32 len, int blocked, __u64 cgroup_id)
{
    struct netra_pkt_scratch *sc = netra_scratch();
    if (!sc) return;
    __builtin_memset(&sc->flowk, 0, sizeof(sc->flowk));
    sc->flowk.family=family; sc->flowk.direction=direction; sc->flowk.hook=hook; sc->flowk.protocol=proto;
    sc->flowk.src_port=sport; sc->flowk.dst_port=dport;
    __builtin_memcpy(sc->flowk.src_addr, src, 16);
    __builtin_memcpy(sc->flowk.dst_addr, dst, 16);
    __builtin_memset(&sc->flowv, 0, sizeof(sc->flowv));
    struct flow_value *v = bpf_map_lookup_elem(&flow_stats, &sc->flowk);
    if (!v) {
        bpf_map_update_elem(&flow_stats, &sc->flowk, &sc->flowv, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&flow_stats, &sc->flowk);
    }
    if (v) {
        __sync_fetch_and_add(&v->packets, 1);
        __sync_fetch_and_add(&v->bytes, len);
        if (blocked) __sync_fetch_and_add(&v->blocked, 1);
        v->last_ns = bpf_ktime_get_ns();
    }
    if (cgroup_id) {
        __builtin_memset(&sc->wflowk, 0, sizeof(sc->wflowk));
        sc->wflowk.cgroup_id = cgroup_id;
        __builtin_memcpy(&sc->wflowk.flow, &sc->flowk, sizeof(sc->flowk));
        struct flow_value *wv = bpf_map_lookup_elem(&workload_flow_stats, &sc->wflowk);
        if (!wv) {
            bpf_map_update_elem(&workload_flow_stats, &sc->wflowk, &sc->flowv, BPF_NOEXIST);
            wv = bpf_map_lookup_elem(&workload_flow_stats, &sc->wflowk);
        }
        if (wv) {
            __sync_fetch_and_add(&wv->packets, 1);
            __sync_fetch_and_add(&wv->bytes, len);
            if (blocked) __sync_fetch_and_add(&wv->blocked, 1);
            wv->last_ns = bpf_ktime_get_ns();
        }
    }
}

static __always_inline void update_iface_flow(__u32 ifindex, __u8 family, __u8 direction, __u8 hook, __u8 proto,
                                              __u16 sport, __u16 dport, const __u8 src[16], const __u8 dst[16],
                                              __u32 len, int blocked)
{
    struct netra_pkt_scratch *sc = netra_scratch();
    if (!sc) return;
    __builtin_memset(&sc->ifk, 0, sizeof(sc->ifk));
    sc->ifk.ifindex = ifindex;
    sc->ifk.flow.family=family; sc->ifk.flow.direction=direction; sc->ifk.flow.hook=hook; sc->ifk.flow.protocol=proto;
    sc->ifk.flow.src_port=sport; sc->ifk.flow.dst_port=dport;
    __builtin_memcpy(sc->ifk.flow.src_addr, src, 16);
    __builtin_memcpy(sc->ifk.flow.dst_addr, dst, 16);
    __builtin_memset(&sc->flowv, 0, sizeof(sc->flowv));
    struct flow_value *v = bpf_map_lookup_elem(&iface_flow_stats, &sc->ifk);
    if (!v) {
        bpf_map_update_elem(&iface_flow_stats, &sc->ifk, &sc->flowv, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&iface_flow_stats, &sc->ifk);
    }
    if (v) {
        __sync_fetch_and_add(&v->packets, 1);
        __sync_fetch_and_add(&v->bytes, len);
        if (blocked) __sync_fetch_and_add(&v->blocked, 1);
        v->last_ns = bpf_ktime_get_ns();
    }
}

// Only ever called from the cgroup_skb (HOOK_CGROUP) branch of
// handle_v4/handle_v6 for unblocked IPPROTO_UDP packets, where cgroup_id
// is real (bpf_get_current_cgroup_id(), not the TC branch's hardcoded 0)
// and full packet length is available — unlike cgroup/sendmsg4/6, which
// only sees per-syscall send attempts, not per-packet bytes. Local/remote
// are normalized by direction so both halves of a flow land in one entry,
// matching tcp_health's convention.
static __always_inline void update_udp_flow_health(__u8 family, __u8 direction, __u16 sport, __u16 dport,
                                                    const __u8 src[16], const __u8 dst[16], __u32 len,
                                                    __u64 cgroup_id)
{
    if (!cgroup_id) return;
    struct netra_pkt_scratch *sc = netra_scratch();
    if (!sc) return;
    __builtin_memset(&sc->ufk, 0, sizeof(sc->ufk));
    sc->ufk.cgroup_id = cgroup_id;
    sc->ufk.family = family;
    const __u8 *local = direction == DIR_EGRESS ? src : dst;
    const __u8 *remote = direction == DIR_EGRESS ? dst : src;
    __u16 local_port = direction == DIR_EGRESS ? sport : dport;
    __u16 remote_port = direction == DIR_EGRESS ? dport : sport;
    if (family == FAMILY_V4) {
        __builtin_memcpy(&sc->ufk.local_ip4, local, 4);
        __builtin_memcpy(&sc->ufk.remote_ip4, remote, 4);
    } else {
        __builtin_memcpy(sc->ufk.local_ip6, local, 16);
        __builtin_memcpy(sc->ufk.remote_ip6, remote, 16);
    }
    sc->ufk.local_port = local_port;
    sc->ufk.remote_port = remote_port;
    __builtin_memset(&sc->ufv, 0, sizeof(sc->ufv));
    struct udp_flow_value *v = bpf_map_lookup_elem(&udp_flow_health, &sc->ufk);
    if (!v) {
        bpf_map_update_elem(&udp_flow_health, &sc->ufk, &sc->ufv, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&udp_flow_health, &sc->ufk);
    }
    if (!v) return;
    __sync_fetch_and_add(&v->packets, 1);
    __sync_fetch_and_add(&v->bytes, len);
    v->last_ns = bpf_ktime_get_ns();
}

// Only called for UDP/443 traffic from the same HOOK_CGROUP call site as
// update_udp_flow_health, with the same real cgroup_id. See the
// quic_observed_key/value comment above for why this counts long-header
// packets rather than extracting SNI.
static __always_inline void update_quic_observed(__u8 family, __u8 direction, __u16 sport, __u16 dport,
                                                  const __u8 src[16], const __u8 dst[16],
                                                  void *payload, void *data_end, __u64 cgroup_id)
{
    __u16 remote_port = direction == DIR_EGRESS ? dport : sport;
    if (remote_port != __builtin_bswap16(443) || !cgroup_id || !payload) return;
    struct netra_pkt_scratch *sc = netra_scratch();
    if (!sc) return;
    __builtin_memset(&sc->qok, 0, sizeof(sc->qok));
    sc->qok.cgroup_id = cgroup_id;
    sc->qok.family = family;
    const __u8 *remote = direction == DIR_EGRESS ? dst : src;
    if (family == FAMILY_V4) {
        __builtin_memcpy(sc->qok.remote_addr, remote, 4);
    } else {
        __builtin_memcpy(sc->qok.remote_addr, remote, 16);
    }
    sc->qok.remote_port = remote_port;
    __builtin_memset(&sc->qov, 0, sizeof(sc->qov));
    struct quic_observed_value *v = bpf_map_lookup_elem(&quic_observed, &sc->qok);
    if (!v) {
        bpf_map_update_elem(&quic_observed, &sc->qok, &sc->qov, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&quic_observed, &sc->qok);
    }
    if (!v) return;
    __sync_fetch_and_add(&v->packets, 1);
    unsigned char *p = payload;
    if ((void *)(p + 1) <= data_end) {
        __u8 byte0 = p[0];
        if ((byte0 & 0x80) && (byte0 & 0x40)) __sync_fetch_and_add(&v->long_header_packets, 1);
    }
    v->last_ns = bpf_ktime_get_ns();
}

static __always_inline struct obs_event *new_event(__u8 family, __u8 direction, __u8 hook, __u8 proto,
                                                    __u8 action, __u8 type, __u8 reason)
{
    struct obs_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->ts_ns = bpf_ktime_get_ns();
    e->family = family;
    e->direction = direction;
    e->hook = hook;
    e->protocol = proto;
    e->action = action;
    e->event_type = type;
    e->reason = reason;
    return e;
}

static __always_inline void submit_packet_event(__u8 family, __u8 direction, __u8 hook, __u8 proto,
                                                 __u8 action, __u8 type, __u8 reason, __u32 ifindex,
                                                 __u32 len, const __u8 src[16], const __u8 dst[16],
                                                 __u16 sport, __u16 dport, __u8 tcp_flags,
                                                 const char *dns, int dns_len, __u64 cgroup_id)
{
    struct obs_event *e = new_event(family,direction,hook,proto,action,type,reason);
    if (!e) return;
    e->ifindex=ifindex; e->length=len; e->src_port=sport; e->dst_port=dport; e->tcp_flags=tcp_flags; e->cgroup_id=cgroup_id;
    __builtin_memcpy(e->src_addr,src,16); __builtin_memcpy(e->dst_addr,dst,16);
    if (dns && dns_len > 0) __builtin_memcpy(e->dns, dns, 96);
    bpf_ringbuf_submit(e,0);
}

static __always_inline void submit_socket_event(struct bpf_sock_addr *ctx, __u8 family, __u8 proto,
                                                 __u8 action, __u8 reason, const __u8 dst[16])
{
    struct obs_event *e = new_event(family,DIR_EGRESS,HOOK_SOCKET,proto,action,
                                    action==ACT_BLOCK?EVT_BLOCK:EVT_CONNECT,reason);
    if (!e) return;
    __u64 pt=bpf_get_current_pid_tgid(), ug=bpf_get_current_uid_gid();
    e->pid=(__u32)(pt>>32); e->uid=(__u32)ug; e->cgroup_id=bpf_get_current_cgroup_id();
    e->dst_port=(__u16)ctx->user_port; __builtin_memcpy(e->dst_addr,dst,16);
    bpf_get_current_comm(e->comm,sizeof(e->comm));
    bpf_ringbuf_submit(e,0);
}

// Only ever called from inside handle_v4/handle_v6's existing blocked==1
// branch, for an exact-IP-matched (REASON_EXACT) TCP packet that is not a
// new-connection SYN — never on the common allow path. One extra hash
// lookup, gated behind three cheap comparisons the caller already made.
static __always_inline int syndrop_allows4(__u32 addr, __u8 direction)
{
    struct syndrop_key4 k = {.addr = addr, .direction = direction};
    return bpf_map_lookup_elem(&syndrop_v4, &k) != 0;
}
static __always_inline int syndrop_allows6(const __u8 addr[16], __u8 direction)
{
    struct syndrop_key6 k = {.direction = direction};
    __builtin_memcpy(k.addr, addr, 16);
    return bpf_map_lookup_elem(&syndrop_v6, &k) != 0;
}

// CIDR counterparts of syndrop_allows4/6 above — same call-site discipline
// (only ever reached from inside the existing rare blocked==1 branch, one
// extra LPM lookup gated behind cheap comparisons the caller already
// made). Key packing matches blocked_cidr4/6 exactly (direction in
// data[0], address afterward, full-width prefixlen for an exact-address
// query against whatever narrower CIDR prefixes are actually stored) so a
// syndrop_cidr_v4/v6 entry is looked up the same way it was inserted.
static __always_inline int syndrop_cidr_allows4(__u8 direction, __u32 addr)
{
    struct lpm4_key k = {.prefixlen = 40};
    k.data[0] = direction;
    __builtin_memcpy(&k.data[1], &addr, 4);
    return bpf_map_lookup_elem(&syndrop_cidr_v4, &k) != 0;
}
static __always_inline int syndrop_cidr_allows6(__u8 direction, const __u8 addr[16])
{
    struct lpm6_key k = {.prefixlen = 136};
    k.data[0] = direction;
    __builtin_memcpy(&k.data[1], addr, 16);
    return bpf_map_lookup_elem(&syndrop_cidr_v6, &k) != 0;
}

static __always_inline int decide4(__u8 direction, __u32 addr, __u8 proto, __u16 dport, __u8 *reason, int apply_rate, __u64 cgroup_id, __u32 len)
{
    if (!enforcing() || !scope_allows(cgroup_id)) return 0;
    if (bpf_map_lookup_elem(&allowed_v4, &addr)) return 0;
    if (allowed_cidr4(direction, addr)) return 0;
    if (dport && allowed_port(direction, proto, dport)) return 0;
    if (direction==DIR_INGRESS && bpf_map_lookup_elem(&blocked_ingress_v4,&addr)) { *reason=REASON_EXACT; return 1; }
    if (direction==DIR_EGRESS && bpf_map_lookup_elem(&blocked_v4,&addr)) { *reason=REASON_EXACT; return 1; }
    if (blocked_cidr4(direction,addr)) { *reason=REASON_CIDR; return 1; }
    if (dport && blocked_port(direction,proto,dport)) { *reason=REASON_PORT; return 1; }
    if (apply_rate && direction==DIR_EGRESS && rate_limited4(addr)) { *reason=REASON_RATE; return 1; }
    if (apply_rate && direction==DIR_EGRESS && bps_limited4(addr, len)) { *reason=REASON_BPS; return 1; }
    return 0;
}
static __always_inline int decide6(__u8 direction, const __u8 addr[16], __u8 proto, __u16 dport, __u8 *reason, int apply_rate, __u64 cgroup_id, __u32 len)
{
    if (!enforcing() || !scope_allows(cgroup_id)) return 0;
    struct ip6_key k={}; __builtin_memcpy(k.addr,addr,16);
    if (bpf_map_lookup_elem(&allowed_v6, &k)) return 0;
    if (allowed_cidr6(direction, addr)) return 0;
    if (dport && allowed_port(direction, proto, dport)) return 0;
    if (direction==DIR_INGRESS && bpf_map_lookup_elem(&blocked_ingress_v6,&k)) { *reason=REASON_EXACT; return 1; }
    if (direction==DIR_EGRESS && bpf_map_lookup_elem(&blocked_v6,&k)) { *reason=REASON_EXACT; return 1; }
    if (blocked_cidr6(direction,addr)) { *reason=REASON_CIDR; return 1; }
    if (dport && blocked_port(direction,proto,dport)) { *reason=REASON_PORT; return 1; }
    if (apply_rate && direction==DIR_EGRESS && rate_limited6(addr)) { *reason=REASON_RATE; return 1; }
    if (apply_rate && direction==DIR_EGRESS && bps_limited6(addr, len)) { *reason=REASON_BPS; return 1; }
    return 0;
}

// dns_qname/tls_sni/http_method/http_host/lower_ascii/hostname_char live in
// bpf/netra_l7.h (included above) so they're natively unit-testable
// (bpf/tests/l7_parse_test.c) independent of the BPF toolchain.

static __always_inline void track_tls(__u64 cgroup_id, const char sni[96], int blocked)
{
    if (!cgroup_id || !sni[0]) return;
    struct netra_pkt_scratch *sc = netra_scratch();
    if (!sc) return;
    __builtin_memset(&sc->tlsk, 0, sizeof(sc->tlsk));
    sc->tlsk.cgroup_id = cgroup_id;
    __builtin_memcpy(sc->tlsk.sni, sni, 96);
    __builtin_memset(&sc->tlsv, 0, sizeof(sc->tlsv));
    struct tls_meta_value *v = bpf_map_lookup_elem(&tls_sni_stats, &sc->tlsk);
    if (!v) { bpf_map_update_elem(&tls_sni_stats, &sc->tlsk, &sc->tlsv, BPF_NOEXIST); v = bpf_map_lookup_elem(&tls_sni_stats, &sc->tlsk); }
    if (!v) return;
    __sync_fetch_and_add(&v->handshakes, 1);
    if (blocked) __sync_fetch_and_add(&v->blocked, 1);
    v->last_ns = bpf_ktime_get_ns();
}

static __always_inline void track_http(__u64 cgroup_id, const char method[8], const char host[96])
{
    if (!cgroup_id || !method[0] || !host[0]) return;
    struct netra_pkt_scratch *sc = netra_scratch();
    if (!sc) return;
    __builtin_memset(&sc->httpk, 0, sizeof(sc->httpk));
    sc->httpk.cgroup_id = cgroup_id;
    __builtin_memcpy(sc->httpk.method, method, 8);
    __builtin_memcpy(sc->httpk.host, host, 96);
    __builtin_memset(&sc->httpv, 0, sizeof(sc->httpv));
    struct http_meta_value *v = bpf_map_lookup_elem(&http_host_stats, &sc->httpk);
    if (!v) { bpf_map_update_elem(&http_host_stats, &sc->httpk, &sc->httpv, BPF_NOEXIST); v = bpf_map_lookup_elem(&http_host_stats, &sc->httpk); }
    if (!v) return;
    __sync_fetch_and_add(&v->requests, 1);
    v->last_ns = bpf_ktime_get_ns();
}

static __always_inline void track_http_status(__u64 cgroup_id, __u16 status)
{
    if (status < 100) return;
    struct netra_pkt_scratch *sc = netra_scratch();
    if (!sc) return;
    __builtin_memset(&sc->httpsk, 0, sizeof(sc->httpsk));
    sc->httpsk.cgroup_id = cgroup_id;
    sc->httpsk.status = status;
    __builtin_memset(&sc->httpsv, 0, sizeof(sc->httpsv));
    struct http_status_value *v = bpf_map_lookup_elem(&http_status_stats, &sc->httpsk);
    if (!v) { bpf_map_update_elem(&http_status_stats, &sc->httpsk, &sc->httpsv, BPF_NOEXIST); v = bpf_map_lookup_elem(&http_status_stats, &sc->httpsk); }
    if (!v) return;
    __sync_fetch_and_add(&v->count, 1);
    v->last_ns = bpf_ktime_get_ns();
}

static __always_inline void track_connect_attempt(__u64 cgroup_id, __u8 family, __u8 proto,
                                                   const __u8 remote[16], __u16 port, int blocked)
{
    if (!cgroup_id) return;
    struct netra_pkt_scratch *sc = netra_scratch();
    if (!sc) return;
    __builtin_memset(&sc->cak, 0, sizeof(sc->cak));
    sc->cak.cgroup_id=cgroup_id; sc->cak.family=family; sc->cak.protocol=proto; sc->cak.remote_port=port;
    __builtin_memcpy(sc->cak.remote, remote, 16);
    __builtin_memset(&sc->cav, 0, sizeof(sc->cav));
    struct connect_attempt_value *v = bpf_map_lookup_elem(&connect_attempts, &sc->cak);
    if (!v) { bpf_map_update_elem(&connect_attempts, &sc->cak, &sc->cav, BPF_NOEXIST); v = bpf_map_lookup_elem(&connect_attempts, &sc->cak); }
    if (!v) return;
    __sync_fetch_and_add(&v->attempts, 1);
    if (blocked) __sync_fetch_and_add(&v->blocked, 1);
    v->last_ns = bpf_ktime_get_ns();
}

static __always_inline void track_tcp_signal(__u64 cgroup_id, __u8 flags)
{
    struct tcp_signal_value zero = {};
    struct tcp_signal_value *v = bpf_map_lookup_elem(&tcp_signals, &cgroup_id);
    if (!v) {
        bpf_map_update_elem(&tcp_signals, &cgroup_id, &zero, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&tcp_signals, &cgroup_id);
    }
    if (!v) return;
    __sync_fetch_and_add(&v->packets, 1);
    if (flags & 0x02) {
        if (flags & 0x10) __sync_fetch_and_add(&v->syn_ack, 1);
        else __sync_fetch_and_add(&v->syn, 1);
    }
    if (flags & 0x01) __sync_fetch_and_add(&v->fin, 1);
    if (flags & 0x04) __sync_fetch_and_add(&v->rst, 1);
}

static __always_inline void dns_query_track(__u64 cgroup_id, __u8 family, const __u8 server[16],
                                             __u16 client_port, __u16 txid,
                                             const char name[96], int name_len)
{
    if (!cgroup_id || name_len <= 0) return;
    struct netra_pkt_scratch *sc = netra_scratch();
    if (!sc) return;
    __builtin_memset(&sc->dnspk, 0, sizeof(sc->dnspk));
    sc->dnspk.cgroup_id = cgroup_id; sc->dnspk.family = family;
    sc->dnspk.client_port = client_port;
    sc->dnspk.txid = txid;
    __builtin_memcpy(sc->dnspk.server, server, 16);
    __builtin_memset(&sc->dnspv, 0, sizeof(sc->dnspv));
    sc->dnspv.start_ns = bpf_ktime_get_ns();
    __builtin_memcpy(sc->dnspv.name, name, 96);
    bpf_map_update_elem(&dns_pending, &sc->dnspk, &sc->dnspv, BPF_ANY);

    __builtin_memset(&sc->dnshk, 0, sizeof(sc->dnshk));
    sc->dnshk.cgroup_id = cgroup_id;
    __builtin_memcpy(sc->dnshk.name, name, 96);
    __builtin_memset(&sc->dnshv, 0, sizeof(sc->dnshv));
    struct dns_health_value *hv = bpf_map_lookup_elem(&dns_health, &sc->dnshk);
    if (!hv) {
        bpf_map_update_elem(&dns_health, &sc->dnshk, &sc->dnshv, BPF_NOEXIST);
        hv = bpf_map_lookup_elem(&dns_health, &sc->dnshk);
    }
    if (hv) {
        __sync_fetch_and_add(&hv->queries, 1);
        hv->last_ns = bpf_ktime_get_ns();
    }
}

static __always_inline void dns_response_track(__u64 cgroup_id, __u8 family, const __u8 server[16],
                                                __u16 client_port, void *payload, void *data_end,
                                                __u32 ifindex, __u32 len,
                                                const __u8 src[16], const __u8 dst[16])
{
    unsigned char *p = payload;
    if (!cgroup_id || (void *)(p + 12) > data_end) return;
    struct netra_pkt_scratch *sc = netra_scratch();
    if (!sc) return;
    __builtin_memset(&sc->dnspk, 0, sizeof(sc->dnspk));
    sc->dnspk.cgroup_id = cgroup_id; sc->dnspk.family = family;
    sc->dnspk.client_port = client_port;
    sc->dnspk.txid = ((__u16)p[0] << 8) | p[1];
    __builtin_memcpy(sc->dnspk.server, server, 16);
    struct dns_pending_value *pv = bpf_map_lookup_elem(&dns_pending, &sc->dnspk);
    if (!pv) return;

    __u64 now = bpf_ktime_get_ns();
    __u64 latency_us = (now - pv->start_ns) / 1000ULL;
    __u8 rcode = p[3] & 0x0f;
    __builtin_memset(&sc->dnshk, 0, sizeof(sc->dnshk));
    sc->dnshk.cgroup_id = cgroup_id;
    __builtin_memcpy(sc->dnshk.name, pv->name, 96);
    __builtin_memset(&sc->dnshv, 0, sizeof(sc->dnshv));
    struct dns_health_value *hv = bpf_map_lookup_elem(&dns_health, &sc->dnshk);
    if (!hv) {
        bpf_map_update_elem(&dns_health, &sc->dnshk, &sc->dnshv, BPF_NOEXIST);
        hv = bpf_map_lookup_elem(&dns_health, &sc->dnshk);
    }
    if (hv) {
        __sync_fetch_and_add(&hv->responses, 1);
        if (rcode) __sync_fetch_and_add(&hv->failures, 1);
        __sync_fetch_and_add(&hv->total_latency_us, latency_us);
        if (latency_us > hv->max_latency_us) hv->max_latency_us = latency_us;
        hv->last_ns = now;
    }
    __u16 qtype = netra_l7_dns_qtype(payload, data_end);
    struct obs_event *e = new_event(family, DIR_INGRESS, HOOK_CGROUP, IPPROTO_UDP, ACT_ALLOW, EVT_DNS_RESPONSE, REASON_NONE);
    if (e) {
        e->cgroup_id = cgroup_id;
        e->ifindex = ifindex;
        e->length = len;
        e->src_port = __builtin_bswap16(53);
        e->dst_port = client_port;
        e->latency_us = (__u32)(latency_us > 0xffffffffULL ? 0xffffffffULL : latency_us);
        e->dns_rcode = rcode;
        e->dns_qtype = qtype;
        __builtin_memcpy(e->src_addr, src, 16);
        __builtin_memcpy(e->dst_addr, dst, 16);
        __builtin_memcpy(e->dns, pv->name, 96);
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&dns_pending, &sc->dnspk);
}

static __always_inline int handle_v4(struct __sk_buff *skb, __u8 direction, __u8 hook, int l2, int allow_value)
{
    /* Map lookup first, then reload packet pointers (helpers invalidate pkt ptrs). */
    struct netra_pkt_scratch *sc = netra_scratch();
    if (!sc) return allow_value;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u32 ifindex = skb->ifindex;
    __u32 len = skb->len;

    struct iphdr *ip;
    if (l2) {
        struct ethhdr *eth=data;
        if ((void *)(eth+1)>data_end || eth->h_proto!=__builtin_bswap16(ETH_P_IP)) return allow_value;
        ip=(void *)(eth+1);
    } else ip=data;
    if ((void *)(ip+1)>data_end || ip->version!=4 || ip->ihl<5) return allow_value;
    void *l4=(void *)ip + ip->ihl*4;
    if (l4>data_end) return allow_value;
    __u8 proto = ip->protocol;
    __u32 saddr = ip->saddr, daddr = ip->daddr;
    __u16 sport=0,dport=0; __u8 flags=0; void *payload=0;
    if (proto==IPPROTO_TCP) {
        struct tcphdr *tcp=l4; if ((void *)(tcp+1)>data_end || tcp->doff < 5) return allow_value;
        sport=tcp->source; dport=tcp->dest; flags=*(((unsigned char *)tcp)+13);
        payload=(void *)tcp + ((__u32)tcp->doff * 4); if (payload > data_end) payload=0;
    } else if (proto==IPPROTO_UDP) {
        struct udphdr *udp=l4; if ((void *)(udp+1)>data_end) return allow_value;
        sport=udp->source; dport=udp->dest; payload=(void *)(udp+1);
    } else if (proto==IPPROTO_ICMP) {
        unsigned char *ic = l4;
        if ((void *)(ic + 1) <= data_end) bump_icmp_type(ic[0]);
    }
    struct netra_icmp_error icmp = {};
    if (hook == HOOK_TC && proto == IPPROTO_ICMP &&
        !(ip->frag_off & __builtin_bswap16(0x3fff)) &&
        __builtin_bswap16(ip->tot_len) >= ip->ihl * 4U + 8U)
        netra_icmp_parse(l4, data_end, FAMILY_V4, &icmp);
    __u32 peer = direction==DIR_EGRESS ? daddr : saddr;
    __u16 policy_port = dport;
    copy4(sc->src,saddr); copy4(sc->dst,daddr);

    /* TC path stays lean — L7/DNS live on cgroup hooks to keep programs under verifier limits. */
    if (hook == HOOK_TC) {
        record_icmp_error(ifindex, FAMILY_V4, direction, &icmp);
        __u64 cgroup_id = 0;
        int syn_new = (proto==IPPROTO_TCP && (flags & 0x02) && !(flags & 0x10));
        ct_fill(FAMILY_V4, proto, sport, dport, sc->src, sc->dst, &sc->ct);
        int established = (!syn_new && ct_hit(&sc->ct));
        __u8 reason=0; int blocked=0;
        if (!established) {
            blocked=decide4(direction,peer,proto,policy_port,&reason,1,cgroup_id,len);
        }
        if (blocked && proto==IPPROTO_TCP && !syn_new &&
            ((reason==REASON_EXACT && syndrop_allows4(peer,direction)) ||
             (reason==REASON_CIDR  && syndrop_cidr_allows4(direction,peer)))) blocked=0;
        update_flow(FAMILY_V4,direction,hook,proto,sport,dport,sc->src,sc->dst,len,blocked,cgroup_id);
        update_iface_flow(ifindex,FAMILY_V4,direction,hook,proto,sport,dport,sc->src,sc->dst,len,blocked);
        if (blocked) {
            record_policy_drop(FAMILY_V4,proto,direction,reason,sport,dport,sc->src,sc->dst,len);
            submit_packet_event(FAMILY_V4,direction,hook,proto,ACT_BLOCK,EVT_BLOCK,reason,ifindex,len,sc->src,sc->dst,sport,dport,flags,0,0,cgroup_id);
        } else {
            ct_learn_pair(FAMILY_V4,proto,sport,dport,sc->src,sc->dst);
            if ((bpf_ktime_get_ns() & 63)==1) submit_packet_event(FAMILY_V4,direction,hook,proto,ACT_ALLOW,EVT_FLOW,0,ifindex,len,sc->src,sc->dst,sport,dport,flags,0,0,cgroup_id);
        }
        return blocked ? (allow_value==TC_ACT_OK ? TC_ACT_SHOT : 0) : allow_value;
    }

    /* L7/DNS (SNI/HTTP/DNS-qname) is handled by netra_l7_cgroup_egress/ingress,
     * a separate program with its own verifier budget — do not fold it back
     * in here; that's what silently disconnected it before (see CHANGELOG.md
     * and docs/l7-metadata.md). This function stays CT + policy only. */
    __u64 cgroup_id = hook==HOOK_CGROUP ? bpf_get_current_cgroup_id() : 0;
    if (proto==IPPROTO_TCP) track_tcp_signal(cgroup_id, flags);
    int syn_new = (proto==IPPROTO_TCP && (flags & 0x02) && !(flags & 0x10));
    ct_fill(FAMILY_V4, proto, sport, dport, sc->src, sc->dst, &sc->ct);
    int established = (!syn_new && ct_hit(&sc->ct));
    __u8 reason=0; int blocked=0;
    if (!established) {
        __u8 v2_verdict=0;
        if (netpol_v2_lookup4(cgroup_id,direction,peer,proto,policy_port,&v2_verdict)) {
            /* Explicit v2 rule found: deny blocks immediately; allow passes
             * immediately, skipping every check below including the flat
             * deny-list (see netpol_v2_lookup4's doc comment). */
            if (v2_verdict) { blocked=1; reason=REASON_NETPOL_RULE; }
        } else {
            blocked=decide4(direction,peer,proto,policy_port,&reason,1,cgroup_id,len);
            if (!blocked && netpol_denies4(cgroup_id,direction,peer,proto,policy_port)) { blocked=1; reason=REASON_NETPOL; }
            if (!blocked && netpol_v2_default_deny4(cgroup_id)) { blocked=1; reason=REASON_NETPOL_DEFAULT_DENY; }
        }
    }
    if (blocked && proto==IPPROTO_TCP && !syn_new &&
        ((reason==REASON_EXACT && syndrop_allows4(peer,direction)) ||
         (reason==REASON_CIDR  && syndrop_cidr_allows4(direction,peer)))) blocked=0;
    update_flow(FAMILY_V4,direction,hook,proto,sport,dport,sc->src,sc->dst,len,blocked,cgroup_id);
    if (proto==IPPROTO_UDP && !blocked) update_udp_flow_health(FAMILY_V4,direction,sport,dport,sc->src,sc->dst,len,cgroup_id);
    if (proto==IPPROTO_UDP && !blocked) update_quic_observed(FAMILY_V4,direction,sport,dport,sc->src,sc->dst,payload,data_end,cgroup_id);
    if (direction==DIR_EGRESS) {
        sc->destk.dst_ip=daddr; sc->destk.dst_port=dport; sc->destk.protocol=proto; sc->destk.pad=0;
        __builtin_memset(&sc->destv, 0, sizeof(sc->destv));
        struct dest_value *lv=bpf_map_lookup_elem(&dest_stats,&sc->destk);
        if(!lv){bpf_map_update_elem(&dest_stats,&sc->destk,&sc->destv,BPF_NOEXIST);lv=bpf_map_lookup_elem(&dest_stats,&sc->destk);} if(lv){__sync_fetch_and_add(&lv->packets,1);__sync_fetch_and_add(&lv->bytes,len);if(blocked)__sync_fetch_and_add(&lv->blocked,1);lv->last_ns=bpf_ktime_get_ns();}
    }
    if (blocked) {
        record_policy_drop(FAMILY_V4,proto,direction,reason,sport,dport,sc->src,sc->dst,len);
        submit_packet_event(FAMILY_V4,direction,hook,proto,ACT_BLOCK,EVT_BLOCK,reason,ifindex,len,sc->src,sc->dst,sport,dport,flags,0,0,cgroup_id);
    } else {
        ct_learn_pair(FAMILY_V4,proto,sport,dport,sc->src,sc->dst);
        if ((bpf_ktime_get_ns() & 63)==1) submit_packet_event(FAMILY_V4,direction,hook,proto,ACT_ALLOW,EVT_FLOW,0,ifindex,len,sc->src,sc->dst,sport,dport,flags,0,0,cgroup_id);
    }
    return blocked ? (allow_value==TC_ACT_OK ? TC_ACT_SHOT : 0) : allow_value;
}

static __always_inline int handle_v6(struct __sk_buff *skb, __u8 direction, __u8 hook, int l2, int allow_value)
{
    struct netra_pkt_scratch *sc = netra_scratch();
    if (!sc) return allow_value;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u32 ifindex = skb->ifindex;
    __u32 len = skb->len;

    struct ipv6hdr *ip6;
    if (l2) {
        struct ethhdr *eth=data;
        if ((void *)(eth+1)>data_end || eth->h_proto!=__builtin_bswap16(ETH_P_IPV6)) return allow_value;
        ip6=(void *)(eth+1);
    } else ip6=data;
    if ((void *)(ip6+1)>data_end) return allow_value;

    struct netra_ipv6_l4 walk;
    netra_ipv6_walk((unsigned char *)(ip6 + 1), data_end, ip6->nexthdr, &walk);
    track_ipv6_ext(direction, hook, &walk);
    void *l4=walk.l4; __u8 proto=walk.proto; __u16 sport=0,dport=0; __u8 flags=0; void *payload=0;
    int l4_ok=0;
    if (walk.l4_parseable && !walk.nonfirst_fragment && proto==IPPROTO_TCP) {
        struct tcphdr *tcp=l4;
        if ((void *)(tcp+1)<=data_end && tcp->doff>=5) {
            void *tcp_end=(void *)tcp+((__u32)tcp->doff*4);
            if (tcp_end<=data_end) {
                sport=tcp->source; dport=tcp->dest; flags=*(((unsigned char*)tcp)+13);
                payload=tcp_end; l4_ok=1;
            }
        }
    } else if (walk.l4_parseable && !walk.nonfirst_fragment && proto==IPPROTO_UDP) {
        struct udphdr *udp=l4;
        if ((void *)(udp+1)<=data_end) {
            sport=udp->source; dport=udp->dest; payload=(void *)(udp+1); l4_ok=1;
        }
    } else if (walk.l4_parseable && !walk.nonfirst_fragment && proto==IPPROTO_ICMPV6 && l4) {
        unsigned char *ic = l4;
        if ((void *)(ic + 1) <= data_end) bump_icmp6_type(ic[0]);
    }
    struct netra_icmp_error icmp = {};
    if (hook == HOOK_TC && proto == IPPROTO_ICMPV6 && walk.l4_parseable &&
        !walk.fragmented && ip6->version == 6 &&
        (unsigned long)((unsigned char *)l4 - (unsigned char *)(ip6 + 1)) + 8U <=
            __builtin_bswap16(ip6->payload_len))
        netra_icmp_parse(l4, data_end, FAMILY_V6, &icmp);
    copy16(sc->src,&ip6->saddr); copy16(sc->dst,&ip6->daddr);

    if (hook == HOOK_TC) {
        record_icmp_error(ifindex, FAMILY_V6, direction, &icmp);
        const __u8 *peer = direction==DIR_EGRESS ? sc->dst : sc->src;
        __u64 cgroup_id = 0;
        int syn_new = (proto==IPPROTO_TCP && l4_ok && (flags & 0x02) && !(flags & 0x10));
        ct_fill(FAMILY_V6, proto, sport, dport, sc->src, sc->dst, &sc->ct);
        int established = (l4_ok && !syn_new && ct_hit(&sc->ct));
        __u8 reason=0; int blocked=0;
        if (!established) blocked=decide6(direction,peer,proto,dport,&reason,1,cgroup_id,len);
        if (blocked && proto==IPPROTO_TCP && l4_ok && !syn_new &&
            ((reason==REASON_EXACT && syndrop_allows6(peer,direction)) ||
             (reason==REASON_CIDR  && syndrop_cidr_allows6(direction,peer)))) blocked=0;
        update_flow(FAMILY_V6,direction,hook,proto,sport,dport,sc->src,sc->dst,len,blocked,cgroup_id);
        update_iface_flow(ifindex,FAMILY_V6,direction,hook,proto,sport,dport,sc->src,sc->dst,len,blocked);
        if (blocked) {
            record_policy_drop(FAMILY_V6,proto,direction,reason,sport,dport,sc->src,sc->dst,len);
            submit_packet_event(FAMILY_V6,direction,hook,proto,ACT_BLOCK,EVT_BLOCK,reason,ifindex,len,sc->src,sc->dst,sport,dport,flags,0,0,cgroup_id);
        } else {
            if (l4_ok) ct_learn_pair(FAMILY_V6,proto,sport,dport,sc->src,sc->dst);
            if ((bpf_ktime_get_ns()&63)==1) submit_packet_event(FAMILY_V6,direction,hook,proto,ACT_ALLOW,EVT_FLOW,0,ifindex,len,sc->src,sc->dst,sport,dport,flags,0,0,cgroup_id);
        }
        return blocked ? (allow_value==TC_ACT_OK ? TC_ACT_SHOT : 0) : allow_value;
    }

    /* L7/DNS is handled by netra_l7_cgroup_egress/ingress (its own program,
     * own verifier budget) — see the matching comment in handle_v4. */
    (void)payload; (void)data; (void)data_end; (void)walk;
    const __u8 *peer = direction==DIR_EGRESS ? sc->dst : sc->src;
    __u16 policy_port=dport;
    __u64 cgroup_id=hook==HOOK_CGROUP?bpf_get_current_cgroup_id():0;
    if(proto==IPPROTO_TCP && l4_ok) track_tcp_signal(cgroup_id,flags);
    int syn_new = (proto==IPPROTO_TCP && l4_ok && (flags & 0x02) && !(flags & 0x10));
    ct_fill(FAMILY_V6, proto, sport, dport, sc->src, sc->dst, &sc->ct);
    int established = (l4_ok && !syn_new && ct_hit(&sc->ct));
    __u8 reason=0;
    int blocked=0;
    if (!established) blocked=decide6(direction,peer,proto,policy_port,&reason,1,cgroup_id,len);
    if (blocked && proto==IPPROTO_TCP && l4_ok && !syn_new &&
        ((reason==REASON_EXACT && syndrop_allows6(peer,direction)) ||
         (reason==REASON_CIDR  && syndrop_cidr_allows6(direction,peer)))) blocked=0;
    update_flow(FAMILY_V6,direction,hook,proto,sport,dport,sc->src,sc->dst,len,blocked,cgroup_id);
    if (proto==IPPROTO_UDP && !blocked) update_udp_flow_health(FAMILY_V6,direction,sport,dport,sc->src,sc->dst,len,cgroup_id);
    if (proto==IPPROTO_UDP && !blocked) update_quic_observed(FAMILY_V6,direction,sport,dport,sc->src,sc->dst,payload,data_end,cgroup_id);
    if(blocked) {
        record_policy_drop(FAMILY_V6,proto,direction,reason,sport,dport,sc->src,sc->dst,len);
        submit_packet_event(FAMILY_V6,direction,hook,proto,ACT_BLOCK,EVT_BLOCK,reason,ifindex,len,sc->src,sc->dst,sport,dport,flags,0,0,cgroup_id);
    } else {
        if (l4_ok) ct_learn_pair(FAMILY_V6,proto,sport,dport,sc->src,sc->dst);
        if((bpf_ktime_get_ns()&63)==1)submit_packet_event(FAMILY_V6,direction,hook,proto,ACT_ALLOW,EVT_FLOW,0,ifindex,len,sc->src,sc->dst,sport,dport,flags,0,0,cgroup_id);
    }
    return blocked ? (allow_value==TC_ACT_OK ? TC_ACT_SHOT : 0) : allow_value;
}

static __always_inline int handle_l2(struct __sk_buff *skb, __u8 direction)
{
    void *data=(void *)(long)skb->data,*end=(void *)(long)skb->data_end;
    struct ethhdr *eth=data;if((void *)(eth+1)>end)return TC_ACT_OK;
    if(eth->h_proto==__builtin_bswap16(ETH_P_IP))return handle_v4(skb,direction,HOOK_TC,1,TC_ACT_OK);
    if(eth->h_proto==__builtin_bswap16(ETH_P_IPV6))return handle_v6(skb,direction,HOOK_TC,1,TC_ACT_OK);
    return TC_ACT_OK;
}
static __always_inline int handle_l3(struct __sk_buff *skb, __u8 direction)
{
    void *data=(void *)(long)skb->data,*end=(void *)(long)skb->data_end;
    if((void *)((__u8 *)data + 1) > end) return 1;
    __u8 version=(*(__u8*)data)>>4;
    if(version==4)return handle_v4(skb,direction,HOOK_CGROUP,0,1);
    if(version==6)return handle_v6(skb,direction,HOOK_CGROUP,0,1);
    return 1;
}

SEC("tc/egress") int netra_egress(struct __sk_buff *skb){ return handle_l2(skb,DIR_EGRESS); }
SEC("tc/ingress") int netra_ingress(struct __sk_buff *skb){ return handle_l2(skb,DIR_INGRESS); }
SEC("cgroup_skb/egress") int netra_cgroup_egress(struct __sk_buff *skb){ return handle_l3(skb,DIR_EGRESS); }
SEC("cgroup_skb/ingress") int netra_cgroup_ingress(struct __sk_buff *skb){ return handle_l3(skb,DIR_INGRESS); }

/* ---------------------------------------------------------------------
 * Restored cgroup-side L7/DNS observability (SNI/HTTP/DNS-qname), split
 * into its own dedicated cgroup_skb programs rather than folded back into
 * handle_v4/handle_v6. The CT+NetworkPolicy-shaped-deny logic added to
 * those functions already sits at the edge of the 512-byte BPF stack
 * budget for a single force-inlined program frame; adding the L7 scan
 * buffers back into that same frame is what silently disconnected this
 * feature previously (see CHANGELOG.md and docs/l7-metadata.md). Giving
 * L7 parsing its own program gives it its own, independent budget.
 *
 * These programs deliberately do NOT call ct_hit/decide4/decide6/
 * netpol_denies4/update_flow/ct_learn_pair — all conntrack, IP/CIDR/
 * port/rate enforcement, and flow accounting remain exclusively owned by
 * handle_v4/handle_v6 via netra_cgroup_egress/netra_cgroup_ingress. A
 * SNI/DNS deny here returns 0 independently of that program's own
 * verdict for the same skb (the kernel ANDs multiple cgroup_skb
 * programs' verdicts at the same attach point), so the packet is
 * genuinely blocked either way. Known, accepted nuance: flow_stats/
 * workload_flow_stats.blocked will not reflect an SNI/DNS-specific deny
 * (only IP/CIDR/port/rate denies do) — a cosmetic stats-attribution gap,
 * not a correctness bug; Drop Detective still sees the block via
 * policy_drops/REASON_SNI/REASON_DNS from this program's own
 * record_policy_drop call.
 */

static __always_inline int l7_handle_v4(struct __sk_buff *skb, __u8 direction)
{
    struct netra_pkt_scratch *sc = netra_scratch();
    if (!sc) return 1;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u32 ifindex = skb->ifindex;
    __u32 len = skb->len;
    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end || ip->version != 4 || ip->ihl < 5) return 1;
    void *l4 = (void *)ip + ip->ihl * 4;
    if (l4 > data_end) return 1;
    __u8 proto = ip->protocol;
    __u16 sport = 0, dport = 0; void *payload = 0;
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end || tcp->doff < 5) return 1;
        sport = tcp->source; dport = tcp->dest;
        payload = (void *)tcp + ((__u32)tcp->doff * 4);
        if (payload > data_end) payload = 0;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) return 1;
        sport = udp->source; dport = udp->dest; payload = (void *)(udp + 1);
    } else {
        return 1;
    }
    copy4(sc->src, ip->saddr); copy4(sc->dst, ip->daddr);
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!cgroup_id) return 1;

    if (direction == DIR_INGRESS) {
        if (proto == IPPROTO_UDP && sport == __builtin_bswap16(53) && payload)
            dns_response_track(cgroup_id, FAMILY_V4, sc->src, dport, payload, data_end, ifindex, len, sc->src, sc->dst);
        return 1;
    }

    int blocked = 0; __u8 reason = 0; int dns_len = 0;

    if (proto == IPPROTO_UDP && dport == __builtin_bswap16(53) && payload) {
        dns_len = netra_l7_dns_qname(payload, data_end, sc->dns_name);
        if (dns_len > 0) {
            if (enforcing() && scope_allows(cgroup_id)) {
                __builtin_memset(&sc->name_key, 0, sizeof(sc->name_key));
                __builtin_memcpy(sc->name_key.name, sc->dns_name, 96);
                if (bpf_map_lookup_elem(&blocked_dns, &sc->name_key)) { blocked = 1; reason = REASON_DNS; }
            }
            __u16 txid = 0;
            unsigned char *p = payload;
            if ((void *)(p + 2) <= data_end) txid = ((__u16)p[0] << 8) | p[1];
            dns_query_track(cgroup_id, FAMILY_V4, sc->dst, sport, txid, sc->dns_name, dns_len);
        }
    }

    if (proto == IPPROTO_TCP && payload) {
        int sni_len = netra_l7_tls_sni(payload, data_end, sc->sni);
        if (sni_len > 0) {
            if (!blocked && enforcing() && scope_allows(cgroup_id)) {
                __builtin_memset(&sc->name_key, 0, sizeof(sc->name_key));
                __builtin_memcpy(sc->name_key.name, sc->sni, 96);
                if (bpf_map_lookup_elem(&blocked_sni, &sc->name_key)) { blocked = 1; reason = REASON_SNI; }
            }
            track_tls(cgroup_id, sc->sni, blocked && reason == REASON_SNI);
        }
        if (netra_l7_http_method(payload, data_end, sc->http_m) > 0 && netra_l7_http_host(payload, data_end, sc->http_h) > 0)
            track_http(cgroup_id, sc->http_m, sc->http_h);
    }

    if (blocked) {
        record_policy_drop(FAMILY_V4, proto, direction, reason, sport, dport, sc->src, sc->dst, len);
        submit_packet_event(FAMILY_V4, direction, HOOK_CGROUP, proto, ACT_BLOCK, EVT_BLOCK, reason, ifindex, len,
                             sc->src, sc->dst, sport, dport, 0, dns_len > 0 ? sc->dns_name : 0, dns_len, cgroup_id);
        return 0;
    }
    if (dns_len > 0) {
        submit_packet_event(FAMILY_V4, direction, HOOK_CGROUP, proto, ACT_ALLOW, EVT_DNS, 0, ifindex, len,
                             sc->src, sc->dst, sport, dport, 0, sc->dns_name, dns_len, cgroup_id);
    }
    return 1;
}

static __always_inline int l7_handle_v6(struct __sk_buff *skb, __u8 direction)
{
    struct netra_pkt_scratch *sc = netra_scratch();
    if (!sc) return 1;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u32 ifindex = skb->ifindex;
    __u32 len = skb->len;
    struct ipv6hdr *ip6 = data;
    if ((void *)(ip6 + 1) > data_end) return 1;

    struct netra_ipv6_l4 walk;
    netra_ipv6_walk((unsigned char *)(ip6 + 1), data_end, ip6->nexthdr, &walk);
    void *l4 = walk.l4; __u8 proto = walk.proto; __u16 sport = 0, dport = 0; void *payload = 0;
    int l4_ok = 0;
    if (walk.l4_parseable && !walk.nonfirst_fragment && proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) <= data_end && tcp->doff >= 5) {
            void *tcp_end = (void *)tcp + ((__u32)tcp->doff * 4);
            if (tcp_end <= data_end) { sport = tcp->source; dport = tcp->dest; payload = tcp_end; l4_ok = 1; }
        }
    } else if (walk.l4_parseable && !walk.nonfirst_fragment && proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) <= data_end) { sport = udp->source; dport = udp->dest; payload = (void *)(udp + 1); l4_ok = 1; }
    }
    if (!l4_ok) return 1;
    copy16(sc->src, &ip6->saddr); copy16(sc->dst, &ip6->daddr);
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!cgroup_id) return 1;

    if (direction == DIR_INGRESS) {
        if (proto == IPPROTO_UDP && sport == __builtin_bswap16(53) && payload)
            dns_response_track(cgroup_id, FAMILY_V6, sc->src, dport, payload, data_end, ifindex, len, sc->src, sc->dst);
        return 1;
    }

    int blocked = 0; __u8 reason = 0; int dns_len = 0;

    if (proto == IPPROTO_UDP && dport == __builtin_bswap16(53) && payload) {
        dns_len = netra_l7_dns_qname(payload, data_end, sc->dns_name);
        if (dns_len > 0) {
            if (enforcing() && scope_allows(cgroup_id)) {
                __builtin_memset(&sc->name_key, 0, sizeof(sc->name_key));
                __builtin_memcpy(sc->name_key.name, sc->dns_name, 96);
                if (bpf_map_lookup_elem(&blocked_dns, &sc->name_key)) { blocked = 1; reason = REASON_DNS; }
            }
            __u16 txid = 0;
            unsigned char *p = payload;
            if ((void *)(p + 2) <= data_end) txid = ((__u16)p[0] << 8) | p[1];
            dns_query_track(cgroup_id, FAMILY_V6, sc->dst, sport, txid, sc->dns_name, dns_len);
        }
    }

    if (proto == IPPROTO_TCP && payload) {
        int sni_len = netra_l7_tls_sni(payload, data_end, sc->sni);
        if (sni_len > 0) {
            if (!blocked && enforcing() && scope_allows(cgroup_id)) {
                __builtin_memset(&sc->name_key, 0, sizeof(sc->name_key));
                __builtin_memcpy(sc->name_key.name, sc->sni, 96);
                if (bpf_map_lookup_elem(&blocked_sni, &sc->name_key)) { blocked = 1; reason = REASON_SNI; }
            }
            track_tls(cgroup_id, sc->sni, blocked && reason == REASON_SNI);
        }
        if (netra_l7_http_method(payload, data_end, sc->http_m) > 0 && netra_l7_http_host(payload, data_end, sc->http_h) > 0)
            track_http(cgroup_id, sc->http_m, sc->http_h);
    }

    if (blocked) {
        record_policy_drop(FAMILY_V6, proto, direction, reason, sport, dport, sc->src, sc->dst, len);
        submit_packet_event(FAMILY_V6, direction, HOOK_CGROUP, proto, ACT_BLOCK, EVT_BLOCK, reason, ifindex, len,
                             sc->src, sc->dst, sport, dport, 0, dns_len > 0 ? sc->dns_name : 0, dns_len, cgroup_id);
        return 0;
    }
    if (dns_len > 0) {
        submit_packet_event(FAMILY_V6, direction, HOOK_CGROUP, proto, ACT_ALLOW, EVT_DNS, 0, ifindex, len,
                             sc->src, sc->dst, sport, dport, 0, sc->dns_name, dns_len, cgroup_id);
    }
    return 1;
}

static __always_inline int l7_handle(struct __sk_buff *skb, __u8 direction)
{
    void *data = (void *)(long)skb->data, *end = (void *)(long)skb->data_end;
    if ((void *)((__u8 *)data + 1) > end) return 1;
    __u8 version = (*(__u8 *)data) >> 4;
    if (version == 4) return l7_handle_v4(skb, direction);
    if (version == 6) return l7_handle_v6(skb, direction);
    return 1;
}

SEC("cgroup_skb/egress") int netra_l7_cgroup_egress(struct __sk_buff *skb) { return l7_handle(skb, DIR_EGRESS); }
SEC("cgroup_skb/ingress") int netra_l7_cgroup_ingress(struct __sk_buff *skb) { return l7_handle(skb, DIR_INGRESS); }

/* Copy 16 bytes at a compile-time offset. A variable offset makes the
 * verifier explore every byte and stalls collection load. */
#define NETRA_HTTP_STATUS_LOAD(skb, off, line) \
    (bpf_skb_load_bytes((skb), (off), (line), 16) < 0)

static __always_inline int http_status_note(void *line, void *end, __u64 cgroup_id)
{
    int st = netra_l7_http_status(line, end);
    if (st <= 0) return 0;
    track_http_status(cgroup_id, (__u16)st);
    return 1;
}

/* Status counting is its own program so it still loads on kernels that
 * reject the SNI/Host scan loops above. Linear packets are read through
 * skb->data. Non-linear packets use bpf_skb_load_bytes at the two offsets
 * real TCP uses: 40 (no options) and 52 (timestamps). IPv4 options are
 * skipped. Returns 1 always: never drops. */
static __always_inline int http_status_skb(struct __sk_buff *skb)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    unsigned char *p = data;
    int noted = 0;
    if ((void *)(p + 54) <= end && (p[0] >> 4) == 4 && (p[0] & 0x0f) == 5 && p[9] == IPPROTO_TCP) {
        __u32 doff = p[32] >> 4;
        if (doff == 5)
            noted = http_status_note(p + 40, end, cgroup_id);
        else if (doff == 8 && (void *)(p + 68) <= end)
            noted = http_status_note(p + 52, end, cgroup_id);
    }
    if (noted) return 1;
    unsigned char hdr[20];
    unsigned char line[16];
    if (skb->len < 40) return 1;
    if (bpf_skb_load_bytes(skb, 0, hdr, 20) < 0) return 1;
    if ((hdr[0] >> 4) == 4 && (hdr[0] & 0x0f) == 5 && hdr[9] == IPPROTO_TCP) {
        if (!NETRA_HTTP_STATUS_LOAD(skb, 40, line))
            noted = http_status_note(line, line + 16, cgroup_id);
        if (!noted && !NETRA_HTTP_STATUS_LOAD(skb, 52, line))
            http_status_note(line, line + 16, cgroup_id);
    } else if ((hdr[0] >> 4) == 6 && hdr[6] == IPPROTO_TCP) {
        if (!NETRA_HTTP_STATUS_LOAD(skb, 60, line))
            noted = http_status_note(line, line + 16, cgroup_id);
        if (!noted && !NETRA_HTTP_STATUS_LOAD(skb, 72, line))
            http_status_note(line, line + 16, cgroup_id);
    }
    return 1;
}

SEC("cgroup_skb/egress") int netra_http_status_egress(struct __sk_buff *skb) { return http_status_skb(skb); }
SEC("cgroup_skb/ingress") int netra_http_status_ingress(struct __sk_buff *skb) { return http_status_skb(skb); }

static __always_inline int socket4(struct bpf_sock_addr *ctx,__u8 proto)
{
    __u32 dst=ctx->user_ip4;__u16 dport=(__u16)ctx->user_port;__u8 reason=0;__u8 addr[16];copy4(addr,dst);
    __u32 uid=(__u32)bpf_get_current_uid_gid();__u64 cgroup_id=bpf_get_current_cgroup_id();
    __u32 pid=(__u32)(bpf_get_current_pid_tgid()>>32);
    int blocked=0;
    struct comm_key ck={}; bpf_get_current_comm(ck.name,sizeof(ck.name));
    if(enforcing()&&scope_allows(cgroup_id)&&!bpf_map_lookup_elem(&allowed_uids,&uid)&&!bpf_map_lookup_elem(&allowed_comms,&ck)){
        if(bpf_map_lookup_elem(&blocked_uids,&uid)){reason=REASON_UID;blocked=1;}
        else if(bpf_map_lookup_elem(&blocked_comms,&ck)){reason=REASON_PROCESS;blocked=1;}
        else if(bpf_map_lookup_elem(&capgate_pids,&pid)){reason=REASON_CAPABILITY;blocked=1;}
    }
    if(!blocked && proto==IPPROTO_TCP && conn_rate_limited(cgroup_id)){reason=REASON_CONN_RATE;blocked=1;}
    if(!blocked)blocked=decide4(DIR_EGRESS,dst,proto,dport,&reason,0,cgroup_id,0);
    if (!blocked && proto==IPPROTO_TCP) { __u64 cookie=bpf_get_socket_cookie(ctx); if(cookie){ struct socket_owner_value ov={.cgroup_id=cgroup_id,.pid=(__u32)(bpf_get_current_pid_tgid()>>32),.uid=uid}; bpf_get_current_comm(ov.comm,sizeof(ov.comm)); bpf_map_update_elem(&socket_owner,&cookie,&ov,BPF_ANY); struct connect_start_value cv={}; cv.start_ns=bpf_ktime_get_ns(); cv.key.cgroup_id=cgroup_id; cv.key.family=FAMILY_V4; cv.key.protocol=IPPROTO_TCP; cv.key.remote_port=dport; copy4(cv.key.remote,dst); bpf_map_update_elem(&connect_start,&cookie,&cv,BPF_ANY); } }
    track_connect_attempt(cgroup_id,FAMILY_V4,proto,addr,dport,blocked);
    submit_socket_event(ctx,FAMILY_V4,proto,blocked?ACT_BLOCK:ACT_ALLOW,reason,addr);return blocked?0:1;
}
static __always_inline int socket6(struct bpf_sock_addr *ctx,__u8 proto)
{
    __u8 addr[16];__builtin_memcpy(addr,ctx->user_ip6,16);__u16 dport=(__u16)ctx->user_port;__u8 reason=0;__u32 uid=(__u32)bpf_get_current_uid_gid();__u64 cgroup_id=bpf_get_current_cgroup_id();
    __u32 pid=(__u32)(bpf_get_current_pid_tgid()>>32);
    int blocked=0;
    struct comm_key ck={}; bpf_get_current_comm(ck.name,sizeof(ck.name));
    if(enforcing()&&scope_allows(cgroup_id)&&!bpf_map_lookup_elem(&allowed_uids,&uid)&&!bpf_map_lookup_elem(&allowed_comms,&ck)){
        if(bpf_map_lookup_elem(&blocked_uids,&uid)){reason=REASON_UID;blocked=1;}
        else if(bpf_map_lookup_elem(&blocked_comms,&ck)){reason=REASON_PROCESS;blocked=1;}
        else if(bpf_map_lookup_elem(&capgate_pids,&pid)){reason=REASON_CAPABILITY;blocked=1;}
    }
    if(!blocked && proto==IPPROTO_TCP && conn_rate_limited(cgroup_id)){reason=REASON_CONN_RATE;blocked=1;}
    if(!blocked)blocked=decide6(DIR_EGRESS,addr,proto,dport,&reason,0,cgroup_id,0);
    if (!blocked && proto==IPPROTO_TCP) { __u64 cookie=bpf_get_socket_cookie(ctx); if(cookie){ struct socket_owner_value ov={.cgroup_id=cgroup_id,.pid=(__u32)(bpf_get_current_pid_tgid()>>32),.uid=uid}; bpf_get_current_comm(ov.comm,sizeof(ov.comm)); bpf_map_update_elem(&socket_owner,&cookie,&ov,BPF_ANY); struct connect_start_value cv={}; cv.start_ns=bpf_ktime_get_ns(); cv.key.cgroup_id=cgroup_id; cv.key.family=FAMILY_V6; cv.key.protocol=IPPROTO_TCP; cv.key.remote_port=dport; copy16(cv.key.remote,addr); bpf_map_update_elem(&connect_start,&cookie,&cv,BPF_ANY); } }
    track_connect_attempt(cgroup_id,FAMILY_V6,proto,addr,dport,blocked);
    submit_socket_event(ctx,FAMILY_V6,proto,blocked?ACT_BLOCK:ACT_ALLOW,reason,addr);return blocked?0:1;
}
SEC("cgroup/connect4") int netra_connect4(struct bpf_sock_addr *ctx){return socket4(ctx,IPPROTO_TCP);}
SEC("cgroup/connect6") int netra_connect6(struct bpf_sock_addr *ctx){return socket6(ctx,IPPROTO_TCP);}
SEC("cgroup/sendmsg4") int netra_sendmsg4(struct bpf_sock_addr *ctx){return socket4(ctx,IPPROTO_UDP);}
SEC("cgroup/sendmsg6") int netra_sendmsg6(struct bpf_sock_addr *ctx){return socket6(ctx,IPPROTO_UDP);}


static __always_inline void tcp_health_key_from_sockops(struct bpf_sock_ops *skops, __u64 cgroup_id,
                                                         struct tcp_health_key *k)
{
    __builtin_memset(k, 0, sizeof(*k));
    k->cgroup_id = cgroup_id;
    k->family = skops->family == 2 ? FAMILY_V4 : FAMILY_V6;
    if (skops->family == 2) {
        k->local_ip4 = skops->local_ip4;
        k->remote_ip4 = skops->remote_ip4;
    } else {
        __builtin_memcpy(k->local_ip6, skops->local_ip6, 16);
        __builtin_memcpy(k->remote_ip6, skops->remote_ip6, 16);
    }
    k->local_port = (__u16)skops->local_port;
    k->remote_port = (__u16)__builtin_bswap32(skops->remote_port);
}

SEC("sockops") int netra_sockops(struct bpf_sock_ops *skops)
{
    if (skops->family != 2 && skops->family != 10) return 0;
    __u64 cookie = bpf_get_socket_cookie(skops);
    struct socket_owner_value *owner = cookie ? bpf_map_lookup_elem(&socket_owner, &cookie) : 0;
    __u64 cgroup_id = owner ? owner->cgroup_id : 0;
    struct tcp_health_key key;
    tcp_health_key_from_sockops(skops, cgroup_id, &key);
    struct tcp_health_value zero = {};
    struct tcp_health_value *v = bpf_map_lookup_elem(&tcp_health, &key);
    if (!v) {
        bpf_map_update_elem(&tcp_health, &key, &zero, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&tcp_health, &key);
    }
    if (!v) return 0;
    __u64 now = bpf_ktime_get_ns();
    if (owner) {
        v->pid = owner->pid;
        v->uid = owner->uid;
        __builtin_memcpy(v->comm, owner->comm, 16);
    }
    v->last_ns = now;
    if (skops->is_fullsock) {
        v->srtt_us = ((__u64)skops->srtt_us) >> 3;
        v->rtt_min_us = skops->rtt_min;
        v->snd_cwnd = skops->snd_cwnd;
        v->bytes_acked = skops->bytes_acked;
        v->bytes_received = skops->bytes_received;
        v->segs_in = skops->segs_in;
        v->segs_out = skops->segs_out;
    }
    struct tcp_pressure_value pzero = {};
    struct tcp_pressure_value *pv = bpf_map_lookup_elem(&tcp_pressure, &key);
    if (!pv) {
        bpf_map_update_elem(&tcp_pressure, &key, &pzero, BPF_NOEXIST);
        pv = bpf_map_lookup_elem(&tcp_pressure, &key);
    }
    if (pv) {
        __sync_fetch_and_add(&pv->callbacks, 1);
        pv->last_ns = now;
        pv->state = skops->state;
        if (skops->is_fullsock) {
            pv->snd_cwnd = skops->snd_cwnd;
            pv->snd_ssthresh = skops->snd_ssthresh;
            pv->packets_out = skops->packets_out;
            pv->retrans_out = skops->retrans_out;
            pv->total_retrans = skops->total_retrans;
            pv->lost_out = skops->lost_out;
            pv->sacked_out = skops->sacked_out;
            pv->rate_delivered = skops->rate_delivered;
            pv->rate_interval_us = skops->rate_interval_us;
            pv->mss_cache = skops->mss_cache;
        }
    }
    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        __sync_fetch_and_add(&v->active_established, 1);
        if (cookie) {
            struct connect_start_value *cs = bpf_map_lookup_elem(&connect_start, &cookie);
            if (cs && now >= cs->start_ns) {
                struct connect_health_value chzero = {};
                struct connect_health_value *ch = bpf_map_lookup_elem(&connect_health, &cs->key);
                if (!ch) {
                    bpf_map_update_elem(&connect_health, &cs->key, &chzero, BPF_NOEXIST);
                    ch = bpf_map_lookup_elem(&connect_health, &cs->key);
                }
                if (ch) {
                    __u64 latency = (now - cs->start_ns) / 1000;
                    __sync_fetch_and_add(&ch->established, 1);
                    __sync_fetch_and_add(&ch->total_latency_us, latency);
                    if (latency > ch->max_latency_us) ch->max_latency_us = latency;
                    ch->last_ns = now;
                }
                bpf_map_delete_elem(&connect_start, &cookie);
            }
        }
        bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_RTO_CB_FLAG | BPF_SOCK_OPS_RETRANS_CB_FLAG |
                                         BPF_SOCK_OPS_STATE_CB_FLAG | BPF_SOCK_OPS_RTT_CB_FLAG);
        break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        __sync_fetch_and_add(&v->passive_established, 1);
        bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_RTO_CB_FLAG | BPF_SOCK_OPS_RETRANS_CB_FLAG |
                                         BPF_SOCK_OPS_STATE_CB_FLAG | BPF_SOCK_OPS_RTT_CB_FLAG);
        break;
    case BPF_SOCK_OPS_RTO_CB:
        __sync_fetch_and_add(&v->rto, 1);
        break;
    case BPF_SOCK_OPS_RETRANS_CB:
        __sync_fetch_and_add(&v->retrans, 1);
        break;
    case BPF_SOCK_OPS_RTT_CB:
        __sync_fetch_and_add(&v->rtt_samples, 1);
        break;
    case BPF_SOCK_OPS_STATE_CB:
        // args[1] is the new TCP state. TCP_CLOSE is 7 in the Linux UAPI.
        if (skops->args[1] == 7) __sync_fetch_and_add(&v->closes, 1);
        break;
    default:
        break;
    }
    return 0;
}


SEC("raw_tracepoint/kfree_skb") int netra_kfree_skb(struct bpf_raw_tracepoint_args *ctx)
{
    struct kernel_drop_key key = {.reason = (__u32)ctx->args[2]};
    struct kernel_drop_value zero = {};
    struct kernel_drop_value *v = bpf_map_lookup_elem(&kernel_drops, &key);
    if (!v) {
        bpf_map_update_elem(&kernel_drops, &key, &zero, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&kernel_drops, &key);
    }
    if (v) {
        __sync_fetch_and_add(&v->count, 1);
        v->last_ns = bpf_ktime_get_ns();
    }
    return 0;
}

SEC("xdp") int netra_xdp_ingress(struct xdp_md *ctx)
{
    void *data=(void *)(long)ctx->data,*end=(void *)(long)ctx->data_end;struct ethhdr *eth=data;if((void *)(eth+1)>end)return XDP_PASS;
    if(!enforcing())return XDP_PASS;
    if(eth->h_proto==__builtin_bswap16(ETH_P_IP)){
        struct iphdr *ip=(void *)(eth+1);if((void *)(ip+1)>end)return XDP_PASS;void *l4=(void *)ip+ip->ihl*4;__u16 sport=0,dport=0;if(ip->protocol==IPPROTO_TCP){struct tcphdr*t=l4;if((void*)(t+1)>end)return XDP_PASS;sport=t->source;dport=t->dest;}else if(ip->protocol==IPPROTO_UDP){struct udphdr*u=l4;if((void*)(u+1)>end)return XDP_PASS;sport=u->source;dport=u->dest;}__u8 reason=0;if(decide4(DIR_INGRESS,ip->saddr,ip->protocol,dport,&reason,0,0,(__u32)((long)end-(long)data))){__u8 src[16],dst[16];copy4(src,ip->saddr);copy4(dst,ip->daddr);update_flow(FAMILY_V4,DIR_INGRESS,HOOK_XDP,ip->protocol,sport,dport,src,dst,(__u32)((long)end-(long)data),1,0);submit_packet_event(FAMILY_V4,DIR_INGRESS,HOOK_XDP,ip->protocol,ACT_BLOCK,EVT_BLOCK,reason,ctx->ingress_ifindex,(__u32)((long)end-(long)data),src,dst,sport,dport,0,0,0,0);return XDP_DROP;}
    } else if(eth->h_proto==__builtin_bswap16(ETH_P_IPV6)){
        struct ipv6hdr *ip6=(void *)(eth+1);
        if((void *)(ip6+1)>end)return XDP_PASS;
        struct netra_ipv6_l4 walk;
        netra_ipv6_walk((unsigned char *)(ip6+1),end,ip6->nexthdr,&walk);
        track_ipv6_ext(DIR_INGRESS, HOOK_XDP, &walk);
        void*l4=walk.l4;__u16 sport=0,dport=0;
        if(walk.l4_parseable&&!walk.nonfirst_fragment&&walk.proto==IPPROTO_TCP){
            struct tcphdr*t=l4;
            if((void*)(t+1)<=end&&t->doff>=5){
                void*tend=(void*)t+((__u32)t->doff*4);
                if(tend<=end){sport=t->source;dport=t->dest;}
            }
        }else if(walk.l4_parseable&&!walk.nonfirst_fragment&&walk.proto==IPPROTO_UDP){
            struct udphdr*u=l4;if((void*)(u+1)<=end){sport=u->source;dport=u->dest;}
        }
        __u8 reason=0;
        if(decide6(DIR_INGRESS,(const __u8*)&ip6->saddr,walk.proto,dport,&reason,0,0,(__u32)((long)end-(long)data))){
            __u8 src[16],dst[16];copy16(src,&ip6->saddr);copy16(dst,&ip6->daddr);
            update_flow(FAMILY_V6,DIR_INGRESS,HOOK_XDP,walk.proto,sport,dport,src,dst,(__u32)((long)end-(long)data),1,0);
            submit_packet_event(FAMILY_V6,DIR_INGRESS,HOOK_XDP,walk.proto,ACT_BLOCK,EVT_BLOCK,reason,ctx->ingress_ifindex,(__u32)((long)end-(long)data),src,dst,sport,dport,0,0,0,0);
            return XDP_DROP;
        }
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int netra_xdp_shield(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    __u32 z = 0;
    struct shield_config *cfg = bpf_map_lookup_elem(&shield_cfg, &z);
    if (!cfg || cfg->mode == 0) return XDP_PASS;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) return XDP_PASS;
    __u8 src[16] = {};
    __u8 family = 0;
    __u8 class_id = 4; /* other */
    __u32 daddr4 = 0;
    int protected = cfg->protect_all != 0;
    if (eth->h_proto == __builtin_bswap16(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > end) return XDP_PASS;
        family = FAMILY_V4; copy4(src, ip->saddr); daddr4 = ip->daddr;
        if (!protected) {
            struct shield_ip4_key pk = {.generation = cfg->generation, .addr = daddr4};
            protected = bpf_map_lookup_elem(&shield_protected4, &pk) != 0;
        }
        if (!protected) return XDP_PASS;
        if (ip->protocol == IPPROTO_TCP) {
            void *l4 = (void *)ip + ip->ihl * 4;
            struct tcphdr *tcp = l4;
            if ((void *)(tcp + 1) <= end && tcp->syn && !tcp->ack) class_id = 1;
        } else if (ip->protocol == IPPROTO_UDP) class_id = 2;
        else if (ip->protocol == IPPROTO_ICMP) class_id = 3;
    } else if (eth->h_proto == __builtin_bswap16(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > end) return XDP_PASS;
        family = FAMILY_V6; copy16(src, &ip6->saddr);
        if (!protected) {
            struct shield_ip6_key pk6 = {.generation = cfg->generation};
            copy16(pk6.addr, &ip6->daddr);
            protected = bpf_map_lookup_elem(&shield_protected6, &pk6) != 0;
        }
        if (!protected) return XDP_PASS;
        if (ip6->nexthdr == IPPROTO_UDP) class_id = 2;
        else if (ip6->nexthdr == IPPROTO_ICMPV6) class_id = 3;
        else if (ip6->nexthdr == IPPROTO_TCP) class_id = 1;
    } else return XDP_PASS;
    __u32 pps = cfg->other_pps;
    if (class_id == 1) pps = cfg->syn_pps;
    else if (class_id == 2) pps = cfg->udp_pps;
    else if (class_id == 3) pps = cfg->icmp_pps;
    int ok = shield_rate_ok(family, class_id, src, pps, cfg->burst_seconds ? cfg->burst_seconds : 2);
    struct shield_stat_value *st = bpf_map_lookup_elem(&shield_stats, &z);
    __u32 class_key = (__u32)class_id;
    struct shield_stat_value *cst = bpf_map_lookup_elem(&shield_class_stats, &class_key);
    if (ok) {
        if (st) __sync_fetch_and_add(&st->allowed, 1);
        if (cst) __sync_fetch_and_add(&cst->allowed, 1);
        return XDP_PASS;
    }
    if (cfg->mode == 1) {
        if (st) __sync_fetch_and_add(&st->audited, 1);
        if (cst) __sync_fetch_and_add(&cst->audited, 1);
        return XDP_PASS;
    }
    if (st) __sync_fetch_and_add(&st->dropped, 1);
    if (cst) __sync_fetch_and_add(&cst->dropped, 1);
    return XDP_DROP;
}

