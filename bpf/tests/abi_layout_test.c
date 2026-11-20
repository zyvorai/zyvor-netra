// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Compile-time guard for every BPF map struct that Go decodes by raw byte
// offset (internal/agent/agent.go's `[N]byte` + manual-offset readers,
// e.g. readStats()/readInterfaceFlowStats()). These mirror bpf/netra_tc.c's
// struct layouts using fixed-width stdint types (no BPF/kernel headers
// needed, so this compiles anywhere with a C11 compiler) and assert their
// sizes with _Static_assert. If a struct in bpf/netra_tc.c changes shape,
// update BOTH this file and the corresponding Go decoder — that pairing is
// exactly the failure mode this guard exists to catch early.
//
// This is a static/structural check only. It does not exercise behavior
// (see ipv6_walk_test.c / l7_parse_test.c for that) and does not touch any
// already-pinned map — the whole point of Netra's "add a new map, never
// resize an old one" ABI-safety rule is that these sizes should never need
// to change for maps already shipped.

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

struct flow_key {
    uint8_t family;
    uint8_t direction;
    uint8_t hook;
    uint8_t protocol;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t src_addr[16];
    uint8_t dst_addr[16];
};
_Static_assert(sizeof(struct flow_key) == 40, "flow_key must stay 40 bytes: it backs the already-pinned flow_stats map");

struct workload_flow_key {
    uint64_t cgroup_id;
    struct flow_key flow;
};
_Static_assert(sizeof(struct workload_flow_key) == 48, "workload_flow_key must stay 48 bytes: it backs the already-pinned workload_flow_stats map");

struct iface_flow_key {
    uint32_t ifindex;
    struct flow_key flow;
};
_Static_assert(sizeof(struct iface_flow_key) == 44, "iface_flow_key must stay 44 bytes to match internal/agent readInterfaceFlowStats()'s [44]byte decode");

struct shield_src_key {
    uint8_t family;
    uint8_t class_id;
    uint16_t pad;
    uint8_t addr[16];
};
_Static_assert(sizeof(struct shield_src_key) == 20, "shield_src_key must stay 20 bytes: it backs the already-pinned shield_sources map and the new shield_source_hits map");

struct tcp_health_key {
    uint64_t cgroup_id;
    uint8_t family;
    uint8_t pad[3];
    uint32_t local_ip4;
    uint32_t remote_ip4;
    uint8_t local_ip6[16];
    uint8_t remote_ip6[16];
    uint16_t local_port;
    uint16_t remote_port;
};
_Static_assert(sizeof(struct tcp_health_key) == 56, "tcp_health_key must stay 56 bytes: it backs the already-pinned tcp_health/tcp_pressure maps");

struct udp_flow_key {
    uint64_t cgroup_id;
    uint8_t family;
    uint8_t pad[3];
    uint32_t local_ip4;
    uint32_t remote_ip4;
    uint8_t local_ip6[16];
    uint8_t remote_ip6[16];
    uint16_t local_port;
    uint16_t remote_port;
};
_Static_assert(sizeof(struct udp_flow_key) == 56, "udp_flow_key must stay 56 bytes to match internal/agent readUDPFlowHealth()'s [56]byte decode");

struct udp_flow_value {
    uint64_t packets;
    uint64_t bytes;
    uint64_t last_ns;
};
_Static_assert(sizeof(struct udp_flow_value) == 24, "udp_flow_value must stay 24 bytes to match internal/agent readUDPFlowHealth()'s [24]byte decode");

struct quic_observed_key {
    uint64_t cgroup_id;
    uint8_t family;
    uint8_t pad[3];
    uint8_t remote_addr[16];
    uint16_t remote_port;
    uint16_t pad2;
};
_Static_assert(sizeof(struct quic_observed_key) == 32, "quic_observed_key must stay 32 bytes to match internal/agent readQUICObserved()'s [32]byte decode");

struct quic_observed_value {
    uint64_t packets;
    uint64_t long_header_packets;
    uint64_t last_ns;
};
_Static_assert(sizeof(struct quic_observed_value) == 24, "quic_observed_value must stay 24 bytes to match internal/agent readQUICObserved()'s [24]byte decode");

struct ipv6_ext_key {
    uint8_t direction;
    uint8_t hook;
    uint16_t pad;
};
_Static_assert(sizeof(struct ipv6_ext_key) == 4, "ipv6_ext_key must stay 4 bytes to match internal/agent readIPv6ExtStats()'s key struct");

struct ipv6_ext_value {
    uint64_t packets;
    uint64_t ext_header_packets;
    uint64_t total_ext_headers;
    uint64_t fragmented;
    uint64_t nonfirst_fragments;
    uint64_t more_fragments;
    uint64_t chain_truncated;
};
_Static_assert(sizeof(struct ipv6_ext_value) == 56, "ipv6_ext_value must stay 56 bytes to match internal/agent readIPv6ExtStats()'s value struct");

struct shield_stat_value {
    uint64_t allowed;
    uint64_t dropped;
    uint64_t audited;
};
_Static_assert(sizeof(struct shield_stat_value) == 24, "shield_stat_value must stay 24 bytes: it backs the already-pinned shield_stats map and the new shield_class_stats map");

struct shield_source_hit_value {
    uint64_t denied;
    uint64_t last_ns;
    uint64_t attempts;
};
_Static_assert(sizeof(struct shield_source_hit_value) == 24, "shield_source_hit_value must stay 24 bytes to match internal/agent readShieldSourceHits()'s value struct");
_Static_assert(offsetof(struct shield_source_hit_value, attempts) == 16, "attempts must be the third field to match internal/agent readShieldSourceHits()'s value struct order");

/* Continuous TLS hello ringbuf event (new map; not a resize of tls_sni_stats). */
struct tls_hello_event {
    uint64_t cgroup_id;
    uint64_t ts_ns;
    uint16_t copy_len;
    uint16_t pad;
    uint8_t data[256];
} __attribute__((packed));
_Static_assert(sizeof(struct tls_hello_event) == 276, "tls_hello_event must stay 276 bytes to match internal/agent readTLSHelloEvents");

int main(void)
{
    puts("netra ABI layout guard: ok");
    return 0;
}
