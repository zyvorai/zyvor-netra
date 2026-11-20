// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
#ifndef NETRA_EVENT_H
#define NETRA_EVENT_H
#include <linux/types.h>
struct obs_event {
    __u64 ts_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 uid;
    __u32 ifindex;
    __u32 length;
    __u8 src_addr[16];
    __u8 dst_addr[16];
    __u16 src_port;
    __u16 dst_port;
    __u8 family;
    __u8 protocol;
    __u8 direction;
    __u8 hook;
    __u8 action;
    __u8 event_type;
    __u8 tcp_flags;
    __u8 reason;
    char comm[16];
    char dns[96];
    __u32 latency_us;
    __u8 dns_rcode;
    __u8 pad_event;
    __u16 dns_qtype; /* offset 194, native-endian: consumes padding, ABI stays 196 */
} __attribute__((packed));
#endif
