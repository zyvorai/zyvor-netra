// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Who changed the network — an fentry on rtnetlink_rcv_msg, passive and fail-open.
//
// The netlink change recorder (internal/netlinkwatch) hears every link, address,
// route and neighbor change over RTNL multicast, but a multicast notification does
// not say who asked for it. rtnetlink_rcv_msg runs synchronously, in the task that
// called sendmsg() on its NETLINK_ROUTE socket, so at this point the current task
// IS the requester. For every request that MODIFIES state this records:
//
//   - the process: comm (16 bytes), tgid and thread id,
//   - its cgroup id (userspace maps it to a workload; it is the same id the rest
//     of the agent already uses),
//   - the RTM_* message type,
//   - the interface the request names: an index (a fixed field for address and
//     neighbor requests, RTA_OIF for a route, and for a link request when it gives
//     one) or, for a link request that names its device only by name (modern
//     `ip link set dev X` sends index 0 and IFLA_IFNAME, so altnames work), the
//     name, plus the message flags so a create (which also creates a peer whose name
//     is not in that attribute) can be told from an operation on an existing link,
//   - for a route, its destination (RTA_DST and the prefix length), since two
//     processes can add routes on one interface in the same instant and only the
//     destination tells them apart, and
//   - a monotonic timestamp (userspace joins it to the recorded change by type,
//     interface, destination and time).
//
// Not recorded: argv, environment, or any of the message beyond the interface (index
// or name) and, for a route, its destination: values the recorder already publishes
// about the change. Read-only requests (RTM_GET*, dumps) are dropped in the
// kernel before anything is reserved, so a monitoring tool listing routes costs
// nothing. It only observes: the return value is ignored and no packet, message or
// program state is changed.
//
// Requests from the kernel itself (carrier loss, router advertisements handled in
// the kernel) never pass through here, so a change with no matching record was not
// issued by a process. That absence is information, and userspace reports it as
// such only while this sensor is running.
//
// Network namespace. Interface indexes are per namespace, and this function runs
// for every namespace's requests (a pod's CNI setup included), so a request in some
// pod's namespace for ifindex 3 must never be credited with a host change on ifindex
// 3. The requester's namespace (the socket's, as rtnetlink_rcv_msg itself uses it:
// skb->sk->sk_net.net->ns.inum, read with CO-RE) is recorded with every event, and
// userspace names the one namespace it records changes in through rtnl_config[0]:
// requests from any other are dropped here, before anything is reserved, which also
// keeps a busy node's pod churn out of the ring buffer.
//
// Ring buffer, not a map of counters: the join needs each request. If it fills,
// events are dropped and counted (rtnl_stats), never blocked on.
//
// Kernel memory read: the 16-byte struct nlmsghdr and a few uAPI fields after it (the 4-byte interface index of a
// link/address/neighbor message; for a route the rtmsg header and a bounded walk of
// its attributes for RTA_OIF and RTA_DST), all fetched with bpf_probe_read_kernel
// from the second argument, and the namespace inode through three CO-RE-relocated
// member reads (the loader relocates them against the running kernel's BTF, which an
// fentry needs anyway to resolve the function's address and signature).

#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define __core __attribute__((preserve_access_index))

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)BPF_FUNC_probe_read_kernel;
static long (*bpf_probe_read_kernel_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)BPF_FUNC_probe_read_kernel_str;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)BPF_FUNC_get_current_cgroup_id;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)BPF_FUNC_get_current_comm;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_submit;

/* Only the members read to find the requester's network namespace; the loader
 * relocates each against the running kernel's types. skb->sk is the requester's
 * netlink socket, and sock_net(sk) is sk->__sk_common.skc_net.net. */
struct ns_common {
	unsigned int inum;
} __core;
struct net {
	struct ns_common ns;
} __core;
typedef struct {
	struct net *net;
} __core possible_net_t;
struct sock_common {
	possible_net_t skc_net;
} __core;
struct sock {
	struct sock_common __sk_common;
} __core;
struct sk_buff {
	struct sock *sk;
} __core;

#define CORE_READ(dst, ptr, field) bpf_probe_read_kernel(&(dst), sizeof(dst), &((ptr)->field))

/* linux/netlink.h's struct nlmsghdr, restated so this object needs no more than
 * linux/bpf.h. The layout is uAPI and never changes. */
struct rtnl_nlmsghdr {
	__u32 nlmsg_len;
	__u16 nlmsg_type;
	__u16 nlmsg_flags;
	__u32 nlmsg_seq;
	__u32 nlmsg_pid;
};

/* One request that modifies network state. Mirrored by internal/rtnlactor.Record;
 * 96 bytes, little endian, checked by both sides. */
struct rtnl_event {
	__u64 ts_ns;       /* bpf_ktime_get_ns(): CLOCK_MONOTONIC */
	__u64 cgroup_id;   /* the requester's cgroup */
	__u32 tgid;        /* process id */
	__u32 pid;         /* thread id */
	__u16 nlmsg_type;  /* RTM_NEWLINK ... */
	__u16 nlmsg_flags; /* NLM_F_CREATE (0x400) marks a create */
	__u32 ifindex;     /* the interface the request names by index, 0 if none */
	__u8 family;       /* routes: rtm_family */
	__u8 dst_len;      /* routes: rtm_dst_len (the prefix length) */
	__u16 _pad;
	__u32 nlmsg_len;   /* the whole message: 32 for a link request with no attributes */
	char comm[16];
	__u8 dst[16];      /* routes: RTA_DST (4 bytes of IPv4 or 16 of IPv6), else zero */
	char ifname[16];   /* link requests naming the device by IFLA_IFNAME, else empty */
	__u32 netns_ino;   /* the requester's network namespace (its inode), 0 if unknown */
	__u32 _pad2;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 262144);
} rtnl_events SEC(".maps");

/* rtnl_config[0] = the network namespace (inode) whose requests are recorded; 0 means
 * every namespace. Set by userspace after load. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} rtnl_config SEC(".maps");

/* [0] = requests dropped because the ring buffer was full. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} rtnl_stats SEC(".maps");

/* RTM_NEWLINK 16, DELLINK 17, SETLINK 19, NEWADDR 20, DELADDR 21, NEWROUTE 24,
 * DELROUTE 25, NEWNEIGH 28, DELNEIGH 29. The GET* types (18, 22, 26, 30) and every
 * other family are ignored. */
static inline int modifies_network(__u16 t)
{
	switch (t) {
	case 16: case 17: case 19:
	case 20: case 21:
	case 24: case 25:
	case 28: case 29:
		return 1;
	}
	return 0;
}

/* ifinfomsg, ifaddrmsg and ndmsg all carry the interface index as a 32-bit field at
 * byte 4 of their payload (family and padding first), i.e. 16 (NLMSG_HDRLEN) + 4
 * from the start of the message. rtmsg has no such field. */
static inline int names_interface(__u16 t)
{
	switch (t) {
	case 16: case 17: case 19: /* link */
	case 20: case 21:          /* address */
	case 28: case 29:          /* neighbor */
		return 1;
	}
	return 0;
}

#define RTA_DST_TYPE 1
#define RTA_OIF_TYPE 4
#define IFLA_IFNAME_TYPE 3

/* struct rtattr, restated (uAPI). */
struct rtnl_rtattr {
	__u16 rta_len;
	__u16 rta_type;
};

/* A route request is an rtmsg (12 bytes: family, dst_len, src_len, tos, table,
 * protocol, scope, type, flags) after the netlink header, then attributes. Read the
 * family and prefix length, then walk a bounded number of attributes for the output
 * interface and the destination. A route with no RTA_DST is the default route
 * (dst_len 0). RTA_MULTIPATH nexthops are not descended into: their interfaces stay
 * unknown (ifindex 0), which userspace treats as "matches any". */
static inline void route_fields(struct rtnl_event *e, const char *nlh, __u32 msglen)
{
	__u8 rt[2] = {};
	__u32 off = 16 + 12; /* NLMSG_HDRLEN + sizeof(struct rtmsg) */
	int i;

	if (bpf_probe_read_kernel(rt, sizeof(rt), nlh + 16) != 0)
		return;
	e->family = rt[0];
	e->dst_len = rt[1];

#pragma unroll
	for (i = 0; i < 24; i++) {
		struct rtnl_rtattr a = {};

		if (off + 4 > msglen)
			break;
		if (bpf_probe_read_kernel(&a, sizeof(a), nlh + off) != 0)
			break;
		if (a.rta_len < 4)
			break;
		if (a.rta_type == RTA_OIF_TYPE && a.rta_len >= 8) {
			__s32 idx = 0;

			if (bpf_probe_read_kernel(&idx, sizeof(idx), nlh + off + 4) == 0 && idx > 0)
				e->ifindex = (__u32)idx;
		} else if (a.rta_type == RTA_DST_TYPE) {
			if (a.rta_len >= 20)
				bpf_probe_read_kernel(e->dst, 16, nlh + off + 4);
			else if (a.rta_len >= 8)
				bpf_probe_read_kernel(e->dst, 4, nlh + off + 4);
		}
		off += ((__u32)a.rta_len + 3) & ~3U;
	}
}

/* A link request names its device by index (ifi_index, at byte 4 of the ifinfomsg)
 * or, when that is 0, by name in an IFLA_IFNAME attribute after the 16-byte
 * ifinfomsg. Walk a bounded number of attributes for the name. */
static inline void link_name(struct rtnl_event *e, const char *nlh, __u32 msglen)
{
	__u32 off = 16 + 16; /* NLMSG_HDRLEN + sizeof(struct ifinfomsg) */
	int i;

#pragma unroll
	for (i = 0; i < 24; i++) {
		struct rtnl_rtattr a = {};

		if (off + 4 > msglen)
			break;
		if (bpf_probe_read_kernel(&a, sizeof(a), nlh + off) != 0)
			break;
		if (a.rta_len < 4)
			break;
		if (a.rta_type == IFLA_IFNAME_TYPE) {
			bpf_probe_read_kernel_str(e->ifname, sizeof(e->ifname), nlh + off + 4);
			break;
		}
		off += ((__u32)a.rta_len + 3) & ~3U;
	}
}

/* The network namespace the request applies to: the inode of sock_net(skb->sk). */
static inline __u32 request_netns(const void *skb_ptr)
{
	const struct sk_buff *skb = skb_ptr;
	struct sock *sk = 0;
	struct net *net = 0;
	__u32 inum = 0;

	if (CORE_READ(sk, skb, sk) != 0 || !sk)
		return 0;
	if (CORE_READ(net, sk, __sk_common.skc_net.net) != 0 || !net)
		return 0;
	if (CORE_READ(inum, net, ns.inum) != 0)
		return 0;
	return inum;
}

/* rtnetlink_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh,
 *                   struct netlink_ext_ack *extack): the fentry context is the
 * array of the traced function's arguments. */
SEC("fentry/rtnetlink_rcv_msg")
int netra_rtnl_msg(unsigned long long *ctx)
{
	struct rtnl_nlmsghdr hdr = {};
	struct rtnl_event *e;
	__u32 *want, netns, zero = 0;
	__u64 pt;

	if (bpf_probe_read_kernel(&hdr, sizeof(hdr), (const void *)ctx[1]) != 0)
		return 0;
	if (!modifies_network(hdr.nlmsg_type))
		return 0;

	/* Only the namespace userspace records changes in: interface indexes of any other
	 * namespace would collide with it. An unreadable namespace (0) is kept. */
	netns = request_netns((const void *)ctx[0]);
	want = bpf_map_lookup_elem(&rtnl_config, &zero);
	if (want && *want != 0 && netns != 0 && netns != *want)
		return 0;

	e = bpf_ringbuf_reserve(&rtnl_events, sizeof(*e), 0);
	if (!e) {
		__u32 k = 0;
		__u64 *drops = bpf_map_lookup_elem(&rtnl_stats, &k);
		if (drops)
			__sync_fetch_and_add(drops, 1);
		return 0;
	}
	pt = bpf_get_current_pid_tgid();
	e->ts_ns = bpf_ktime_get_ns();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->tgid = pt >> 32;
	e->pid = (__u32)pt;
	e->nlmsg_type = hdr.nlmsg_type;
	e->nlmsg_flags = hdr.nlmsg_flags;
	e->nlmsg_len = hdr.nlmsg_len;
	e->netns_ino = netns;
	e->_pad2 = 0;
	e->family = 0;
	e->dst_len = 0;
	e->ifindex = 0;
	/* The ring buffer hands back uninitialised memory: never let it reach userspace. */
	e->_pad = 0;
	__builtin_memset(e->dst, 0, sizeof(e->dst));
	__builtin_memset(e->ifname, 0, sizeof(e->ifname));
	if (names_interface(hdr.nlmsg_type)) {
		__s32 idx = 0;
		if (bpf_probe_read_kernel(&idx, sizeof(idx), (const char *)ctx[1] + 20) == 0 && idx > 0)
			e->ifindex = (__u32)idx;
		/* A link request may name its device only by name. */
		if (e->ifindex == 0 && (hdr.nlmsg_type == 16 || hdr.nlmsg_type == 17 || hdr.nlmsg_type == 19))
			link_name(e, (const char *)ctx[1], hdr.nlmsg_len);
	} else if (hdr.nlmsg_type == 24 || hdr.nlmsg_type == 25) {
		route_fields(e, (const char *)ctx[1], hdr.nlmsg_len);
	}
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
