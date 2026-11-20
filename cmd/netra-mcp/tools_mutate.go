// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/zyvorai/netra/internal/mcpserver"
)

// registerMutateTools registers every tool that changes cluster or
// controller state. It is only called when NETRA_MCP_ALLOW_MUTATIONS=true
// at startup (see main.go); with that unset, none of these tool names
// exist and an MCP client has no way to invoke them. Every mutation here
// is already audited by the controller itself (queryable via
// netra_audit) under this process's configured actor label
// (NETRA_MCP_ACTOR, default "mcp:hermes").
func registerMutateTools(srv *mcpserver.Server, c *client) error {
	tools := []endpointTool{
		{
			name: "netra_ebpf_mode", method: "PUT", path: "/api/v1/ebpf/mode",
			description: "Switch the eBPF fast path between \"observe\" (monitor only) and \"enforce\" (actively block). Enforce mode requires a lease (default 15m, 1m-24h); the controller automatically reverts to observe when the lease expires, so this is self-limiting and safe to use experimentally.",
			schema: objSchema(map[string]any{
				"mode":  enumProp("Target mode.", "observe", "enforce"),
				"lease": strProp("Enforce-mode lease duration, e.g. \"30m\" (1m-24h). Only used when mode=enforce; default 15m."),
			}, "mode"),
			queryParams: []string{"lease"},
			bodyFields:  true,
		},
		{
			name: "netra_capture_start", method: "PUT", path: "/api/v1/vms/{node}/capture",
			description: "Start a packet-capture session on one node. Captures full packet bytes by default (not just headers) — captured traffic can contain cleartext application secrets (auth headers, tokens, cookies), so only use this when you specifically need to inspect wire traffic, and prefer narrowing protocol/host/port over an unfiltered capture (at least one filter field is required). Duration is capped at 5 minutes and auto-expires; live packets stream to the Capture dashboard page, not through this tool.",
			schema: objSchema(map[string]any{
				"node":            strProp("Kubernetes node name to capture on."),
				"backend":         enumProp("Capture engine. eBPF (default, omit to use it): in-kernel TCX observer, in-kernel filtering/rate-limiting, requires the packet-capture BPF object to be loaded on the node. AF_PACKET: pure userspace raw-socket capture, no BPF object dependency, works anywhere the interface is visible in the pod's network namespace. Requesting a backend unavailable on the target node surfaces an error rather than silently falling back.", "ebpf", "afpacket"),
				"protocol":        enumProp("Filter to one L4 protocol. Omit for any.", "tcp", "udp", "icmp", "icmpv6"),
				"host":            strProp("Filter to packets with this IPv4/IPv6 address as either source or destination. Omit for any host."),
				"port":            intProp("Filter to packets with this port as either source or destination. Omit for any port."),
				"snapLen":         intProp("Bytes captured per packet. Omit for a full-frame capture."),
				"maxPps":          intProp("In-kernel per-second capture cap. Omit for the default (2000)."),
				"durationSeconds": intProp("How long the capture runs before auto-stopping, 1-300. Default 60."),
			}, "node"),
			pathParams: []string{"node"},
			bodyFields: true,
		},
		{
			name: "netra_capture_stop", method: "DELETE", path: "/api/v1/vms/{node}/capture",
			description: "Stop an active packet-capture session on one node before its duration expires.",
			schema:      objSchema(map[string]any{"node": strProp("Kubernetes node name to stop capturing on.")}, "node"),
			pathParams:  []string{"node"},
		},
		{
			name: "netra_ebpf_scope_set", method: "PUT", path: "/api/v1/ebpf/scope",
			description: "Set which workloads the eBPF fast path applies to: \"all\" (cluster-wide) or \"selected\" (only the given scopes). Preview matches first with netra_ebpf_scope_preview.",
			schema: objSchema(map[string]any{
				"mode":   enumProp("Scope mode.", "all", "selected"),
				"scopes": map[string]any{"type": "array", "description": "Required when mode=selected. Each item may specify namespace/pod/workloadKind/workloadName/labels/cgroupId.", "items": map[string]any{"type": "object"}},
			}, "mode"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_deny_add", method: "POST", path: "/api/v1/ebpf/deny",
			description: "Add an exact IPv4 or IPv6 address to the eBPF deny list (blocks all traffic to/from it). Returns the full updated fast-path config.",
			schema: objSchema(map[string]any{
				"ip":        strProp("IPv4 or IPv6 address to block."),
				"direction": strProp("egress, ingress, or both. Defaults to egress."),
			}, "ip"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_deny_delete", method: "DELETE", path: "/api/v1/ebpf/deny/{ip}",
			description: "Remove an address from the eBPF deny list. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"ip": strProp("IPv4 or IPv6 address to unblock.")}, "ip"),
			pathParams:  []string{"ip"},
		},
		{
			name: "netra_ebpf_allow_add", method: "POST", path: "/api/v1/ebpf/allow",
			description: "Add an exact IPv4 or IPv6 exception. Evaluated before deny/rate. Still requires an enforce lease to change verdicts. Returns the updated fast-path config.",
			schema:      objSchema(map[string]any{"ip": strProp("IPv4 or IPv6 address that must never be denied by the flat lists.")}, "ip"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_allow_delete", method: "DELETE", path: "/api/v1/ebpf/allow/{ip}",
			description: "Remove an allow-list exception.",
			schema:      objSchema(map[string]any{"ip": strProp("IPv4 or IPv6 address to drop from the exception list.")}, "ip"),
			pathParams:  []string{"ip"},
		},
		{
			name: "netra_ebpf_allow_cidr_add", method: "POST", path: "/api/v1/ebpf/allow-cidr",
			description: "Add a CIDR exception evaluated before deny/rate. Direction ingress|egress|both.",
			schema: objSchema(map[string]any{
				"cidr":      strProp("CIDR exception, e.g. \"10.0.0.0/24\"."),
				"direction": strProp("ingress, egress, or both."),
			}, "cidr"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_allow_cidr_delete", method: "POST", path: "/api/v1/ebpf/allow-cidr/delete",
			description: "Remove a CIDR exception.",
			schema: objSchema(map[string]any{
				"cidr":      strProp("CIDR exception to remove."),
				"direction": strProp("ingress, egress, or both."),
			}, "cidr"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_cidr_add", method: "POST", path: "/api/v1/ebpf/cidr",
			description: "Add a CIDR to the eBPF fast-path CIDR deny rule set. Returns the full updated fast-path config.",
			schema: objSchema(map[string]any{
				"cidr":      strProp("CIDR to block, e.g. \"10.0.0.0/8\"."),
				"direction": enumProp("Direction to block. Default egress.", "egress", "ingress", "both"),
			}, "cidr"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_cidr_delete", method: "POST", path: "/api/v1/ebpf/cidr/delete",
			description: "Remove a CIDR from the eBPF fast-path CIDR deny rule set. Returns the full updated fast-path config.",
			schema: objSchema(map[string]any{
				"cidr":      strProp("CIDR to unblock."),
				"direction": enumProp("Direction it was blocked in. Default egress.", "egress", "ingress", "both"),
			}, "cidr"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_syn_drop_add", method: "POST", path: "/api/v1/ebpf/syn-drop",
			description: "Flag an exact-IP deny entry (blockedIPv4/blockedIPv6 for egress, blockedIngressIPv4/blockedIngressIPv6 for ingress) for SYN-drop mode: only a genuinely new TCP connection attempt is dropped for that address+direction; any other TCP packet is allowed through instead of unconditionally dropped. Has no effect unless a matching exact-IP deny entry for the same address+direction already exists (does not itself create one) — add that first with netra_ebpf_deny_add. CIDR-matched deny is not covered. Returns the full updated fast-path config.",
			schema: objSchema(map[string]any{
				"address":   strProp("Exact IPv4 or IPv6 address — must match an existing exact-IP deny entry to have any effect."),
				"direction": enumProp("Direction it was denied in. Unlike CIDR rules, \"both\" is not valid — the underlying kernel maps are per-direction; add two entries for both.", "egress", "ingress"),
			}, "address", "direction"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_syn_drop_delete", method: "POST", path: "/api/v1/ebpf/syn-drop/delete",
			description: "Remove a SYN-drop-mode flag, reverting that exact-IP deny entry to dropping every packet (not just new SYNs). Returns the full updated fast-path config.",
			schema: objSchema(map[string]any{
				"address":   strProp("Exact IPv4 or IPv6 address."),
				"direction": enumProp("Direction it was flagged in.", "egress", "ingress"),
			}, "address", "direction"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_port_add", method: "POST", path: "/api/v1/ebpf/port",
			description: "Add a port to the eBPF fast-path port deny rule set. Returns the full updated fast-path config.",
			schema: objSchema(map[string]any{
				"port":      intProp("Port to block, 1-65535."),
				"protocol":  enumProp("Protocol. Default ANY.", "TCP", "UDP", "ANY"),
				"direction": enumProp("Direction to block. Default egress.", "egress", "ingress", "both"),
			}, "port"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_port_delete", method: "POST", path: "/api/v1/ebpf/port/delete",
			description: "Remove a port from the eBPF fast-path port deny rule set. Returns the full updated fast-path config.",
			schema: objSchema(map[string]any{
				"port":      intProp("Port to unblock."),
				"protocol":  enumProp("Protocol it was blocked under. Default ANY.", "TCP", "UDP", "ANY"),
				"direction": enumProp("Direction it was blocked in. Default egress.", "egress", "ingress", "both"),
			}, "port"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_allow_port_add", method: "POST", path: "/api/v1/ebpf/allow-port",
			description: "Add an L4 port exception evaluated before deny/CIDR/port/rate. Returns the full updated fast-path config.",
			schema: objSchema(map[string]any{
				"port":      intProp("Port to except, 1-65535."),
				"protocol":  enumProp("Protocol. Default ANY.", "TCP", "UDP", "ANY"),
				"direction": enumProp("Direction to except. Default egress.", "egress", "ingress", "both"),
			}, "port"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_allow_port_delete", method: "POST", path: "/api/v1/ebpf/allow-port/delete",
			description: "Remove an L4 port exception. Returns the full updated fast-path config.",
			schema: objSchema(map[string]any{
				"port":      intProp("Port exception to remove."),
				"protocol":  enumProp("Protocol it was excepted under. Default ANY.", "TCP", "UDP", "ANY"),
				"direction": enumProp("Direction it was excepted in. Default egress.", "egress", "ingress", "both"),
			}, "port"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_uid_add", method: "POST", path: "/api/v1/ebpf/uid",
			description: "Add a Linux UID to the eBPF fast-path deny rule set (blocks all sockets opened by that UID). Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"uid": intProp("Linux UID to block.")}, "uid"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_uid_delete", method: "DELETE", path: "/api/v1/ebpf/uid/{uid}",
			description: "Remove a UID from the eBPF fast-path deny rule set. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"uid": strProp("Linux UID to unblock.")}, "uid"),
			pathParams:  []string{"uid"},
		},
		{
			name: "netra_ebpf_allow_uid_add", method: "POST", path: "/api/v1/ebpf/allow-uid",
			description: "Add a Linux UID exception evaluated before UID/comm deny at the socket hook. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"uid": intProp("Linux UID to except.")}, "uid"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_allow_uid_delete", method: "DELETE", path: "/api/v1/ebpf/allow-uid/{uid}",
			description: "Remove a UID exception. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"uid": strProp("Linux UID exception to remove.")}, "uid"),
			pathParams:  []string{"uid"},
		},
		{
			name: "netra_ebpf_dns_add", method: "POST", path: "/api/v1/ebpf/dns",
			description: "Add an exact plain-DNS query name (over UDP/53) to the eBPF deny rule set. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"name": strProp("DNS name to block, e.g. \"evil.example.com\". No wildcards.")}, "name"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_dns_delete", method: "POST", path: "/api/v1/ebpf/dns/delete",
			description: "Remove a DNS name from the eBPF deny rule set. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"name": strProp("DNS name to unblock.")}, "name"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_process_add", method: "POST", path: "/api/v1/ebpf/process",
			description: "Add a process name (Linux \"comm\", up to 15 bytes) to the eBPF deny rule set. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"name": strProp("Process comm name to block, e.g. \"curl\".")}, "name"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_process_delete", method: "POST", path: "/api/v1/ebpf/process/delete",
			description: "Remove a process name from the eBPF deny rule set. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"name": strProp("Process comm name to unblock.")}, "name"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_capability_add", method: "POST", path: "/api/v1/ebpf/capability",
			description: "Deny new socket() attempts for any process with a given Linux capability currently effective (CAP_NET_RAW/CAP_NET_ADMIN only — a small, fixed vocabulary, not arbitrary capability names). Agent-sourced: the agent periodically scans /proc and only catches a capability a process already had at the last scan — TOCTOU-caveated, not a live kernel credential read. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"name": enumProp("Capability to deny.", "CAP_NET_RAW", "CAP_NET_ADMIN")}, "name"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_capability_delete", method: "POST", path: "/api/v1/ebpf/capability/delete",
			description: "Remove a capability-gated socket deny entry. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"name": enumProp("Capability to stop denying.", "CAP_NET_RAW", "CAP_NET_ADMIN")}, "name"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_allow_process_add", method: "POST", path: "/api/v1/ebpf/allow-process",
			description: "Add a process name (Linux \"comm\", up to 15 bytes) exception evaluated before UID/comm deny at the socket hook. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"name": strProp("Process comm name to except, e.g. \"coredns\".")}, "name"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_allow_process_delete", method: "POST", path: "/api/v1/ebpf/allow-process/delete",
			description: "Remove a process name exception. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"name": strProp("Process comm name exception to remove.")}, "name"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_sni_add", method: "POST", path: "/api/v1/ebpf/sni",
			description: "Add an exact TLS SNI name to the eBPF deny rule set (best-effort, requires ClientHello SNI parsing). Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"name": strProp("TLS SNI name to block. No wildcards.")}, "name"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_sni_delete", method: "POST", path: "/api/v1/ebpf/sni/delete",
			description: "Remove a TLS SNI name from the eBPF deny rule set. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"name": strProp("TLS SNI name to unblock.")}, "name"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_rate_set", method: "PUT", path: "/api/v1/ebpf/rate",
			description: "Set a packets-per-second and/or bytes-per-second rate limit for an exact IPv4 or IPv6 destination — at least one of pps/bps is required (the server refuses an all-zero rule as a no-op). Returns the full updated fast-path config.",
			schema: objSchema(map[string]any{
				"destination": strProp("Exact IPv4 or IPv6 destination address."),
				"pps":         intProp("Packets-per-second ceiling, 1-10000000. Omit or 0 to leave this destination's PPS cap unset (bps must then be set)."),
				"bps":         intProp("Bytes-per-second ceiling. Independent of pps — a destination may have either, both, or (on delete) neither."),
			}, "destination"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_rate_delete", method: "DELETE", path: "/api/v1/ebpf/rate/{ip}",
			description: "Remove the rate limit for an IPv4 or IPv6 destination. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"ip": strProp("Exact IPv4 or IPv6 destination address.")}, "ip"),
			pathParams:  []string{"ip"},
		},
		{
			name: "netra_ebpf_shield_set", method: "PUT", path: "/api/v1/ebpf/shield",
			description: "Configure the XDP DDoS shield: a per-source-class (SYN/UDP/ICMP/other) PPS token-bucket rate limiter, independent of the eBPF fast-path deny-list and its own mode. \"enforce\" actively drops traffic exceeding thresholds for protected IPs; use \"audit\" first to see what would be dropped. Returns the full updated fast-path config.",
			schema: objSchema(map[string]any{
				"mode":          enumProp("Shield mode.", "off", "audit", "enforce"),
				"protectAll":    map[string]any{"type": "boolean", "description": "Apply thresholds to all traffic instead of just protectedIpv4/protectedIpv6."},
				"protectedIpv4": map[string]any{"type": "array", "description": "Exact IPv4 addresses to protect (ignored if protectAll is true).", "items": map[string]any{"type": "string"}},
				"protectedIpv6": map[string]any{"type": "array", "description": "Exact IPv6 addresses to protect (ignored if protectAll is true).", "items": map[string]any{"type": "string"}},
				"synPps":        intProp("SYN packets-per-second threshold, 0-10000000. 0 disables that class."),
				"udpPps":        intProp("UDP packets-per-second threshold, 0-10000000. 0 disables that class."),
				"icmpPps":       intProp("ICMP packets-per-second threshold, 0-10000000. 0 disables that class."),
				"otherPps":      intProp("Other-protocol packets-per-second threshold, 0-10000000. 0 disables that class."),
				"burstSeconds":  intProp("Token-bucket burst window in seconds, 0-60."),
			}, "mode"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_netpol_config_set", method: "PUT", path: "/api/v1/ebpf/netpol/config",
			description: "Enable or disable the legacy per-workload NetPol-emulation deny engine (independent of the eBPF fast-path deny-list, and independent of the v2 allow/default-deny engine below). Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"enabled": map[string]any{"type": "boolean", "description": "Whether legacy NetPol-emulation enforcement is active."}}, "enabled"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_netpol_v2_config_set", method: "PUT", path: "/api/v1/ebpf/netpol/v2/config",
			description: "Enable or disable the v2 per-workload allow-list/default-deny engine (independent of the legacy NetPol-emulation deny engine above). An explicit allow rule (netra_ebpf_netpol_rule_add) can override even the flat eBPF fast-path deny-list for that specific workload+peer — this is deliberate, not a bug.",
			schema:      objSchema(map[string]any{"enabled": map[string]any{"type": "boolean", "description": "Whether the v2 engine evaluates rules/default-deny posture at all."}}, "enabled"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_netpol_rule_add", method: "POST", path: "/api/v1/ebpf/netpol/rules",
			description: "Add a v2 allow/deny rule for workloads matching a selector (namespace/pod/owner/labels — same shape as netra_ebpf_scope_set), exact IPv4 peer only. An \"allow\" rule can override the flat fast-path deny-list for matching traffic. Returns the full updated fast-path config with the new rule's assigned id.",
			schema: objSchema(map[string]any{
				"selector":  map[string]any{"type": "object", "description": "Workload selector: namespace/pod/workloadKind/workloadName/labels/cgroupId. At least one field required."},
				"peerIpv4":  strProp("Exact IPv4 peer address."),
				"port":      intProp("Peer port, 0/omitted = any port."),
				"protocol":  enumProp("Default ANY.", "TCP", "UDP", "ANY"),
				"direction": enumProp("Default egress.", "egress", "ingress", "both"),
				"action":    enumProp("allow overrides even the flat deny-list; deny blocks immediately.", "allow", "deny"),
			}, "selector", "peerIpv4", "action"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_netpol_rule_delete", method: "DELETE", path: "/api/v1/ebpf/netpol/rules/{id}",
			description: "Delete a v2 allow/deny rule by its id (from the fast-path config's netPolRules, or netra_ebpf_netpol_rule_add's response).",
			schema:      objSchema(map[string]any{"id": strProp("Rule id.")}, "id"),
			pathParams:  []string{"id"},
		},
		{
			name: "netra_ebpf_conn_rate_limit_add", method: "POST", path: "/api/v1/ebpf/conn-rate-limit",
			description: "Cap new TCP connection attempts per second for every workload matching a selector (namespace/pod/owner/labels — same shape as netra_ebpf_scope_set). Checked only on TCP connect() attempts, not UDP sendmsg. When multiple rules match the same workload the strictest (lowest) perSecond applies. Returns the full updated fast-path config with the new rule's assigned id.",
			schema: objSchema(map[string]any{
				"selector":  map[string]any{"type": "object", "description": "Workload selector: namespace/pod/workloadKind/workloadName/labels/cgroupId. At least one field required."},
				"perSecond": intProp("New-TCP-connection ceiling per second. Must be greater than zero."),
			}, "selector", "perSecond"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_conn_rate_limit_delete", method: "DELETE", path: "/api/v1/ebpf/conn-rate-limit/{id}",
			description: "Delete a connection-rate-limit rule by its id (from the fast-path config's connRateLimits, or netra_ebpf_conn_rate_limit_add's response).",
			schema:      objSchema(map[string]any{"id": strProp("Rule id.")}, "id"),
			pathParams:  []string{"id"},
		},
		{
			name: "netra_ebpf_netpol_default_deny_plan", method: "POST", path: "/api/v1/ebpf/netpol/default-deny/plan",
			description: "Mandatory first step to activate/deactivate v2 default-deny for a workload selector: assesses risk (workloads with zero covering allow rules make this \"critical\" and the call is refused unless allow_no_rules is set) and issues a receipt.token (5-minute, single-use) required by netra_ebpf_netpol_default_deny_set. Deactivating is always risk \"low\". Mutates nothing else.",
			schema: objSchema(map[string]any{
				"selector":     map[string]any{"type": "object", "description": "Workload selector this default-deny posture targets."},
				"enabled":      map[string]any{"type": "boolean", "description": "true to plan activation, false to plan deactivation."},
				"lease":        strProp("Intended lease duration if activating, e.g. \"5m\" (1m-60m). Default 5m."),
				"allowNoRules": map[string]any{"type": "boolean", "description": "Override the critical-risk refusal when zero matched workloads have a covering allow rule. Use deliberately, not by default."},
			}, "selector", "enabled"),
			queryParams: []string{"allowNoRules"},
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_rules_patch", method: "PATCH", path: "/api/v1/ebpf/rules/{id}",
			description: "Edit one eBPF fast-path rule in place by its stable ID (from netra_ebpf_rules_list), preserving the ID and recording a before/after revision (see netra_ebpf_rules_history). The body fields must match the rule's type: {ip} for ip4/ip6, {cidr,direction} for cidr, {protocol,port,direction} for port, {uid} for uid, {name} for dns/sni/process, {destination,pps} for rate. Validated identically to the corresponding add tool.",
			schema: objSchema(map[string]any{
				"id":          strProp("Rule ID from netra_ebpf_rules_list."),
				"ip":          strProp("New address (ip4/ip6 rules only)."),
				"cidr":        strProp("New CIDR (cidr rules only)."),
				"direction":   enumProp("New direction (cidr/port rules only).", "egress", "ingress", "both"),
				"protocol":    enumProp("New protocol (port rules only).", "TCP", "UDP", "ANY"),
				"port":        intProp("New port (port rules only)."),
				"uid":         intProp("New UID (uid rules only)."),
				"name":        strProp("New name (dns/sni/process rules only)."),
				"destination": strProp("New destination (rate rules only)."),
				"pps":         intProp("New packets-per-second, 1-10000000 (rate rules only)."),
			}, "id"),
			pathParams: []string{"id"},
			bodyFields: true,
		},
		{
			name: "netra_ebpf_rules_delete", method: "DELETE", path: "/api/v1/ebpf/rules/{id}",
			description: "Delete one eBPF fast-path rule by its stable ID — a thin wrapper resolving to the same store mutation the legacy value-keyed delete tools use.",
			schema:      objSchema(map[string]any{"id": strProp("Rule ID from netra_ebpf_rules_list.")}, "id"),
			pathParams:  []string{"id"},
		},
		{
			name: "netra_ebpf_rules_rollback", method: "POST", path: "/api/v1/ebpf/rules/{id}/rollback/{revision}",
			description: "Undo one specific edit to a rule: restores the value it had before that revision (from netra_ebpf_rules_history), recorded as a new revision rather than rewriting history.",
			schema: objSchema(map[string]any{
				"id":       strProp("Rule ID from netra_ebpf_rules_list."),
				"revision": strProp("Revision ID from netra_ebpf_rules_history to undo."),
			}, "id", "revision"),
			pathParams: []string{"id", "revision"},
		},
		{
			name: "netra_insights_baseline_capture", method: "POST", path: "/api/v1/insights/baseline",
			description: "Capture a new behavior baseline from current agent reports, replacing any existing one. netra_insights_drift compares future traffic against this snapshot.",
			schema:      emptySchema(),
		},
		{
			name: "netra_insights_baseline_clear", method: "DELETE", path: "/api/v1/insights/baseline",
			description: "Clear the captured behavior baseline.",
			schema:      emptySchema(),
			headers:     map[string]string{"X-Netra-Confirm-Baseline-Clear": "clear"},
		},
		{
			name: "netra_insights_rate_baseline_capture", method: "POST", path: "/api/v1/insights/rate-baseline",
			description: "Capture a new traffic-rate baseline over a window of current agent reports, replacing any existing one. netra_insights_rate_drift compares future traffic against this snapshot.",
			schema:      objSchema(map[string]any{"window": strProp("Duration string, e.g. \"5m\", between 30s and 2h. Default 5m.")}),
			queryParams: []string{"window"},
		},
		{
			name: "netra_insights_rate_baseline_clear", method: "DELETE", path: "/api/v1/insights/rate-baseline",
			description: "Clear the captured traffic-rate baseline.",
			schema:      emptySchema(),
			headers:     map[string]string{"X-Netra-Confirm-Rate-Baseline-Clear": "clear"},
		},
		{
			name: "netra_policy_rollback", method: "POST", path: "/api/v1/policies/{namespace}/{name}/rollback/{revision}",
			description: "Roll a CiliumNetworkPolicy back to a previously recorded revision (from netra_policies_history). Pass dryRun=true first to preview the risk; if risk comes back high/critical, repeat with confirmRisk set to that same value to actually apply.",
			schema: objSchema(map[string]any{
				"namespace":   strProp("Policy namespace."),
				"name":        strProp("Policy name."),
				"revision":    strProp("Revision id from netra_policies_history."),
				"dryRun":      map[string]any{"type": "boolean", "description": "If true, only preview the rollback plan and risk; nothing is changed."},
				"confirmRisk": enumProp("Required to actually apply when the plan's risk is high/critical; must match exactly.", "low", "medium", "high", "critical"),
			}, "namespace", "name", "revision"),
			pathParams:  []string{"namespace", "name", "revision"},
			queryParams: []string{"dryRun", "confirmRisk"},
		},
		{
			name: "netra_policy_delete", method: "DELETE", path: "/api/v1/policies/{namespace}/{name}",
			description: "Delete a CiliumNetworkPolicy from the cluster. A checkpoint of the deleted manifest is recorded in policy history.",
			schema:      objSchema(map[string]any{"namespace": strProp("Policy namespace."), "name": strProp("Policy name.")}, "namespace", "name"),
			pathParams:  []string{"namespace", "name"},
		},
		{
			name: "netra_policy_unlock", method: "DELETE", path: "/api/v1/policies/lockdown/{namespace}/{name}",
			description: "Remove an applied lockdown (deny-all) policy for a workload, restoring its normal network access. This deletes the lockdown CiliumNetworkPolicy from the cluster.",
			schema:      objSchema(map[string]any{"namespace": strProp("Workload namespace."), "name": strProp("Workload name (not the policy name — Netra derives the lockdown policy name from it).")}, "namespace", "name"),
			pathParams:  []string{"namespace", "name"},
		},
	}

	for _, t := range tools {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}

	if err := registerPolicyPlan(srv, c); err != nil {
		return err
	}
	if err := registerPolicyApply(srv, c); err != nil {
		return err
	}
	if err := registerPolicyHistoryImport(srv, c); err != nil {
		return err
	}
	if err := registerNetPolDefaultDenySet(srv, c); err != nil {
		return err
	}
	if err := registerIntelFeedPut(srv, c); err != nil {
		return err
	}
	if err := registerIntelApply(srv, c); err != nil {
		return err
	}
	if err := registerAIDestinationsDeny(srv, c); err != nil {
		return err
	}
	return registerPolicyGitOpsResync(srv, c)
}

func registerIntelFeedPut(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name:        "netra_intel_feed_put",
		Description: "Replace the active threat-intel feed (JSON/CSV/bare list). Does not apply denies; use netra_intel_apply under an enforce lease.",
		InputSchema: objSchema(map[string]any{
			"text": strProp("Feed body: JSON, CSV, or newline-separated IPs/CIDRs/names."),
		}, "text"),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			var x struct {
				Text string `json:"text"`
			}
			if err := json.Unmarshal(raw, &x); err != nil {
				return fmt.Sprintf("invalid arguments: %v", err), true, nil
			}
			out, status, err := c.do(ctx, "PUT", "/api/v1/intel/feed", []byte(x.Text), nil)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}

func registerIntelApply(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name:        "netra_intel_apply",
		Description: "Import the active threat-intel feed into deny maps. Requires mode=enforce with an active lease and confirm_risk=high. Optional matched_only imports only currently observed hits.",
		InputSchema: objSchema(map[string]any{
			"confirm_risk": enumProp("Must be high.", "high"),
			"matched_only": map[string]any{"type": "boolean", "description": "When true, only apply entries that currently match live traffic."},
		}, "confirm_risk"),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			var x struct {
				ConfirmRisk string `json:"confirm_risk"`
				MatchedOnly bool   `json:"matched_only"`
			}
			if err := json.Unmarshal(raw, &x); err != nil {
				return fmt.Sprintf("invalid arguments: %v", err), true, nil
			}
			path := "/api/v1/intel/apply"
			if x.MatchedOnly {
				path += "?matchedOnly=true"
			}
			extra := map[string]string{"X-Netra-Confirm-Risk": x.ConfirmRisk}
			out, status, err := c.do(ctx, "POST", path, nil, extra)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}

func registerAIDestinationsDeny(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name:        "netra_ebpf_ai_destinations_deny",
		Description: "Lease-deny currently observed GenAI/MCP SaaS SNI hosts. Requires mode=enforce with an active lease and confirm_risk=high. Metadata only.",
		InputSchema: objSchema(map[string]any{
			"confirm_risk": enumProp("Must be high.", "high"),
		}, "confirm_risk"),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			var x struct {
				ConfirmRisk string `json:"confirm_risk"`
			}
			if err := json.Unmarshal(raw, &x); err != nil {
				return fmt.Sprintf("invalid arguments: %v", err), true, nil
			}
			extra := map[string]string{"X-Netra-Confirm-Risk": x.ConfirmRisk}
			out, status, err := c.do(ctx, "POST", "/api/v1/ebpf/ai-destinations/deny", nil, extra)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}

// registerNetPolDefaultDenySet wraps PUT /api/v1/ebpf/netpol/default-deny.
// Like registerPolicyApply, this can't be a plain endpointTool: plan_token
// and confirm_risk are headers, not part of the JSON body, and the body's
// exact bytes must match what netra_ebpf_netpol_default_deny_plan hashed.
func registerNetPolDefaultDenySet(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name: "netra_ebpf_netpol_default_deny_set",
		Description: "Activate or deactivate v2 default-deny for a workload selector. Requires plan_token from a prior " +
			"netra_ebpf_netpol_default_deny_plan call with the identical selector/enabled/lease (tokens are single-use, " +
			"5-minute). If the plan's risk was \"medium\" or higher, confirm_risk must equal that risk. This is the " +
			"single highest-blast-radius mutation in the firewall feature — a workload in default-deny posture only " +
			"accepts traffic an explicit allow rule (netra_ebpf_netpol_rule_add) permits.",
		InputSchema: objSchema(map[string]any{
			"selector":     map[string]any{"type": "object", "description": "Must exactly match the selector passed to netra_ebpf_netpol_default_deny_plan."},
			"enabled":      map[string]any{"type": "boolean", "description": "Must exactly match the plan call."},
			"lease":        strProp("Must exactly match the plan call, if it was set."),
			"plan_token":   strProp("receipt.token from netra_ebpf_netpol_default_deny_plan's result."),
			"confirm_risk": enumProp("Required when the plan's risk was medium/high/critical; must match exactly.", "low", "medium", "high", "critical"),
		}, "selector", "enabled", "plan_token"),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			// The preflight token from netra_ebpf_netpol_default_deny_plan
			// is hash-bound to that call's exact request body — which,
			// since plan is a plain endpointTool with bodyFields:true, is
			// just json.Marshal of its incoming args map after stripping
			// allowNoRules. To reproduce byte-identical bytes here (so the
			// hash actually matches when the caller passes the same
			// selector/enabled/lease to both calls, whether or not lease
			// was included), do the same transform: parse to a generic
			// map, strip only the fields that are specific to this call,
			// re-marshal — do not reconstruct the body from typed fields.
			args := map[string]any{}
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &args); err != nil {
					return fmt.Sprintf("invalid arguments: %v", err), true, nil
				}
			}
			planToken, _ := args["plan_token"].(string)
			confirmRisk, _ := args["confirm_risk"].(string)
			delete(args, "plan_token")
			delete(args, "confirm_risk")
			body, err := json.Marshal(args)
			if err != nil {
				return fmt.Sprintf("invalid arguments: %v", err), true, nil
			}
			extra := map[string]string{"X-Netra-Plan-Token": planToken}
			if confirmRisk != "" {
				extra["X-Netra-Confirm-Risk"] = confirmRisk
			}
			out, status, err := c.do(ctx, "PUT", "/api/v1/ebpf/netpol/default-deny", body, extra)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}

// registerPolicyPlan and registerPolicyApply encode Netra's existing
// plan-then-apply safety dance (internal/api/server.go planPolicy /
// applyPolicy): plan does a server-side dry-run and issues a single-use,
// content-hash-bound, 5-minute preflight token; apply requires that
// exact token, plus an explicit risk echo for high/critical changes.
// This hand-off can't be expressed as a plain endpointTool because the
// request body is the raw manifest itself, not a JSON object of named
// arguments, and apply needs values from plan's result threaded into
// its own headers.
func registerPolicyPlan(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name: "netra_policy_plan",
		Description: "Dry-run a CiliumNetworkPolicy manifest change against the live cluster and risk-assess it. " +
			"Returns a receipt.token (valid 5 minutes, single use) that MUST be passed as plan_token to " +
			"netra_policy_apply to actually apply this exact manifest. If plan.risk is \"high\" or \"critical\", " +
			"netra_policy_apply also requires confirm_risk set to that same risk string.",
		InputSchema: objSchema(map[string]any{
			"manifest": strProp("Full CiliumNetworkPolicy manifest (YAML or JSON) to plan."),
		}, "manifest"),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			var x struct {
				Manifest string `json:"manifest"`
			}
			if err := json.Unmarshal(raw, &x); err != nil {
				return fmt.Sprintf("invalid arguments: %v", err), true, nil
			}
			out, status, err := c.do(ctx, "POST", "/api/v1/policies/plan", []byte(x.Manifest), nil)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}

func registerPolicyApply(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name: "netra_policy_apply",
		Description: "Apply a CiliumNetworkPolicy manifest. Requires plan_token from a prior netra_policy_plan call " +
			"on this exact manifest (tokens are single-use and expire after 5 minutes). If the plan's risk was " +
			"\"high\" or \"critical\", confirm_risk must also be passed and must equal that risk level, or the call " +
			"is rejected.",
		InputSchema: objSchema(map[string]any{
			"manifest":     strProp("The same manifest passed to netra_policy_plan."),
			"plan_token":   strProp("receipt.token from netra_policy_plan's result."),
			"confirm_risk": enumProp("Required only when the plan's risk was high/critical; must match exactly.", "low", "medium", "high", "critical"),
		}, "manifest", "plan_token"),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			var x struct {
				Manifest    string `json:"manifest"`
				PlanToken   string `json:"plan_token"`
				ConfirmRisk string `json:"confirm_risk"`
			}
			if err := json.Unmarshal(raw, &x); err != nil {
				return fmt.Sprintf("invalid arguments: %v", err), true, nil
			}
			extra := map[string]string{"X-Netra-Plan-Token": x.PlanToken}
			if x.ConfirmRisk != "" {
				extra["X-Netra-Confirm-Risk"] = x.ConfirmRisk
			}
			out, status, err := c.do(ctx, "POST", "/api/v1/policies/apply", []byte(x.Manifest), extra)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}

// registerPolicyGitOpsResync wraps POST /api/v1/policies/gitops/resync, the
// explicit human override for a manifest the GitOps reconciler's unattended
// pass declined to auto-apply (drift detected, or risk too high) — bespoke
// for the same reason netra_policy_apply is: the request body is the raw
// candidate manifest, and the risk confirmation travels as a header, not a
// JSON field.
func registerPolicyGitOpsResync(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name:        "netra_policy_gitops_resync",
		Description: "Explicitly apply a candidate manifest via the GitOps pipeline, bypassing the reconciler's own auto-apply gating (drift or high/critical risk) — the human override for a manifest netra_policy_gitops_status shows as pending. If the computed risk is \"high\" or \"critical\", confirm_risk must be passed and must equal that risk level, or the call is rejected. 409 if GitOps is not enabled.",
		InputSchema: objSchema(map[string]any{
			"manifest":     strProp("Full CiliumNetworkPolicy manifest (YAML or JSON) to resync."),
			"confirm_risk": enumProp("Required only when the computed risk is high/critical; must match exactly.", "low", "medium", "high", "critical"),
		}, "manifest"),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			var x struct {
				Manifest    string `json:"manifest"`
				ConfirmRisk string `json:"confirm_risk"`
			}
			if err := json.Unmarshal(raw, &x); err != nil {
				return fmt.Sprintf("invalid arguments: %v", err), true, nil
			}
			var extra map[string]string
			if x.ConfirmRisk != "" {
				extra = map[string]string{"X-Netra-Confirm-Risk": x.ConfirmRisk}
			}
			out, status, err := c.do(ctx, "POST", "/api/v1/policies/gitops/resync", []byte(x.Manifest), extra)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}

// registerPolicyHistoryImport wraps POST /api/v1/policies/history/import,
// which needs a conditional confirmation header only when mode=replace
// (internal/api/server.go importPolicyHistory) — the one other mutating
// endpoint whose header depends on an argument value rather than being
// fixed per-tool.
func registerPolicyHistoryImport(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name: "netra_policy_history_import",
		Description: "Import a previously exported policy revision archive (from netra_policies_history_export). " +
			"mode=\"merge\" (default) adds to existing history; mode=\"replace\" discards existing history first and " +
			"requires confirm_replace=true.",
		InputSchema: objSchema(map[string]any{
			"archive":         map[string]any{"type": "object", "description": "The archive object as returned by netra_policies_history_export."},
			"mode":            enumProp("Import mode. Default merge.", "merge", "replace"),
			"confirm_replace": map[string]any{"type": "boolean", "description": "Must be true when mode=replace."},
		}, "archive"),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			var x struct {
				Archive        json.RawMessage `json:"archive"`
				Mode           string          `json:"mode"`
				ConfirmReplace bool            `json:"confirm_replace"`
			}
			if err := json.Unmarshal(raw, &x); err != nil {
				return fmt.Sprintf("invalid arguments: %v", err), true, nil
			}
			path := "/api/v1/policies/history/import"
			if x.Mode != "" {
				path += "?mode=" + x.Mode
			}
			extra := map[string]string{}
			if x.Mode == "replace" && x.ConfirmReplace {
				extra["X-Netra-Confirm-History-Replace"] = "replace"
			}
			out, status, err := c.do(ctx, "POST", path, x.Archive, extra)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}
