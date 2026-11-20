// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/nodeiso"
)

// nodeIsoTop bounds the would-block/blocked destination list in each report.
const nodeIsoTop = 20

// attachNodeIsolation loads bpf/netra_nodeiso.c onto the agent interfaces.
// NETRA_NODE_ISOLATION is auto|off|required with the same convention as
// NETRA_EDGE_INTEL: in auto a missing object or failed attach only means
// the node reports node isolation as unavailable.
func (a *Agent) attachNodeIsolation(ifs []string) error {
	mode := strings.ToLower(env("NETRA_NODE_ISOLATION", "auto"))
	if mode == "off" {
		return nil
	}
	ifs = nodeIsolationInterfaces(env("NETRA_NODE_ISOLATION_INTERFACES", ""), ifs)
	iso, err := nodeiso.Load(nodeiso.Options{ObjectPath: a.nodeIsoObject, Interfaces: ifs, Log: a.log})
	if err != nil {
		if mode == "required" {
			return err
		}
		a.nodeIsoWhy = err.Error()
		a.log.Warn("node isolation unavailable; continuing without it", "object", a.nodeIsoObject, "error", err)
		return nil
	}
	a.nodeIso = iso
	a.nodeIsoImplicit = controllerRules(a.server)
	a.hooks = append(a.hooks, iso.Attached()...)
	a.markAttached("netra_nodeiso_egress")
	return nil
}

// applyNodeIsolation publishes spec into the kernel. demoted forces enforce
// down to shadow (controller stale); an enforce lease that has lapsed
// locally is demoted the same way, without waiting for the controller.
func (a *Agent) applyNodeIsolation(spec *models.NodeIsolationSpec, demoted string) {
	a.nodeIsoSpec = spec
	if a.nodeIso == nil {
		return
	}
	if demoted == "" && spec != nil && spec.Mode == models.NodeIsolationEnforce &&
		(spec.LeaseUntil == nil || !time.Now().Before(*spec.LeaseUntil)) {
		demoted = "lease expired"
	}
	if err := a.nodeIso.Apply(spec, a.nodeIsoImplicit, demoted); err != nil {
		a.log.Warn("apply node isolation", "error", err)
		// Never leave a policy enforcing that could not be fully replaced.
		if ferr := a.nodeIso.Apply(spec, a.nodeIsoImplicit, "apply failed"); ferr != nil {
			a.log.Error("node isolation shadow fallback", "error", ferr)
		}
	}
}

func (a *Agent) readNodeIsolation() *models.NodeIsolationStatus {
	if a.nodeIso == nil {
		if a.nodeIsoWhy != "" {
			return &models.NodeIsolationStatus{Unavailable: a.nodeIsoWhy}
		}
		return nil
	}
	st, err := a.nodeIso.Snapshot(nodeIsoTop)
	if err != nil {
		a.log.Warn("read node isolation", "error", err)
		return &models.NodeIsolationStatus{Attached: a.nodeIso.Attached(), Unavailable: err.Error()}
	}
	return st
}

// controllerRules allows TCP to every address of the controller URL, so an
// enforce policy can never stop the agent reaching the controller (and with
// it, the lease renewals and the delete that end isolation).
func controllerRules(server string) []models.NodeIsolationRule {
	u, err := url.Parse(server)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 && p < 65536 {
		port = p
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ips, _ := net.DefaultResolver.LookupNetIP(ctx, "ip", u.Hostname())
		addrs = ips
	}
	var out []models.NodeIsolationRule
	for _, ip := range addrs {
		if len(out) == nodeiso.MaxRules-64 {
			break
		}
		ip = ip.Unmap()
		out = append(out, models.NodeIsolationRule{CIDR: netip.PrefixFrom(ip, ip.BitLen()).String(), Protocol: "tcp", PortFrom: uint16(port), PortTo: uint16(port)})
	}
	return out
}

// nodeIsolationInterfaces picks where the egress filter attaches: an explicit
// NETRA_NODE_ISOLATION_INTERFACES list, else the agent's TC interfaces, else
// the default-route uplinks. The last case is a node where Netra runs in
// cgroup mode beside a CNI that owns TC, so the agent has no interfaces.
func nodeIsolationInterfaces(explicit string, agentIfs []string) []string {
	if list := splitList(explicit); len(list) > 0 {
		return list
	}
	if len(agentIfs) > 0 {
		return agentIfs
	}
	route4, _ := os.ReadFile("/proc/net/route")
	route6, _ := os.ReadFile("/proc/net/ipv6_route")
	return defaultRouteInterfaces(string(route4), string(route6))
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// defaultRouteInterfaces returns the devices of the IPv4 and IPv6 default
// routes, from /proc/net/route and /proc/net/ipv6_route text, sorted.
func defaultRouteInterfaces(route4, route6 string) []string {
	seen := map[string]bool{}
	for i, line := range strings.Split(route4, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 8 {
			continue
		}
		if f[1] == "00000000" && f[7] == "00000000" && f[0] != "lo" {
			seen[f[0]] = true
		}
	}
	for _, line := range strings.Split(route6, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		if f[0] == strings.Repeat("0", 32) && f[1] == "00" && f[9] != "lo" {
			seen[f[9]] = true
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
