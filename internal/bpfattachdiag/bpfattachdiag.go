// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package bpfattachdiag compares what each agent believes it attached with what
// the kernel reports is attached (internal/bpfattach), and says where they
// differ.
//
// The agent resolves its interface list once and attaches with bpf_link, so a
// NIC or bond that is deleted and recreated, or a privileged detach, removes
// Netra's hook without any signal: the agent's own hook list still shows it. The
// traffic on that interface is then simply no longer observed. This is the
// blind spot this package exists to expose.
//
// The shape is the one every health-signal package uses (Build, then Anomalies),
// so findings reach the alert poller, incidents, the AI brief and the SIEM
// export through internal/health. Findings are level-triggered: they clear when
// the kernel shows the programs attached again. Subjects are the node.
package bpfattachdiag

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/bpfattach"
	"github.com/zyvorai/netra/internal/models"
)

const (
	KindHookMissing   = "bpf-netra-hook-missing"
	KindXDPReplaced   = "bpf-xdp-replaced"
	KindNoCoverage    = "bpf-no-interface-coverage"
	KindInventoryGap  = "bpf-inventory-unavailable"
	maxListed         = 3
	inventoryMaxStale = 3 * time.Minute
)

// hookSpec maps the hook names the agent records ("tcx-ingress:eth0") to the
// program that should be attached and where.
type hookSpec struct {
	program string
	egress  bool
	xdp     bool
}

var hookSpecs = map[string]hookSpec{
	"tcx-ingress":         {program: "netra_ingress"},
	"tcx-egress":          {program: "netra_egress", egress: true},
	"edge-tcx-ingress":    {program: "netra_edge_ingress"},
	"edge-tcx-egress":     {program: "netra_edge_egress", egress: true},
	"capture-tcx-ingress": {program: "netra_capture_ingress"},
	"capture-tcx-egress":  {program: "netra_capture_egress", egress: true},
	"xdp":                 {program: "netra_xdp_ingress", xdp: true},
	"xdp-shield":          {program: "netra_xdp_shield", xdp: true},
}

// expectedHook is one hook the agent believes it attached to one interface.
type expectedHook struct {
	hook, iface string
	spec        hookSpec
}

func expected(hooks []string) []expectedHook {
	var out []expectedHook
	for _, h := range hooks {
		name, iface, ok := strings.Cut(h, ":")
		if !ok || iface == "" {
			continue // cgroup and tracepoint hooks have no interface
		}
		if spec, known := hookSpecs[name]; known {
			out = append(out, expectedHook{hook: name, iface: iface, spec: spec})
		}
	}
	return out
}

// Build evaluates every fresh agent. now is explicit so the result is pure.
func Build(agents []models.AgentStatus, now time.Time) models.BPFAttachFindingsResponse {
	resp := models.BPFAttachFindingsResponse{ObservedAt: now.UTC(), Findings: []models.BPFAttachFinding{}}
	for _, a := range agents {
		inv := a.BPFAttach
		if a.Stale || inv == nil || !inv.Available {
			resp.Skipped++
			continue
		}
		resp.Evaluated++
		resp.Findings = append(resp.Findings, evaluate(a, inv, now)...)
	}
	rank := map[string]int{"critical": 3, "warning": 2, "info": 1}
	sort.SliceStable(resp.Findings, func(i, j int) bool {
		x, y := resp.Findings[i], resp.Findings[j]
		if rank[x.Severity] != rank[y.Severity] {
			return rank[x.Severity] > rank[y.Severity]
		}
		if x.Node != y.Node {
			return x.Node < y.Node
		}
		return x.Kind < y.Kind
	})
	return resp
}

// Anomalies converts findings to the shared health-anomaly shape.
func Anomalies(findings []models.BPFAttachFinding) []models.NetworkHealthAnomaly {
	out := make([]models.NetworkHealthAnomaly, 0, len(findings))
	for _, f := range findings {
		out = append(out, models.NetworkHealthAnomaly{
			Severity: f.Severity, Kind: f.Kind, Subject: f.Subject,
			SourceKey: "node:" + f.Node, Message: f.Message, Value: f.Value,
		})
	}
	return out
}

func evaluate(a models.AgentStatus, inv *models.BPFAttachReport, now time.Time) []models.BPFAttachFinding {
	var out []models.BPFAttachFinding
	f := func(sev, kind, msg string, value float64, ifs []string) {
		sort.Strings(ifs)
		out = append(out, models.BPFAttachFinding{Severity: sev, Kind: kind, Node: a.Node, Subject: a.Node, Message: msg, Value: value, Interfaces: ifs})
	}
	hooks := expected(a.Hooks)

	// An agent with no interface hooks at all sees cgroup-level traffic only.
	// Worth saying, because "attached: false" on four programs otherwise reads as
	// a fault when it is a configuration.
	if len(a.Interfaces) == 0 && len(a.XDPInterfaces) == 0 && len(hooks) == 0 {
		f("info", KindNoCoverage, "the agent has no interface-level (TCX/XDP) hooks: traffic is observed at the cgroup level only, so nothing is seen on a NIC or a host-network flow that does not belong to a cgroup. Set agent.interfaces to observe an interface.", 0, nil)
	}

	// The inventory is a snapshot; without one we cannot say a hook is gone.
	// (A report marked Unchanged whose list the controller could not restore has
	// no interfaces and no way to judge.)
	if inv.Unchanged {
		return out
	}
	if !inv.ObservedAt.IsZero() && now.Sub(inv.ObservedAt) > inventoryMaxStale {
		f("info", KindInventoryGap, fmt.Sprintf("the attachment inventory is %s old, so hook drift cannot be judged right now", now.Sub(inv.ObservedAt).Round(time.Second)), 0, nil)
		return out
	}

	byName := map[string]models.BPFInterfaceAttach{}
	for _, ia := range inv.Interfaces {
		byName[ia.Name] = ia
	}
	unreadable := map[string]bool{}
	for _, n := range inv.Failed {
		unreadable[n] = true
	}
	var missing, replaced []string
	var missingIfs, replacedIfs []string
	for _, h := range hooks {
		if unreadable[h.iface] {
			continue // the kernel refused the query: unknown, never "detached"
		}
		ia, found := byName[h.iface]
		// Not listed at all can also mean the inventory was capped: only judge
		// an absent interface when nothing was truncated.
		if !found && inv.Truncated > 0 {
			continue
		}
		if !h.spec.xdp && !inv.TCXSupported {
			continue // cannot list TCX on this kernel, so absence proves nothing
		}
		if h.spec.xdp {
			switch {
			case !found || ia.XDP == nil:
				missing = append(missing, fmt.Sprintf("%s on %s", h.hook, h.iface))
				missingIfs = append(missingIfs, h.iface)
			case !bpfattach.Same(h.spec.program, ia.XDP.Name):
				replaced = append(replaced, fmt.Sprintf("%s is now %s", h.iface, describe(*ia.XDP)))
				replacedIfs = append(replacedIfs, h.iface)
			}
			continue
		}
		list := ia.TCXIngress
		if h.spec.egress {
			list = ia.TCXEgress
		}
		if !found || !hasProgram(list, h.spec.program) {
			missing = append(missing, fmt.Sprintf("%s on %s", h.hook, h.iface))
			missingIfs = append(missingIfs, h.iface)
		}
	}
	if len(missing) > 0 {
		f("warning", KindHookMissing,
			fmt.Sprintf("Netra hook(s) the agent believes it attached are no longer attached: %s. The interface was probably deleted and recreated, or the program was detached; traffic on it is no longer observed until the agent restarts.", listed(missing)),
			float64(len(missing)), dedupe(missingIfs))
	}
	if len(replaced) > 0 {
		f("warning", KindXDPReplaced,
			fmt.Sprintf("the XDP program Netra attached was replaced by another: %s", listed(replaced)),
			float64(len(replaced)), dedupe(replacedIfs))
	}
	return out
}

func hasProgram(list []models.BPFProgram, program string) bool {
	for _, p := range list {
		if p.Owner == models.BPFOwnerNetra && bpfattach.Same(program, p.Name) {
			return true
		}
	}
	return false
}

func describe(p models.BPFProgram) string {
	name := p.Name
	if name == "" {
		name = fmt.Sprintf("program %d", p.ID)
	}
	return fmt.Sprintf("%s (%s)", name, p.Owner)
}

func listed(items []string) string {
	sort.Strings(items)
	if len(items) <= maxListed {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:maxListed], ", "), len(items)-maxListed)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
