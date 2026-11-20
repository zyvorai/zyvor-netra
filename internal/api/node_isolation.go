// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// Node isolation API (docs/node-isolation.md):
//
//	GET    /api/v1/ebpf/node-isolation              desired policy + agent status per node
//	PUT    /api/v1/ebpf/node-isolation/{node}       set shadow or enforce (?lease=15m)
//	DELETE /api/v1/ebpf/node-isolation/{node}       remove the node's policy
const (
	nodeIsolationMaxRules       = 64
	nodeIsolationMaxExempt      = 16
	nodeIsolationDefaultLease   = 15 * time.Minute
	nodeIsolationMaxLease       = time.Hour
	nodeIsolationMinLease       = time.Minute
	nodeIsolationDefaultSSHPort = 22
)

type nodeIsolationBody struct {
	PolicyID         string                     `json:"policyId"`
	Mode             string                     `json:"mode"`
	Rules            []models.NodeIsolationRule `json:"rules"`
	ExemptLocalPorts *[]uint16                  `json:"exemptLocalPorts"`
}

// validateNodeIsolation normalizes a request into a spec. A nil
// exemptLocalPorts keeps SSH (22) exempt; an explicit list replaces it.
func validateNodeIsolation(node string, x nodeIsolationBody, leaseRaw string, now time.Time) (models.NodeIsolationSpec, error) {
	spec := models.NodeIsolationSpec{Node: node, PolicyID: strings.TrimSpace(x.PolicyID), Mode: strings.ToLower(strings.TrimSpace(x.Mode))}
	if len(node) > 253 || strings.ContainsAny(node, "/ \t\r\n") {
		return spec, fmt.Errorf("invalid node name")
	}
	if len(spec.PolicyID) > 128 {
		return spec, fmt.Errorf("policyId is too long")
	}
	if spec.Mode != models.NodeIsolationShadow && spec.Mode != models.NodeIsolationEnforce {
		return spec, fmt.Errorf("mode must be shadow or enforce")
	}
	if len(x.Rules) == 0 || len(x.Rules) > nodeIsolationMaxRules {
		return spec, fmt.Errorf("rules must contain 1 to %d entries", nodeIsolationMaxRules)
	}
	for i, r := range x.Rules {
		p, err := netip.ParsePrefix(strings.TrimSpace(r.CIDR))
		if err != nil || p.Masked() != p {
			return spec, fmt.Errorf("rules[%d].cidr must be a canonical CIDR", i)
		}
		proto := strings.ToLower(strings.TrimSpace(r.Protocol))
		if proto == "any" {
			proto = ""
		}
		if proto != "" && proto != "tcp" && proto != "udp" {
			return spec, fmt.Errorf("rules[%d].protocol must be tcp, udp or any", i)
		}
		from, to := r.PortFrom, r.PortTo
		if to == 0 {
			to = from
		}
		if from > to || (from == 0 && to != 0) {
			return spec, fmt.Errorf("rules[%d] has an invalid port range", i)
		}
		spec.Rules = append(spec.Rules, models.NodeIsolationRule{CIDR: p.String(), Protocol: proto, PortFrom: from, PortTo: to})
	}
	if x.ExemptLocalPorts == nil {
		spec.ExemptLocalPorts = []uint16{nodeIsolationDefaultSSHPort}
	} else {
		if len(*x.ExemptLocalPorts) > nodeIsolationMaxExempt {
			return spec, fmt.Errorf("exemptLocalPorts allows at most %d ports", nodeIsolationMaxExempt)
		}
		seen := map[uint16]bool{}
		for _, port := range *x.ExemptLocalPorts {
			if port == 0 {
				return spec, fmt.Errorf("exemptLocalPorts must be 1-65535")
			}
			if !seen[port] {
				seen[port] = true
				spec.ExemptLocalPorts = append(spec.ExemptLocalPorts, port)
			}
		}
		sort.Slice(spec.ExemptLocalPorts, func(i, j int) bool { return spec.ExemptLocalPorts[i] < spec.ExemptLocalPorts[j] })
	}
	if spec.Mode == models.NodeIsolationEnforce {
		lease := nodeIsolationDefaultLease
		if leaseRaw != "" {
			d, err := time.ParseDuration(leaseRaw)
			if err != nil || d < nodeIsolationMinLease || d > nodeIsolationMaxLease {
				return spec, fmt.Errorf("lease must be a duration between %s and %s", nodeIsolationMinLease, nodeIsolationMaxLease)
			}
			lease = d
		}
		until := now.UTC().Add(lease)
		spec.LeaseUntil = &until
	}
	return spec, nil
}

// nodeIsolationItem joins the desired policy with what the node's agent
// reports. Fields are flat so a consumer (Duvora) can read them directly.
type nodeIsolationItem struct {
	models.NodeIsolationSpec
	EffectiveMode     string                     `json:"effectiveMode"`
	AppliedRevision   uint64                     `json:"appliedRevision,omitempty"`
	Demoted           string                     `json:"demoted,omitempty"`
	AgentStale        bool                       `json:"agentStale"`
	Unavailable       string                     `json:"unavailable,omitempty"`
	Attached          []string                   `json:"attached,omitempty"`
	AllowedPackets    uint64                     `json:"allowedPackets"`
	WouldBlockPackets uint64                     `json:"wouldBlockPackets"`
	WouldBlockBytes   uint64                     `json:"wouldBlockBytes"`
	BlockedPackets    uint64                     `json:"blockedPackets"`
	BlockedBytes      uint64                     `json:"blockedBytes"`
	ExemptPackets     uint64                     `json:"exemptPackets"`
	Top               []models.NodeIsolationDest `json:"top,omitempty"`
}

func (s *Server) nodeIsolationList(w http.ResponseWriter, r *http.Request) {
	statuses := map[string]models.AgentStatus{}
	for _, a := range s.store.AgentStatuses(time.Now(), s.agentStaleAfter) {
		statuses[a.Node] = a
	}
	items := []nodeIsolationItem{}
	for _, spec := range s.store.NodeIsolations() {
		item := nodeIsolationItem{NodeIsolationSpec: spec, AgentStale: true}
		if a, ok := statuses[spec.Node]; ok {
			item.AgentStale = a.Stale
			if st := a.NodeIsolation; st != nil {
				item.Unavailable, item.Attached, item.Demoted = st.Unavailable, st.Attached, st.Demoted
				item.AllowedPackets, item.ExemptPackets = st.Allowed, st.Exempt
				item.WouldBlockPackets, item.WouldBlockBytes = st.WouldBlock, st.WouldBlockBytes
				item.BlockedPackets, item.BlockedBytes, item.Top = st.Blocked, st.BlockedBytes, st.Top
				if st.PolicyID == spec.PolicyID {
					item.EffectiveMode, item.AppliedRevision = st.Mode, st.Revision
				}
			} else {
				item.Unavailable = "agent does not report node isolation"
			}
		}
		items = append(items, item)
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) nodeIsolationSet(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimSpace(r.PathValue("node"))
	if node == "" {
		errorJSON(w, 400, "node is required")
		return
	}
	var x nodeIsolationBody
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	spec, err := validateNodeIsolation(node, x, strings.TrimSpace(r.URL.Query().Get("lease")), time.Now())
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	saved, err := s.store.SetNodeIsolation(spec, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist node isolation: "+err.Error())
		return
	}
	writeJSON(w, 200, saved)
}

func (s *Server) nodeIsolationClear(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimSpace(r.PathValue("node"))
	ok, err := s.store.ClearNodeIsolation(node, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist node isolation: "+err.Error())
		return
	}
	if !ok {
		errorJSON(w, 404, "no node isolation on "+node)
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": node})
}
