// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

const denyImportMaxEntries = 1000

var (
	errInvalidIP             = errors.New("a valid IPv4 or IPv6 address is required")
	errInvalidCIDR           = errors.New("valid IPv4 or IPv6 CIDR required")
	errInvalidDirection      = errors.New("direction must be egress, ingress, or both")
	errUnknownDenyImportType = errors.New(`type must be one of "ip", "cidr", "dns", "sni"`)
)

type denyImportEntry struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Direction string `json:"direction,omitempty"`
}

type denyImportRequest struct {
	Entries []denyImportEntry `json:"entries"`
}

type denyImportResult struct {
	Index int    `json:"index"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// ebpfDenyImport bulk-populates the existing exact-IP/CIDR/DNS/SNI deny
// primitives from an operator-supplied list. It adds no new validation or
// detection logic — every entry is dispatched through the exact same
// per-type validator and store Add function the single-rule handlers above
// already use. Partial success is expected and reported per entry, not
// all-or-nothing, since a large operator-supplied list realistically
// contains some bad lines.
func (s *Server) ebpfDenyImport(w http.ResponseWriter, r *http.Request) {
	var x denyImportRequest
	if err := decodeJSON(r, &x, 1<<20); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if len(x.Entries) == 0 {
		errorJSON(w, 400, "entries must not be empty")
		return
	}
	if len(x.Entries) > denyImportMaxEntries {
		errorJSON(w, 400, "at most 1000 entries per import")
		return
	}
	act := actor(r)
	results := make([]denyImportResult, len(x.Entries))
	var cfg models.EBPFFastPathConfig
	applied, failed := 0, 0
	for i, e := range x.Entries {
		res := denyImportResult{Index: i}
		newCfg, err := s.applyDenyImportEntry(e, act)
		if err != nil {
			res.Error = err.Error()
			failed++
		} else {
			res.OK = true
			cfg = newCfg
			applied++
		}
		results[i] = res
	}
	writeJSON(w, 200, map[string]any{"results": results, "applied": applied, "failed": failed, "config": cfg})
}

func (s *Server) applyDenyImportEntry(e denyImportEntry, actor string) (models.EBPFFastPathConfig, error) {
	switch strings.ToLower(strings.TrimSpace(e.Type)) {
	case "ip":
		a, err := netip.ParseAddr(strings.TrimSpace(e.Value))
		if err != nil {
			return models.EBPFFastPathConfig{}, errInvalidIP
		}
		dir, ok := normalizeDirection(e.Direction)
		if !ok {
			return models.EBPFFastPathConfig{}, errInvalidDirection
		}
		var cfg models.EBPFFastPathConfig
		if dir == "egress" || dir == "both" {
			if a.Is4() {
				cfg, err = s.store.AddBlocked(a.String(), actor)
			} else {
				cfg, err = s.store.AddBlockedIPv6(a.String(), actor)
			}
			if err != nil {
				return cfg, err
			}
		}
		if dir == "ingress" || dir == "both" {
			if a.Is4() {
				cfg, err = s.store.AddBlockedIngress(a.String(), actor)
			} else {
				cfg, err = s.store.AddBlockedIngressIPv6(a.String(), actor)
			}
		}
		return cfg, err
	case "cidr":
		p, err := netip.ParsePrefix(strings.TrimSpace(e.Value))
		if err != nil {
			return models.EBPFFastPathConfig{}, errInvalidCIDR
		}
		dir, ok := normalizeDirection(e.Direction)
		if !ok {
			return models.EBPFFastPathConfig{}, errInvalidDirection
		}
		return s.store.AddCIDR(models.EBPFCIDRRule{CIDR: p.Masked().String(), Direction: dir}, actor)
	case "dns":
		name, err := normalizeDNSName(e.Value)
		if err != nil {
			return models.EBPFFastPathConfig{}, err
		}
		return s.store.AddDNS(name, actor)
	case "sni":
		name, err := normalizeDNSName(e.Value)
		if err != nil {
			return models.EBPFFastPathConfig{}, err
		}
		return s.store.AddSNI(name, actor)
	default:
		return models.EBPFFastPathConfig{}, errUnknownDenyImportType
	}
}
