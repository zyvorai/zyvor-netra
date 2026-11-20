// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package store

import (
	"fmt"
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// Node isolation (docs/node-isolation.md) is per-node operator state, like a
// capture session, but persisted: a shadow policy is a long-running review.
// Enforce is never resurrected from disk (see load) and always has a lease.

func cloneNodeIsolation(in models.NodeIsolationSpec) models.NodeIsolationSpec {
	out := in
	out.Rules = append([]models.NodeIsolationRule(nil), in.Rules...)
	out.ExemptLocalPorts = append([]uint16(nil), in.ExemptLocalPorts...)
	if in.LeaseUntil != nil {
		t := *in.LeaseUntil
		out.LeaseUntil = &t
	}
	return out
}

// expireNodeIsolationLocked demotes enforce entries whose lease has lapsed.
// It reports whether anything changed (the caller persists).
func (s *Store) expireNodeIsolationLocked(now time.Time) bool {
	changed := false
	for node, spec := range s.nodeIsolation {
		if spec.Mode != models.NodeIsolationEnforce || spec.LeaseUntil == nil || now.Before(*spec.LeaseUntil) {
			continue
		}
		spec.Mode = models.NodeIsolationShadow
		spec.LeaseUntil = nil
		s.nodeIsolationRev++
		spec.Revision = s.nodeIsolationRev
		spec.UpdatedAt = now.UTC()
		s.nodeIsolation[node] = spec
		s.appendAuditLocked(models.AuditEvent{At: now.UTC(), Actor: "system", Action: "ebpf.node-isolation.lease-expired", Target: node, Details: map[string]any{"policyId": spec.PolicyID}})
		changed = true
	}
	return changed
}

// SetNodeIsolation creates or replaces node's policy. Revision is a
// controller-wide counter so an agent can never confuse two policies.
func (s *Store) SetNodeIsolation(spec models.NodeIsolationSpec, actor string) (models.NodeIsolationSpec, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	before, had := s.nodeIsolation[spec.Node]
	auditLen := len(s.audit)
	s.nodeIsolationRev++
	spec.Revision = s.nodeIsolationRev
	spec.Requestor = actor
	spec.UpdatedAt = now
	if spec.Mode != models.NodeIsolationEnforce {
		spec.LeaseUntil = nil
	}
	s.nodeIsolation[spec.Node] = cloneNodeIsolation(spec)
	details := map[string]any{"policyId": spec.PolicyID, "mode": spec.Mode, "rules": len(spec.Rules), "revision": spec.Revision}
	if spec.LeaseUntil != nil {
		details["leaseUntil"] = spec.LeaseUntil.UTC()
	}
	s.appendAuditLocked(models.AuditEvent{At: now, Actor: actor, Action: "ebpf.node-isolation.set", Target: spec.Node, Details: details})
	if err := s.persistLocked(); err != nil {
		if had {
			s.nodeIsolation[spec.Node] = before
		} else {
			delete(s.nodeIsolation, spec.Node)
		}
		s.audit = s.audit[:auditLen]
		return models.NodeIsolationSpec{}, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneNodeIsolation(spec), nil
}

// ClearNodeIsolation removes node's policy and reports whether one existed.
func (s *Store) ClearNodeIsolation(node, actor string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, ok := s.nodeIsolation[node]
	if !ok {
		return false, nil
	}
	auditLen := len(s.audit)
	delete(s.nodeIsolation, node)
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.node-isolation.clear", Target: node, Details: map[string]any{"policyId": before.PolicyID}})
	if err := s.persistLocked(); err != nil {
		s.nodeIsolation[node] = before
		s.audit = s.audit[:auditLen]
		return false, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return true, nil
}

// NodeIsolation returns node's current policy (after lease expiry), or nil.
func (s *Store) NodeIsolation(node string) *models.NodeIsolationSpec {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expireNodeIsolationLocked(time.Now()) {
		_ = s.persistLocked()
	}
	spec, ok := s.nodeIsolation[node]
	if !ok {
		return nil
	}
	out := cloneNodeIsolation(spec)
	return &out
}

// NodeIsolations lists every node policy, sorted by node.
func (s *Store) NodeIsolations() []models.NodeIsolationSpec {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expireNodeIsolationLocked(time.Now()) {
		_ = s.persistLocked()
	}
	out := make([]models.NodeIsolationSpec, 0, len(s.nodeIsolation))
	for _, spec := range s.nodeIsolation {
		out = append(out, cloneNodeIsolation(spec))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}
