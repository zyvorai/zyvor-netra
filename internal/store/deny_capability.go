// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package store

import (
	"fmt"
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// AddDeniedCapability/DelDeniedCapability manage DeniedCapabilities — a
// plain string list, mirrored on allow_identity.go's
// AddAllowedProcess/DelAllowedProcess shape (dedup, sort, participate in
// the generic ruleIndex system). name must be one of the capabilities
// models.CapabilityBit knows about; callers (internal/api) are expected to
// validate that before calling, same convention as every other add
// mutator here.
func (s *Store) AddDeniedCapability(name, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.DeniedCapabilities {
		if x == name {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.DeniedCapabilities = append(s.config.DeniedCapabilities, name)
	sort.Strings(s.config.DeniedCapabilities)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.deny-capability.add", Target: name})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelDeniedCapability(name, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]string, 0, len(s.config.DeniedCapabilities))
	for _, x := range s.config.DeniedCapabilities {
		if x != name {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.DeniedCapabilities) {
		return cloneConfig(s.config), nil
	}
	s.config.DeniedCapabilities = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.deny-capability.delete", Target: name})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}
