// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package store

import (
	"fmt"
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func (s *Store) AddAllowedUID(uid uint32, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.AllowedUIDs {
		if x == uid {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.AllowedUIDs = append(s.config.AllowedUIDs, uid)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.allow-uid.add", Target: fmt.Sprintf("%d", uid)})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelAllowedUID(uid uint32, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]uint32, 0, len(s.config.AllowedUIDs))
	for _, x := range s.config.AllowedUIDs {
		if x != uid {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.AllowedUIDs) {
		return cloneConfig(s.config), nil
	}
	s.config.AllowedUIDs = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.allow-uid.delete", Target: fmt.Sprintf("%d", uid)})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddAllowedProcess(name, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.AllowedProcesses {
		if x == name {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.AllowedProcesses = append(s.config.AllowedProcesses, name)
	sort.Strings(s.config.AllowedProcesses)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.allow-process.add", Target: name})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelAllowedProcess(name, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]string, 0, len(s.config.AllowedProcesses))
	for _, x := range s.config.AllowedProcesses {
		if x != name {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.AllowedProcesses) {
		return cloneConfig(s.config), nil
	}
	s.config.AllowedProcesses = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.allow-process.delete", Target: name})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}
