// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package store

import (
	"fmt"
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func (s *Store) AddAllowed(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.AllowedIPv4 {
		if x == ip {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.AllowedIPv4 = append(s.config.AllowedIPv4, ip)
	sort.Strings(s.config.AllowedIPv4)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.allow.add", Target: ip})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelAllowed(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := s.config.AllowedIPv4[:0]
	for _, x := range s.config.AllowedIPv4 {
		if x != ip {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.AllowedIPv4) {
		return cloneConfig(s.config), nil
	}
	s.config.AllowedIPv4 = append([]string(nil), out...)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.allow.delete", Target: ip})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddAllowedIPv6(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.AllowedIPv6 {
		if x == ip {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.AllowedIPv6 = append(s.config.AllowedIPv6, ip)
	sort.Strings(s.config.AllowedIPv6)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.allow6.add", Target: ip})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelAllowedIPv6(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]string, 0, len(s.config.AllowedIPv6))
	for _, x := range s.config.AllowedIPv6 {
		if x != ip {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.AllowedIPv6) {
		return cloneConfig(s.config), nil
	}
	s.config.AllowedIPv6 = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.allow6.delete", Target: ip})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddAllowedCIDR(rule models.EBPFCIDRRule, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.AllowedCIDRs {
		if x == rule {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.AllowedCIDRs = append(s.config.AllowedCIDRs, rule)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.allow-cidr.add", Target: rule.CIDR, Details: map[string]any{"direction": rule.Direction}})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelAllowedCIDR(rule models.EBPFCIDRRule, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]models.EBPFCIDRRule, 0, len(s.config.AllowedCIDRs))
	for _, x := range s.config.AllowedCIDRs {
		if x != rule {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.AllowedCIDRs) {
		return cloneConfig(s.config), nil
	}
	s.config.AllowedCIDRs = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.allow-cidr.delete", Target: rule.CIDR, Details: map[string]any{"direction": rule.Direction}})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddBlockedIngress(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.BlockedIngressIPv4 {
		if x == ip {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.BlockedIngressIPv4 = append(s.config.BlockedIngressIPv4, ip)
	sort.Strings(s.config.BlockedIngressIPv4)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.deny-ingress.add", Target: ip})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelBlockedIngress(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]string, 0, len(s.config.BlockedIngressIPv4))
	for _, x := range s.config.BlockedIngressIPv4 {
		if x != ip {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.BlockedIngressIPv4) {
		return cloneConfig(s.config), nil
	}
	s.config.BlockedIngressIPv4 = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.deny-ingress.delete", Target: ip})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddBlockedIngressIPv6(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.BlockedIngressIPv6 {
		if x == ip {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.BlockedIngressIPv6 = append(s.config.BlockedIngressIPv6, ip)
	sort.Strings(s.config.BlockedIngressIPv6)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.deny-ingress6.add", Target: ip})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelBlockedIngressIPv6(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]string, 0, len(s.config.BlockedIngressIPv6))
	for _, x := range s.config.BlockedIngressIPv6 {
		if x != ip {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.BlockedIngressIPv6) {
		return cloneConfig(s.config), nil
	}
	s.config.BlockedIngressIPv6 = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.deny-ingress6.delete", Target: ip})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddAllowedPort(rule models.EBPFPortRule, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.AllowedPorts {
		if x == rule {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.AllowedPorts = append(s.config.AllowedPorts, rule)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.allow-port.add", Target: fmt.Sprintf("%s/%d", rule.Protocol, rule.Port), Details: map[string]any{"direction": rule.Direction}})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelAllowedPort(rule models.EBPFPortRule, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]models.EBPFPortRule, 0, len(s.config.AllowedPorts))
	for _, x := range s.config.AllowedPorts {
		if x != rule {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.AllowedPorts) {
		return cloneConfig(s.config), nil
	}
	s.config.AllowedPorts = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.allow-port.delete", Target: fmt.Sprintf("%s/%d", rule.Protocol, rule.Port), Details: map[string]any{"direction": rule.Direction}})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}
