// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package store

import (
	"fmt"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func (s *Store) Baseline() models.BehaviorBaseline {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneBaseline(s.baseline)
}

func (s *Store) SetBaseline(b models.BehaviorBaseline, actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := cloneBaseline(s.baseline)
	auditLen := len(s.audit)
	b.CapturedAt = b.CapturedAt.UTC()
	s.baseline = cloneBaseline(b)
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "insights.baseline.capture", Target: "behavior", Details: map[string]any{"entries": len(b.Entries)}})
	if err := s.persistLocked(); err != nil {
		s.baseline = before
		s.audit = s.audit[:auditLen]
		return fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return nil
}

func (s *Store) ClearBaseline(actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := cloneBaseline(s.baseline)
	auditLen := len(s.audit)
	s.baseline = models.BehaviorBaseline{}
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "insights.baseline.clear", Target: "behavior"})
	if err := s.persistLocked(); err != nil {
		s.baseline = before
		s.audit = s.audit[:auditLen]
		return fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return nil
}

func cloneBaseline(in models.BehaviorBaseline) models.BehaviorBaseline {
	out := in
	out.Entries = append([]models.BehaviorBaselineEntry(nil), in.Entries...)
	return out
}
