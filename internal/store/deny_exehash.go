// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package store

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// AddBlockedExeHash appends a lowercase hex SHA-256 digest. Lease/enforce
// gating is in the datapath (exehash_pids only consulted while enforcing).
func (s *Store) AddBlockedExeHash(hash, actor string) (models.EBPFFastPathConfig, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.BlockedExeHashes {
		if x == hash {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.BlockedExeHashes = append(s.config.BlockedExeHashes, hash)
	sort.Strings(s.config.BlockedExeHashes)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.exehash.add", Target: hash})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelBlockedExeHash(hash, actor string) (models.EBPFFastPathConfig, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]string, 0, len(s.config.BlockedExeHashes))
	for _, x := range s.config.BlockedExeHashes {
		if x != hash {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.BlockedExeHashes) {
		return cloneConfig(s.config), nil
	}
	s.config.BlockedExeHashes = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.exehash.delete", Target: hash})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}
