// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"errors"
	"github.com/zyvorai/netra/internal/dnsdetect"
	"github.com/zyvorai/netra/internal/intel"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/scandetect"
	"github.com/zyvorai/netra/internal/securityreview"
	"net/http"
	"strconv"
	"time"
)

func (s *Server) securityOptimizer(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	writeJSON(w, 200, securityreview.Optimize(s.store.Config(), s.store.AgentStatuses(now, s.agentStaleAfter), now))
}
func (s *Server) securityIncidents(w http.ResponseWriter, _ *http.Request) {
	var dns []dnsdetect.Finding
	var scan []scandetect.Finding
	if s.dnsDetector != nil {
		dns = s.dnsDetector.Findings()
	}
	if s.scanDetector != nil {
		scan = s.scanDetector.Findings()
	}
	now := time.Now().UTC()
	writeJSON(w, 200, map[string]any{"result": securityreview.Correlate(s.store.AgentStatuses(now, s.agentStaleAfter), dns, scan, s.intelFeed.Entries(), now), "dnsEnabled": s.dnsDetector != nil, "scanEnabled": s.scanDetector != nil})
}
func (s *Server) intelHistory(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"feed": s.intelFeed.Status(), "revisions": s.intelFeed.History()})
}
func intelExpected(r *http.Request) (*uint64, error) {
	raw := r.Header.Get("X-Netra-Intel-Revision")
	if raw == "" {
		return nil, nil
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return nil, errors.New("X-Netra-Intel-Revision must be an unsigned integer")
	}
	return &n, nil
}
func intelWriteError(w http.ResponseWriter, err error) {
	code := http.StatusInsufficientStorage
	if errors.Is(err, intel.ErrConflict) {
		code = http.StatusConflict
	}
	errorJSON(w, code, err.Error())
}
func (s *Server) intelRollback(w http.ResponseWriter, r *http.Request) {
	rev, err := strconv.ParseUint(r.PathValue("revision"), 10, 64)
	if err != nil || rev == 0 {
		errorJSON(w, 400, "revision must be a positive integer")
		return
	}
	expected, err := intelExpected(r)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	st, err := s.intelFeed.Rollback(rev, expected)
	if err != nil {
		if errors.Is(err, intel.ErrConflict) {
			errorJSON(w, 409, err.Error())
		} else {
			errorJSON(w, 400, err.Error())
		}
		return
	}
	recorded := s.store.AddAudit(models.AuditEvent{At: time.Now().UTC(), Actor: actor(r), Action: "intel.rollback", Target: strconv.FormatUint(st.Revision, 10), Details: map[string]any{"restoredRevision": rev}}) == nil
	writeJSON(w, 200, map[string]any{"feed": st, "autoApplied": false, "auditRecorded": recorded})
}
