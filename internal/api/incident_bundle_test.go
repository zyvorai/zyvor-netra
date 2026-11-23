// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/incidentbundle"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/store"
)

func bundleServer(t *testing.T, now time.Time) *Server {
	t.Helper()
	st := store.New()
	st.Report(models.AgentReport{Node: "worker-1", Mode: "observe", ObservedAt: now, Interfaces: []string{"eth0"},
		DNSHealth:    []models.DNSHealthStat{{Name: "api.example.com", Queries: 3, Failures: 1}},
		HTTPMetadata: []models.HTTPMetadataStat{{Method: "GET", Host: "svc.example.com/admin?token=hunter2-SECRET", Requests: 2}},
		Netlink:      &models.NetlinkReport{Available: true, Epoch: 1, Sequence: 1, Cursor: 1, Events: []models.NetlinkEvent{nlEvent(1, "route", "new", now.Add(-5*time.Minute))}},
		BPFAttach:    &models.BPFAttachReport{Available: true, ObservedAt: now, Interfaces: []models.BPFInterfaceAttach{{Name: "eth0", XDP: &models.BPFProgram{ID: 5, Name: "netra_xdp", Owner: "netra"}}}}})
	st.Report(models.AgentReport{Node: "worker-2", ObservedAt: now})
	if err := st.AddAudit(models.AuditEvent{At: now.Add(-2 * time.Minute), Actor: "alice", Action: "ebpf.mode", Details: map[string]any{"mode": "observe", "password": "hunter2-SECRET", "body": "payload"}}); err != nil {
		t.Fatal(err)
	}
	return &Server{store: st, agentStaleAfter: time.Minute, metricsData: &telemetry{}}
}

func getBundle(t *testing.T, s *Server, q string, hdr ...string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/v1/incident/bundle"+q, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	s.incidentBundle(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func TestIncidentBundleEndpoint(t *testing.T) {
	now := time.Now().UTC()
	s := bundleServer(t, now)
	code, body := getBundle(t, s, "?minutes=30")
	if code != 200 {
		t.Fatalf("code %d: %s", code, body)
	}
	if rep := incidentbundle.VerifyFile(body); !rep.OK {
		t.Fatalf("endpoint bundle fails verify: %v", rep.Problems)
	}
	if strings.Contains(string(body), "hunter2-SECRET") {
		t.Fatal("a planted secret reached the bundle")
	}
	var doc incidentbundle.Bundle
	_ = json.Unmarshal(body, &doc)
	if doc.Schema != incidentbundle.Schema || doc.Identity.Version != controllerVersion || doc.Identity.Nodes != 2 || doc.Window.Minutes != 30 {
		t.Fatalf("envelope %+v", doc)
	}
	if !strings.Contains(string(doc.Sections[incidentbundle.SecNetwork]), `"kind":"route"`) || !strings.Contains(string(doc.Sections[incidentbundle.SecAudit]), "alice") {
		t.Fatalf("sections missing content")
	}
	// disabled stores are reported, not silently absent
	if !strings.Contains(string(doc.Sections[incidentbundle.SecMetrics]), "metrics platform disabled") || !strings.Contains(string(doc.Sections[incidentbundle.SecInsights]), "metric alerts are disabled") {
		t.Fatalf("gaps not stated")
	}

	code, body = getBundle(t, s, "?minutes=30&node=worker-2&exclude=audit,flows&mask_ips=prefix", "X-Netra-Mask-Key", "k1")
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	_ = json.Unmarshal(body, &doc)
	if doc.Identity.Scope != "node" || doc.Identity.Nodes != 1 || doc.Redaction.MaskIPs != "prefix" || len(doc.Redaction.ExcludedSections) != 2 || doc.Redaction.MaskKeyID == "" {
		t.Fatalf("scoped bundle %+v", doc)
	}
	_, again := getBundle(t, s, "?minutes=30&node=worker-2&exclude=audit,flows&mask_ips=prefix", "X-Netra-Mask-Key", "k1")
	var d2 incidentbundle.Bundle
	_ = json.Unmarshal(again, &d2)
	if d2.Redaction.MaskKeyID != doc.Redaction.MaskKeyID {
		t.Fatal("same mask key gave a different key id")
	}
}

func TestIncidentBundleRejectsBadInput(t *testing.T) {
	s := bundleServer(t, time.Now().UTC())
	for _, q := range []string{"?minutes=0", "?minutes=1441", "?minutes=abc", "?minutes=-5", "?node=../../etc", "?node=a%20b", "?node=" + strings.Repeat("a", 300),
		"?exclude=nope", "?exclude=audit,,x", "?mask_ips=maybe"} {
		if code, _ := getBundle(t, s, q); code != 400 {
			t.Errorf("%s accepted: %d", q, code)
		}
	}
	if code, _ := getBundle(t, s, "", "X-Netra-Mask-Key", strings.Repeat("k", 129)); code != 400 {
		t.Error("oversized mask key accepted")
	}
	if code, _ := getBundle(t, s, ""); code != 200 {
		t.Error("defaults rejected")
	}
}

func TestIncidentBundleNeedsUnscopedRole(t *testing.T) {
	s := bundleServer(t, time.Now().UTC())
	req := httptest.NewRequest("GET", "/api/v1/incident/bundle", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalKey{}, principal{Namespaces: []string{"team-a"}}))
	rec := httptest.NewRecorder()
	s.incidentBundle(rec, req)
	if rec.Code != 403 {
		t.Fatalf("namespace-scoped principal got %d", rec.Code)
	}
}
