// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/store"
)

func TestInsightsProtocolDowngradesWiring(t *testing.T) {
	s := &Server{store: store.New(), agentStaleAfter: time.Hour}
	if err := s.store.SetBaseline(insightsBaselineFixture(), "test"); err != nil {
		t.Fatal(err)
	}
	// Current state has no TLSMetadata at all — TLS activity has stopped
	// since baseline, which is the "warning" case.
	s.store.Report(models.AgentReport{Node: "n1", ObservedAt: time.Now(), HTTPMetadata: []models.HTTPMetadataStat{
		{Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api", Host: "svc.example.com", Method: "GET", Requests: 4},
	}})

	r := httptest.NewRequest("GET", "/api/v1/insights/protocol-downgrades", nil)
	rec := httptest.NewRecorder()
	s.insightsProtocolDowngrades(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out models.ProtocolDowngradeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 || out.Findings[0].Severity != "warning" {
		t.Fatalf("findings=%#v", out.Findings)
	}
}

func insightsBaselineFixture() models.BehaviorBaseline {
	return models.BehaviorBaseline{
		SchemaVersion: 1,
		CapturedAt:    time.Now().Add(-time.Hour),
		Entries: []models.BehaviorBaselineEntry{
			{Source: "workload:prod:deployment:api", Kind: "sni", Value: "svc.example.com", Count: 5},
		},
	}
}
