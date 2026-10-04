// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/metricalert"
)

func authedDo(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer api-secret")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestMetricAlertsAPI(t *testing.T) {
	s, _ := metricsTestServer(t)
	eng, err := metricalert.New(metricalert.Options{
		Rules:   []metricalert.Rule{{Name: "cpu_hot", Context: "system.cpu", Lookup: "average -30s", Every: "1s", Warn: "$this > 10", Units: "%"}},
		Sources: s.metricsHub.Sources,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.WithMetricAlerts(eng)
	h := s.Handler()
	now := time.Now().Unix()
	if _, err := s.metricsHub.Ingest(cpuBatch("n1", now-60, now)); err != nil {
		t.Fatal(err)
	}
	eng.Evaluate(time.Unix(now, 0))

	code, body := authedGet(t, h, "/api/v1/metrics/alerts")
	if code != http.StatusOK {
		t.Fatalf("alerts %d %v", code, body)
	}
	active := body["active"].([]any)
	if len(active) != 1 || active[0].(map[string]any)["status"] != "warning" || active[0].(map[string]any)["rule"] != "cpu_hot" {
		t.Fatalf("active %v", active)
	}
	id := active[0].(map[string]any)["id"].(string)

	if rr := authedDo(t, h, http.MethodPost, "/api/v1/metrics/alerts/"+id+"/ack", ""); rr.Code != http.StatusOK {
		t.Fatalf("ack %d %s", rr.Code, rr.Body)
	}
	if rr := authedDo(t, h, http.MethodPost, "/api/v1/metrics/alerts/nope/ack", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("ack unknown %d", rr.Code)
	}
	if rr := authedDo(t, h, http.MethodPost, "/api/v1/metrics/alerts/silences", `{"duration":"1h"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("silence without matcher %d", rr.Code)
	}
	rr := authedDo(t, h, http.MethodPost, "/api/v1/metrics/alerts/silences", `{"rule":"cpu_*","duration":"2h","comment":"upgrade"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("silence %d %s", rr.Code, rr.Body)
	}
	var sil metricalert.Silence
	_ = json.Unmarshal(rr.Body.Bytes(), &sil)
	if sil.CreatedBy != "apikey" {
		t.Fatalf("createdBy %q", sil.CreatedBy)
	}
	_, body = authedGet(t, h, "/api/v1/metrics/alerts")
	if a := body["active"].([]any)[0].(map[string]any); a["silenced"] != true || a["acked"] != true {
		t.Fatalf("silenced/acked flags %v", a)
	}
	if rr := authedDo(t, h, http.MethodDelete, "/api/v1/metrics/alerts/silences/"+sil.ID, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("unsilence %d", rr.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/metrics/alerts/silences", strings.NewReader(`{"rule":"x","duration":"1h"}`))
	unauth := httptest.NewRecorder()
	h.ServeHTTP(unauth, req)
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated silence %d", unauth.Code)
	}
}

func TestMetricAlertsDisabled(t *testing.T) {
	_, h := metricsTestServer(t)
	if code, _ := authedGet(t, h, "/api/v1/metrics/alerts"); code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", code)
	}
}
