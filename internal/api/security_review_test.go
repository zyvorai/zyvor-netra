// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityAndIntelLifecycleAuthenticatedRoutes(t *testing.T) {
	s := testExportServer(t)
	h := s.Handler()
	for _, path := range []string{"/api/v1/security/optimizer", "/api/v1/security/incidents", "/api/v1/intel/history", "/api/v1/intel/rollback/1"} {
		method := "GET"
		if strings.Contains(path, "rollback") {
			method = "POST"
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: %d", path, rec.Code)
		}
	}
	send := func(method, path, body, revision string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer ci-test-token")
		if revision != "" {
			r.Header.Set("X-Netra-Intel-Revision", revision)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	for _, path := range []string{"/api/v1/security/optimizer", "/api/v1/security/incidents", "/api/v1/intel/history"} {
		if rec := send("GET", path, "", ""); rec.Code != 200 {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
	r := send("PUT", "/api/v1/intel/feed?ttl=1h", "192.0.2.1", "0")
	if r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	var out map[string]any
	json.Unmarshal(r.Body.Bytes(), &out)
	if out["autoApplied"] != false || out["auditRecorded"] != true {
		t.Fatal(out)
	}
	if r = send("PUT", "/api/v1/intel/feed", "192.0.2.2", "0"); r.Code != 409 {
		t.Fatal(r.Body.String())
	}
	if r = send("POST", "/api/v1/intel/rollback/1", "", "0"); r.Code != 409 {
		t.Fatal(r.Body.String())
	}
	if r = send("POST", "/api/v1/intel/rollback/1", "", "1"); r.Code != 200 || s.intelFeed.Status().Revision != 2 {
		t.Fatal(r.Body.String())
	}
	if r = send("DELETE", "/api/v1/intel/feed", "", "1"); r.Code != 409 {
		t.Fatal(r.Body.String())
	}
	if r = send("DELETE", "/api/v1/intel/feed", "", "2"); r.Code != 200 || s.intelFeed.Status().Count != 0 {
		t.Fatal(r.Body.String())
	}
	if s.store.Config().Mode != "observe" || len(s.store.Config().BlockedIPv4) != 0 {
		t.Fatal("feed write changed enforcement")
	}
}
func TestIntelFeedInputLimits(t *testing.T) {
	s := testExportServer(t)
	for _, tc := range []struct {
		path, body, rev string
		code            int
	}{
		{"/api/v1/intel/feed", strings.Repeat("x", (1<<20)+1), "", 413},
		{"/api/v1/intel/feed?ttl=-1h", "192.0.2.1", "", 400},
		{"/api/v1/intel/feed?ttl=721h", "192.0.2.1", "", 400},
		{"/api/v1/intel/feed", "192.0.2.1", "wrong", 400},
	} {
		r := httptest.NewRequest("PUT", tc.path, strings.NewReader(tc.body))
		r.Header.Set("X-Netra-Intel-Revision", tc.rev)
		w := httptest.NewRecorder()
		s.intelFeedPut(w, r)
		if w.Code != tc.code || s.intelFeed.Status().Revision != 0 {
			t.Fatalf("code=%d state=%+v", w.Code, s.intelFeed.Status())
		}
	}
}
