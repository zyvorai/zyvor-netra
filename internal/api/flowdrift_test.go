// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/flowdrift"
	"github.com/zyvorai/netra/internal/incidentbundle"
	"github.com/zyvorai/netra/internal/models"
)

func driftGet(t *testing.T, s *Server, path string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	rec := httptest.NewRecorder()
	if strings.Contains(path, "volume-shift") {
		s.volumeShift(rec, req)
	} else {
		s.dependencyDrift(rec, req)
	}
	return rec.Code, rec.Body.Bytes()
}

func TestDependencyDriftEndpoint(t *testing.T) {
	s := bundleServer(t, time.Now().UTC())
	code, body := driftGet(t, s, "/api/v1/insights/dependency-drift?recent=30m&baseline=6h")
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	var rep flowdrift.Report
	if err := json.Unmarshal(body, &rep); err != nil || rep.Schema != flowdrift.Schema {
		t.Fatalf("%v %s", err, body)
	}
	// A fresh store has no history before the recent window, so it is not ready and says so.
	if rep.Ready || rep.NotReady == "" || len(rep.NewEdges) != 0 {
		t.Fatalf("%+v", rep)
	}
	for _, bad := range []string{"?recent=nonsense", "?recent=1s", "?recent=500h", "?baseline=30m", "?baseline=9999h", "?min_baseline=0s"} {
		if code, _ := driftGet(t, s, "/api/v1/insights/dependency-drift"+bad); code != 400 {
			t.Errorf("%s: %d", bad, code)
		}
	}
	for _, bad := range []string{"?factor=1", "?factor=x", "?min_bytes=0", "?min_bytes=-1"} {
		if code, _ := driftGet(t, s, "/api/v1/insights/volume-shift"+bad); code != 400 {
			t.Errorf("%s: %d", bad, code)
		}
	}
	code, body = driftGet(t, s, "/api/v1/insights/volume-shift?factor=2&min_bytes=1")
	var sh flowdrift.ShiftReport
	if code != 200 || json.Unmarshal(body, &sh) != nil || sh.Schema != flowdrift.ShiftSchema || sh.Factor != 2 || sh.MinBytes != 1 {
		t.Fatalf("%d %s", code, body)
	}
}

func incBundle(t *testing.T) []byte {
	t.Helper()
	s := bundleServer(t, time.Now().UTC())
	code, body := getBundle(t, s, "?minutes=30")
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	return body
}

func TestIncidentVerifyReportAndSealEndpoints(t *testing.T) {
	bundle := incBundle(t)
	s := bundleServer(t, time.Now().UTC())

	do := func(path, body string, hdr ...string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		rec := httptest.NewRecorder()
		switch {
		case strings.Contains(path, "verify"):
			s.incidentVerify(rec, req)
		default:
			s.incidentReport(rec, req)
		}
		return rec
	}

	rec := do("/api/v1/incident/verify", string(bundle))
	var v struct {
		Verify incidentbundle.VerifyReport `json:"verify"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &v) != nil || !v.Verify.OK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// The MCP wrapper form (bundle as a string) verifies too.
	wrapped, _ := json.Marshal(map[string]any{"bundle": string(bundle)})
	if rec := do("/api/v1/incident/verify", string(wrapped)); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// A tampered bundle is reported, not accepted.
	bad := strings.Replace(string(bundle), `"mode":"observe"`, `"mode":"enforce"`, 1)
	if rec := do("/api/v1/incident/verify", bad); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok":false`) {
		t.Fatalf("tamper not detected: %d %s", rec.Code, rec.Body)
	}
	if rec := do("/api/v1/incident/verify", ""); rec.Code != 400 {
		t.Fatalf("%d", rec.Code)
	}

	rec = do("/api/v1/incident/report", string(bundle))
	var rep incidentbundle.Report
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &rep) != nil || rep.Schema != incidentbundle.ReportSchema {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := do("/api/v1/incident/report?format=markdown", string(bundle)); rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/markdown") || !strings.Contains(rec.Body.String(), "#") {
		t.Fatalf("%d %q", rec.Code, rec.Header())
	}
	if rec := do("/api/v1/incident/report?format=pdf", string(bundle)); rec.Code != 400 {
		t.Fatalf("%d", rec.Code)
	}
	if rec := do("/api/v1/incident/report", bad); rec.Code != 422 {
		t.Fatalf("a bundle that does not verify must not yield a report: %d %s", rec.Code, rec.Body)
	}

	// Seal: refused without a controller key; with one, the header verifies server-side.
	t.Setenv(sealKeyEnv, "")
	if code, body := getBundle(t, s, "?minutes=30&seal=true"); code != 400 || !strings.Contains(string(body), sealKeyEnv) {
		t.Fatalf("seal without a key: %d %s", code, body)
	}
	if rec := do("/api/v1/incident/verify", string(bundle), "X-Netra-Incident-Seal", "{}"); rec.Code != 400 {
		t.Fatalf("seal check without a key: %d", rec.Code)
	}
	key := "0123456789abcdef-secret-key"
	t.Setenv(sealKeyEnv, key)
	req := httptest.NewRequest("GET", "/api/v1/incident/bundle?minutes=30&seal=true", nil)
	rr := httptest.NewRecorder()
	s.incidentBundle(rr, req)
	seal := rr.Header().Get("X-Netra-Incident-Seal")
	if rr.Code != 200 || seal == "" || strings.Contains(seal, key) || strings.Contains(rr.Body.String(), key) {
		t.Fatalf("%d seal=%q", rr.Code, seal)
	}
	rec = do("/api/v1/incident/verify", rr.Body.String(), "X-Netra-Incident-Seal", seal)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"seal":{"checked":true,"ok":true}`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// Another bundle (different window head) does not match this seal.
	other := incBundleAt(t, s)
	rec = do("/api/v1/incident/verify", string(other), "X-Netra-Incident-Seal", seal)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok":false`) {
		t.Fatalf("seal for a different bundle must fail: %d %s", rec.Code, rec.Body)
	}
	_ = models.AgentReport{}
}

func incBundleAt(t *testing.T, s *Server) []byte {
	t.Helper()
	time.Sleep(1100 * time.Millisecond)
	code, body := getBundle(t, s, "?minutes=45")
	if code != 200 {
		t.Fatal(code)
	}
	return body
}
