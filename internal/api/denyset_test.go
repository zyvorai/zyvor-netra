// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/leaserails"
	"github.com/zyvorai/netra/internal/store"
)

func dsServer(t *testing.T, cfg leaserails.Config) (*Server, http.Handler) {
	t.Helper()
	st := store.New()
	st.SetLeaseRails(cfg)
	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil)), apiKey: "k", metricsData: &telemetry{}, store: st}
	return s, s.Handler()
}

func dsCall(h http.Handler, method, path string, body any, hdr map[string]string) (int, map[string]any) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Authorization", "Bearer k")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func dsText(rules ...string) string {
	return "netra-denyset/1\nname: inc\nlease: 10m\n" + strings.Join(rules, "\n") + "\n"
}

func TestDenysetPlanApplyFlow(t *testing.T) {
	t.Setenv("NETRA_PROTECTED_DESTINATIONS", "")
	s, h := dsServer(t, leaserails.Config{})
	file := dsText("deny cidr 203.0.113.0/24 egress", "deny port tcp 445 ingress")
	code, plan := dsCall(h, "POST", "/api/v1/ebpf/denysets/plan", map[string]string{"file": file}, nil)
	if code != 200 {
		t.Fatalf("%d %v", code, plan)
	}
	hash, _ := plan["planHash"].(string)
	rcpt, _ := plan["receipt"].(map[string]any)
	if hash == "" || rcpt == nil || plan["risk"] != "high" {
		t.Fatalf("%v", plan)
	}
	token, _ := rcpt["token"].(string)
	// Plan must not have changed anything.
	if len(s.store.Config().BlockedCIDRs) != 0 {
		t.Fatal("plan applied")
	}
	// Missing token, wrong hash, missing risk confirm each refuse.
	body := map[string]string{"file": file, "planHash": hash}
	if c, o := dsCall(h, "POST", "/api/v1/ebpf/denysets/apply", body, nil); c != 428 || o["code"] != "plan_token_required" {
		t.Fatalf("%d %v", c, o)
	}
	if c, o := dsCall(h, "POST", "/api/v1/ebpf/denysets/apply", map[string]string{"file": file, "planHash": "deadbeef"}, map[string]string{"X-Netra-Plan-Token": token}); c != 409 || o["code"] != "plan_hash_mismatch" {
		t.Fatalf("%d %v", c, o)
	}
	if c, o := dsCall(h, "POST", "/api/v1/ebpf/denysets/apply", map[string]string{"file": file}, nil); c != 400 || o["code"] != "plan_hash_required" {
		t.Fatalf("%d %v", c, o)
	}
	if c, o := dsCall(h, "POST", "/api/v1/ebpf/denysets/apply", body, map[string]string{"X-Netra-Plan-Token": token}); c != 409 || o["code"] != "risk_confirm_required" {
		t.Fatalf("%d %v", c, o)
	}
	if len(s.store.Config().BlockedCIDRs) != 0 {
		t.Fatal("refused apply changed rules")
	}
	// The token was burned by the failed confirm: plan again.
	_, plan = dsCall(h, "POST", "/api/v1/ebpf/denysets/plan", map[string]string{"file": file}, nil)
	token = plan["receipt"].(map[string]any)["token"].(string)
	// A token for a different file does not apply this one.
	other := dsText("deny cidr 198.18.0.0/24 egress")
	_, oplan := dsCall(h, "POST", "/api/v1/ebpf/denysets/plan", map[string]string{"file": other}, nil)
	otoken := oplan["receipt"].(map[string]any)["token"].(string)
	if c, o := dsCall(h, "POST", "/api/v1/ebpf/denysets/apply", body, map[string]string{"X-Netra-Plan-Token": otoken, "X-Netra-Confirm-Risk": "high"}); c != 412 || o["code"] != "plan_token_invalid" {
		t.Fatalf("%d %v", c, o)
	}
	c, o := dsCall(h, "POST", "/api/v1/ebpf/denysets/apply", body, map[string]string{"X-Netra-Plan-Token": token, "X-Netra-Confirm-Risk": "high", "X-Netra-Actor": "alice"})
	if c != 200 || o["added"] != float64(2) {
		t.Fatalf("%d %v", c, o)
	}
	cfg := s.store.Config()
	if len(cfg.BlockedCIDRs) != 1 || len(cfg.BlockedPorts) != 1 || cfg.Mode != "observe" {
		t.Fatalf("%+v", cfg)
	}
	// Token is single use.
	if c, _ := dsCall(h, "POST", "/api/v1/ebpf/denysets/apply", body, map[string]string{"X-Netra-Plan-Token": token, "X-Netra-Confirm-Risk": "high"}); c == 200 {
		t.Fatal("token reused")
	}
	// Replan: unchanged, no receipt, apply is a no-op.
	_, plan2 := dsCall(h, "POST", "/api/v1/ebpf/denysets/plan", map[string]string{"file": file}, nil)
	if plan2["receipt"] != nil || plan2["summary"].(map[string]any)["unchanged"] != float64(2) {
		t.Fatalf("%v", plan2)
	}
	if c, o := dsCall(h, "POST", "/api/v1/ebpf/denysets/apply", map[string]string{"file": file, "planHash": plan2["planHash"].(string)}, nil); c != 200 || o["noop"] != true {
		t.Fatalf("%d %v", c, o)
	}
	// Views.
	c, o = dsCall(h, "GET", "/api/v1/ebpf/deny-leases", nil, nil)
	if items, _ := o["items"].([]any); c != 200 || len(items) != 2 {
		t.Fatalf("%d %v", c, o)
	}
	_, o = dsCall(h, "GET", "/api/v1/ebpf/deny-leases?within=1m&expiring=true", nil, nil)
	if items, _ := o["items"].([]any); len(items) != 0 {
		t.Fatalf("%v", o)
	}
	_, o = dsCall(h, "GET", "/api/v1/ebpf/deny-leases?within=11m&expiring=true", nil, nil)
	if items, _ := o["items"].([]any); len(items) != 2 {
		t.Fatalf("%v", o)
	}
	_, o = dsCall(h, "GET", "/api/v1/ebpf/deny-leases/history", nil, nil)
	ev, _ := o["items"].([]any)
	if len(ev) != 2 || ev[0].(map[string]any)["actor"] != "alice" || ev[0].(map[string]any)["action"] != "create" {
		t.Fatalf("%v", o)
	}
	if c, _ := dsCall(h, "GET", "/api/v1/ebpf/deny-leases/history?limit=0", nil, nil); c != 400 {
		t.Fatal(c)
	}
	if c, _ := dsCall(h, "GET", "/api/v1/ebpf/deny-leases?within=bogus", nil, nil); c != 400 {
		t.Fatal(c)
	}
}

func TestDenysetInvalidFileHasLineNumbers(t *testing.T) {
	_, h := dsServer(t, leaserails.Config{})
	c, o := dsCall(h, "POST", "/api/v1/ebpf/denysets/plan", map[string]string{"file": "netra-denyset/1\nname: a\nlease: 5m\ndeny cidr nope egress\nbogus\n"}, nil)
	errs, _ := o["errors"].([]any)
	if c != 422 || o["code"] != "denyset_invalid" || len(errs) != 2 || errs[0].(map[string]any)["line"] != float64(4) {
		t.Fatalf("%d %v", c, o)
	}
	if c, o := dsCall(h, "POST", "/api/v1/ebpf/denysets/plan", map[string]any{"file": "x", "extra": 1}, nil); c != 400 {
		t.Fatalf("%d %v", c, o)
	}
}

func TestDenysetRailsEndToEnd(t *testing.T) {
	t.Setenv("NETRA_PROTECTED_DESTINATIONS", "")
	s, h := dsServer(t, leaserails.Config{MaxDuration: 5 * time.Minute, BreakGlass: true})
	// Dry run reports the rail and issues no receipt.
	_, plan := dsCall(h, "POST", "/api/v1/ebpf/denysets/plan", map[string]string{"file": dsText("deny ip 203.0.113.9 egress")}, nil)
	rails := plan["rails"].(map[string]any)
	trips := rails["trips"].([]any)
	if plan["applicable"] != false || plan["receipt"] != nil || trips[0].(map[string]any)["code"] != leaserails.CodeMaxDuration {
		t.Fatalf("%v", plan)
	}
	f := "netra-denyset/1\nname: inc\nlease: 4m\n"
	// Catch-all: plan needs break-glass but still hands out a receipt.
	file := f + "deny cidr 0.0.0.0/0 egress\n"
	_, plan = dsCall(h, "POST", "/api/v1/ebpf/denysets/plan", map[string]string{"file": file}, nil)
	if plan["breakGlassRequired"] != true || plan["risk"] != "critical" || plan["receipt"] == nil {
		t.Fatalf("%v", plan)
	}
	hash := plan["planHash"].(string)
	// Applying without break-glass is refused with a stable code, audited, recorded.
	c, o := dsCall(h, "POST", "/api/v1/ebpf/denysets/apply", map[string]string{"file": file, "planHash": hash}, map[string]string{"X-Netra-Plan-Token": plan["receipt"].(map[string]any)["token"].(string), "X-Netra-Confirm-Risk": "critical"})
	if c != 422 || o["code"] != leaserails.CodeCatchAll {
		t.Fatalf("%d %v", c, o)
	}
	if len(s.store.Config().BlockedCIDRs) != 0 {
		t.Fatal("catch-all applied without break-glass")
	}
	found := false
	for _, e := range s.store.Audit(50) {
		if e.Action == "ebpf.denyset.rail.reject" {
			found = true
		}
	}
	if !found {
		t.Fatal("reject not audited")
	}
	// With break-glass it applies and the break-glass is audited.
	_, plan = dsCall(h, "POST", "/api/v1/ebpf/denysets/plan", map[string]string{"file": file, "breakGlass": "incident 4711 approved by oncall"}, nil)
	if plan["applicable"] != true {
		t.Fatalf("%v", plan)
	}
	c, o = dsCall(h, "POST", "/api/v1/ebpf/denysets/apply", map[string]string{"file": file, "planHash": hash, "breakGlass": "incident 4711 approved by oncall"}, map[string]string{"X-Netra-Plan-Token": plan["receipt"].(map[string]any)["token"].(string), "X-Netra-Confirm-Risk": "critical", "X-Netra-Actor": "bob"})
	if c != 200 || o["breakGlass"] != true {
		t.Fatalf("%d %v", c, o)
	}
	bg := false
	for _, e := range s.store.Audit(50) {
		if e.Action == "ebpf.denyset.breakglass" && e.Actor == "bob" {
			bg = true
		}
	}
	if !bg {
		t.Fatal("break-glass not audited")
	}
	// Status endpoint and metrics.
	_, st := dsCall(h, "GET", "/api/v1/ebpf/deny-leases/rails", nil, nil)
	if st["enabled"] != true || st["usage"].(map[string]any)["activeLeases"] != float64(1) {
		t.Fatalf("%v", st)
	}
	rec := httptest.NewRecorder()
	s.metrics(rec, httptest.NewRequest("GET", "/metrics", nil))
	for _, want := range []string{`netra_lease_rail_trips_total{code="lease_rail_catch_all"} 1`, "netra_deny_leases_active 1", "netra_deny_leases_expiring_soon 1", "netra_lease_rails_enabled 1", "netra_denyset_applies_total 1"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("metrics missing %q", want)
		}
	}
	// Mode lease rail.
	if c, o := dsCall(h, "PUT", "/api/v1/ebpf/mode?lease=30m", map[string]string{"mode": "enforce"}, nil); c != 422 || o["code"] != leaserails.CodeMaxDuration {
		t.Fatalf("%d %v", c, o)
	}
	if c, _ := dsCall(h, "PUT", "/api/v1/ebpf/mode?lease=4m", map[string]string{"mode": "enforce"}, nil); c != 200 {
		t.Fatal(c)
	}
}

func TestDenysetNoReceiptHeaderAndRailsDefaultOff(t *testing.T) {
	_, h := dsServer(t, leaserails.Config{})
	_, plan := dsCall(h, "POST", "/api/v1/ebpf/denysets/plan", map[string]string{"file": dsText("deny cidr 0.0.0.0/0 both")}, map[string]string{"X-Netra-No-Receipt": "1"})
	if plan["receipt"] != nil || plan["railsEnabled"] != false || plan["applicable"] != true {
		t.Fatalf("%v", plan)
	}
}

func TestDenysetLockoutLikelyIsCritical(t *testing.T) {
	t.Setenv("NETRA_PROTECTED_DESTINATIONS", "198.51.100.0/24")
	_, h := dsServer(t, leaserails.Config{})
	_, plan := dsCall(h, "POST", "/api/v1/ebpf/denysets/plan", map[string]string{"file": dsText("deny ip 198.51.100.7 egress")}, nil)
	if plan["risk"] != "critical" {
		t.Fatalf("%v", plan)
	}
	it := plan["items"].([]any)[0].(map[string]any)
	if it["lockout"].(map[string]any)["risk"] != "likely" {
		t.Fatalf("%v", it)
	}
}

func TestDenysetRoutesRBAC(t *testing.T) {
	_, h := dsServer(t, leaserails.Config{})
	req := httptest.NewRequest("POST", "/api/v1/ebpf/denysets/plan", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("unauthenticated plan allowed: %d", rec.Code)
	}
}
