// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/oidcauth"
	"github.com/zyvorai/netra/internal/store"
)

func nodeIsoServer(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	t.Setenv("NETRA_API_KEY", "")
	t.Setenv("NETRA_AGENT_KEY", "")
	t.Setenv("NETRA_METRICS_TOKEN", "")
	st := store.New()
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, st).Handler(), st
}

func do(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	h.ServeHTTP(rec, httptest.NewRequest(method, path, r))
	return rec
}

func TestNodeIsolationValidation(t *testing.T) {
	now := time.Now()
	ok := func(x nodeIsolationBody, lease string) models.NodeIsolationSpec {
		t.Helper()
		spec, err := validateNodeIsolation("n1", x, lease, now)
		if err != nil {
			t.Fatal(err)
		}
		return spec
	}
	spec := ok(nodeIsolationBody{Mode: "shadow", Rules: []models.NodeIsolationRule{{CIDR: "10.0.0.0/8", Protocol: "ANY", PortFrom: 443}}}, "")
	if spec.Rules[0].Protocol != "" || spec.Rules[0].PortTo != 443 || spec.LeaseUntil != nil {
		t.Fatalf("normalized shadow spec: %+v", spec)
	}
	if len(spec.ExemptLocalPorts) != 1 || spec.ExemptLocalPorts[0] != 22 {
		t.Fatalf("omitted exemptLocalPorts must keep SSH exempt: %v", spec.ExemptLocalPorts)
	}
	none := []uint16{}
	if got := ok(nodeIsolationBody{Mode: "shadow", Rules: []models.NodeIsolationRule{{CIDR: "10.0.0.0/8"}}, ExemptLocalPorts: &none}, ""); len(got.ExemptLocalPorts) != 0 {
		t.Fatal("an explicit empty list removes the SSH exemption")
	}
	enforce := ok(nodeIsolationBody{Mode: "enforce", Rules: []models.NodeIsolationRule{{CIDR: "10.0.0.0/8"}}}, "")
	if enforce.LeaseUntil == nil || enforce.LeaseUntil.Sub(now) != nodeIsolationDefaultLease {
		t.Fatalf("enforce gets the default lease: %v", enforce.LeaseUntil)
	}
	for name, tc := range map[string]struct {
		x     nodeIsolationBody
		lease string
	}{
		"bad mode":      {nodeIsolationBody{Mode: "on", Rules: []models.NodeIsolationRule{{CIDR: "10.0.0.0/8"}}}, ""},
		"no rules":      {nodeIsolationBody{Mode: "shadow"}, ""},
		"non-canonical": {nodeIsolationBody{Mode: "shadow", Rules: []models.NodeIsolationRule{{CIDR: "10.0.0.1/8"}}}, ""},
		"protocol":      {nodeIsolationBody{Mode: "shadow", Rules: []models.NodeIsolationRule{{CIDR: "10.0.0.0/8", Protocol: "icmp"}}}, ""},
		"port range":    {nodeIsolationBody{Mode: "shadow", Rules: []models.NodeIsolationRule{{CIDR: "10.0.0.0/8", PortFrom: 90, PortTo: 80}}}, ""},
		"lease too big": {nodeIsolationBody{Mode: "enforce", Rules: []models.NodeIsolationRule{{CIDR: "10.0.0.0/8"}}}, "3h"},
	} {
		if _, err := validateNodeIsolation("n1", tc.x, tc.lease, now); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestNodeIsolationAPIRoundTripAndAgentStatus(t *testing.T) {
	h, st := nodeIsoServer(t)
	if rec := do(h, "GET", "/api/v1/ebpf/node-isolation", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"items":[]`) {
		t.Fatalf("empty list: %d %s", rec.Code, rec.Body.String())
	}
	rec := do(h, "PUT", "/api/v1/ebpf/node-isolation/n1?lease=5m", `{"policyId":"p1","mode":"enforce","rules":[{"cidr":"10.0.0.0/8","protocol":"tcp","portFrom":443}]}`)
	if rec.Code != 200 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	var saved models.NodeIsolationSpec
	_ = json.Unmarshal(rec.Body.Bytes(), &saved)
	if saved.Revision == 0 || saved.LeaseUntil == nil || saved.Mode != "enforce" {
		t.Fatalf("saved: %+v", saved)
	}
	// The node's agent config carries the policy; other nodes' does not.
	rec = do(h, "GET", "/api/v1/ebpf/config?node=n1", "")
	var cfg models.EBPFFastPathConfig
	_ = json.Unmarshal(rec.Body.Bytes(), &cfg)
	if cfg.NodeIsolation == nil || cfg.NodeIsolation.PolicyID != "p1" || cfg.Mode != "observe" {
		t.Fatalf("config for n1: %+v (node isolation must not change the cluster mode)", cfg.NodeIsolation)
	}
	rec = do(h, "GET", "/api/v1/ebpf/config?node=n2", "")
	cfg = models.EBPFFastPathConfig{}
	_ = json.Unmarshal(rec.Body.Bytes(), &cfg)
	if cfg.NodeIsolation != nil {
		t.Fatal("n2 must not receive n1's policy")
	}

	st.Report(models.AgentReport{Node: "n1", ObservedAt: time.Now().UTC(), NodeIsolation: &models.NodeIsolationStatus{
		Attached: []string{"nodeiso-tcx-egress:eth0"}, PolicyID: "p1", Revision: saved.Revision, Mode: "enforce",
		Allowed: 9, Blocked: 3, BlockedBytes: 180, Top: []models.NodeIsolationDest{{Address: "8.8.8.8", Protocol: "udp", Port: 53, Packets: 3, Bytes: 180}},
	}})
	rec = do(h, "GET", "/api/v1/ebpf/node-isolation", "")
	var list struct {
		Items []nodeIsolationItem `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Items) != 1 {
		t.Fatalf("items: %s", rec.Body.String())
	}
	it := list.Items[0]
	if it.EffectiveMode != "enforce" || it.AppliedRevision != saved.Revision || it.BlockedPackets != 3 || it.AgentStale || len(it.Top) != 1 {
		t.Fatalf("item: %+v", it)
	}

	if rec := do(h, "DELETE", "/api/v1/ebpf/node-isolation/n1", ""); rec.Code != 200 {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec := do(h, "DELETE", "/api/v1/ebpf/node-isolation/n1", ""); rec.Code != 404 {
		t.Fatalf("second delete: %d", rec.Code)
	}
	if rec := do(h, "PUT", "/api/v1/ebpf/node-isolation/n1", `{"mode":"shadow","rules":[{"cidr":"10.0.0.0/8"}],"extra":1}`); rec.Code != 400 {
		t.Fatalf("unknown fields must be rejected: %d", rec.Code)
	}
}

func TestNodeIsolationPutIsAdminOnly(t *testing.T) {
	for method, want := range map[string]oidcauth.Role{"PUT": oidcauth.RoleAdmin, "DELETE": oidcauth.RoleOperator, "GET": oidcauth.RoleViewer} {
		pattern := method + " /api/v1/ebpf/node-isolation/{node}"
		if method == "GET" {
			pattern = "GET /api/v1/ebpf/node-isolation"
		}
		r := httptest.NewRequest(method, "/x", nil)
		r.Pattern = pattern
		if got := requiredRole(r); got != want {
			t.Errorf("%s: role %v, want %v", pattern, got, want)
		}
	}
}
