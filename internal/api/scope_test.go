// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/zyvorai/netra/internal/flowlog"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/oidcauth"
	"github.com/zyvorai/netra/internal/store"
)

func TestPrincipalAllows(t *testing.T) {
	p := principal{Namespaces: []string{"a"}, Clusters: []string{"c1"}, Tenants: []string{"t1"}}
	if !p.Allows("a", "c1", "t1") {
		t.Fatal("expected allow")
	}
	if p.Allows("b", "c1", "t1") {
		t.Fatal("namespace")
	}
	if p.Allows("a", "c2", "t1") {
		t.Fatal("cluster")
	}
	if p.Unrestricted() {
		t.Fatal("scoped")
	}
	if !(principal{}).Unrestricted() {
		t.Fatal("empty is unrestricted")
	}
}

func TestServiceCredAuthAndFlowFilter(t *testing.T) {
	dir := t.TempDir()
	key := "scoped-secret-key"
	hash, err := bcrypt.GenerateFromPassword([]byte(key), bcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "creds.json")
	body, _ := json.Marshal([]map[string]any{{
		"id": "reader", "keyHash": string(hash), "role": "viewer",
		"namespaces": []string{"payments"},
	}})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETRA_API_KEY", "admin-key")
	t.Setenv("NETRA_AGENT_KEY", "agent-key")
	t.Setenv("NETRA_SERVICE_CREDENTIALS_FILE", path)
	t.Setenv("NETRA_AGENT_MTLS", "")
	t.Setenv("NETRA_CLUSTER_NAME", "home")
	t.Setenv("NETRA_CLUSTER_TENANT", "")

	st := store.New()
	base := time.Now().UTC().Truncate(time.Second)
	st.Report(models.AgentReport{
		Node: "n1", ObservedAt: base,
		Stats: []models.DestinationStat{
			{DestinationIP: "10.0.0.1", Port: 80, Protocol: "TCP", Packets: 10, Namespace: "payments", Pod: "api"},
			{DestinationIP: "10.0.0.2", Port: 80, Protocol: "TCP", Packets: 10, Namespace: "other", Pod: "api"},
		},
	})
	st.Report(models.AgentReport{
		Node: "n1", ObservedAt: base.Add(time.Second),
		Stats: []models.DestinationStat{
			{DestinationIP: "10.0.0.1", Port: 80, Protocol: "TCP", Packets: 20, Namespace: "payments", Pod: "api"},
			{DestinationIP: "10.0.0.2", Port: 80, Protocol: "TCP", Packets: 20, Namespace: "other", Pod: "api"},
		},
	})

	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, st)
	if len(s.serviceCreds) != 1 {
		t.Fatalf("creds %d", len(s.serviceCreds))
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("whoami %d", rec.Code)
	}
	var who map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &who)
	if who["kind"] != "service" || who["scoped"] != true {
		t.Fatalf("whoami %+v", who)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/v1/flows/history?since=1h", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("flows %d %s", rec.Code, rec.Body.String())
	}
	var res flowlog.Result
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	for _, r := range res.Records {
		if r.Namespace != "payments" {
			t.Fatalf("leaked namespace %q", r.Namespace)
		}
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("PUT", "/api/v1/ebpf/mode", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("admin route with scoped viewer: %d", rec.Code)
	}
}

func TestScopedAdminRoleStillBlockedFromAdminOnly(t *testing.T) {
	p := principal{kind: "service", role: oidcauth.RoleAdmin, Namespaces: []string{"ns"}}
	if p.Unrestricted() {
		t.Fatal("expected scoped")
	}
}
