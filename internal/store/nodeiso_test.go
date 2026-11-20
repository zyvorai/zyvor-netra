// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package store

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func nodeIsoSpec(node, mode string, lease time.Duration) models.NodeIsolationSpec {
	spec := models.NodeIsolationSpec{Node: node, PolicyID: "p-" + node, Mode: mode, Rules: []models.NodeIsolationRule{{CIDR: "10.0.0.0/8"}}}
	if lease != 0 {
		until := time.Now().UTC().Add(lease)
		spec.LeaseUntil = &until
	}
	return spec
}

func TestNodeIsolationLeaseExpiryDemotesToShadow(t *testing.T) {
	s := New()
	first, err := s.SetNodeIsolation(nodeIsoSpec("n1", models.NodeIsolationEnforce, -time.Second), "admin")
	if err != nil {
		t.Fatal(err)
	}
	got := s.NodeIsolation("n1")
	if got == nil || got.Mode != models.NodeIsolationShadow || got.LeaseUntil != nil || got.Revision <= first.Revision {
		t.Fatalf("expired enforce must become shadow with a new revision: %+v", got)
	}
	found := false
	for _, e := range s.Audit(10) {
		found = found || e.Action == "ebpf.node-isolation.lease-expired"
	}
	if !found {
		t.Fatal("lease expiry must be audited")
	}
	if spec, _ := s.SetNodeIsolation(nodeIsoSpec("n2", models.NodeIsolationShadow, time.Hour), "admin"); spec.LeaseUntil != nil {
		t.Fatal("shadow never carries a lease")
	}
	if len(s.NodeIsolations()) != 2 {
		t.Fatal("two nodes")
	}
	if ok, _ := s.ClearNodeIsolation("n1", "admin"); !ok || s.NodeIsolation("n1") != nil {
		t.Fatal("clear")
	}
}

func TestNodeIsolationRestartKeepsShadowAndFailsOpenEnforce(t *testing.T) {
	path := t.TempDir() + "/state.json"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetNodeIsolation(nodeIsoSpec("a", models.NodeIsolationShadow, 0), "admin"); err != nil {
		t.Fatal(err)
	}
	enforced, err := s.SetNodeIsolation(nodeIsoSpec("b", models.NodeIsolationEnforce, time.Hour), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, b := s.NodeIsolation("a"), s.NodeIsolation("b")
	if a == nil || a.Mode != models.NodeIsolationShadow {
		t.Fatalf("shadow survives restart: %+v", a)
	}
	if b == nil || b.Mode != models.NodeIsolationShadow || b.LeaseUntil != nil || b.Revision <= enforced.Revision {
		t.Fatalf("enforce must never resume after restart: %+v", b)
	}
	next, _ := s.SetNodeIsolation(nodeIsoSpec("c", models.NodeIsolationShadow, 0), "admin")
	if next.Revision <= b.Revision {
		t.Fatal("revisions keep increasing across restarts")
	}
}
