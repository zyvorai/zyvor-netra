// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package sqlitestore

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/flowlog"
	"github.com/zyvorai/netra/internal/models"
)

func TestSQLiteAppendQueryPrune(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flows.db")
	s, err := Open(path, flowlog.Options{Retain: time.Hour, Max: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now().UTC().Truncate(time.Second)
	recs := []flowlog.Record{
		{ObservedAt: now.Add(-2 * time.Minute), Peer: "10.0.0.1", Port: 80, Namespace: "a", Pod: "p", Packets: 1},
		{ObservedAt: now.Add(-time.Minute), Peer: "10.0.0.2", Port: 443, Namespace: "a", Pod: "p", Packets: 2},
		{ObservedAt: now.Add(-30 * time.Second), Peer: "10.0.0.3", Port: 53, Namespace: "b", Pod: "q", Packets: 3},
		{ObservedAt: now, Peer: "10.0.0.4", Port: 22, Namespace: "a", Pod: "p", Packets: 4},
	}
	if err := s.Append(recs); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 3 {
		t.Fatalf("len after max prune: %d", s.Len())
	}
	res := s.Query(flowlog.Query{Namespace: "a", Limit: 10})
	if res.Matched != 2 {
		t.Fatalf("matched %d want 2: %+v", res.Matched, res.Records)
	}
	if len(res.Records) != 2 || res.Records[0].Peer != "10.0.0.4" {
		t.Fatalf("newest-first: %+v", res.Records)
	}
	for _, line := range res.Limitations {
		if line == "" {
			t.Fatal("empty limitation")
		}
	}
}

func TestSQLiteByteBudget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flows.db")
	s, err := Open(path, flowlog.Options{Retain: 24 * time.Hour, Max: 10000, MaxBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	batch := make([]flowlog.Record, 0, 200)
	for i := 0; i < 200; i++ {
		batch = append(batch, flowlog.Record{
			ObservedAt: now.Add(time.Duration(i) * time.Second),
			Peer:       "10.0.0.9", Port: 8080, Namespace: "ns", Pod: "pod",
			Packets: uint64(i + 1), Bytes: uint64(i * 100), Comm: "pad-comm-value",
		})
	}
	if err := s.Append(batch); err != nil {
		t.Fatal(err)
	}
	if s.Len() >= 200 {
		t.Fatalf("expected row prune under byte budget, len=%d", s.Len())
	}
}

func TestImportJSON(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "state.flows")
	dbPath := filepath.Join(dir, "state.flows.db")
	mem := flowlog.NewLimited(time.Hour, 100)
	base := time.Now().UTC().Truncate(time.Second)
	mk := func(packets uint64) models.AgentReport {
		return models.AgentReport{
			Node: "n1",
			Stats: []models.DestinationStat{{
				DestinationIP: "10.0.0.8", Port: 80, Protocol: "TCP",
				Packets: packets, Bytes: packets * 10, Namespace: "app", Pod: "api",
			}},
		}
	}
	mem.Ingest(base, mk(10))
	mem.Ingest(base.Add(time.Second), mk(20))
	if err := mem.Save(jsonPath); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dbPath, flowlog.Options{Retain: time.Hour, Max: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.ImportJSON(jsonPath); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 {
		t.Fatalf("imported len %d", s.Len())
	}
}
