// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package flowlog

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json.flows")
	l := NewLimited(time.Hour, 10)
	base := time.Now().UTC().Add(-time.Minute)
	l.Ingest(base, models.AgentReport{Node: "n", Stats: []models.DestinationStat{{
		DestinationIP: "10.0.0.1", Port: 80, Protocol: "tcp", Packets: 1, Bytes: 10, Namespace: "app", Pod: "web",
	}}})
	l.Ingest(base.Add(time.Second), models.AgentReport{Node: "n", Stats: []models.DestinationStat{{
		DestinationIP: "10.0.0.1", Port: 80, Protocol: "tcp", Packets: 5, Bytes: 50, Namespace: "app", Pod: "web",
	}}})
	if err := l.Save(path); err != nil {
		t.Fatal(err)
	}
	l2 := NewLimited(time.Hour, 10)
	if err := l2.Load(path); err != nil {
		t.Fatal(err)
	}
	if l2.Len() != 1 {
		t.Fatalf("len %d", l2.Len())
	}
	got := l2.Query(Query{Limit: 5})
	if got.Records[0].Pod != "web" || got.Records[0].Packets != 4 {
		t.Fatalf("%+v", got.Records[0])
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file left behind")
	}
}
