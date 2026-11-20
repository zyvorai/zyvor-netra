// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package capture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestArtifactStoreWriteAndPrune(t *testing.T) {
	dir := t.TempDir()
	s, err := NewArtifactStore(dir, 2, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	id, err := s.Begin("node-a", "kerneldiag", "qdisc", "node-a/qdisc", now)
	if err != nil || id == "" {
		t.Fatalf("begin: id=%q err=%v", id, err)
	}
	frame := EncodeFrame(Frame{
		ObservedAtUnixNano: now.UnixNano(),
		OrigLen:            4,
		Data:               []byte{1, 2, 3, 4},
	})
	s.WriteFrame("node-a", frame)
	s.WriteFrame("node-a", frame)
	meta, ok := s.Finalize("node-a", now.Add(time.Second))
	if !ok || meta.Frames != 2 || meta.ID != id {
		t.Fatalf("finalize: %+v ok=%v", meta, ok)
	}
	if _, err := os.Stat(meta.Path); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Get(id)
	if !ok || got.Path != meta.Path {
		t.Fatalf("get: %+v", got)
	}
	f, _, err := s.Open(id)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Create two more to force prune of oldest.
	for _, node := range []string{"node-b", "node-c"} {
		id2, err := s.Begin(node, "dropdiag", "softnet-drop", node, now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		s.WriteFrame(node, frame)
		s.Finalize(node, now.Add(2*time.Minute))
		_ = id2
	}
	s.mu.Lock()
	n := len(s.index)
	s.mu.Unlock()
	if n > 2 {
		t.Fatalf("prune: index size %d", n)
	}
	entries, _ := os.ReadDir(dir)
	pcaps := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".pcap" {
			pcaps++
		}
	}
	if pcaps > 2 {
		t.Fatalf("prune files: %d", pcaps)
	}
}

func TestArtifactContextRoundTripAndPrune(t *testing.T) {
	dir := t.TempDir()
	s, err := NewArtifactStore(dir, 1, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	s.StageContext("node-a", models.DropIncidentContext{
		Node:   models.DropIncidentNode{Name: "node-a", Hostname: "host-a"},
		CPUHot: true,
	})
	id, err := s.Begin("node-a", "dropdiag", "softnet-drop", "node-a", now)
	if err != nil || id == "" {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, id+".context.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"hostname": "host-a"`) || strings.Contains(string(raw), "cmdline") {
		t.Fatalf("context body: %s", raw)
	}
	frame := EncodeFrame(Frame{ObservedAtUnixNano: now.UnixNano(), OrigLen: 4, Data: []byte{1, 2, 3, 4}})
	s.WriteFrame("node-a", frame)
	meta, ok := s.Finalize("node-a", now.Add(time.Second))
	if !ok || meta.ContextPath == "" {
		t.Fatalf("finalize context: %+v ok=%v", meta, ok)
	}
	old := now.Add(-time.Hour)
	_ = os.Chtimes(meta.Path, old, old)
	_ = os.Chtimes(meta.ContextPath, old, old)
	f, _, err := s.OpenContext(id)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	// A second artifact must prune the first PCAP and its context JSON.
	s.StageContext("node-b", models.DropIncidentContext{Node: models.DropIncidentNode{Name: "node-b"}})
	id2, err := s.Begin("node-b", "dropdiag", "softnet-drop", "node-b", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	s.WriteFrame("node-b", frame)
	if _, ok := s.Finalize("node-b", now.Add(2*time.Minute)); !ok {
		t.Fatal("finalize b")
	}
	if _, err := os.Stat(filepath.Join(dir, id+".context.json")); !os.IsNotExist(err) {
		t.Fatalf("pruned context still present: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, id+".pcap")); !os.IsNotExist(err) {
		t.Fatalf("pruned pcap still present: %v", err)
	}
	if _, _, err := s.OpenContext(id2); err != nil {
		t.Fatal(err)
	}

	// Restart scan pairs a leftover JSON with its PCAP stem.
	s2, err := NewArtifactStore(dir, 1, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Get(id2)
	if !ok || got.ContextPath == "" {
		t.Fatalf("rescan: %+v ok=%v", got, ok)
	}
}

func TestArtifactEmptyCaptureDropsContext(t *testing.T) {
	dir := t.TempDir()
	s, err := NewArtifactStore(dir, 5, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	s.StageContext("node-a", models.DropIncidentContext{Node: models.DropIncidentNode{Name: "node-a"}})
	id, err := s.Begin("node-a", "dropdiag", "softnet-drop", "node-a", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Finalize("node-a", now); !ok {
		t.Fatal("finalize")
	}
	if _, err := os.Stat(filepath.Join(dir, id+".context.json")); !os.IsNotExist(err) {
		t.Fatalf("empty capture kept context: %v", err)
	}
}

func TestParseAutoRequestor(t *testing.T) {
	src, kind, ok := ParseAutoRequestor("auto-capture:kerneldiag/qdisc")
	if !ok || src != "kerneldiag" || kind != "qdisc" {
		t.Fatalf("%s %s %v", src, kind, ok)
	}
}
