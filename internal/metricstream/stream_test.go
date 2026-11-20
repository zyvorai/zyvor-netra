// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package metricstream

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/zyvorai/netra/internal/tsdb"
)

func fill(t *testing.T, db *tsdb.DB, from, to int64) {
	t.Helper()
	for ts := from; ts <= to; ts++ {
		for _, d := range []string{"user", "system"} {
			if err := db.Append(tsdb.Sample{Series: tsdb.Series{Context: "system.cpu", Chart: "system.cpu", Dimension: d, Units: "%"}, T: ts, V: float64(ts), Anomalous: ts%10 == 0}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

type flakyHub struct {
	hub  *Hub
	down atomic.Bool
}

func (f *flakyHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.down.Load() {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	f.hub.ServeHTTP(w, r)
}

func drain(t *testing.T, s *Sender) {
	t.Helper()
	for i := 0; i < 100; i++ {
		more, err := s.Once(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !more {
			return
		}
	}
	t.Fatal("sender never caught up")
}

func countPoints(db *tsdb.DB) int {
	n := 0
	for _, info := range db.List() {
		n += len(db.Points(info.Key, 0, 1<<40))
	}
	return n
}

func TestSenderReplicatesAcrossOutageAndParentRestart(t *testing.T) {
	agentDB, _ := tsdb.Open(tsdb.Options{})
	hub, _ := OpenHub(HubOptions{})
	fh := &flakyHub{hub: hub}
	srv := httptest.NewServer(fh)
	defer srv.Close()
	s := &Sender{DB: agentDB, Server: srv.URL, Node: "node-a", Client: srv.Client(), MaxPoints: 50}

	fill(t, agentDB, 1, 100)
	drain(t, s)
	if got := countPoints(hub.DB("node-a")); got != 200 {
		t.Fatalf("initial sync stored %d points, want 200", got)
	}

	// Outage: the agent keeps collecting, sends fail, the cursor holds.
	fh.down.Store(true)
	fill(t, agentDB, 101, 160)
	if _, err := s.Once(context.Background()); err == nil {
		t.Fatal("expected failure while parent is down")
	}
	fh.down.Store(false)
	drain(t, s)
	if got := countPoints(hub.DB("node-a")); got != 320 {
		t.Fatalf("after outage stored %d points, want 320", got)
	}

	// Parent restart with an empty in-memory store: the agent replays.
	fh.hub, _ = OpenHub(HubOptions{})
	fill(t, agentDB, 161, 170)
	drain(t, s)
	db := fh.hub.DB("node-a")
	if got := countPoints(db); got != 340 {
		t.Fatalf("after parent restart stored %d points, want 340", got)
	}
	if s.Status().Replays == 0 {
		t.Fatal("expected a replay")
	}
	pts := db.Points(tsdb.Series{Context: "system.cpu", Chart: "system.cpu", Dimension: "user"}.Key(), 10, 10)
	if len(pts) != 1 || !pts[0].Anomalous {
		t.Fatalf("anomaly bit lost in transit: %+v", pts)
	}
}

func TestHubRejectsBadInput(t *testing.T) {
	hub, _ := OpenHub(HubOptions{MaxNodes: 1})
	for _, tc := range []struct {
		node string
		code int
	}{{"../etc", 400}, {"ok-node", 200}, {"second", 429}} {
		body, _ := Encode(&Batch{Node: tc.node})
		req := httptest.NewRequest(http.MethodPost, Path, bytes.NewReader(body))
		req.Header.Set("Content-Encoding", "gzip")
		rr := httptest.NewRecorder()
		hub.ServeHTTP(rr, req)
		if rr.Code != tc.code {
			t.Fatalf("node %q: code %d want %d (%s)", tc.node, rr.Code, tc.code, rr.Body)
		}
	}
	rr := httptest.NewRecorder()
	hub.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, Path, strings.NewReader("{")))
	if rr.Code != 400 {
		t.Fatalf("malformed body: %d", rr.Code)
	}
}

func TestHubPersistsNodesOnDisk(t *testing.T) {
	dir := t.TempDir()
	hub, err := OpenHub(HubOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hub.Ingest(&Batch{Node: "n1", Series: []WireSeries{{Series: tsdb.Series{Context: "c", Chart: "c", Dimension: "d"}, Points: [][3]float64{{100, 1, 0}, {101, 2, 1}}}}}); err != nil {
		t.Fatal(err)
	}
	if err := hub.Close(); err != nil {
		t.Fatal(err)
	}
	hub2, err := OpenHub(HubOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if db := hub2.DB("n1"); db == nil || db.LastT() != 101 {
		t.Fatal("node store not reopened")
	}
	resp, _ := hub2.Ingest(&Batch{Node: "n1", From: 101})
	if resp.PrevLastT != 101 {
		t.Fatalf("prevLastT %d", resp.PrevLastT)
	}
}
