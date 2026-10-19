// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package fleet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/flowlog"
)

func TestAggregateFlowsMergesAndSurfacesPeerError(t *testing.T) {
	peerOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(flowlog.Result{
			Records: []flowlog.Record{{
				ObservedAt: time.Now().UTC().Add(-time.Minute),
				Peer:       "10.1.0.1", Port: 443, Packets: 9,
			}},
			Matched: 1,
		})
	}))
	defer peerOK.Close()

	local := flowlog.Result{
		Records: []flowlog.Record{{
			ObservedAt: time.Now().UTC(),
			Peer:       "10.0.0.1", Port: 80, Packets: 3,
		}},
		Matched: 1,
	}
	out := AggregateFlows(context.Background(), "home", local, flowlog.Query{Limit: 10},
		[]Peer{
			{Name: "west", URL: peerOK.URL, APIKey: "k"},
			{Name: "dead", URL: "http://127.0.0.1:1"},
		}, peerOK.Client())
	if out.Matched != 2 {
		t.Fatalf("matched %d", out.Matched)
	}
	if len(out.Records) != 2 {
		t.Fatalf("records %d", len(out.Records))
	}
	if out.Records[0].Peer != "10.0.0.1" {
		t.Fatalf("want newest local first, got %+v", out.Records[0])
	}
	var sawDead bool
	for _, c := range out.Clusters {
		if c.Name == "dead" {
			sawDead = true
			if c.OK || c.Error == "" {
				t.Fatalf("dead peer: %+v", c)
			}
		}
	}
	if !sawDead {
		t.Fatal("missing dead peer cluster")
	}
	if len(out.Limitations) < 2 {
		t.Fatalf("limitations: %v", out.Limitations)
	}
}
