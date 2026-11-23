// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/changeline"
)

func TestIncidentChangesJoinsNetlinkAndReportsGaps(t *testing.T) {
	now := time.Now().UTC()
	s := nlServer(now)
	get := func(q string) (int, changeline.Result) {
		rec := httptest.NewRecorder()
		s.incidentChanges(rec, httptest.NewRequest("GET", "/api/v1/incidents/changes"+q, nil))
		var out changeline.Result
		if rec.Code == 200 {
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
		}
		return rec.Code, out
	}
	code, res := get("?since=30m")
	if code != 200 || res.Counts[changeline.ClassChange] != 3 {
		t.Fatalf("code=%d counts=%v entries=%+v", code, res.Counts, res.Entries)
	}
	joined := strings.Join(res.Gaps, "|")
	for _, want := range []string{"off-node", "lost events", "metrics platform disabled", "metric alerts disabled"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("gap %q missing: %v", want, res.Gaps)
		}
	}
	if res.Caveat == "" {
		t.Fatal("caveat missing")
	}
	// node filter drops the other node's change
	if _, res := get("?since=30m&node=worker-2"); res.Counts[changeline.ClassChange] != 1 {
		t.Fatalf("node filter: %+v", res.Entries)
	}
	for _, bad := range []string{"?since=abc", "?since=25h", "?since=-1m", "?lead=0s", "?lead=x"} {
		if code, _ := get(bad); code != 400 {
			t.Fatalf("%s accepted: %d", bad, code)
		}
	}
}
