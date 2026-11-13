// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ai

import (
	"context"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// resetDigestState clears digest.go's package-level "last fingerprint"
// singleton so a test isn't affected by whatever earlier tests in this
// binary left it at, and restores it afterward.
func resetDigestState(t *testing.T) {
	t.Helper()
	watchMu.Lock()
	prevPrint, prevAt, prevComponents, prevHave := lastPrint, lastAt, lastComponents, haveComponents
	lastPrint, lastComponents, haveComponents = "", fingerprintComponents{}, false
	watchMu.Unlock()
	t.Cleanup(func() {
		watchMu.Lock()
		lastPrint, lastAt, lastComponents, haveComponents = prevPrint, prevAt, prevComponents, prevHave
		watchMu.Unlock()
	})
}

func TestExplainFingerprintChangeEachDimension(t *testing.T) {
	base := fingerprintComponents{Mode: "observe", Severity: "info", HealthBucket: 9, AgentsStale: 0, Exposure: 0, Drift: 0}

	cases := []struct {
		name string
		cur  fingerprintComponents
		want string
	}{
		{"mode", fingerprintComponents{Mode: "enforce", Severity: "info", HealthBucket: 9}, "fast-path mode changed from observe to enforce"},
		{"severity", fingerprintComponents{Mode: "observe", Severity: "critical", HealthBucket: 9}, "severity moved from info to critical"},
		{"health drop", fingerprintComponents{Mode: "observe", Severity: "info", HealthBucket: 7}, "health score band dropped"},
		{"stale", fingerprintComponents{Mode: "observe", Severity: "info", HealthBucket: 9, AgentsStale: 2}, "stale agent count changed from 0 to 2"},
		{"exposure", fingerprintComponents{Mode: "observe", Severity: "info", HealthBucket: 9, Exposure: 3}, "high-exposure item count changed from 0 to 3"},
		{"drift", fingerprintComponents{Mode: "observe", Severity: "info", HealthBucket: 9, Drift: 4}, "drift finding count changed from 0 to 4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := explainFingerprintChange(base, tc.cur)
			if len(got) == 0 {
				t.Fatal("expected at least one bullet")
			}
			found := false
			for _, g := range got {
				if strings.Contains(g, tc.want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("bullets=%v missing substring %q", got, tc.want)
			}
		})
	}
}

func TestExplainFingerprintChangeHealthImproved(t *testing.T) {
	prev := fingerprintComponents{HealthBucket: 5}
	cur := fingerprintComponents{HealthBucket: 8}
	got := explainFingerprintChange(prev, cur)
	if len(got) != 1 || !strings.Contains(got[0], "improved") {
		t.Fatalf("bullets=%v", got)
	}
}

func TestExplainFingerprintChangeKindAddedAndResolved(t *testing.T) {
	prev := fingerprintComponents{AnomalyKinds: []string{"dns"}, DriftKinds: []string{"cidr"}, ExposureSeverity: []string{"low"}}
	cur := fingerprintComponents{AnomalyKinds: []string{"rst-storm"}, DriftKinds: []string{}, ExposureSeverity: []string{"low", "high"}}
	got := explainFingerprintChange(prev, cur)

	want := []string{
		"new anomaly kind: rst-storm",
		"anomaly kind resolved: dns",
		"drift kind resolved: cidr",
		"new exposure severity present: high",
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
			}
		}
		if !found {
			t.Fatalf("bullets=%v missing %q", got, w)
		}
	}
}

func TestExplainFingerprintChangeNoDifferenceIsEmpty(t *testing.T) {
	c := fingerprintComponents{Mode: "observe", Severity: "info", AnomalyKinds: []string{"dns"}}
	if got := explainFingerprintChange(c, c); len(got) != 0 {
		t.Fatalf("identical components should produce no bullets, got %v", got)
	}
}

// TestFingerprintChangeAlwaysExplainable is a property test: fingerprintComponents
// is exactly the input Fingerprint hashes, so whenever two random snapshots
// produce different fingerprints, explainFingerprintChange must return at
// least one bullet -- never silently empty for a real change.
func TestFingerprintChangeAlwaysExplainable(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	kinds := []string{"dns", "rst-storm", "latency", ""}
	sevs := []string{"info", "warning", "critical"}
	modes := []string{"observe", "enforce"}

	randSnap := func() (Snapshot, string) {
		snap := Snapshot{
			HealthScore:   rnd.Intn(101),
			AgentsStale:   rnd.Intn(3),
			HighExposure:  rnd.Intn(3),
			DriftFindings: rnd.Intn(3),
			Mode:          modes[rnd.Intn(len(modes))],
		}
		for i := 0; i < rnd.Intn(3); i++ {
			snap.Anomalies = append(snap.Anomalies, Finding{Kind: kinds[rnd.Intn(len(kinds))]})
		}
		return snap, sevs[rnd.Intn(len(sevs))]
	}

	for i := 0; i < 200; i++ {
		snapA, sevA := randSnap()
		snapB, sevB := randSnap()
		fpA := Fingerprint(snapA, sevA)
		fpB := Fingerprint(snapB, sevB)
		if fpA == fpB {
			continue
		}
		compA := fingerprintComponentsOf(snapA, sevA)
		compB := fingerprintComponentsOf(snapB, sevB)
		if len(explainFingerprintChange(compA, compB)) == 0 {
			t.Fatalf("fingerprints differ (%s vs %s) but no bullet explains it: snapA=%#v sevA=%q snapB=%#v sevB=%q", fpA, fpB, snapA, sevA, snapB, sevB)
		}
	}
}

func TestBuildDigestPopulatesWhyChangedOnlyWhenChanged(t *testing.T) {
	resetDigestState(t)

	snap1 := Snapshot{HealthScore: 90, Mode: "observe"}
	d1 := BuildDigest(BuildBrief(snap1))
	if d1.Changed || len(d1.WhyChanged) != 0 {
		t.Fatalf("first digest after reset should not report a change: %#v", d1)
	}

	snap2 := Snapshot{HealthScore: 90, Mode: "observe"}
	d2 := BuildDigest(BuildBrief(snap2))
	if d2.Changed || len(d2.WhyChanged) != 0 {
		t.Fatalf("identical snapshot should not change the fingerprint: %#v", d2)
	}

	snap3 := Snapshot{HealthScore: 90, Mode: "enforce"}
	d3 := BuildDigest(BuildBrief(snap3))
	if !d3.Changed {
		t.Fatal("mode change should change the fingerprint")
	}
	if len(d3.WhyChanged) == 0 {
		t.Fatal("expected WhyChanged to be populated")
	}
	found := false
	for _, w := range d3.WhyChanged {
		if strings.Contains(w, "fast-path mode changed from observe to enforce") {
			found = true
		}
	}
	if !found {
		t.Fatalf("WhyChanged=%v missing the mode-change bullet", d3.WhyChanged)
	}
	if !strings.Contains(d3.Card, "Why:") {
		t.Fatalf("card missing Why section: %s", d3.Card)
	}
}

func TestBuildDigestPeekDoesNotAdvanceSlot(t *testing.T) {
	resetDigestState(t)
	snap1 := Snapshot{HealthScore: 90, Mode: "observe"}
	_ = BuildDigest(BuildBrief(snap1))

	peekSame := BuildDigestPeek(BuildBrief(snap1))
	if peekSame.Changed {
		t.Fatalf("peek of identical snapshot should not report changed: %#v", peekSame)
	}

	snap2 := Snapshot{HealthScore: 90, Mode: "enforce"}
	peekChanged := BuildDigestPeek(BuildBrief(snap2))
	if !peekChanged.Changed {
		t.Fatal("peek should still report Changed against the last recorded digest")
	}

	again := BuildDigestPeek(BuildBrief(snap2))
	if !again.Changed {
		t.Fatal("peek must not advance the slot; a second peek of the new mode should still look changed vs the recorded observe digest")
	}

	recorded := BuildDigest(BuildBrief(snap2))
	if !recorded.Changed {
		t.Fatal("first interactive record of the new mode should still report Changed vs the prior observe digest")
	}
	follow := BuildDigest(BuildBrief(snap2))
	if follow.Changed {
		t.Fatalf("after record, identical digest should be stable: %#v", follow)
	}
}

func TestNarrateWhyChangedNoOpCases(t *testing.T) {
	d := Digest{Changed: false, WhyChanged: []string{"x"}}
	if got := NarrateWhyChanged(context.Background(), d, nil); got.WhyChangedProse != "" {
		t.Fatalf("nil provider should no-op, got %q", got.WhyChangedProse)
	}

	p := &Provider{BaseURL: "http://unused", APIKey: "k", Model: "m"}
	if got := NarrateWhyChanged(context.Background(), Digest{Changed: false, WhyChanged: []string{"x"}}, p); got.WhyChangedProse != "" {
		t.Fatalf("!Changed should no-op, got %q", got.WhyChangedProse)
	}
	if got := NarrateWhyChanged(context.Background(), Digest{Changed: true, WhyChanged: nil}, p); got.WhyChangedProse != "" {
		t.Fatalf("empty WhyChanged should no-op, got %q", got.WhyChangedProse)
	}
}

func TestNarrateWhyChangedCallsProvider(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": "mode flipped to enforce, dropping the health score band."}}},
		})
	}))
	t.Cleanup(srv.Close)
	p := &Provider{BaseURL: srv.URL, APIKey: "k", Model: "m", HTTPClient: srv.Client()}

	d := Digest{Changed: true, WhyChanged: []string{"fast-path mode changed from observe to enforce", "health score band dropped (was 90s, now 70s)"}}
	got := NarrateWhyChanged(context.Background(), d, p)
	if got.WhyChangedProse == "" {
		t.Fatal("expected WhyChangedProse to be set")
	}
	if !strings.Contains(gotBody, "fast-path mode changed from observe to enforce") {
		t.Fatalf("provider request body missing the bullets: %s", gotBody)
	}
}
