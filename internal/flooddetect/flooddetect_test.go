// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package flooddetect

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func flat(n int, v float64) []float64 {
	out := make([]float64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func withTail(base []float64, tail ...float64) []float64 {
	return append(append([]float64(nil), base...), tail...)
}

func TestAnalyzeSignal(t *testing.T) {
	noisy := make([]float64, 60)
	for i := range noisy {
		noisy[i] = 100 + float64(i%5)*3 // 100..112
	}
	tests := []struct {
		name    string
		sig     Signal
		want    bool
		wantSev string
	}{
		{"quiet node floods", Signal{Vector: VectorSYN, Floor: 1, MinRatio: 3, Values: withTail(flat(60, 0), 500, 600, 550)}, true, SeverityCritical},
		{"moderate rise", Signal{Vector: VectorUDP, Floor: 1000, MinRatio: 3, Values: withTail(flat(60, 1000), 4200, 4300, 4100)}, true, SeverityHigh},
		{"rise below floor", Signal{Vector: VectorICMP, Floor: 500, MinRatio: 3, Values: withTail(flat(60, 10), 100, 120, 110)}, false, ""},
		{"normal noise", Signal{Vector: VectorUDP, Floor: 50, MinRatio: 3, Values: withTail(noisy, 110, 108, 112)}, false, ""},
		{"single spiky bucket", Signal{Vector: VectorSYN, Floor: 1, MinRatio: 3, Values: withTail(flat(60, 0), 0, 0, 900)}, false, ""},
		{"two of three buckets", Signal{Vector: VectorSYN, Floor: 1, MinRatio: 3, Values: withTail(flat(60, 0), 0, 900, 900)}, true, SeverityCritical},
		{"high but baseline already high", Signal{Vector: VectorUDP, Floor: 100, MinRatio: 3, Values: withTail(flat(60, 5000), 5200, 5100, 5300)}, false, ""},
		{"too little history", Signal{Vector: VectorSYN, Floor: 1, MinRatio: 3, Values: flat(10, 9)}, false, ""},
		{"zero floor is refused", Signal{Vector: VectorSYN, Floor: 0, Values: withTail(flat(60, 0), 9, 9, 9)}, false, ""},
		{"nan floor is refused", Signal{Vector: VectorSYN, Floor: math.NaN(), Values: withTail(flat(60, 0), 9, 9, 9)}, false, ""},
		{"nan and inf baseline points ignored", Signal{Vector: VectorSYN, Floor: 1, MinRatio: 3, Values: withTail(withTail(flat(30, 0), math.NaN(), math.Inf(1), -5), withTail(flat(30, 0), 400, 400, 400)...)}, true, SeverityCritical},
		{"tail mostly missing", Signal{Vector: VectorSYN, Floor: 1, MinRatio: 3, Values: withTail(flat(60, 0), math.NaN(), math.NaN(), 900)}, false, ""},
		{"all missing", Signal{Vector: VectorSYN, Floor: 1, Values: flat(80, math.NaN())}, false, ""},
		{"negative rates are not rates", Signal{Vector: VectorSYN, Floor: 1, Values: flat(80, -3)}, false, ""},
		{"invalid ratio falls back", Signal{Vector: VectorSYN, Floor: 1, MinRatio: math.NaN(), Values: withTail(flat(60, 0), 50, 50, 50)}, true, SeverityCritical},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.sig.Node, tc.sig.Name = "n1", "sig"
			f, ok := AnalyzeSignal(tc.sig)
			if ok != tc.want {
				t.Fatalf("got %v want %v (%+v)", ok, tc.want, f)
			}
			if ok && f.Severity != tc.wantSev {
				t.Fatalf("severity %q want %q (%+v)", f.Severity, tc.wantSev, f)
			}
		})
	}
}

func TestHugeSignalIsBounded(t *testing.T) {
	v := withTail(flat(MaxValues*4, 0), 500, 500, 500)
	if _, ok := AnalyzeSignal(Signal{Floor: 1, MinRatio: 3, Values: v}); !ok {
		t.Fatal("the newest points must still be analysed after truncation")
	}
}

func TestAnalyzeOrdersAndBounds(t *testing.T) {
	var sigs []Signal
	for i := 0; i < MaxFindings+50; i++ {
		sigs = append(sigs, Signal{Node: fmt.Sprintf("n%04d", i), Vector: VectorSYN, Name: "a", Floor: 1, MinRatio: 3, Values: withTail(flat(60, 0), 5, 5, 5)})
	}
	sigs = append(sigs, Signal{Node: "zz", Vector: VectorUDP, Name: "b", Floor: 1, MinRatio: 3, Values: withTail(flat(60, 0), 9000, 9000, 9000)})
	out := Analyze(sigs)
	if len(out) != MaxFindings {
		t.Fatalf("len %d", len(out))
	}
	if out[0].Node != "zz" {
		t.Fatalf("most severe first, got %+v", out[0])
	}
}

func TestSuggest(t *testing.T) {
	tests := []struct {
		addr, class string
		want        bool
		proto       string
	}{
		{"203.0.113.9", "syn", true, "TCP"},
		{"8.8.4.4", "udp", true, ""},
		{"2001:4860:4860::8888", "icmp", true, ""},
		{"::ffff:8.8.8.8", "udp", true, ""},
		{" 8.8.8.8 ", "syn", true, "TCP"},
		{"10.0.0.5", "syn", false, ""},
		{"192.168.1.1", "udp", false, ""},
		{"172.16.0.1", "udp", false, ""},
		{"fd00::1", "udp", false, ""},
		{"127.0.0.1", "udp", false, ""},
		{"169.254.1.1", "udp", false, ""},
		{"224.0.0.1", "udp", false, ""},
		{"0.0.0.0", "udp", false, ""},
		{"::", "udp", false, ""},
		{"255.255.255.255", "udp", false, ""},
		{"not-an-ip", "syn", false, ""},
		{"", "syn", false, ""},
		{"8.8.8.8/24", "syn", false, ""},
		{"8.8.8.8; rm", "syn", false, ""},
	}
	for _, tc := range tests {
		sg, why := Suggest(tc.addr, tc.class)
		if (sg != nil) != tc.want {
			t.Fatalf("%q: suggestion=%v why=%q", tc.addr, sg, why)
		}
		if sg == nil {
			if why == "" {
				t.Fatalf("%q: a refusal needs a reason", tc.addr)
			}
			continue
		}
		if sg.Protocol != tc.proto || sg.Direction != "ingress" || sg.Kind != "ip" || len(sg.Steps) == 0 {
			t.Fatalf("%q: %+v", tc.addr, sg)
		}
		if sg.PreviewRequest["kind"] != "ip" || sg.PreviewRequest["direction"] != "ingress" {
			t.Fatalf("%q: preview %v", tc.addr, sg.PreviewRequest)
		}
		if strings.Contains(sg.Value, " ") {
			t.Fatalf("value not normalised: %q", sg.Value)
		}
	}
}

func src(class, addr string, attempts, denied uint64) models.ShieldSourceStat {
	return models.ShieldSourceStat{Family: "ipv4", Class: class, Address: addr, Attempts: attempts, Denied: denied}
}

func TestTrackerRatesAndFindings(t *testing.T) {
	tr := NewTracker()
	t0 := time.Unix(1_700_000_000, 0)
	if !tr.Warming(t0) {
		t.Fatal("empty tracker is warming")
	}
	tr.Observe("n1", t0, []models.ShieldSourceStat{
		src("syn", "203.0.113.9", 1000, 0), src("syn", "10.1.2.3", 0, 0), src("udp", "198.51.100.7", 0, 0), src("syn", "198.51.100.8", 50, 0),
	})
	if !tr.Warming(t0) || len(tr.Findings(t0)) != 0 {
		t.Fatal("one observation gives no rate")
	}
	t1 := t0.Add(10 * time.Second)
	tr.Observe("n1", t1, []models.ShieldSourceStat{
		src("syn", "203.0.113.9", 1000+30000, 0), // 3000/s
		src("syn", "10.1.2.3", 5000, 0),          // 500/s, private
		src("udp", "198.51.100.7", 0, 100),       // 10/s: below the UDP floor
		src("syn", "198.51.100.8", 100, 0),       // 5/s: below floor
		src("syn", "192.0.2.77", 99999, 0),       // new source: no baseline, no rate
	})
	if tr.Warming(t1) {
		t.Fatal("should not be warming after two observations")
	}
	f := tr.Findings(t1)
	if len(f) != 2 {
		t.Fatalf("findings %+v", f)
	}
	if f[0].Address != "203.0.113.9" || f[0].Severity != SeverityCritical || f[0].Suggestion == nil || f[0].Suggestion.Protocol != "TCP" {
		t.Fatalf("top finding %+v", f[0])
	}
	if f[1].Address != "10.1.2.3" || f[1].Suggestion != nil || f[1].NoSuggestion == "" {
		t.Fatalf("private source must not get a suggestion: %+v", f[1])
	}
	if f[0].Share < 0.8 || f[0].Share > 0.9 {
		t.Fatalf("share %v", f[0].Share)
	}
	// Findings age out.
	if got := tr.Findings(t1.Add(StaleAfter + time.Second)); len(got) != 0 {
		t.Fatalf("stale findings %v", got)
	}
}

func TestTrackerHostileInput(t *testing.T) {
	tr := NewTracker()
	t0 := time.Unix(1_700_000_000, 0)
	tr.Observe("", t0, []models.ShieldSourceStat{src("syn", "1.2.3.4", 1, 0)}) // no node: ignored
	var many []models.ShieldSourceStat
	for i := 0; i < MaxSourcesPerSnapshot*2; i++ {
		many = append(many, src("syn", fmt.Sprintf("203.0.%d.%d", i/250, i%250), uint64(i), 0))
	}
	many = append(many, src("syn", "", 5, 0), src("syn", strings.Repeat("9", 500), 5, 0), src("bogus-class", "203.9.9.9", 0, 7))
	tr.Observe("n1", t0, many)
	// counter reset and an out-of-range interval are skipped, not turned into huge rates
	tr.Observe("n1", t0.Add(100*time.Millisecond), many)
	tr.Observe("n1", t0.Add(time.Hour), many)
	for i := range many {
		many[i].Attempts = 0
		many[i].Denied = 0
	}
	tr.Observe("n1", t0.Add(time.Hour+10*time.Second), many)
	if got := tr.Findings(t0.Add(time.Hour + 10*time.Second)); len(got) != 0 {
		t.Fatalf("resets must not look like floods: %v", got)
	}
	// node count is bounded
	for i := 0; i < MaxNodes+10; i++ {
		tr.Observe(fmt.Sprintf("node-%d", i), t0, nil)
	}
	tr.mu.Lock()
	n := len(tr.prev)
	tr.mu.Unlock()
	if n > MaxNodes {
		t.Fatalf("tracked %d nodes", n)
	}
}

func TestNilTrackerIsSafe(t *testing.T) {
	var tr *Tracker
	tr.Observe("n", time.Now(), nil)
	if !tr.Warming(time.Now()) || tr.Findings(time.Now()) != nil {
		t.Fatal("nil tracker")
	}
}
