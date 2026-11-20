// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package tsdb

import (
	"errors"
	"math"
	"math/rand"
	"sync"
	"testing"
	"time"
)

func cpuSeries(dim string) Series {
	return Series{Context: "system.cpu", Chart: "system.cpu", Dimension: dim, Units: "%", Family: "cpu"}
}

func TestChunkRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var c chunk
	type pt struct {
		t int64
		v float64
		a bool
	}
	var want []pt
	ts := int64(1_700_000_000)
	for i := 0; i < chunkCap; i++ {
		switch i % 7 {
		case 3:
			ts += 2
		case 5:
			ts += 300
		case 6:
			ts += 100000
		default:
			ts++
		}
		v := math.Floor(rng.Float64()*1000) / 10
		if i%4 == 0 {
			v = 42
		}
		if i == 9 {
			v = math.Inf(1)
		}
		p := pt{ts, v, i%13 == 0}
		want = append(want, p)
		c.append(p.t, p.v, p.a)
	}
	i := 0
	c.forEach(func(tt int64, v float64, a bool) bool {
		w := want[i]
		if tt != w.t || v != w.v || a != w.a {
			t.Fatalf("sample %d: got (%d,%v,%v) want (%d,%v,%v)", i, tt, v, a, w.t, w.v, w.a)
		}
		i++
		return true
	})
	if i != len(want) {
		t.Fatalf("decoded %d samples, want %d", i, len(want))
	}
	if c.sizeBytes() > chunkCap*16 {
		t.Fatalf("chunk not compressed: %d bytes", c.sizeBytes())
	}
}

func TestChunkCompressesSteadySeries(t *testing.T) {
	var c chunk
	for i := 0; i < chunkCap; i++ {
		c.append(int64(1000+i), 12.5, false)
	}
	if len(c.w.b) > 100 {
		t.Fatalf("steady series used %d bytes", len(c.w.b))
	}
}

func TestAppendOrderAndPoints(t *testing.T) {
	db, err := Open(Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := cpuSeries("user")
	for i := int64(0); i < 1000; i++ {
		if err := db.Append(Sample{Series: s, T: 100 + i, V: float64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Append(Sample{Series: s, T: 150, V: 1}); !errors.Is(err, ErrOutOfOrder) {
		t.Fatalf("want ErrOutOfOrder, got %v", err)
	}
	pts := db.Points(s.Key(), 500, 509)
	if len(pts) != 10 || pts[0].T != 500 || pts[0].V != 400 {
		t.Fatalf("unexpected points %+v", pts)
	}
	last, ok := db.Last(s.Key())
	if !ok || last.T != 1099 {
		t.Fatalf("last = %+v", last)
	}
}

func TestSeriesLimit(t *testing.T) {
	db, _ := Open(Options{MaxSeries: 2})
	for i, d := range []string{"a", "b"} {
		if err := db.Append(Sample{Series: cpuSeries(d), T: int64(i + 1), V: 1}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Append(Sample{Series: cpuSeries("c"), T: 5, V: 1}); !errors.Is(err, ErrSeriesLimit) {
		t.Fatalf("want ErrSeriesLimit, got %v", err)
	}
}

func TestRollupsMemoryAndDisk(t *testing.T) {
	for _, dir := range []string{"", t.TempDir()} {
		db, err := Open(Options{Dir: dir})
		if err != nil {
			t.Fatal(err)
		}
		s := cpuSeries("user")
		base := int64(1_700_000_040) - int64(1_700_000_040)%3600
		for i := int64(0); i < 3*3600; i++ {
			if err := db.Append(Sample{Series: s, T: base + i, V: float64(i % 60), Anomalous: i%60 == 0}); err != nil {
				t.Fatal(err)
			}
		}
		r1, err := db.Rollups(1, []string{s.Key()}, base, base+3*3600)
		if err != nil {
			t.Fatal(err)
		}
		rows := r1[s.Key()]
		if len(rows) != 180 {
			t.Fatalf("dir=%q tier1 rows = %d", dir, len(rows))
		}
		if rows[0].Count != 60 || rows[0].Min != 0 || rows[0].Max != 59 || math.Abs(rows[0].Avg()-29.5) > 1e-3 || rows[0].Anomalous != 1 {
			t.Fatalf("dir=%q bad rollup %+v", dir, rows[0])
		}
		r2, _ := db.Rollups(2, []string{s.Key()}, base, base+3*3600)
		if len(r2[s.Key()]) != 3 || r2[s.Key()][0].Count != 3600 {
			t.Fatalf("dir=%q tier2 = %+v", dir, r2[s.Key()])
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDiskIndexSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	db, _ := Open(Options{Dir: dir})
	s := cpuSeries("system")
	for i := int64(0); i < 600; i++ {
		_ = db.Append(Sample{Series: s, T: 6000 + i, V: 7})
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db2, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(db2.List()) != 1 || db2.LastT() != 6599 {
		t.Fatalf("index not restored: %+v", db2.List())
	}
	if err := db2.Append(Sample{Series: s, T: 6599, V: 1}); !errors.Is(err, ErrOutOfOrder) {
		t.Fatalf("restored lastT not enforced: %v", err)
	}
	r, _ := db2.Rollups(1, []string{s.Key()}, 0, 10000)
	if len(r[s.Key()]) != 10 {
		t.Fatalf("restored tier1 rows = %d", len(r[s.Key()]))
	}
}

func TestMaintainEvictsTier0AndQuota(t *testing.T) {
	dir := t.TempDir()
	db, _ := Open(Options{Dir: dir, Tier0Retention: 10 * time.Minute, DiskQuotaBytes: 10})
	s := cpuSeries("user")
	start := int64(1_700_000_000)
	for i := int64(0); i < 3*86400; i += 30 {
		_ = db.Append(Sample{Series: s, T: start + i, V: 1})
	}
	now := time.Unix(start+3*86400, 0)
	if err := db.Maintain(now); err != nil {
		t.Fatal(err)
	}
	// Eviction is per chunk, so up to one chunk older than the cut survives.
	if pts := db.Points(s.Key(), 0, now.Unix()); len(pts) == 0 || pts[0].T < now.Unix()-10*60-chunkCap*30 {
		t.Fatalf("tier0 not evicted: first=%v n=%d", pts[0].T, len(pts))
	}
	segs, _ := db.tiers[0].(*diskTier).segments()
	if len(segs) != 1 {
		t.Fatalf("quota should keep only the open segment, have %d", len(segs))
	}
}

func TestQueryTier0Grouping(t *testing.T) {
	a, _ := Open(Options{})
	b, _ := Open(Options{})
	now := time.Unix(10_000, 0)
	for i := int64(0); i < 120; i++ {
		ts := now.Unix() - 119 + i
		_ = a.Append(Sample{Series: Series{Context: "net.net", Chart: "net.eth0", Dimension: "received", Units: "kilobits/s", Labels: map[string]string{"interface": "eth0"}}, T: ts, V: 10})
		_ = a.Append(Sample{Series: Series{Context: "net.net", Chart: "net.eth1", Dimension: "received", Units: "kilobits/s", Labels: map[string]string{"interface": "eth1"}}, T: ts, V: 5, Anomalous: i%2 == 0})
		_ = b.Append(Sample{Series: Series{Context: "net.net", Chart: "net.eth0", Dimension: "received", Units: "kilobits/s", Labels: map[string]string{"interface": "eth0"}}, T: ts, V: 1})
	}
	src := []Source{{Node: "n1", DB: a}, {Node: "n2", DB: b}}
	res, err := Run(src, Query{Context: "net.net", After: -60, Points: 6}, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tier != 0 || res.Interval != 10 || len(res.Dimensions) != 1 {
		t.Fatalf("unexpected result shape %+v", res)
	}
	d := res.Dimensions[0]
	if d.Series != 3 || float64(d.Values[1]) != 16 {
		t.Fatalf("sum across series: %+v", d)
	}
	if ar := float64(d.AnomalyRate[1]); ar < 10 || ar > 25 {
		t.Fatalf("anomaly rate %v", ar)
	}
	byNode, _ := Run(src, Query{Context: "net.net", After: -60, Points: 6, GroupBy: "node"}, now)
	if len(byNode.Dimensions) != 2 || byNode.Dimensions[1].Name != "n2" || float64(byNode.Dimensions[1].Values[1]) != 1 {
		t.Fatalf("group by node: %+v", byNode.Dimensions)
	}
	byLabel, _ := Run(src, Query{Context: "net.net", After: -60, Points: 6, GroupBy: "label:interface", Labels: map[string]string{"node": "n1"}}, now)
	if len(byLabel.Dimensions) != 2 || float64(byLabel.Dimensions[0].Values[1]) != 10 {
		t.Fatalf("group by label: %+v", byLabel.Dimensions)
	}
	ctxs := Contexts(src, nil)
	if len(ctxs) != 1 || len(ctxs[0].Charts) != 3 {
		t.Fatalf("contexts: %+v", ctxs)
	}
}

func TestQueryPicksRollupTier(t *testing.T) {
	db, _ := Open(Options{Tier0Retention: time.Hour})
	base := int64(1_700_000_000) - int64(1_700_000_000)%3600
	s := cpuSeries("user")
	for i := int64(0); i < 6*3600; i += 10 {
		_ = db.Append(Sample{Series: s, T: base + i, V: 50})
	}
	now := time.Unix(base+6*3600, 0)
	res, err := Run([]Source{{Node: "n", DB: db}}, Query{Context: "system.cpu", After: -5 * 3600, Points: 50}, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tier != 1 || res.Interval%60 != 0 {
		t.Fatalf("expected tier 1, got tier %d interval %d", res.Tier, res.Interval)
	}
	if float64(res.Dimensions[0].Values[2]) != 50 {
		t.Fatalf("avg from rollups: %v", res.Dimensions[0].Values[:3])
	}
}

func TestSinceBatchesAndCursor(t *testing.T) {
	db, _ := Open(Options{})
	for i := int64(1); i <= 100; i++ {
		_ = db.Append(Sample{Series: cpuSeries("a"), T: i, V: 1})
		_ = db.Append(Sample{Series: cpuSeries("b"), T: i, V: 2})
	}
	batch, cur := db.Since(0, 40)
	if cur != 20 || len(batch) != 2 || len(batch[0].Points) != 20 {
		t.Fatalf("first batch cursor=%d len=%d", cur, len(batch))
	}
	total := 40
	for cur < 100 {
		batch, cur = db.Since(cur, 40)
		for _, b := range batch {
			total += len(b.Points)
		}
	}
	if total != 200 {
		t.Fatalf("replayed %d points, want 200", total)
	}
	if b, c := db.Since(100, 40); b != nil || c != 100 {
		t.Fatal("expected empty batch at head")
	}
}

func TestConcurrentAppendAndQuery(t *testing.T) {
	db, _ := Open(Options{})
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			s := cpuSeries(string(rune('a' + w)))
			for i := int64(1); i <= 2000; i++ {
				_ = db.Append(Sample{Series: s, T: i, V: float64(i)})
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_, _ = Run([]Source{{Node: "n", DB: db}}, Query{Context: "system.cpu", After: 1, Before: 2000}, time.Unix(2000, 0))
			_ = db.Stats()
		}
	}()
	wg.Wait()
	if st := db.Stats(); st.Series != 4 || st.NewestT != 2000 {
		t.Fatalf("stats %+v", st)
	}
}

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		p, s string
		ok   bool
	}{{"", "x", true}, {"net.*", "net.eth0", true}, {"*eth*", "net.eth0", true}, {"net.eth?", "net.eth0", false}, {"a*c", "abc", true}, {"a*c", "abd", false}}
	for _, c := range cases {
		if MatchGlob(c.p, c.s) != c.ok {
			t.Errorf("MatchGlob(%q,%q) != %v", c.p, c.s, c.ok)
		}
	}
}
