// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package anomaly

import (
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/tsdb"
)

func noisySeries(n int, seed int64) []float64 {
	rng := rand.New(rand.NewSource(seed))
	out := make([]float64, n)
	for i := range out {
		out[i] = 50 + 10*math.Sin(float64(i)/30) + rng.NormFloat64()
	}
	return out
}

func TestFeaturesShape(t *testing.T) {
	f := features([]float64{1, 2, 4, 7, 11, 16, 22, 29, 37, 46}, 5, 3)
	// 9 diffs -> 7 smoothed -> 2 lagged vectors of length 6
	if len(f) != 2 || len(f[0]) != 6 {
		t.Fatalf("got %d vectors of %d", len(f), len(f[0]))
	}
	if f[0][0] != 2 { // mean of diffs 1,2,3
		t.Fatalf("smoothing wrong: %v", f[0])
	}
}

func TestDetectorFlagsSpikeButNotNoise(t *testing.T) {
	d := New(Options{})
	s := tsdb.Series{Context: "system.cpu", Chart: "system.cpu", Dimension: "user"}
	train := noisySeries(4000, 1)
	if !d.TrainSeries(s.Key(), train, 4000*time.Second, time.Now()) {
		t.Fatal("training refused")
	}
	normal := noisySeries(600, 2)
	var falsePos int
	for i, v := range normal {
		smp := []tsdb.Sample{{Series: s, T: int64(i), V: v}}
		d.Annotate(smp)
		if smp[0].Anomalous {
			falsePos++
		}
	}
	if rate := float64(falsePos) / float64(len(normal)); rate > 0.05 {
		t.Fatalf("false positive rate %.3f on normal data", rate)
	}
	flagged := false
	for i, v := range []float64{50, 51, 49, 400, 420, 410} {
		smp := []tsdb.Sample{{Series: s, T: int64(1000 + i), V: v}}
		d.Annotate(smp)
		flagged = flagged || smp[0].Anomalous
	}
	if !flagged {
		t.Fatal("spike not flagged")
	}
}

func TestTrainDueUsesStoreAndBacksOff(t *testing.T) {
	db, _ := tsdb.Open(tsdb.Options{Tier0Retention: 2 * time.Hour})
	s := tsdb.Series{Context: "c", Chart: "c", Dimension: "d"}
	short := tsdb.Series{Context: "c", Chart: "c", Dimension: "short"}
	start := int64(1_700_000_000)
	vals := noisySeries(1200, 3)
	for i, v := range vals {
		_ = db.Append(tsdb.Sample{Series: s, T: start + int64(i), V: v})
	}
	for i := 0; i < 10; i++ {
		_ = db.Append(tsdb.Sample{Series: short, T: start + int64(i), V: 1})
	}
	d := New(Options{})
	now := time.Unix(start+1200, 0)
	if n := d.TrainDue(db, now, 10); n != 1 {
		t.Fatalf("trained %d models, want 1", n)
	}
	if d.due(short.Key(), now.Add(10*time.Second)) {
		t.Fatal("series without enough data should back off")
	}
	if d.due(s.Key(), now.Add(time.Minute)) {
		t.Fatal("fresh model retrained too soon")
	}
	if !d.due(s.Key(), now.Add(11*time.Minute)) {
		t.Fatal("young model should retrain after YoungEvery")
	}
}

func TestKS(t *testing.T) {
	a := []float64{1, 2, 3, 4, 5}
	if d := KS(a, a); d != 0 {
		t.Fatalf("identical samples D=%v", d)
	}
	if d := KS(a, []float64{10, 11, 12}); d != 1 {
		t.Fatalf("disjoint samples D=%v", d)
	}
}

func TestSummarizeAndCorrelate(t *testing.T) {
	db, _ := tsdb.Open(tsdb.Options{})
	now := time.Unix(10_000, 0)
	steady := tsdb.Series{Context: "net.net", Chart: "net.eth0", Dimension: "received"}
	shifts := tsdb.Series{Context: "disk.io", Chart: "disk.io_sda", Dimension: "writes"}
	for ts := now.Unix() - 999; ts <= now.Unix(); ts++ {
		v := 100.0
		a := false
		if ts > now.Unix()-100 {
			v, a = 900, true
		}
		_ = db.Append(tsdb.Sample{Series: steady, T: ts, V: 10 + float64(ts%3)})
		_ = db.Append(tsdb.Sample{Series: shifts, T: ts, V: v, Anomalous: a})
	}
	src := []tsdb.Source{{Node: "n1", DB: db}}
	sum := Summarize(src, nil, now.Unix()-999, now.Unix(), 10, now)
	if len(sum.Nodes) != 1 || sum.Nodes[0].Anomalous != 1 || sum.Nodes[0].Dimensions != 2 {
		t.Fatalf("node summary %+v", sum.Nodes)
	}
	if math.Abs(sum.Nodes[0].AnomalyRate-5) > 0.01 {
		t.Fatalf("node anomaly rate %v", sum.Nodes[0].AnomalyRate)
	}
	if len(sum.Ranked) != 1 || sum.Ranked[0].Dimension != "writes" {
		t.Fatalf("ranked %+v", sum.Ranked)
	}
	if len(sum.Nodes[0].Timeline) != 60 {
		t.Fatalf("timeline buckets %d", len(sum.Nodes[0].Timeline))
	}
	cor := Correlate(src, nil, now.Unix()-99, now.Unix(), 10, now)
	if len(cor) == 0 || cor[0].Dimension != "writes" || cor[0].Score != 1 {
		t.Fatalf("correlate %+v", cor)
	}
}
