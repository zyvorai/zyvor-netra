// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package metricalert

import (
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/notify"
	"github.com/zyvorai/netra/internal/tsdb"
)

func TestExprEval(t *testing.T) {
	vars := func(n string) float64 {
		return map[string]float64{"this": 90, "status": 3, "WARNING": 3, "CRITICAL": 4, "used": 30, "free": 70}[n]
	}
	cases := map[string]float64{
		"1 + 2 * 3":   7,
		"(1 + 2) * 3": 9,
		"$this > 80":  1,
		"$this > (($status >= $WARNING) ? 85 : 95)":  1,
		"$this > (($status == $CRITICAL) ? 85 : 95)": 0,
		"$used * 100 / ($used + $free)":              30,
		"abs(-4) + max(1, 2) - min(5, 3)":            3,
		"!($this > 100) && $this >= 90":              1,
		"$this < 10 or $this == 90":                  1,
		"-$this % 7":                                 -6,
		"${used} + 1":                                31,
		"1 ? 2 : 3 ? 4 : 5":                          2,
		"0 ? 2 : 0 ? 4 : 5":                          5,
		"2e1 + .5":                                   20.5,
	}
	for src, want := range cases {
		e, err := Compile(src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if got := e.Eval(vars); got != want {
			t.Errorf("%s = %v, want %v", src, got, want)
		}
	}
	nan, _ := Compile("$missing > 1")
	if nan.Eval(func(string) float64 { return math.NaN() }) != 0 {
		t.Error("comparison with NaN must be false")
	}
	for _, bad := range []string{"1 +", "(1", "$", "1 ? 2", "abs(1, 2)", "foo(1)", "1 # 2"} {
		if _, err := Compile(bad); err == nil {
			t.Errorf("%q compiled", bad)
		}
	}
}

func TestDefaultRulesCompile(t *testing.T) {
	rs := DefaultRules()
	if len(rs) < 40 {
		t.Fatalf("only %d default rules", len(rs))
	}
	if _, err := New(Options{Rules: rs}); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRulesOverridesAndDisables(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "10-local.yaml"), []byte(`
alerts:
  - alarm: ram_in_use
    on: mem.used_percent
    lookup: average -1m
    warn: $this > 50
  - alarm: cpu_usage_high
    enabled: false
  - alarm: custom
    on: app.requests
    lookup: sum -1m
    crit: $this > 10
`), 0o600)
	rs, err := LoadRules(true, dir)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Rule{}
	for _, r := range rs {
		byName[r.Name] = r
	}
	if _, ok := byName["cpu_usage_high"]; ok {
		t.Error("disabled rule still loaded")
	}
	if byName["ram_in_use"].Warn != "$this > 50" || byName["custom"].Source == "builtin" {
		t.Errorf("override not applied: %+v", byName["ram_in_use"])
	}
	if _, err := New(Options{Rules: rs}); err != nil {
		t.Fatal(err)
	}
}

func TestDeployExampleRulesLoad(t *testing.T) {
	rs, err := LoadRules(true, filepath.Join("..", "..", "deploy", "metricalert.d"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Rules: rs}); err != nil {
		t.Fatal(err)
	}
}

type harness struct {
	db     *tsdb.DB
	eng    *Engine
	mu     sync.Mutex
	events []notify.Event
}

func newHarness(t *testing.T, rules ...Rule) *harness {
	t.Helper()
	db, err := tsdb.Open(tsdb.Options{})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{db: db}
	h.eng, err = New(Options{
		Rules:   rules,
		Sources: func() []tsdb.Source { return []tsdb.Source{{Node: "n1", DB: db}} },
		Publish: func(ev notify.Event) bool {
			h.mu.Lock()
			h.events = append(h.events, ev)
			h.mu.Unlock()
			return true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) feed(s tsdb.Series, from, to int64, v float64) {
	for ts := from; ts <= to; ts++ {
		_ = h.db.Append(tsdb.Sample{Series: s, T: ts, V: v})
	}
}

func (h *harness) status() Status {
	snap := h.eng.Snapshot(true, 0)
	if len(snap.Active) == 0 {
		return ""
	}
	return snap.Active[0].Status
}

var memSeries = tsdb.Series{Context: "mem.used_percent", Chart: "mem.used_percent", Dimension: "used", Units: "%"}

func memRule() Rule {
	return Rule{Name: "ram", Context: "mem.used_percent", Lookup: "average -10s", Every: "1s",
		Warn: "$this > (($status >= $WARNING) ? 70 : 80)", Crit: "$this > 95", DelayUp: "3s", DelayDown: "5s", Units: "%"}
}

func TestEngineDelaysHysteresisAndNotifies(t *testing.T) {
	h := newHarness(t, memRule())
	t0 := int64(1_700_000_000)
	h.feed(memSeries, t0-20, t0, 50)
	h.eng.Evaluate(time.Unix(t0, 0))
	if s := h.status(); s != StatusClear {
		t.Fatalf("status %s, want clear", s)
	}
	// Rise above 80: warning only after delay_up of 3s.
	for i := int64(1); i <= 15; i++ {
		h.feed(memSeries, t0+i, t0+i, 90)
		h.eng.Evaluate(time.Unix(t0+i, 0))
		if i == 8 && h.status() != StatusClear {
			t.Fatalf("raised before delay_up at +%ds: %s", i, h.status())
		}
	}
	if s := h.status(); s != StatusWarning {
		t.Fatalf("status %s, want warning", s)
	}
	// 75 is inside the hysteresis band (clears below 70 once raised).
	tt := t0 + 15
	for i := int64(1); i <= 20; i++ {
		h.feed(memSeries, tt+i, tt+i, 75)
		h.eng.Evaluate(time.Unix(tt+i, 0))
	}
	if s := h.status(); s != StatusWarning {
		t.Fatalf("hysteresis: status %s, want warning", s)
	}
	tt += 20
	for i := int64(1); i <= 30; i++ {
		h.feed(memSeries, tt+i, tt+i, 40)
		h.eng.Evaluate(time.Unix(tt+i, 0))
	}
	if s := h.status(); s != StatusClear {
		t.Fatalf("status %s, want clear", s)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.events) != 2 || h.events[0].Severity != "warning" || h.events[1].Severity != "info" || h.events[0].Source != "metricalert" {
		t.Fatalf("events %+v", h.events)
	}
	snap := h.eng.Snapshot(false, 0)
	if len(snap.History) != 3 || snap.History[0].To != StatusClear {
		t.Fatalf("history %+v", snap.History)
	}
}

func TestEngineSilenceAckAndRepeat(t *testing.T) {
	r := memRule()
	r.DelayUp, r.Repeat = "", "5s"
	h := newHarness(t, r)
	t0 := int64(1_700_000_000)
	h.feed(memSeries, t0-20, t0, 99)
	h.eng.Evaluate(time.Unix(t0, 0))
	if s := h.status(); s != StatusCritical {
		t.Fatalf("status %s", s)
	}
	for i := int64(1); i <= 6; i++ {
		h.feed(memSeries, t0+i, t0+i, 99)
		h.eng.Evaluate(time.Unix(t0+i, 0))
	}
	h.mu.Lock()
	if len(h.events) != 2 {
		t.Fatalf("repeat: %d events", len(h.events))
	}
	h.mu.Unlock()
	id := h.eng.Active()[0].ID
	if err := h.eng.Ack(id, "alice"); err != nil {
		t.Fatal(err)
	}
	for i := int64(7); i <= 20; i++ {
		h.feed(memSeries, t0+i, t0+i, 99)
		h.eng.Evaluate(time.Unix(t0+i, 0))
	}
	h.mu.Lock()
	if len(h.events) != 2 {
		t.Fatalf("acked alert repeated: %d events", len(h.events))
	}
	h.mu.Unlock()
	now := time.Unix(t0+20, 0)
	if _, err := h.eng.AddSilence(Silence{}, now); err == nil {
		t.Fatal("matcher-less silence accepted")
	}
	s, err := h.eng.AddSilence(Silence{Rule: "ra*", Until: now.Add(time.Hour)}, now)
	if err != nil {
		t.Fatal(err)
	}
	// Recovery while silenced: tracked, not notified.
	for i := int64(21); i <= 40; i++ {
		h.feed(memSeries, t0+i, t0+i, 10)
		h.eng.Evaluate(time.Unix(t0+i, 0))
	}
	h.mu.Lock()
	if len(h.events) != 2 {
		t.Fatalf("silenced alert notified: %+v", h.events)
	}
	h.mu.Unlock()
	if err := h.eng.DeleteSilence(s.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.eng.DeleteSilence(s.ID); err != ErrNotFound {
		t.Fatalf("second delete: %v", err)
	}
}

func TestEnginePerDimensionCalcAndAnomalyRate(t *testing.T) {
	swap := Rule{Name: "swap", Context: "mem.swap", Lookup: "average -10s", Every: "1s",
		Calc: "$used * 100 / ($used + $free)", Warn: "$this > 50"}
	anom := Rule{Name: "anom", Context: "net.net", Lookup: "anomaly-rate -10s", Every: "1s", Per: "dimension", Warn: "$this > 20"}
	h := newHarness(t, swap, anom)
	t0 := int64(1_700_000_000)
	h.feed(tsdb.Series{Context: "mem.swap", Chart: "mem.swap", Dimension: "used"}, t0-20, t0, 60)
	h.feed(tsdb.Series{Context: "mem.swap", Chart: "mem.swap", Dimension: "free"}, t0-20, t0, 40)
	rx := tsdb.Series{Context: "net.net", Chart: "net.eth0", Dimension: "received"}
	tx := tsdb.Series{Context: "net.net", Chart: "net.eth0", Dimension: "sent"}
	for ts := t0 - 20; ts <= t0; ts++ {
		_ = h.db.Append(tsdb.Sample{Series: rx, T: ts, V: 1, Anomalous: ts > t0-5})
		_ = h.db.Append(tsdb.Sample{Series: tx, T: ts, V: 1})
	}
	h.eng.Evaluate(time.Unix(t0, 0))
	got := map[string]Alert{}
	for _, a := range h.eng.Snapshot(true, 0).Active {
		got[a.Rule+"/"+a.Dimension] = a
	}
	if a := got["swap/"]; a.Status != StatusWarning || math.Abs(float64(a.Value)-60) > 1e-9 {
		t.Fatalf("swap %+v", a)
	}
	if a := got["anom/received"]; a.Status != StatusWarning {
		t.Fatalf("anomalous dimension %+v", a)
	}
	if a := got["anom/sent"]; a.Status != StatusClear {
		t.Fatalf("quiet dimension %+v", a)
	}
}

func TestDefaultWorkloadREDRules(t *testing.T) {
	var rules []Rule
	for _, r := range DefaultRules() {
		if r.Name == "workload_http_5xx_ratio" || r.Name == "workload_tcp_retransmits" {
			r.Every, r.DelayUp = "1s", ""
			rules = append(rules, r)
		}
	}
	if len(rules) != 2 {
		t.Fatalf("rules %d", len(rules))
	}
	h := newHarness(t, rules...)
	t0 := int64(1_700_000_000)
	lbl := map[string]string{"namespace": "shop", "workload": "cart"}
	sr := func(ctx, dim string) tsdb.Series {
		return tsdb.Series{Context: ctx, Chart: "red_shop_cart." + ctx[len("workload.red_"):], Dimension: dim, Labels: lbl}
	}
	h.feed(sr("workload.red_http", "responses"), t0-300, t0, 10)
	h.feed(sr("workload.red_http", "errors_5xx"), t0-300, t0, 1)
	h.feed(sr("workload.red_errors", "retransmits"), t0-300, t0, 8)
	h.feed(sr("workload.red_errors", "rtos"), t0-300, t0, 4)
	h.feed(sr("workload.red_errors", "blocked"), t0-300, t0, 1000)
	h.eng.Evaluate(time.Unix(t0, 0))
	got := map[string]Alert{}
	for _, a := range h.eng.Snapshot(true, 0).Active {
		got[a.Rule] = a
	}
	if a := got["workload_http_5xx_ratio"]; a.Status != StatusWarning || math.Abs(float64(a.Value)-10) > 1e-9 {
		t.Fatalf("5xx ratio %+v", a)
	}
	// blocked is excluded by the dimension filter: 8 + 4 = 12/s.
	if a := got["workload_tcp_retransmits"]; a.Status != StatusWarning || math.Abs(float64(a.Value)-12) > 1e-9 {
		t.Fatalf("retransmits %+v", a)
	}
}

func TestSilencesPersist(t *testing.T) {
	file := filepath.Join(t.TempDir(), "silences.json")
	now := time.Now()
	e, _ := New(Options{SilenceFile: file})
	if _, err := e.AddSilence(Silence{Node: "n1", Until: now.Add(time.Hour), Comment: "maintenance"}, now); err != nil {
		t.Fatal(err)
	}
	e2, _ := New(Options{SilenceFile: file})
	if ss := e2.Snapshot(false, 0).Silences; len(ss) != 1 || ss[0].Comment != "maintenance" {
		t.Fatalf("silences after reload %+v", ss)
	}
}
