// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package workloadobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/slo"
)

// SLI names an SLO may select. Each is a good/total ratio built from counters
// Netra genuinely has; none is a latency SLI, because Netra sees counters and
// averages, not per-request durations.
//
// There is deliberately no TCP-retransmit SLI: the agent reports the sockets
// with the WORST retransmission/RTT scores (capped at 1000), so retransmissions
// over segments computed from that report would be inflated by construction.
const (
	SLIHTTP5xx    = "http_5xx"    // errors: 5xx responses; total: HTTP/1 responses seen
	SLIDNSFailure = "dns_failure" // errors: non-zero rcode; total: DNS queries
)

var validSLIs = map[string]bool{SLIHTTP5xx: true, SLIDNSFailure: true}

const (
	// observationBucket coalesces SLO observations. It is also the finest
	// window resolution: the 5-minute short window of a page alert sees one or
	// two buckets.
	observationBucket = 5 * time.Minute
	maxSLOWindow      = 90 * 24 * time.Hour
	maxSLOs           = 64
	minInterval       = 5 * time.Second
)

// Config is the Observer's configuration.
type Config struct {
	// PromSeries exports per-workload counters on /metrics. Off by default:
	// the aggregate metrics carry no workload labels by design.
	PromSeries   bool
	MaxWorkloads int
	IdleTimeout  time.Duration
	// Interval is how often agent counters are folded in. Default 60s.
	Interval time.Duration
	SLOs     []slo.Definition
}

// Enabled reports whether anything needs the Observer to run.
func (c Config) Enabled() bool { return c.PromSeries || len(c.SLOs) > 0 }

var sloNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ConfigFromEnv reads NETRA_METRICS_WORKLOAD_LABELS, _MAX, _IDLE,
// NETRA_WORKLOAD_OBS_INTERVAL and NETRA_SLO_DEFINITIONS. It returns an error
// for anything malformed so the caller can refuse to start, rather than run
// with a silently ignored SLO.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	c := Config{MaxWorkloads: 100, IdleTimeout: time.Hour, Interval: time.Minute}

	switch v := strings.ToLower(strings.TrimSpace(getenv("NETRA_METRICS_WORKLOAD_LABELS"))); v {
	case "", "off", "false", "0":
	case "on", "true", "1":
		c.PromSeries = true
	default:
		return c, fmt.Errorf("NETRA_METRICS_WORKLOAD_LABELS must be on or off, got %q", v)
	}
	if v := strings.TrimSpace(getenv("NETRA_METRICS_WORKLOAD_MAX")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			return c, fmt.Errorf("NETRA_METRICS_WORKLOAD_MAX must be 1..1000, got %q", v)
		}
		c.MaxWorkloads = n
	}
	if v := strings.TrimSpace(getenv("NETRA_METRICS_WORKLOAD_IDLE")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute {
			return c, fmt.Errorf("NETRA_METRICS_WORKLOAD_IDLE must be a duration of at least 1m, got %q", v)
		}
		c.IdleTimeout = d
	}
	if v := strings.TrimSpace(getenv("NETRA_WORKLOAD_OBS_INTERVAL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < minInterval || d > observationBucket {
			return c, fmt.Errorf("NETRA_WORKLOAD_OBS_INTERVAL must be between %s and %s, got %q", minInterval, observationBucket, v)
		}
		c.Interval = d
	}
	defs, err := ParseDefinitions(getenv("NETRA_SLO_DEFINITIONS"))
	if err != nil {
		return c, err
	}
	c.SLOs = defs
	return c, nil
}

type defJSON struct {
	Name      string    `json:"name"`
	Namespace string    `json:"namespace"`
	Workload  string    `json:"workload"`
	SLI       string    `json:"sli"`
	TargetPct flexFloat `json:"targetPct"`
	Window    string    `json:"window"`
}

// flexFloat reads a JSON number or a numeric string. Helm's --set turns 99.9
// into the string "99.9", which would otherwise make a perfectly good SLO fail
// with a baffling type error.
type flexFloat float64

func (f *flexFloat) UnmarshalJSON(b []byte) error {
	t := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if t == "" || t == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseFloat(t, 64)
	if err != nil {
		return fmt.Errorf("targetPct %s is not a number", b)
	}
	*f = flexFloat(v)
	return nil
}

// ParseDefinitions reads NETRA_SLO_DEFINITIONS: a JSON array such as
//
//	[{"name":"checkout-availability","namespace":"shop","workload":"Deployment/checkout",
//	  "sli":"http_5xx","targetPct":99.9,"window":"30d"}]
//
// Empty input means no SLOs. Windows accept Go durations plus a "d" (days)
// suffix. Invalid entries are rejected outright: the slo package would
// otherwise quietly replace a bad target with 99.9.
func ParseDefinitions(raw string) ([]slo.Definition, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var in []defJSON
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return nil, fmt.Errorf("NETRA_SLO_DEFINITIONS is not a JSON array of SLOs: %w", err)
	}
	if len(in) > maxSLOs {
		return nil, fmt.Errorf("NETRA_SLO_DEFINITIONS has %d SLOs; the limit is %d", len(in), maxSLOs)
	}
	seen := map[string]bool{}
	out := make([]slo.Definition, 0, len(in))
	for i, d := range in {
		where := fmt.Sprintf("SLO #%d (%q)", i+1, d.Name)
		if !sloNameRE.MatchString(d.Name) {
			return nil, fmt.Errorf("%s: name must match %s", where, sloNameRE)
		}
		if seen[d.Name] {
			return nil, fmt.Errorf("%s: duplicate name", where)
		}
		seen[d.Name] = true
		if !validSLIs[d.SLI] {
			return nil, fmt.Errorf("%s: sli must be %s or %s", where, SLIHTTP5xx, SLIDNSFailure)
		}
		if d.TargetPct < 50 || d.TargetPct >= 100 {
			return nil, fmt.Errorf("%s: targetPct must be at least 50 and below 100, got %v", where, float64(d.TargetPct))
		}
		win, err := parseWindow(d.Window)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		out = append(out, slo.Definition{
			Name: d.Name, Namespace: d.Namespace, Workload: d.Workload, SLI: d.SLI,
			TargetPct: float64(d.TargetPct), Window: win,
		})
	}
	return out, nil
}

func parseWindow(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 30 * 24 * time.Hour, nil
	}
	var d time.Duration
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 1 {
			return 0, fmt.Errorf("window %q is not a duration", s)
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		v, err := time.ParseDuration(s)
		if err != nil {
			return 0, fmt.Errorf("window %q is not a duration", s)
		}
		d = v
	}
	if d < time.Hour || d > maxSLOWindow {
		return 0, fmt.Errorf("window %q must be between 1h and 90d", s)
	}
	return d, nil
}

// Observer owns the Tracker and the SLO registry and is safe for concurrent
// reads (HTTP handlers) alongside the single Run loop.
type Observer struct {
	cfg     Config
	tracker *Tracker
	reg     *slo.Registry

	mu       sync.Mutex
	lastTick time.Time
	prevSev  map[string]slo.BurnSeverity
}

// NewObserver builds an Observer from a validated Config.
func NewObserver(cfg Config) (*Observer, error) {
	if cfg.MaxWorkloads <= 0 {
		cfg.MaxWorkloads = 100
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = time.Hour
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	sc := slo.DefaultConfig()
	sc.BucketWidth = observationBucket
	longest := 30 * 24 * time.Hour
	for _, d := range cfg.SLOs {
		if d.Window > longest {
			longest = d.Window
		}
	}
	// Size the ring to hold the longest window in buckets, so a 30-day budget
	// really covers 30 days instead of being cut at the default cap.
	if need := int(longest/observationBucket) + 64; need > sc.MaxObsPerSLO {
		sc.MaxObsPerSLO = need
	}
	if len(cfg.SLOs) > sc.MaxSLOs {
		return nil, errors.New("too many SLOs")
	}
	o := &Observer{
		cfg:     cfg,
		tracker: NewTracker(TrackerConfig{MaxNamed: cfg.MaxWorkloads, IdleTimeout: cfg.IdleTimeout}),
		reg:     slo.New(sc),
		prevSev: map[string]slo.BurnSeverity{},
	}
	for _, d := range cfg.SLOs {
		o.reg.Register(d)
	}
	return o, nil
}

// PromSeriesEnabled reports whether per-workload series are exported.
func (o *Observer) PromSeriesEnabled() bool { return o != nil && o.cfg.PromSeries }

// HasSLOs reports whether any SLO is defined.
func (o *Observer) HasSLOs() bool { return o != nil && len(o.cfg.SLOs) > 0 }

// Interval is the configured fold-in cadence.
func (o *Observer) Interval() time.Duration { return o.cfg.Interval }

// Snapshot returns the current per-workload totals.
func (o *Observer) Snapshot() Snapshot { return o.tracker.Snapshot() }

// SLOStatus returns the current state of every SLO.
func (o *Observer) SLOStatus(now time.Time) []slo.Status { return o.reg.Status(now) }

// Tick folds the agents' current counters in, feeds the SLOs the resulting
// per-workload growth, and calls audit for every SLO whose severity changed
// (including back to healthy, which slo.Registry.Evaluate never reports).
func (o *Observer) Tick(agents []models.AgentStatus, now time.Time, audit func(models.AuditEvent)) {
	o.mu.Lock()
	defer o.mu.Unlock()
	// The registry requires non-decreasing timestamps.
	if now.Before(o.lastTick) {
		now = o.lastTick
	}
	o.lastTick = now

	deltas := o.tracker.Update(agents, now)
	if !o.HasSLOs() {
		return
	}
	for _, d := range deltas {
		feed := func(sli string, total, errs uint64) {
			if total == 0 {
				return
			}
			o.reg.Observe(slo.Observation{
				Timestamp: now, Namespace: d.Key.Namespace, Workload: d.Key.Workload,
				SLI: sli, Total: total, Errors: min(errs, total),
			})
		}
		feed(SLIHTTP5xx, d.V[HTTPResponses], d.V[HTTP5xx])
		feed(SLIDNSFailure, d.V[DNSQueries], d.V[DNSFailures])
	}

	if audit == nil {
		return
	}
	for _, st := range o.reg.Status(now) {
		name := st.Definition.Name
		prev := o.prevSev[name]
		if prev == "" {
			prev = slo.BurnNone
		}
		if st.Severity == prev {
			continue
		}
		o.prevSev[name] = st.Severity
		action, actor := "slo.burn", "slo"
		details := map[string]any{
			"severity": string(st.Severity), "previous": string(prev),
			"compliancePct": st.CompliancePct, "budgetRemaining": st.BudgetRemaining,
			"sli": st.Definition.SLI, "targetPct": st.Definition.TargetPct,
		}
		if st.Severity == slo.BurnNone {
			action = "slo.recovered"
		} else {
			for _, w := range st.Windows {
				if w.Firing {
					details["window"] = w.Long.String() + "/" + w.Short.String()
					details["burnRate"] = w.LongBurn
					break
				}
			}
		}
		audit(models.AuditEvent{At: now.UTC(), Actor: actor, Action: action, Target: name, Details: details})
	}
}

// Run calls Tick every Interval until ctx ends, first immediately so the
// baseline exists as early as possible.
func (o *Observer) Run(ctx context.Context, fetch func() []models.AgentStatus, audit func(models.AuditEvent)) {
	tick := time.NewTicker(o.cfg.Interval)
	defer tick.Stop()
	o.Tick(fetch(), time.Now(), audit)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			o.Tick(fetch(), time.Now(), audit)
		}
	}
}
