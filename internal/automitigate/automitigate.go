// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package automitigate applies lease-bounded emergency controls when
// volumetric abuse is detected. Off by default; never runs without an
// active enforce lease. Fails open when the lease expires.
package automitigate

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/scandetect"
	"github.com/zyvorai/netra/internal/store"
)

// Config gates the feature. All knobs are env/Helm driven.
type Config struct {
	Enabled           bool
	Interval          time.Duration
	ConnRatePerSecond uint32 // applied to SYN-flood workloads
	UDPPacketDelta    uint64 // packets-per-interval threshold for UDP dest amplify
	MaxActionsPerTick int
	ShieldUDPPPS      uint32 // optional ceiling applied when UDP amplify trips
	ShieldSynPPS      uint32 // optional ceiling applied when SYN-flood trips
}

// DefaultConfig returns conservative defaults (still requires Enabled).
func DefaultConfig() Config {
	return Config{
		Enabled:           false,
		Interval:          30 * time.Second,
		ConnRatePerSecond: 10,
		UDPPacketDelta:    100000,
		MaxActionsPerTick: 20,
		ShieldUDPPPS:      20000,
		ShieldSynPPS:      10000,
	}
}

// Action records one auto-applied control for status/API.
type Action struct {
	At        time.Time `json:"at"`
	Kind      string    `json:"kind"` // conn_rate | syn_drop | blocked_ip | shield
	Target    string    `json:"target"`
	FindingID string    `json:"findingId,omitempty"`
	Detail    string    `json:"detail,omitempty"`
}

// Engine polls scan findings + agent dest rates and applies leased controls.
type Engine struct {
	log      *slog.Logger
	store    *store.Store
	scan     *scandetect.Detector
	cfg      Config
	mu       sync.Mutex
	recent   []Action
	seen     map[string]time.Time
	lastPkts map[string]uint64 // node|dst|proto → packets
}

// New builds an engine. scan may be nil (UDP-only path still runs).
func New(log *slog.Logger, st *store.Store, scan *scandetect.Detector, cfg Config) *Engine {
	if log == nil {
		log = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.ConnRatePerSecond == 0 {
		cfg.ConnRatePerSecond = 10
	}
	if cfg.MaxActionsPerTick <= 0 {
		cfg.MaxActionsPerTick = 20
	}
	if cfg.UDPPacketDelta == 0 {
		cfg.UDPPacketDelta = 100000
	}
	return &Engine{
		log: log, store: st, scan: scan, cfg: cfg,
		seen: map[string]time.Time{}, lastPkts: map[string]uint64{},
	}
}

// Status is GET /api/v1/ebpf/auto-mitigate.
type Status struct {
	Enabled bool     `json:"enabled"`
	Recent  []Action `json:"recent"`
	Note    string   `json:"note"`
}

// StatusSnapshot returns recent actions (copy).
func (e *Engine) StatusSnapshot() Status {
	if e == nil {
		return Status{Note: "disabled"}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	cp := make([]Action, len(e.recent))
	copy(cp, e.recent)
	return Status{
		Enabled: e.cfg.Enabled,
		Recent:  cp,
		Note:    "Actions require mode=enforce with an active lease; expire with the lease fail-open model.",
	}
}

// Run ticks until ctx is cancelled.
func (e *Engine) Run(ctx context.Context, fetchAgents func() []models.AgentStatus) {
	if e == nil || !e.cfg.Enabled || e.store == nil {
		return
	}
	tick := time.NewTicker(e.cfg.Interval)
	defer tick.Stop()
	e.tick(fetchAgents)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			e.tick(fetchAgents)
		}
	}
}

func (e *Engine) tick(fetchAgents func() []models.AgentStatus) {
	cfg := e.store.Config()
	if cfg.Mode != "enforce" || cfg.EnforceUntil == nil || !time.Now().Before(*cfg.EnforceUntil) {
		return
	}
	acted := 0
	if e.scan != nil {
		for _, f := range e.scan.Findings() {
			if acted >= e.cfg.MaxActionsPerTick {
				break
			}
			if f.Type != scandetect.FindingSYNFlood && f.Type != scandetect.FindingFanOut &&
				f.Type != scandetect.FindingLateral && f.Type != scandetect.FindingPortScan {
				continue
			}
			if e.already(f.ID) {
				continue
			}
			if f.Type == scandetect.FindingSYNFlood {
				if e.mitigateSYNFlood(f) {
					acted++
				}
				continue
			}
			// Fan-out / lateral / port-scan → conn-rate only.
			if e.mitigateConnRate(f) {
				acted++
			}
		}
	}
	if fetchAgents == nil {
		return
	}
	for _, a := range fetchAgents() {
		if a.Stale || acted >= e.cfg.MaxActionsPerTick {
			continue
		}
		for _, st := range a.Stats {
			if acted >= e.cfg.MaxActionsPerTick {
				break
			}
			if !strings.EqualFold(st.Protocol, "UDP") {
				continue
			}
			key := a.Node + "|" + st.DestinationIP + "|udp"
			delta := e.packetDelta(key, st.Packets)
			if delta < e.cfg.UDPPacketDelta {
				continue
			}
			ukey := "udp|" + st.DestinationIP
			if e.already(ukey) {
				continue
			}
			if e.mitigateHighUDP(st.DestinationIP, delta) {
				acted++
			}
		}
	}
}

func (e *Engine) packetDelta(key string, now uint64) uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	prev := e.lastPkts[key]
	e.lastPkts[key] = now
	if now < prev {
		return now
	}
	return now - prev
}

func (e *Engine) already(key string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if t, ok := e.seen[key]; ok && time.Since(t) < 10*time.Minute {
		return true
	}
	return false
}

func (e *Engine) mark(key string, act Action) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seen[key] = time.Now().UTC()
	e.recent = append([]Action{act}, e.recent...)
	if len(e.recent) > 100 {
		e.recent = e.recent[:100]
	}
}

func (e *Engine) mitigateSYNFlood(f scandetect.Finding) bool {
	if !e.mitigateConnRate(f) {
		return false
	}
	// Replace last action detail for clarity.
	e.mu.Lock()
	if len(e.recent) > 0 && e.recent[0].FindingID == f.ID {
		e.recent[0].Detail = "syn_flood → conn-rate lease control"
	}
	e.mu.Unlock()

	if e.cfg.ShieldSynPPS > 0 {
		e.tightenShield("syn", e.cfg.ShieldSynPPS, f.ID)
	}

	for _, dst := range f.ExampleDsts {
		host, _, _ := strings.Cut(dst, ":")
		addr, err := netip.ParseAddr(host)
		if err != nil {
			continue
		}
		entry := models.EBPFSynDropEntry{Address: addr.String(), Direction: "egress"}
		if _, err := e.store.AddSynDrop(entry, "automitigate"); err == nil {
			e.mark(f.ID+"|syn|"+addr.String(), Action{
				At: time.Now().UTC(), Kind: "syn_drop", Target: addr.String(), FindingID: f.ID,
			})
		}
	}
	return true
}

func (e *Engine) mitigateConnRate(f scandetect.Finding) bool {
	sel := models.EBPFWorkloadScope{Namespace: f.Namespace, Pod: f.Pod}
	if f.Workload != "" {
		sel.WorkloadName = f.Workload
	}
	rule := models.EBPFConnRateLimit{
		Selector:  sel,
		PerSecond: e.cfg.ConnRatePerSecond,
	}
	_, err := e.store.AddConnRateLimit(rule, "automitigate")
	if err != nil {
		e.log.Warn("automitigate conn-rate failed", "err", err, "finding", f.ID)
		return false
	}
	act := Action{
		At: time.Now().UTC(), Kind: "conn_rate", Target: f.Namespace + "/" + f.Pod,
		FindingID: f.ID, Detail: string(f.Type) + " → conn-rate lease control",
	}
	e.mark(f.ID, act)
	e.log.Info("automitigate applied conn-rate", "ns", f.Namespace, "pod", f.Pod, "finding", f.ID, "type", f.Type)
	return true
}

func (e *Engine) mitigateHighUDP(dst string, delta uint64) bool {
	addr, err := netip.ParseAddr(dst)
	if err != nil {
		return false
	}
	var addErr error
	if addr.Is4() {
		_, addErr = e.store.AddBlocked(addr.String(), "automitigate")
	} else {
		_, addErr = e.store.AddBlockedIPv6(addr.String(), "automitigate")
	}
	if addErr != nil {
		e.log.Warn("automitigate block high-udp failed", "err", addErr, "dst", dst)
		return false
	}
	key := "udp|" + dst
	e.mark(key, Action{
		At: time.Now().UTC(), Kind: "blocked_ip", Target: dst,
		Detail: "udp amplify packet delta",
	})
	if e.cfg.ShieldUDPPPS > 0 {
		e.tightenShield("udp", e.cfg.ShieldUDPPPS, key)
	}
	e.log.Info("automitigate blocked high-udp dest", "dst", dst, "delta", delta)
	return true
}

func (e *Engine) tightenShield(kind string, pps uint32, ref string) {
	cur := e.store.Config().Shield
	next := models.ShieldConfig{}
	if cur != nil {
		next = *cur
	}
	if next.Mode == "" || next.Mode == "off" {
		next.Mode = "enforce"
	}
	next.ProtectAll = true
	switch kind {
	case "syn":
		if next.SynPPS == 0 || next.SynPPS > pps {
			next.SynPPS = pps
		}
	case "udp":
		if next.UDPPPS == 0 || next.UDPPPS > pps {
			next.UDPPPS = pps
		}
	}
	if next.BurstSeconds == 0 {
		next.BurstSeconds = 1
	}
	if _, err := e.store.SetShield(next, "automitigate"); err != nil {
		e.log.Warn("automitigate shield tighten failed", "err", err)
		return
	}
	e.mark("shield|"+kind+"|"+ref, Action{
		At: time.Now().UTC(), Kind: "shield", Target: kind,
		Detail: "tightened XDP Shield PPS ceiling",
	})
}
