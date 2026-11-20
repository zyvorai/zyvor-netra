// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package alert

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/notify"
)

const (
	autoCaptureActorPrefix = "auto-capture"
	defaultAutoDuration    = 60 * time.Second
	maxAutoDuration        = 5 * time.Minute
	defaultAutoCooldown    = 10 * time.Minute
	defaultAutoMaxPPS      = 1000
	defaultAutoConcurrent  = 5
)

// AutoConfig controls opt-in automatic packet capture on critical
// drop/congestion alerts. Off unless Enabled.
type AutoConfig struct {
	Enabled       bool
	Duration      time.Duration
	Cooldown      time.Duration
	Protocol      string // default "tcp"
	Backend       string // "" or "ebpf" (default) or "afpacket"
	MaxPPS        uint32
	MaxConcurrent int
}

func (c *AutoConfig) applyDefaults() {
	if c.Duration <= 0 {
		c.Duration = defaultAutoDuration
	}
	if c.Duration > maxAutoDuration {
		c.Duration = maxAutoDuration
	}
	if c.Cooldown <= 0 {
		c.Cooldown = defaultAutoCooldown
	}
	if c.Protocol == "" {
		c.Protocol = "tcp"
	}
	if b, err := models.NormalizeCaptureBackend(c.Backend); err == nil {
		c.Backend = b
	} else {
		c.Backend = models.CaptureBackendEBPF
	}
	if c.MaxPPS == 0 {
		c.MaxPPS = defaultAutoMaxPPS
	}
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = defaultAutoConcurrent
	}
}

// CaptureStartFunc starts a capture session (typically store.SetCapture).
// actor is already set on spec.Requestor by AutoCapture before the call.
type CaptureStartFunc func(spec models.CaptureSpec) models.CaptureSpec

// CaptureActiveFunc returns the active capture for a node, if any.
type CaptureActiveFunc func(node string) *models.CaptureSpec

// CaptureCountFunc returns how many captures are currently active cluster-wide.
type CaptureCountFunc func() int

// StageContextFunc stores a drop-incident snapshot for node until the
// auto-capture PCAP begins. Nil is allowed.
type StageContextFunc func(node string, ctx models.DropIncidentContext)

// AutoCapture starts filtered, time-bounded captures when critical
// drop/congestion events fire. Safe for concurrent MaybeStart calls.
type AutoCapture struct {
	log     *slog.Logger
	cfg     AutoConfig
	start   CaptureStartFunc
	active  CaptureActiveFunc
	count   CaptureCountFunc
	publish func(notify.Event) bool
	stage   StageContextFunc

	mu         sync.Mutex
	lastByNode map[string]time.Time
}

// NewAutoCapture returns an AutoCapture. start/active/count/publish must be non-nil when Enabled.
func NewAutoCapture(log *slog.Logger, cfg AutoConfig, start CaptureStartFunc, active CaptureActiveFunc, count CaptureCountFunc, publish func(notify.Event) bool) *AutoCapture {
	cfg.applyDefaults()
	if log == nil {
		log = slog.Default()
	}
	return &AutoCapture{
		log:        log,
		cfg:        cfg,
		start:      start,
		active:     active,
		count:      count,
		publish:    publish,
		lastByNode: map[string]time.Time{},
	}
}

// WithStage attaches the callback that freezes drop-incident context
// before a capture starts. The blob is not placed on CaptureSpec, which
// the agent pulls.
func (a *AutoCapture) WithStage(stage StageContextFunc) *AutoCapture {
	if a != nil {
		a.stage = stage
	}
	return a
}

// Enabled reports whether auto-capture is configured on.
func (a *AutoCapture) Enabled() bool {
	return a != nil && a.cfg.Enabled
}

// ShouldTrigger reports whether ev is a critical drop/congestion signal
// that may start an auto-capture.
func ShouldTrigger(ev notify.Event) bool {
	if !strings.EqualFold(ev.Severity, "critical") {
		return false
	}
	switch ev.Source {
	case "kerneldiag":
		return true
	case "dropdiag-baseline":
		return ev.Kind == "kernel-drop-spike" || ev.Kind == "policy-drop-spike"
	case "dropdiag":
		return ev.Kind == "softnet-drop"
	default:
		return false
	}
}

// MaybeStart considers starting an auto-capture for ev using the current
// agent snapshot for policy-drop filter enrichment.
func (a *AutoCapture) MaybeStart(now time.Time, ev notify.Event, agents []models.AgentStatus) {
	if a == nil || !a.cfg.Enabled || !ShouldTrigger(ev) {
		return
	}
	node := resolveNode(ev, agents)
	if node == "" {
		a.log.Warn("auto-capture: cannot resolve node", "source", ev.Source, "kind", ev.Kind, "subject", ev.Subject)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if last, ok := a.lastByNode[node]; ok && now.Sub(last) < a.cfg.Cooldown {
		return
	}
	if a.active != nil {
		if cur := a.active(node); cur != nil {
			return
		}
	}
	if a.count != nil && a.count() >= a.cfg.MaxConcurrent {
		a.log.Warn("auto-capture: concurrent cap reached", "cap", a.cfg.MaxConcurrent, "node", node)
		return
	}

	proto, host, port := a.cfg.Protocol, "", uint16(0)
	if ev.Source == "dropdiag-baseline" && ev.Kind == "policy-drop-spike" {
		if p, h, po, ok := enrichFromPolicyDrops(node, agents); ok {
			proto, host, port = p, h, po
		}
	}

	spec := models.CaptureSpec{
		Node:      node,
		Backend:   a.cfg.Backend,
		Protocol:  proto,
		Host:      host,
		Port:      port,
		MaxPPS:    a.cfg.MaxPPS,
		Requestor: fmt.Sprintf("%s:%s/%s", autoCaptureActorPrefix, ev.Source, ev.Kind),
		ExpiresAt: now.UTC().Add(a.cfg.Duration),
	}
	if a.stage != nil {
		a.stage(node, BuildDropContext(now, ev, agentForNode(node, agents)))
	}
	if a.start == nil {
		return
	}
	started := a.start(spec)
	a.lastByNode[node] = now
	a.log.Info("auto-capture started",
		"node", node, "duration", a.cfg.Duration, "protocol", started.Protocol,
		"host", started.Host, "port", started.Port, "trigger", ev.Source+"/"+ev.Kind)

	if a.publish != nil {
		msg := fmt.Sprintf("auto-capture started on %s for %s/%s (%s); duration %s",
			node, ev.Source, ev.Kind, ev.Subject, a.cfg.Duration)
		_ = a.publish(notify.Event{
			Source:    "auto-capture",
			Kind:      "started",
			Severity:  "warning",
			Subject:   node,
			Message:   msg,
			Node:      node,
			Timestamp: now.UTC(),
		})
	}
}

func resolveNode(ev notify.Event, agents []models.AgentStatus) string {
	if n := strings.TrimSpace(ev.Node); n != "" {
		return n
	}
	subj := strings.TrimSpace(ev.Subject)
	if subj == "" {
		return ""
	}
	// Subjects are typically "node", "node/iface", "node/layer", "node/reason".
	if i := strings.IndexByte(subj, '/'); i > 0 {
		return subj[:i]
	}
	for _, a := range agents {
		if a.Node == subj {
			return subj
		}
	}
	return subj
}

func agentForNode(node string, agents []models.AgentStatus) models.AgentStatus {
	for i := range agents {
		if agents[i].Node == node {
			return agents[i]
		}
	}
	return models.AgentStatus{AgentReport: models.AgentReport{Node: node}}
}

func enrichFromPolicyDrops(node string, agents []models.AgentStatus) (proto, host string, port uint16, ok bool) {
	var best *models.PolicyDropStat
	for i := range agents {
		if agents[i].Node != node || agents[i].Stale {
			continue
		}
		for j := range agents[i].PolicyDrops {
			d := &agents[i].PolicyDrops[j]
			if best == nil || d.Packets > best.Packets {
				best = d
			}
		}
	}
	if best == nil {
		return "", "", 0, false
	}
	proto = ipProtoName(best.Protocol)
	host = best.DstAddr
	if host == "" {
		host = best.SrcAddr
	}
	port = best.DstPort
	if port == 0 {
		port = best.SrcPort
	}
	if proto == "" && host == "" && port == 0 {
		return "", "", 0, false
	}
	if proto == "" {
		proto = "tcp"
	}
	return proto, host, port, true
}

func ipProtoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	default:
		return ""
	}
}

// IsAutoCaptureRequestor reports whether actor/requestor is an auto-capture session.
func IsAutoCaptureRequestor(requestor string) bool {
	return strings.HasPrefix(requestor, autoCaptureActorPrefix+":") || requestor == autoCaptureActorPrefix
}
