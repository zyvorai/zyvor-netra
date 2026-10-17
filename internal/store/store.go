// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/flowlog"
	"github.com/zyvorai/netra/internal/models"
)

var ErrPersistence = errors.New("state persistence failed")

type preflight struct {
	hash      [32]byte
	expiresAt time.Time
	risk      string
	actor     string
}

// firewallRuleIndex gives one entry from EBPFFastPathConfig's flat rule
// slices a stable identity across add/edit/delete. It is deliberately kept
// out of EBPFFastPathConfig itself (see FirewallRule doc comment) — Key is
// the same canonical string used as the map key in ruleIndexByKey, letting
// both structures be rebuilt/verified against each other cheaply.
type firewallRuleIndex struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Key       string    `json:"key"`
	CreatedAt time.Time `json:"createdAt"`
	CreatedBy string    `json:"createdBy,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
	UpdatedBy string    `json:"updatedBy,omitempty"`
}

// RuleEdit is a small tagged union carrying the new value for a PatchRule
// call — exactly one field is meaningful, chosen by the target rule's Type.
// Exported so internal/api can construct one after validating a PATCH body
// the same way the corresponding Add* handler already validates its body.
type RuleEdit struct {
	Str  string // ip4, ip6, dns, sni, process
	UID  uint32
	CIDR models.EBPFCIDRRule
	Port models.EBPFPortRule
	Rate models.EBPFRateLimit
}

type Store struct {
	mu                    sync.RWMutex
	config                models.EBPFFastPathConfig
	agents                map[string]models.AgentReport
	audit                 []models.AuditEvent
	policyRevisions       []models.PolicyRevision
	nextRevisionID        uint64
	preflights            map[string]preflight
	baseline              models.BehaviorBaseline
	rateBaseline          models.RateBaseline
	rateSamples           map[string][]rateSample
	kernelNetworkSamples  map[string][]kernelNetworkSample
	healthSamples         []models.ClusterHealthSample
	ruleIndex             map[string]firewallRuleIndex
	ruleIndexByKey        map[string]string
	nextRuleSeq           map[string]uint64
	firewallRuleRevisions []models.FirewallRuleRevision
	nextFirewallRevID     uint64
	nextNetPolRuleSeq     uint64
	nextConnRateLimitSeq  uint64
	backend               *fileBackend
	// captures holds at most one desired CaptureSpec per node — deliberately
	// not part of config (which is a single cluster-wide struct) since a
	// capture session always targets one specific node. Ephemeral only
	// (never persisted): a capture session is capped at a few minutes, so
	// losing it across a controller restart is an acceptable, self-healing
	// tradeoff, unlike firewall policy or mode.
	captures map[string]models.CaptureSpec
	// captureHistory records ended sessions (metadata only, never packet
	// bytes) so the Capture page can show past captures. Unlike captures
	// above, this IS persisted (see persistence.go) since it's a small,
	// bounded audit-style log rather than live session state.
	captureHistory []models.CaptureHistoryEntry
	// nodeIsolation holds at most one allow-only egress policy per node
	// (nodeiso.go). Persisted, but enforce is demoted to shadow on load.
	nodeIsolation    map[string]models.NodeIsolationSpec
	nodeIsolationRev uint64
	// flowLog is a ring of flow deltas. Records live in memory and in
	// flowPath (state file + ".flows"), not inside the state JSON.
	flowLog  *flowlog.Log
	flowPath string
}

func New() *Store {
	return &Store{
		config:               models.EBPFFastPathConfig{Mode: "observe", ScopeMode: "all", Revision: 1},
		agents:               map[string]models.AgentReport{},
		preflights:           map[string]preflight{},
		captures:             map[string]models.CaptureSpec{},
		nodeIsolation:        map[string]models.NodeIsolationSpec{},
		rateSamples:          map[string][]rateSample{},
		kernelNetworkSamples: map[string][]kernelNetworkSample{},
		ruleIndex:            map[string]firewallRuleIndex{},
		ruleIndexByKey:       map[string]string{},
		nextRuleSeq:          map[string]uint64{},
		flowLog:              flowlog.New(),
	}
}

// reconcileRuleIndexLocked keeps ruleIndex/ruleIndexByKey in sync with the
// 9 flat rule slices on s.config, diffing against the current config rather
// than being told what changed. This means every Add*/Del*/SetRateLimit
// mutator only needs to call it once after mutating s.config — new values
// get a freshly allocated sequential ID, values no longer present lose
// their index entry, and values that already existed are left untouched
// (so this must not be used for edits, which need to preserve an ID across
// a key change — see PatchRule, which manages its own index entry instead).
// It is also used, deliberately, as a cheap self-heal after a persistence
// failure: calling it again once s.config has been rolled back to `before`
// corrects any index entries the failed attempt had already added/removed.
func (s *Store) reconcileRuleIndexLocked(actor string, now time.Time) {
	if s.ruleIndex == nil {
		s.ruleIndex = map[string]firewallRuleIndex{}
	}
	if s.ruleIndexByKey == nil {
		s.ruleIndexByKey = map[string]string{}
	}
	if s.nextRuleSeq == nil {
		s.nextRuleSeq = map[string]uint64{}
	}
	current := make(map[string]bool, len(s.ruleIndexByKey))
	touch := func(typ, key string) {
		compound := typ + "|" + key
		current[compound] = true
		if _, ok := s.ruleIndexByKey[compound]; ok {
			return
		}
		s.nextRuleSeq[typ]++
		id := typ + "-" + strconv.FormatUint(s.nextRuleSeq[typ], 10)
		s.ruleIndex[id] = firewallRuleIndex{ID: id, Type: typ, Key: key, CreatedAt: now, CreatedBy: actor}
		s.ruleIndexByKey[compound] = id
	}
	for _, v := range s.config.BlockedIPv4 {
		touch("ip4", v)
	}
	for _, v := range s.config.BlockedIPv6 {
		touch("ip6", v)
	}
	for _, v := range s.config.AllowedIPv4 {
		touch("allow4", v)
	}
	for _, v := range s.config.AllowedIPv6 {
		touch("allow6", v)
	}
	for _, v := range s.config.AllowedCIDRs {
		touch("allow-cidr", v.Direction+"|"+v.CIDR)
	}
	for _, v := range s.config.AllowedPorts {
		touch("allow-port", v.Direction+"|"+v.Protocol+"|"+strconv.FormatUint(uint64(v.Port), 10))
	}
	for _, v := range s.config.AllowedUIDs {
		touch("allow-uid", strconv.FormatUint(uint64(v), 10))
	}
	for _, v := range s.config.AllowedProcesses {
		touch("allow-process", v)
	}
	for _, v := range s.config.BlockedIngressIPv4 {
		touch("ip4-in", v)
	}
	for _, v := range s.config.BlockedIngressIPv6 {
		touch("ip6-in", v)
	}
	for _, v := range s.config.BlockedCIDRs {
		touch("cidr", v.Direction+"|"+v.CIDR)
	}
	for _, v := range s.config.BlockedPorts {
		touch("port", v.Direction+"|"+v.Protocol+"|"+strconv.FormatUint(uint64(v.Port), 10))
	}
	for _, v := range s.config.BlockedUIDs {
		touch("uid", strconv.FormatUint(uint64(v), 10))
	}
	for _, v := range s.config.BlockedDNS {
		touch("dns", v)
	}
	for _, v := range s.config.BlockedSNI {
		touch("sni", v)
	}
	for _, v := range s.config.BlockedProcesses {
		touch("process", v)
	}
	for _, v := range s.config.DeniedCapabilities {
		touch("capability", v)
	}
	for _, v := range s.config.RateLimits {
		touch("rate", v.Destination)
	}
	for compound, id := range s.ruleIndexByKey {
		if current[compound] {
			continue
		}
		delete(s.ruleIndex, id)
		delete(s.ruleIndexByKey, compound)
	}
}

func (s *Store) normalizeLocked(now time.Time) {
	if s.config.Mode == "enforce" && s.config.EnforceUntil != nil && !now.Before(*s.config.EnforceUntil) {
		s.config.Mode = "observe"
		s.config.EnforceUntil = nil
		s.config.LeaseSeconds = 0
		s.config.Revision++
		s.appendAuditLocked(models.AuditEvent{At: now.UTC(), Actor: "system", Action: "ebpf.lease.expired", Target: "fast-path"})
	}
	for token, p := range s.preflights {
		if !now.Before(p.expiresAt) {
			delete(s.preflights, token)
		}
	}
	if len(s.config.NetPolDefaultDenies) > 0 {
		out := make([]models.NetPolDefaultDeny, 0, len(s.config.NetPolDefaultDenies))
		expired := false
		for _, d := range s.config.NetPolDefaultDenies {
			if d.EnabledUntil != nil && !now.Before(*d.EnabledUntil) {
				expired = true
				key, _ := json.Marshal(d.Selector)
				s.appendAuditLocked(models.AuditEvent{At: now.UTC(), Actor: "system", Action: "ebpf.netpol.default-deny.expired", Target: string(key)})
				continue
			}
			out = append(out, d)
		}
		if expired {
			s.config.NetPolDefaultDenies = out
			s.config.Revision++
		}
	}
}

func (s *Store) Config() models.EBPFFastPathConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.normalizeLocked(time.Now())
	return cloneConfig(s.config)
}

func (s *Store) SetMode(mode string, lease time.Duration, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.normalizeLocked(time.Now())
	before := cloneConfig(s.config)
	auditLen := len(s.audit)
	s.config.Mode = mode
	s.config.EnforceUntil = nil
	s.config.LeaseSeconds = 0
	if mode == "enforce" && lease > 0 {
		until := time.Now().UTC().Add(lease)
		s.config.EnforceUntil = &until
		s.config.LeaseSeconds = int64(lease.Seconds())
	}
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.mode", Target: mode, Details: map[string]any{"leaseSeconds": s.config.LeaseSeconds}})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

// SetCapture starts (or replaces) the one active capture session for node.
// One concurrent capture per node, enforced by simply overwriting any prior
// entry — the agent-side reconcile in internal/agent's applyCapture treats
// this the same as a fresh start either way.
func (s *Store) SetCapture(spec models.CaptureSpec, actor string) models.CaptureSpec {
	s.mu.Lock()
	defer s.mu.Unlock()
	spec.Requestor = actor
	spec.StartedAt = time.Now().UTC()
	s.captures[spec.Node] = spec
	s.appendAuditLocked(models.AuditEvent{At: spec.StartedAt, Actor: actor, Action: "capture.start", Target: spec.Node, Details: map[string]any{
		"protocol": spec.Protocol, "host": spec.Host, "port": spec.Port, "snapLen": spec.SnapLen, "expiresAt": spec.ExpiresAt,
	}})
	return spec
}

// ClearCapture stops node's active capture, if any, and returns whether one
// was actually active (so callers can tell a real stop from a no-op).
func (s *Store) ClearCapture(node, actor, reason string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	spec, ok := s.captures[node]
	if !ok {
		return false
	}
	delete(s.captures, node)
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "capture.stop", Target: node, Details: map[string]any{"reason": reason}})
	s.recordCaptureHistoryLocked(spec, reason)
	return true
}

// Capture returns node's active capture spec, expiring it in place (and
// audit-logging the expiry) if its deadline has already passed — the same
// lazy-expiry style normalizeLocked already applies to EnforceUntil.
func (s *Store) Capture(node string) *models.CaptureSpec {
	s.mu.Lock()
	defer s.mu.Unlock()
	spec, ok := s.captures[node]
	if !ok {
		return nil
	}
	if !spec.ExpiresAt.IsZero() && time.Now().After(spec.ExpiresAt) {
		delete(s.captures, node)
		s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: "system", Action: "capture.stop", Target: node, Details: map[string]any{"reason": "expired"}})
		s.recordCaptureHistoryLocked(spec, "expired")
		return nil
	}
	out := spec
	return &out
}

// Captures lists every currently active capture session, expiring any that
// have passed their deadline first — backs GET /api/v1/capture/status.
func (s *Store) Captures() []models.CaptureSpec {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	out := make([]models.CaptureSpec, 0, len(s.captures))
	for node, spec := range s.captures {
		if !spec.ExpiresAt.IsZero() && now.After(spec.ExpiresAt) {
			delete(s.captures, node)
			s.appendAuditLocked(models.AuditEvent{At: now.UTC(), Actor: "system", Action: "capture.stop", Target: node, Details: map[string]any{"reason": "expired"}})
			s.recordCaptureHistoryLocked(spec, "expired")
			continue
		}
		out = append(out, spec)
	}
	return out
}

// recordCaptureHistoryLocked appends one ended session to the bounded
// capture-history log. Callers must hold s.mu.
func (s *Store) recordCaptureHistoryLocked(spec models.CaptureSpec, reason string) {
	s.captureHistory = append(s.captureHistory, models.CaptureHistoryEntry{
		Node: spec.Node, Backend: spec.Backend, Protocol: spec.Protocol, Host: spec.Host, Port: spec.Port,
		Requestor: spec.Requestor, StartedAt: spec.StartedAt, EndedAt: time.Now().UTC(), Reason: reason,
	})
	if len(s.captureHistory) > 500 {
		s.captureHistory = append([]models.CaptureHistoryEntry(nil), s.captureHistory[len(s.captureHistory)-500:]...)
	}
}

// PatchCaptureHistory finds the newest history entry for node whose
// StartedAt matches (equal UTC instant) and applies fn. Returns false if
// no matching entry exists. Used to attach auto-capture PCAP metadata
// after the agent stream finalizes.
func (s *Store) PatchCaptureHistory(node string, startedAt time.Time, fn func(*models.CaptureHistoryEntry)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	start := startedAt.UTC()
	for i := len(s.captureHistory) - 1; i >= 0; i-- {
		e := &s.captureHistory[i]
		if e.Node != node {
			continue
		}
		if e.StartedAt.UTC().Equal(start) || e.StartedAt.UTC().Sub(start).Abs() < time.Second {
			fn(e)
			return true
		}
	}
	// Fallback: newest entry for this node (stream may finalize slightly off).
	for i := len(s.captureHistory) - 1; i >= 0; i-- {
		e := &s.captureHistory[i]
		if e.Node == node {
			fn(e)
			return true
		}
	}
	return false
}

// CaptureHistory returns the most recent ended capture sessions, newest
// first, capped at limit (a non-positive limit defaults to 100).
func (s *Store) CaptureHistory(limit int) []models.CaptureHistoryEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}
	// Rebind on both branches so the size passed to make is capped at a
	// constant, not the caller's raw limit.
	const maxCaptureHistoryLimit = 500
	if limit > maxCaptureHistoryLimit {
		limit = maxCaptureHistoryLimit
	} else {
		bounded := limit
		limit = bounded
	}
	if limit > len(s.captureHistory) {
		limit = len(s.captureHistory)
	}
	out := make([]models.CaptureHistoryEntry, limit)
	for i := 0; i < limit; i++ {
		out[i] = s.captureHistory[len(s.captureHistory)-1-i]
	}
	return out
}

func (s *Store) AddBlocked(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.BlockedIPv4 {
		if x == ip {
			return cloneConfig(s.config), nil
		}
	}
	before := cloneConfig(s.config)
	auditLen := len(s.audit)
	s.config.BlockedIPv4 = append(s.config.BlockedIPv4, ip)
	sort.Strings(s.config.BlockedIPv4)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.deny.add", Target: ip})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelBlocked(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := cloneConfig(s.config)
	auditLen := len(s.audit)
	out := s.config.BlockedIPv4[:0]
	for _, x := range s.config.BlockedIPv4 {
		if x != ip {
			out = append(out, x)
		}
	}
	if len(out) != len(s.config.BlockedIPv4) {
		s.config.BlockedIPv4 = append([]string(nil), out...)
		s.config.Revision++
		s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.deny.delete", Target: ip})
		s.reconcileRuleIndexLocked(actor, time.Now().UTC())
		if err := s.persistLocked(); err != nil {
			s.config = before
			s.audit = s.audit[:auditLen]
			s.reconcileRuleIndexLocked("system", time.Now().UTC())
			return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
		}
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddBlockedIPv6(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.BlockedIPv6 {
		if x == ip {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.BlockedIPv6 = append(s.config.BlockedIPv6, ip)
	sort.Strings(s.config.BlockedIPv6)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.deny6.add", Target: ip})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelBlockedIPv6(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]string, 0, len(s.config.BlockedIPv6))
	for _, x := range s.config.BlockedIPv6 {
		if x != ip {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.BlockedIPv6) {
		return cloneConfig(s.config), nil
	}
	s.config.BlockedIPv6 = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.deny6.delete", Target: ip})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

// AddSynDrop/DelSynDrop manage EBPFSynDropEntry entries directly (equality
// comparison, no generated ID) — mirroring AddCIDR/DelCIDR's shape but,
// like AddNetPolRule/AddConnRateLimit, deliberately outside the generic
// ruleIndex/ListRules/PatchRule system: this is a low-cardinality flag
// list, not a primary rule type, and doesn't need edit-in-place/history.
func (s *Store) AddSynDrop(entry models.EBPFSynDropEntry, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.SynDrop {
		if x == entry {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.SynDrop = append(s.config.SynDrop, entry)
	sort.Slice(s.config.SynDrop, func(i, j int) bool {
		if s.config.SynDrop[i].Direction == s.config.SynDrop[j].Direction {
			return s.config.SynDrop[i].Address < s.config.SynDrop[j].Address
		}
		return s.config.SynDrop[i].Direction < s.config.SynDrop[j].Direction
	})
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.syndrop.add", Target: entry.Address, Details: map[string]any{"direction": entry.Direction}})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelSynDrop(entry models.EBPFSynDropEntry, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]models.EBPFSynDropEntry, 0, len(s.config.SynDrop))
	for _, x := range s.config.SynDrop {
		if x != entry {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.SynDrop) {
		return cloneConfig(s.config), nil
	}
	s.config.SynDrop = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.syndrop.delete", Target: entry.Address, Details: map[string]any{"direction": entry.Direction}})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

// AddSynDropCIDR/DelSynDropCIDR are the CIDR counterpart of
// AddSynDrop/DelSynDrop above — same equality-comparison, no-generated-ID,
// outside-the-generic-ruleIndex shape, for EBPFSynDropCIDR entries.
func (s *Store) AddSynDropCIDR(entry models.EBPFSynDropCIDR, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.SynDropCIDR {
		if x == entry {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.SynDropCIDR = append(s.config.SynDropCIDR, entry)
	sort.Slice(s.config.SynDropCIDR, func(i, j int) bool {
		if s.config.SynDropCIDR[i].Direction == s.config.SynDropCIDR[j].Direction {
			return s.config.SynDropCIDR[i].CIDR < s.config.SynDropCIDR[j].CIDR
		}
		return s.config.SynDropCIDR[i].Direction < s.config.SynDropCIDR[j].Direction
	})
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.syndropcidr.add", Target: entry.CIDR, Details: map[string]any{"direction": entry.Direction}})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelSynDropCIDR(entry models.EBPFSynDropCIDR, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]models.EBPFSynDropCIDR, 0, len(s.config.SynDropCIDR))
	for _, x := range s.config.SynDropCIDR {
		if x != entry {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.SynDropCIDR) {
		return cloneConfig(s.config), nil
	}
	s.config.SynDropCIDR = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.syndropcidr.delete", Target: entry.CIDR, Details: map[string]any{"direction": entry.Direction}})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddCIDR(rule models.EBPFCIDRRule, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.BlockedCIDRs {
		if x == rule {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.BlockedCIDRs = append(s.config.BlockedCIDRs, rule)
	sort.Slice(s.config.BlockedCIDRs, func(i, j int) bool {
		if s.config.BlockedCIDRs[i].Direction == s.config.BlockedCIDRs[j].Direction {
			return s.config.BlockedCIDRs[i].CIDR < s.config.BlockedCIDRs[j].CIDR
		}
		return s.config.BlockedCIDRs[i].Direction < s.config.BlockedCIDRs[j].Direction
	})
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.cidr.add", Target: rule.CIDR, Details: map[string]any{"direction": rule.Direction}})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelCIDR(rule models.EBPFCIDRRule, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]models.EBPFCIDRRule, 0, len(s.config.BlockedCIDRs))
	for _, x := range s.config.BlockedCIDRs {
		if x != rule {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.BlockedCIDRs) {
		return cloneConfig(s.config), nil
	}
	s.config.BlockedCIDRs = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.cidr.delete", Target: rule.CIDR, Details: map[string]any{"direction": rule.Direction}})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddPortRule(rule models.EBPFPortRule, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.BlockedPorts {
		if x == rule {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.BlockedPorts = append(s.config.BlockedPorts, rule)
	sort.Slice(s.config.BlockedPorts, func(i, j int) bool {
		a, b := s.config.BlockedPorts[i], s.config.BlockedPorts[j]
		if a.Direction != b.Direction {
			return a.Direction < b.Direction
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.Port < b.Port
	})
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.port.add", Target: fmt.Sprintf("%s/%d", rule.Protocol, rule.Port), Details: map[string]any{"direction": rule.Direction}})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelPortRule(rule models.EBPFPortRule, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]models.EBPFPortRule, 0, len(s.config.BlockedPorts))
	for _, x := range s.config.BlockedPorts {
		if x != rule {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.BlockedPorts) {
		return cloneConfig(s.config), nil
	}
	s.config.BlockedPorts = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.port.delete", Target: fmt.Sprintf("%s/%d", rule.Protocol, rule.Port), Details: map[string]any{"direction": rule.Direction}})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddUID(uid uint32, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.BlockedUIDs {
		if x == uid {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.BlockedUIDs = append(s.config.BlockedUIDs, uid)
	sort.Slice(s.config.BlockedUIDs, func(i, j int) bool { return s.config.BlockedUIDs[i] < s.config.BlockedUIDs[j] })
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.uid.add", Target: fmt.Sprint(uid)})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelUID(uid uint32, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]uint32, 0, len(s.config.BlockedUIDs))
	for _, x := range s.config.BlockedUIDs {
		if x != uid {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.BlockedUIDs) {
		return cloneConfig(s.config), nil
	}
	s.config.BlockedUIDs = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.uid.delete", Target: fmt.Sprint(uid)})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddDNS(name, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.BlockedDNS {
		if x == name {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.BlockedDNS = append(s.config.BlockedDNS, name)
	sort.Strings(s.config.BlockedDNS)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.dns.add", Target: name})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}
func (s *Store) DelDNS(name, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]string, 0, len(s.config.BlockedDNS))
	for _, x := range s.config.BlockedDNS {
		if x != name {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.BlockedDNS) {
		return cloneConfig(s.config), nil
	}
	s.config.BlockedDNS = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.dns.delete", Target: name})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}
func (s *Store) AddSNI(name, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.BlockedSNI {
		if x == name {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.BlockedSNI = append(s.config.BlockedSNI, name)
	sort.Strings(s.config.BlockedSNI)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.sni.add", Target: name})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelSNI(name, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]string, 0, len(s.config.BlockedSNI))
	for _, x := range s.config.BlockedSNI {
		if x != name {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.BlockedSNI) {
		return cloneConfig(s.config), nil
	}
	s.config.BlockedSNI = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.sni.delete", Target: name})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddProcess(name, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.BlockedProcesses {
		if x == name {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.BlockedProcesses = append(s.config.BlockedProcesses, name)
	sort.Strings(s.config.BlockedProcesses)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.process.add", Target: name})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}
func (s *Store) DelProcess(name, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]string, 0, len(s.config.BlockedProcesses))
	for _, x := range s.config.BlockedProcesses {
		if x != name {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.BlockedProcesses) {
		return cloneConfig(s.config), nil
	}
	s.config.BlockedProcesses = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.process.delete", Target: name})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) SetWorkloadScopes(mode string, scopes []models.EBPFWorkloadScope, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := cloneConfig(s.config)
	auditLen := len(s.audit)
	if mode == "" {
		mode = "all"
	}
	s.config.ScopeMode = mode
	s.config.WorkloadScopes = cloneScopes(scopes)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.scope.set", Target: mode, Details: map[string]any{"scopes": len(scopes)}})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) SetRateLimit(rule models.EBPFRateLimit, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]models.EBPFRateLimit, 0, len(s.config.RateLimits)+1)
	for _, x := range s.config.RateLimits {
		if x.Destination != rule.Destination {
			out = append(out, x)
		}
	}
	if rule.PPS > 0 || rule.BPS > 0 {
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Destination < out[j].Destination })
	s.config.RateLimits = out
	s.config.Revision++
	action := "ebpf.rate.set"
	if rule.PPS == 0 && rule.BPS == 0 {
		action = "ebpf.rate.delete"
	}
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: action, Target: rule.Destination, Details: map[string]any{"pps": rule.PPS, "bps": rule.BPS}})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

// RuleType returns the stable-ID rule index's Type for id, or false if no
// such rule exists (already deleted, or never a flat-rule type — Shield and
// NetPol rows in the unified table have no stable ID in this phase).
func (s *Store) RuleType(id string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.ruleIndex[id]
	return idx.Type, ok
}

// ListRules flattens the 9 indexed flat rule types into one summary view
// for the unified Firewall table. Built from ruleIndex (identity/metadata)
// cross-referenced against the live s.config values (current match data) —
// the two are always in sync because every mutator calls
// reconcileRuleIndexLocked before returning.
func (s *Store) ListRules() []models.FirewallRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rateByDest := make(map[string]models.EBPFRateLimit, len(s.config.RateLimits))
	for _, r := range s.config.RateLimits {
		rateByDest[r.Destination] = r
	}
	out := make([]models.FirewallRule, 0, len(s.ruleIndex))
	for id, idx := range s.ruleIndex {
		fr := models.FirewallRule{ID: id, Type: idx.Type, CreatedAt: idx.CreatedAt, CreatedBy: idx.CreatedBy, UpdatedAt: idx.UpdatedAt, UpdatedBy: idx.UpdatedBy}
		switch idx.Type {
		case "ip4", "ip6", "allow4", "allow6", "ip4-in", "ip6-in", "dns", "sni", "process", "allow-process", "capability":
			fr.Value = idx.Key
			fr.Summary = idx.Key
			if idx.Type == "capability" {
				fr.Summary = "deny socket for " + idx.Key
			}
			if idx.Type == "allow4" || idx.Type == "allow6" {
				fr.Summary = "allow " + idx.Key
			}
			if idx.Type == "ip4-in" || idx.Type == "ip6-in" {
				fr.Summary = "ingress deny " + idx.Key
				fr.Direction = "ingress"
			}
			if idx.Type == "allow-process" {
				fr.Summary = "allow " + idx.Key
			}
		case "allow-cidr":
			parts := strings.SplitN(idx.Key, "|", 2)
			if len(parts) == 2 {
				fr.Direction, fr.CIDR = parts[0], parts[1]
			}
			fr.Summary = "allow " + fr.Direction + " · " + fr.CIDR
		case "uid", "allow-uid":
			fr.Value = idx.Key
			fr.Summary = "uid " + idx.Key
			if idx.Type == "allow-uid" {
				fr.Summary = "allow uid " + idx.Key
			}
		case "cidr":
			parts := strings.SplitN(idx.Key, "|", 2)
			if len(parts) == 2 {
				fr.Direction, fr.CIDR = parts[0], parts[1]
			}
			fr.Summary = fr.Direction + " · " + fr.CIDR
		case "port":
			parts := strings.SplitN(idx.Key, "|", 3)
			if len(parts) == 3 {
				fr.Direction, fr.Protocol = parts[0], parts[1]
				if p, err := strconv.ParseUint(parts[2], 10, 16); err == nil {
					fr.Port = uint16(p)
				}
			}
			fr.Summary = fmt.Sprintf("%s · %s/%d", fr.Direction, fr.Protocol, fr.Port)
		case "allow-port":
			parts := strings.SplitN(idx.Key, "|", 3)
			if len(parts) == 3 {
				fr.Direction, fr.Protocol = parts[0], parts[1]
				if p, err := strconv.ParseUint(parts[2], 10, 16); err == nil {
					fr.Port = uint16(p)
				}
			}
			fr.Summary = fmt.Sprintf("allow %s · %s/%d", fr.Direction, fr.Protocol, fr.Port)
		case "rate":
			fr.Destination = idx.Key
			r := rateByDest[idx.Key]
			fr.PPS, fr.BPS = r.PPS, r.BPS
			fr.Summary = fmt.Sprintf("%s · %dpps", fr.Destination, fr.PPS)
			if fr.BPS > 0 {
				fr.Summary += fmt.Sprintf(" · %dBps", fr.BPS)
			}
		default:
			continue
		}
		out = append(out, fr)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Summary < out[j].Summary
	})
	return out
}

// DeleteRule resolves id to its current type/value and calls the same
// Del*/SetRateLimit method the legacy value-keyed routes already use — this
// is a thin ID-based wrapper, not a second deletion code path.
func (s *Store) DeleteRule(id, actor string) (models.EBPFFastPathConfig, error) {
	typ, ok := s.RuleType(id)
	if !ok {
		return s.Config(), fmt.Errorf("rule %s not found", id)
	}
	s.mu.RLock()
	key := s.ruleIndex[id].Key
	s.mu.RUnlock()
	switch typ {
	case "ip4":
		return s.DelBlocked(key, actor)
	case "ip6":
		return s.DelBlockedIPv6(key, actor)
	case "allow4":
		return s.DelAllowed(key, actor)
	case "allow6":
		return s.DelAllowedIPv6(key, actor)
	case "allow-cidr":
		parts := strings.SplitN(key, "|", 2)
		if len(parts) != 2 {
			return s.Config(), fmt.Errorf("corrupt allow-cidr rule index entry")
		}
		return s.DelAllowedCIDR(models.EBPFCIDRRule{Direction: parts[0], CIDR: parts[1]}, actor)
	case "allow-port":
		parts := strings.SplitN(key, "|", 3)
		if len(parts) != 3 {
			return s.Config(), fmt.Errorf("corrupt allow-port rule index entry")
		}
		port, err := strconv.ParseUint(parts[2], 10, 16)
		if err != nil {
			return s.Config(), fmt.Errorf("corrupt allow-port rule index entry")
		}
		return s.DelAllowedPort(models.EBPFPortRule{Direction: parts[0], Protocol: parts[1], Port: uint16(port)}, actor)
	case "allow-uid":
		uid, err := strconv.ParseUint(key, 10, 32)
		if err != nil {
			return s.Config(), fmt.Errorf("corrupt allow-uid rule index entry")
		}
		return s.DelAllowedUID(uint32(uid), actor)
	case "allow-process":
		return s.DelAllowedProcess(key, actor)
	case "ip4-in":
		return s.DelBlockedIngress(key, actor)
	case "ip6-in":
		return s.DelBlockedIngressIPv6(key, actor)
	case "cidr":
		parts := strings.SplitN(key, "|", 2)
		if len(parts) != 2 {
			return s.Config(), fmt.Errorf("corrupt cidr rule index entry")
		}
		return s.DelCIDR(models.EBPFCIDRRule{Direction: parts[0], CIDR: parts[1]}, actor)
	case "port":
		parts := strings.SplitN(key, "|", 3)
		if len(parts) != 3 {
			return s.Config(), fmt.Errorf("corrupt port rule index entry")
		}
		port, err := strconv.ParseUint(parts[2], 10, 16)
		if err != nil {
			return s.Config(), fmt.Errorf("corrupt port rule index entry")
		}
		return s.DelPortRule(models.EBPFPortRule{Direction: parts[0], Protocol: parts[1], Port: uint16(port)}, actor)
	case "uid":
		uid, err := strconv.ParseUint(key, 10, 32)
		if err != nil {
			return s.Config(), fmt.Errorf("corrupt uid rule index entry")
		}
		return s.DelUID(uint32(uid), actor)
	case "dns":
		return s.DelDNS(key, actor)
	case "sni":
		return s.DelSNI(key, actor)
	case "process":
		return s.DelProcess(key, actor)
	case "capability":
		return s.DelDeniedCapability(key, actor)
	case "rate":
		return s.SetRateLimit(models.EBPFRateLimit{Destination: key, PPS: 0}, actor)
	default:
		return s.Config(), fmt.Errorf("rule type %s does not support delete-by-id", typ)
	}
}

// PatchRule atomically replaces one rule's value while preserving its ID,
// recording a before/after revision snapshot. Unlike the generic
// Add*/Del*/SetRateLimit mutators, it manages ruleIndex/ruleIndexByKey
// directly (not via reconcileRuleIndexLocked) so the same ID survives a key
// change, and rolls both back explicitly on persistence failure since
// reconcile's generic self-heal cannot tell "this ID's key changed" apart
// from "this key was deleted and an unrelated new one was added".
func (s *Store) PatchRule(id string, edit RuleEdit, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, ok := s.ruleIndex[id]
	if !ok {
		return cloneConfig(s.config), fmt.Errorf("rule %s not found", id)
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	beforeEntry := idx
	oldCompound := idx.Type + "|" + idx.Key
	beforeEdit, err := currentRuleEditLocked(s.config, idx)
	if err != nil {
		return cloneConfig(s.config), err
	}

	var newKey string
	switch idx.Type {
	case "ip4":
		a, err := netip.ParseAddr(edit.Str)
		if err != nil || !a.Is4() {
			return cloneConfig(s.config), fmt.Errorf("valid IPv4 required")
		}
		newKey = a.String()
		s.config.BlockedIPv4 = replaceStr(s.config.BlockedIPv4, idx.Key, newKey)
		sort.Strings(s.config.BlockedIPv4)
	case "ip6":
		a, err := netip.ParseAddr(edit.Str)
		if err != nil || !a.Is6() || a.Is4In6() {
			return cloneConfig(s.config), fmt.Errorf("valid IPv6 required")
		}
		newKey = a.String()
		s.config.BlockedIPv6 = replaceStr(s.config.BlockedIPv6, idx.Key, newKey)
		sort.Strings(s.config.BlockedIPv6)
	case "cidr":
		newKey = edit.CIDR.Direction + "|" + edit.CIDR.CIDR
		s.config.BlockedCIDRs = replaceCIDR(s.config.BlockedCIDRs, idx.Key, edit.CIDR)
		sort.Slice(s.config.BlockedCIDRs, func(i, j int) bool {
			if s.config.BlockedCIDRs[i].Direction == s.config.BlockedCIDRs[j].Direction {
				return s.config.BlockedCIDRs[i].CIDR < s.config.BlockedCIDRs[j].CIDR
			}
			return s.config.BlockedCIDRs[i].Direction < s.config.BlockedCIDRs[j].Direction
		})
	case "port":
		newKey = edit.Port.Direction + "|" + edit.Port.Protocol + "|" + strconv.FormatUint(uint64(edit.Port.Port), 10)
		s.config.BlockedPorts = replacePort(s.config.BlockedPorts, idx.Key, edit.Port)
		sort.Slice(s.config.BlockedPorts, func(i, j int) bool {
			a, b := s.config.BlockedPorts[i], s.config.BlockedPorts[j]
			if a.Direction != b.Direction {
				return a.Direction < b.Direction
			}
			if a.Protocol != b.Protocol {
				return a.Protocol < b.Protocol
			}
			return a.Port < b.Port
		})
	case "uid":
		newKey = strconv.FormatUint(uint64(edit.UID), 10)
		s.config.BlockedUIDs = replaceUID(s.config.BlockedUIDs, idx.Key, edit.UID)
		sort.Slice(s.config.BlockedUIDs, func(i, j int) bool { return s.config.BlockedUIDs[i] < s.config.BlockedUIDs[j] })
	case "dns":
		newKey = edit.Str
		s.config.BlockedDNS = replaceStr(s.config.BlockedDNS, idx.Key, newKey)
		sort.Strings(s.config.BlockedDNS)
	case "sni":
		newKey = edit.Str
		s.config.BlockedSNI = replaceStr(s.config.BlockedSNI, idx.Key, newKey)
		sort.Strings(s.config.BlockedSNI)
	case "process":
		newKey = edit.Str
		s.config.BlockedProcesses = replaceStr(s.config.BlockedProcesses, idx.Key, newKey)
		sort.Strings(s.config.BlockedProcesses)
	case "capability":
		newKey = edit.Str
		s.config.DeniedCapabilities = replaceStr(s.config.DeniedCapabilities, idx.Key, newKey)
		sort.Strings(s.config.DeniedCapabilities)
	case "rate":
		newKey = edit.Rate.Destination
		s.config.RateLimits = replaceRate(s.config.RateLimits, idx.Key, edit.Rate)
		sort.Slice(s.config.RateLimits, func(i, j int) bool { return s.config.RateLimits[i].Destination < s.config.RateLimits[j].Destination })
	default:
		return cloneConfig(s.config), fmt.Errorf("rule type %s does not support edit", idx.Type)
	}

	now := time.Now().UTC()
	newCompound := idx.Type + "|" + newKey
	delete(s.ruleIndexByKey, oldCompound)
	idx.Key = newKey
	idx.UpdatedAt = now
	idx.UpdatedBy = actor
	s.ruleIndex[id] = idx
	s.ruleIndexByKey[newCompound] = id
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: now, Actor: actor, Action: "ebpf.rule.patch", Target: id, Details: map[string]any{"type": idx.Type}})
	beforeJSON, _ := json.Marshal(beforeEdit)
	afterJSON, _ := json.Marshal(edit)
	s.recordFirewallRuleRevisionLocked(id, "update", actor, beforeJSON, afterJSON)
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		delete(s.ruleIndexByKey, newCompound)
		s.ruleIndex[id] = beforeEntry
		s.ruleIndexByKey[oldCompound] = id
		if len(s.firewallRuleRevisions) > 0 {
			s.firewallRuleRevisions = s.firewallRuleRevisions[:len(s.firewallRuleRevisions)-1]
			s.nextFirewallRevID--
		}
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

// RollbackFirewallRule undoes one specific edit by re-applying that
// revision's Before value as a new PatchRule edit (never mutates history in
// place — the rollback itself becomes a new "update" revision, exactly like
// PolicyRevision rollback). Deliberately restores Before, not After:
// "rollback revision N" means "undo the change revision N made", the
// natural action for a history entry's rollback button, not "re-apply the
// same edit again."
func (s *Store) RollbackFirewallRule(ruleID string, revisionID uint64, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.RLock()
	var target models.FirewallRuleRevision
	found := false
	for _, r := range s.firewallRuleRevisions {
		if r.RuleID == ruleID && r.ID == revisionID {
			target = r
			found = true
			break
		}
	}
	s.mu.RUnlock()
	if !found {
		return s.Config(), fmt.Errorf("revision %d not found for rule %s", revisionID, ruleID)
	}
	if len(target.Before) == 0 {
		return s.Config(), fmt.Errorf("revision %d has no restorable prior state", revisionID)
	}
	var edit RuleEdit
	if err := json.Unmarshal(target.Before, &edit); err != nil {
		return s.Config(), fmt.Errorf("revision %d is not a restorable edit: %w", revisionID, err)
	}
	return s.PatchRule(ruleID, edit, actor)
}

func (s *Store) recordFirewallRuleRevisionLocked(ruleID, action, actor string, before, after []byte) {
	s.nextFirewallRevID++
	s.firewallRuleRevisions = append(s.firewallRuleRevisions, models.FirewallRuleRevision{
		ID: s.nextFirewallRevID, RuleID: ruleID, At: time.Now().UTC(), Actor: actor, Action: action,
		Before: append(json.RawMessage(nil), before...), After: append(json.RawMessage(nil), after...),
	})
	if len(s.firewallRuleRevisions) > 1000 {
		s.firewallRuleRevisions = append([]models.FirewallRuleRevision(nil), s.firewallRuleRevisions[len(s.firewallRuleRevisions)-1000:]...)
	}
}

// FirewallRuleHistory returns revisions newest-first, optionally filtered
// to one rule ID.
func (s *Store) FirewallRuleHistory(ruleID string, limit int) []models.FirewallRuleRevision {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = 50
	}
	out := make([]models.FirewallRuleRevision, 0, limit)
	for i := len(s.firewallRuleRevisions) - 1; i >= 0 && len(out) < limit; i-- {
		r := s.firewallRuleRevisions[i]
		if ruleID != "" && r.RuleID != ruleID {
			continue
		}
		out = append(out, r)
	}
	return out
}

func currentRuleEditLocked(cfg models.EBPFFastPathConfig, idx firewallRuleIndex) (RuleEdit, error) {
	switch idx.Type {
	case "ip4", "ip6", "dns", "sni", "process", "capability":
		return RuleEdit{Str: idx.Key}, nil
	case "uid":
		uid, err := strconv.ParseUint(idx.Key, 10, 32)
		if err != nil {
			return RuleEdit{}, fmt.Errorf("corrupt uid rule index entry")
		}
		return RuleEdit{UID: uint32(uid)}, nil
	case "cidr":
		for _, r := range cfg.BlockedCIDRs {
			if r.Direction+"|"+r.CIDR == idx.Key {
				return RuleEdit{CIDR: r}, nil
			}
		}
	case "port":
		for _, r := range cfg.BlockedPorts {
			if r.Direction+"|"+r.Protocol+"|"+strconv.FormatUint(uint64(r.Port), 10) == idx.Key {
				return RuleEdit{Port: r}, nil
			}
		}
	case "rate":
		for _, r := range cfg.RateLimits {
			if r.Destination == idx.Key {
				return RuleEdit{Rate: r}, nil
			}
		}
	}
	return RuleEdit{}, fmt.Errorf("rule value for %s not found in current config", idx.ID)
}

func replaceStr(in []string, old, new string) []string {
	out := make([]string, 0, len(in))
	for _, x := range in {
		if x != old {
			out = append(out, x)
		}
	}
	return append(out, new)
}
func replaceCIDR(in []models.EBPFCIDRRule, oldKey string, new models.EBPFCIDRRule) []models.EBPFCIDRRule {
	out := make([]models.EBPFCIDRRule, 0, len(in))
	for _, x := range in {
		if x.Direction+"|"+x.CIDR != oldKey {
			out = append(out, x)
		}
	}
	return append(out, new)
}
func replacePort(in []models.EBPFPortRule, oldKey string, new models.EBPFPortRule) []models.EBPFPortRule {
	out := make([]models.EBPFPortRule, 0, len(in))
	for _, x := range in {
		if x.Direction+"|"+x.Protocol+"|"+strconv.FormatUint(uint64(x.Port), 10) != oldKey {
			out = append(out, x)
		}
	}
	return append(out, new)
}
func replaceUID(in []uint32, oldKey string, new uint32) []uint32 {
	out := make([]uint32, 0, len(in))
	for _, x := range in {
		if strconv.FormatUint(uint64(x), 10) != oldKey {
			out = append(out, x)
		}
	}
	return append(out, new)
}
func replaceRate(in []models.EBPFRateLimit, oldKey string, new models.EBPFRateLimit) []models.EBPFRateLimit {
	out := make([]models.EBPFRateLimit, 0, len(in))
	for _, x := range in {
		if x.Destination != oldKey {
			out = append(out, x)
		}
	}
	return append(out, new)
}

// SetShield replaces the DDoS shield config wholesale. Generation is bumped
// last, after ProtectedIPv4/thresholds are already in place, so an agent
// that observes the new generation always sees a fully-populated config —
// never a window where mode has flipped to enforce but the protected-IP set
// is still the old (possibly empty) one. See docs/tcx-and-shield.md.
func (s *Store) SetShield(cfg models.ShieldConfig, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	prevGen := uint32(0)
	if s.config.Shield != nil {
		prevGen = s.config.Shield.Generation
	}
	protected := append([]string(nil), cfg.ProtectedIPv4...)
	sort.Strings(protected)
	next := cfg
	next.ProtectedIPv4 = protected
	next.Generation = prevGen + 1
	s.config.Shield = &next
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.shield.set", Target: cfg.Mode, Details: map[string]any{"protectedCount": len(protected), "generation": next.Generation}})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) SetNetPolEnabled(enabled bool, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.NetPolEnabled = enabled
	s.config.Revision++
	action := "ebpf.netpol.disable"
	if enabled {
		action = "ebpf.netpol.enable"
	}
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: action, Target: "netpol"})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) SetNetPolV2Enabled(enabled bool, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.NetPolV2Enabled = enabled
	s.config.Revision++
	action := "ebpf.netpol.v2.disable"
	if enabled {
		action = "ebpf.netpol.v2.enable"
	}
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: action, Target: "netpol-v2"})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

// AddNetPolRule appends a new v2 allow/deny rule with a freshly allocated
// ID — no dedup-by-value here (unlike the flat rule types): two identical
// rules from different callers are legitimately distinct entries with
// their own lifecycle, since NetPolRule doesn't feed the Phase 2 rule-ID
// system (see docs/firewall.md).
func (s *Store) AddNetPolRule(rule models.NetPolRule, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.nextNetPolRuleSeq++
	rule.ID = "netpolrule-" + strconv.FormatUint(s.nextNetPolRuleSeq, 10)
	rule.CreatedAt = time.Now().UTC()
	rule.CreatedBy = actor
	rule.Selector = cloneScopes([]models.EBPFWorkloadScope{rule.Selector})[0]
	s.config.NetPolRules = append(s.config.NetPolRules, rule)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: rule.CreatedAt, Actor: actor, Action: "ebpf.netpol.rule.add", Target: rule.ID, Details: map[string]any{"action": rule.Action, "peer": rule.PeerIPv4}})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.nextNetPolRuleSeq--
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelNetPolRule(id, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]models.NetPolRule, 0, len(s.config.NetPolRules))
	found := false
	for _, r := range s.config.NetPolRules {
		if r.ID == id {
			found = true
			continue
		}
		out = append(out, r)
	}
	if !found {
		return cloneConfig(s.config), fmt.Errorf("netpol rule %s not found", id)
	}
	s.config.NetPolRules = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.netpol.rule.delete", Target: id})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

// AddConnRateLimit caps new TCP connection attempts per second for every
// workload matching rule.Selector. Mirrors AddNetPolRule's generated-ID
// pattern (compound selector, not a scalar key) rather than allow-uid's
// scalar add/delete pattern.
func (s *Store) AddConnRateLimit(rule models.EBPFConnRateLimit, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rule.PerSecond == 0 {
		return cloneConfig(s.config), fmt.Errorf("perSecond must be greater than zero")
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.nextConnRateLimitSeq++
	rule.ID = "connratelimit-" + strconv.FormatUint(s.nextConnRateLimitSeq, 10)
	rule.CreatedAt = time.Now().UTC()
	rule.CreatedBy = actor
	rule.Selector = cloneScopes([]models.EBPFWorkloadScope{rule.Selector})[0]
	s.config.ConnRateLimits = append(s.config.ConnRateLimits, rule)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: rule.CreatedAt, Actor: actor, Action: "ebpf.connratelimit.add", Target: rule.ID, Details: map[string]any{"perSecond": rule.PerSecond}})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.nextConnRateLimitSeq--
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelConnRateLimit(id, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]models.EBPFConnRateLimit, 0, len(s.config.ConnRateLimits))
	found := false
	for _, r := range s.config.ConnRateLimits {
		if r.ID == id {
			found = true
			continue
		}
		out = append(out, r)
	}
	if !found {
		return cloneConfig(s.config), fmt.Errorf("conn rate limit %s not found", id)
	}
	s.config.ConnRateLimits = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.connratelimit.delete", Target: id})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

// SetNetPolDefaultDeny activates (enabled=true) or deactivates
// (enabled=false) default-deny posture for every workload matching
// selector, replacing any prior entry for the identical selector (compared
// by JSON encoding, which Go's encoding/json produces deterministically —
// map keys sorted — making it a stable equality key despite Labels being a
// map). This is the single highest-blast-radius mutation in the firewall
// feature; callers (internal/api) are expected to have already gone
// through the mandatory plan/confirm preflight before reaching here — this
// method itself has no opinion on risk, it just records the activation.
func (s *Store) SetNetPolDefaultDeny(selector models.EBPFWorkloadScope, enabled bool, lease time.Duration, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	key, err := json.Marshal(selector)
	if err != nil {
		return cloneConfig(s.config), fmt.Errorf("invalid selector: %w", err)
	}
	out := make([]models.NetPolDefaultDeny, 0, len(s.config.NetPolDefaultDenies)+1)
	for _, d := range s.config.NetPolDefaultDenies {
		dk, _ := json.Marshal(d.Selector)
		if string(dk) != string(key) {
			out = append(out, d)
		}
	}
	action := "ebpf.netpol.default-deny.disable"
	leaseSeconds := int64(0)
	if enabled {
		until := time.Now().UTC().Add(lease)
		leaseSeconds = int64(lease.Seconds())
		out = append(out, models.NetPolDefaultDeny{
			Selector: cloneScopes([]models.EBPFWorkloadScope{selector})[0], EnabledUntil: &until, LeaseSeconds: leaseSeconds, Actor: actor,
		})
		action = "ebpf.netpol.default-deny.enable"
	}
	s.config.NetPolDefaultDenies = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: action, Target: string(key), Details: map[string]any{"leaseSeconds": leaseSeconds}})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) Report(r models.AgentReport) {
	s.mu.Lock()
	var flowPath string
	defer func() {
		if flowPath != "" && s.flowLog != nil {
			_ = s.flowLog.SaveDebounced(flowPath, 15*time.Second)
		}
	}()
	defer s.mu.Unlock()
	r.Stats = append([]models.DestinationStat(nil), r.Stats...)
	r.TCPHealth = append([]models.TCPHealthStat(nil), r.TCPHealth...)
	r.TCPSignals = append([]models.TCPSignalStat(nil), r.TCPSignals...)
	r.DNSHealth = append([]models.DNSHealthStat(nil), r.DNSHealth...)
	r.TLSMetadata = append([]models.TLSMetadataStat(nil), r.TLSMetadata...)
	r.HTTPMetadata = append([]models.HTTPMetadataStat(nil), r.HTTPMetadata...)
	r.HTTPStatus = append([]models.HTTPStatusStat(nil), r.HTTPStatus...)
	r.ConnectionAttempts = append([]models.ConnectionAttemptStat(nil), r.ConnectionAttempts...)
	r.Events = append([]models.FastPathEvent(nil), r.Events...)
	r.Workloads = cloneWorkloads(r.Workloads)
	if prev, ok := s.agents[r.Node]; ok && len(prev.Events) > 0 {
		r.Events = append(prev.Events, r.Events...)
		if len(r.Events) > 500 {
			r.Events = append([]models.FastPathEvent(nil), r.Events[len(r.Events)-500:]...)
		}
	}
	if prev, ok := s.agents[r.Node]; ok {
		r.Netlink = mergeNetlink(prev.Netlink, r.Netlink)
		r.BPFAttach = mergeBPFAttach(prev.BPFAttach, r.BPFAttach)
	} else {
		r.Netlink = mergeNetlink(nil, r.Netlink)
		r.BPFAttach = mergeBPFAttach(nil, r.BPFAttach)
	}
	s.appendRateSampleLocked(r)
	s.appendKernelNetworkSampleLocked(r)
	s.agents[r.Node] = r
	if s.flowLog != nil {
		at := r.ObservedAt
		if at.IsZero() {
			at = time.Now().UTC()
		}
		s.flowLog.Ingest(at, r)
	}
	flowPath = s.flowPath
}

// FlowQuery reads retained flow deltas. Disk IO is Save/Load, not this call.
func (s *Store) FlowQuery(q flowlog.Query) flowlog.Result {
	if s == nil || s.flowLog == nil {
		return flowlog.Result{Records: []flowlog.Record{}, Limitations: flowlog.Limitations()}
	}
	return s.flowLog.Query(q)
}

// FlowCount is the number of retained flow deltas. Safe for a Prometheus gauge.
func (s *Store) FlowCount() int {
	if s == nil || s.flowLog == nil {
		return 0
	}
	return s.flowLog.Len()
}

func (s *Store) Agents() []models.AgentReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.AgentReport, 0, len(s.agents))
	for _, r := range s.agents {
		r.Stats = append([]models.DestinationStat(nil), r.Stats...)
		r.TCPHealth = append([]models.TCPHealthStat(nil), r.TCPHealth...)
		r.TCPSignals = append([]models.TCPSignalStat(nil), r.TCPSignals...)
		r.DNSHealth = append([]models.DNSHealthStat(nil), r.DNSHealth...)
		r.TLSMetadata = append([]models.TLSMetadataStat(nil), r.TLSMetadata...)
		r.HTTPMetadata = append([]models.HTTPMetadataStat(nil), r.HTTPMetadata...)
		r.HTTPStatus = append([]models.HTTPStatusStat(nil), r.HTTPStatus...)
		r.ConnectionAttempts = append([]models.ConnectionAttemptStat(nil), r.ConnectionAttempts...)
		r.Events = append([]models.FastPathEvent(nil), r.Events...)
		r.Netlink = cloneNetlink(r.Netlink)
		r.BPFAttach = cloneBPFAttach(r.BPFAttach)
		r.Workloads = cloneWorkloads(r.Workloads)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

func (s *Store) AgentStatuses(now time.Time, staleAfter time.Duration) []models.AgentStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.AgentStatus, 0, len(s.agents))
	for _, r := range s.agents {
		r.Stats = append([]models.DestinationStat(nil), r.Stats...)
		r.TCPHealth = append([]models.TCPHealthStat(nil), r.TCPHealth...)
		r.TCPSignals = append([]models.TCPSignalStat(nil), r.TCPSignals...)
		r.DNSHealth = append([]models.DNSHealthStat(nil), r.DNSHealth...)
		r.TLSMetadata = append([]models.TLSMetadataStat(nil), r.TLSMetadata...)
		r.HTTPMetadata = append([]models.HTTPMetadataStat(nil), r.HTTPMetadata...)
		r.HTTPStatus = append([]models.HTTPStatusStat(nil), r.HTTPStatus...)
		r.ConnectionAttempts = append([]models.ConnectionAttemptStat(nil), r.ConnectionAttempts...)
		r.Events = append([]models.FastPathEvent(nil), r.Events...)
		r.Netlink = cloneNetlink(r.Netlink)
		r.BPFAttach = cloneBPFAttach(r.BPFAttach)
		r.Workloads = cloneWorkloads(r.Workloads)
		age := now.Sub(r.ObservedAt)
		if r.ObservedAt.IsZero() || age < 0 {
			age = 0
		}
		out = append(out, models.AgentStatus{AgentReport: r, Stale: r.ObservedAt.IsZero() || age > staleAfter, AgeSeconds: int64(age.Seconds())})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

func (s *Store) Audit(limit int) []models.AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.audit) {
		limit = len(s.audit)
	}
	start := len(s.audit) - limit
	out := append([]models.AuditEvent(nil), s.audit[start:]...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (s *Store) AddAudit(e models.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	before := append([]models.AuditEvent(nil), s.audit...)
	s.appendAuditLocked(e)
	if err := s.persistLocked(); err != nil {
		s.audit = before
		return fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return nil
}

func (s *Store) appendAuditLocked(e models.AuditEvent) {
	s.audit = append(s.audit, e)
	if len(s.audit) > 1000 {
		s.audit = append([]models.AuditEvent(nil), s.audit[len(s.audit)-1000:]...)
	}
}

func (s *Store) IssuePreflight(body []byte, risk, actor string, ttl time.Duration) (models.PreflightReceipt, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return models.PreflightReceipt{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	now := time.Now().UTC()
	expires := now.Add(ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.normalizeLocked(now)
	s.preflights[token] = preflight{hash: sha256.Sum256(body), expiresAt: expires, risk: risk, actor: actor}
	if err := s.persistLocked(); err != nil {
		delete(s.preflights, token)
		return models.PreflightReceipt{}, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return models.PreflightReceipt{Token: token, ExpiresAt: expires}, nil
}

func (s *Store) ConsumePreflight(token string, body []byte) (string, bool, error) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.normalizeLocked(now)
	p, ok := s.preflights[token]
	if !ok {
		return "", false, nil
	}
	delete(s.preflights, token)
	if err := s.persistLocked(); err != nil {
		s.preflights[token] = p
		return "", false, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	h := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(h[:], p.hash[:]) != 1 {
		return "", false, nil
	}
	return p.risk, true, nil
}

func (s *Store) RecordPolicyRevision(namespace, name, action, actor string, manifest []byte) (models.PolicyRevision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	beforeID := s.nextRevisionID
	beforeRevisions := cloneRevisions(s.policyRevisions)
	s.nextRevisionID++
	r := models.PolicyRevision{
		ID:        s.nextRevisionID,
		At:        time.Now().UTC(),
		Actor:     actor,
		Namespace: namespace,
		Name:      name,
		Action:    action,
		Manifest:  append([]byte(nil), manifest...),
	}
	s.policyRevisions = append(s.policyRevisions, r)
	if len(s.policyRevisions) > 1000 {
		s.policyRevisions = append([]models.PolicyRevision(nil), s.policyRevisions[len(s.policyRevisions)-1000:]...)
	}
	if err := s.persistLocked(); err != nil {
		s.nextRevisionID = beforeID
		s.policyRevisions = beforeRevisions
		return models.PolicyRevision{}, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneRevision(r), nil
}

func (s *Store) ExportPolicyArchive() models.PolicyArchive {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return models.PolicyArchive{SchemaVersion: 1, ExportedAt: time.Now().UTC(), Revisions: cloneRevisions(s.policyRevisions)}
}

func (s *Store) ImportPolicyArchive(a models.PolicyArchive, mode, actor string) (int, error) {
	if a.SchemaVersion != 1 {
		return 0, fmt.Errorf("unsupported policy archive schema %d", a.SchemaVersion)
	}
	if mode == "" {
		mode = "merge"
	}
	if mode != "merge" && mode != "replace" {
		return 0, fmt.Errorf("mode must be merge or replace")
	}
	if len(a.Revisions) > 1000 {
		return 0, fmt.Errorf("archive contains %d revisions; maximum import is 1000", len(a.Revisions))
	}
	for i, r := range a.Revisions {
		if r.Namespace == "" || r.Name == "" || r.Action == "" {
			return 0, fmt.Errorf("revision %d requires namespace, name and action", i)
		}
		if len(r.Manifest) == 0 || len(r.Manifest) > 2<<20 || !json.Valid(r.Manifest) {
			return 0, fmt.Errorf("revision %d contains an invalid or oversized manifest", i)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	beforeID := s.nextRevisionID
	beforeRevisions := cloneRevisions(s.policyRevisions)
	beforeAudit := append([]models.AuditEvent(nil), s.audit...)
	if mode == "replace" {
		s.policyRevisions = nil
		s.nextRevisionID = 0
	}
	for _, imported := range a.Revisions {
		s.nextRevisionID++
		r := cloneRevision(imported)
		r.ID = s.nextRevisionID
		if r.At.IsZero() {
			r.At = time.Now().UTC()
		}
		s.policyRevisions = append(s.policyRevisions, r)
	}
	if len(s.policyRevisions) > 1000 {
		s.policyRevisions = append([]models.PolicyRevision(nil), s.policyRevisions[len(s.policyRevisions)-1000:]...)
	}
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "policy.history.import", Target: mode, Details: map[string]any{"count": len(a.Revisions)}})
	if err := s.persistLocked(); err != nil {
		s.nextRevisionID = beforeID
		s.policyRevisions = beforeRevisions
		s.audit = beforeAudit
		return 0, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return len(a.Revisions), nil
}

func (s *Store) PolicyHistory(namespace, name string, limit int) []models.PolicyRevision {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = 50
	}
	out := make([]models.PolicyRevision, 0, limit)
	for i := len(s.policyRevisions) - 1; i >= 0 && len(out) < limit; i-- {
		r := s.policyRevisions[i]
		if namespace != "" && r.Namespace != namespace {
			continue
		}
		if name != "" && r.Name != name {
			continue
		}
		out = append(out, cloneRevision(r))
	}
	return out
}

func (s *Store) PolicyRevision(namespace, name string, id uint64) (models.PolicyRevision, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := len(s.policyRevisions) - 1; i >= 0; i-- {
		r := s.policyRevisions[i]
		if r.ID == id && r.Namespace == namespace && r.Name == name {
			return cloneRevision(r), true
		}
	}
	return models.PolicyRevision{}, false
}

func cloneScopes(in []models.EBPFWorkloadScope) []models.EBPFWorkloadScope {
	out := make([]models.EBPFWorkloadScope, len(in))
	for i := range in {
		out[i] = in[i]
		if in[i].Labels != nil {
			out[i].Labels = make(map[string]string, len(in[i].Labels))
			for k, v := range in[i].Labels {
				out[i].Labels[k] = v
			}
		}
	}
	return out
}

func cloneWorkloads(in []models.WorkloadIdentity) []models.WorkloadIdentity {
	out := make([]models.WorkloadIdentity, len(in))
	for i := range in {
		out[i] = in[i]
		if in[i].Labels != nil {
			out[i].Labels = make(map[string]string, len(in[i].Labels))
			for k, v := range in[i].Labels {
				out[i].Labels[k] = v
			}
		}
	}
	return out
}

func cloneConfig(c models.EBPFFastPathConfig) models.EBPFFastPathConfig {
	c.BlockedIPv4 = append([]string(nil), c.BlockedIPv4...)
	c.BlockedIPv6 = append([]string(nil), c.BlockedIPv6...)
	c.AllowedIPv4 = append([]string(nil), c.AllowedIPv4...)
	c.AllowedIPv6 = append([]string(nil), c.AllowedIPv6...)
	c.AllowedCIDRs = append([]models.EBPFCIDRRule(nil), c.AllowedCIDRs...)
	c.AllowedPorts = append([]models.EBPFPortRule(nil), c.AllowedPorts...)
	c.AllowedUIDs = append([]uint32(nil), c.AllowedUIDs...)
	c.AllowedProcesses = append([]string(nil), c.AllowedProcesses...)
	c.BlockedIngressIPv4 = append([]string(nil), c.BlockedIngressIPv4...)
	c.BlockedIngressIPv6 = append([]string(nil), c.BlockedIngressIPv6...)
	c.BlockedCIDRs = append([]models.EBPFCIDRRule(nil), c.BlockedCIDRs...)
	c.BlockedPorts = append([]models.EBPFPortRule(nil), c.BlockedPorts...)
	c.BlockedUIDs = append([]uint32(nil), c.BlockedUIDs...)
	c.BlockedDNS = append([]string(nil), c.BlockedDNS...)
	c.BlockedProcesses = append([]string(nil), c.BlockedProcesses...)
	c.DeniedCapabilities = append([]string(nil), c.DeniedCapabilities...)
	c.BlockedExeHashes = append([]string(nil), c.BlockedExeHashes...)
	c.BlockedSNI = append([]string(nil), c.BlockedSNI...)
	c.RateLimits = append([]models.EBPFRateLimit(nil), c.RateLimits...)
	c.WorkloadScopes = cloneScopes(c.WorkloadScopes)
	c.Workloads = cloneWorkloads(c.Workloads)
	c.NetPolDenies = append([]models.NetPolPeerDeny(nil), c.NetPolDenies...)
	if c.Shield != nil {
		sh := *c.Shield
		sh.ProtectedIPv4 = append([]string(nil), c.Shield.ProtectedIPv4...)
		sh.ProtectedIPv6 = append([]string(nil), c.Shield.ProtectedIPv6...)
		c.Shield = &sh
	}
	c.NetPolRules = cloneNetPolRules(c.NetPolRules)
	c.NetPolDefaultDenies = cloneNetPolDefaultDenies(c.NetPolDefaultDenies)
	c.ConnRateLimits = cloneConnRateLimits(c.ConnRateLimits)
	c.SynDrop = append([]models.EBPFSynDropEntry(nil), c.SynDrop...)
	return c
}

func cloneNetPolRules(in []models.NetPolRule) []models.NetPolRule {
	out := make([]models.NetPolRule, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].Selector = cloneScopes([]models.EBPFWorkloadScope{in[i].Selector})[0]
	}
	return out
}

func cloneConnRateLimits(in []models.EBPFConnRateLimit) []models.EBPFConnRateLimit {
	out := make([]models.EBPFConnRateLimit, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].Selector = cloneScopes([]models.EBPFWorkloadScope{in[i].Selector})[0]
	}
	return out
}
func cloneNetPolDefaultDenies(in []models.NetPolDefaultDeny) []models.NetPolDefaultDeny {
	out := make([]models.NetPolDefaultDeny, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].Selector = cloneScopes([]models.EBPFWorkloadScope{in[i].Selector})[0]
		if in[i].EnabledUntil != nil {
			t := *in[i].EnabledUntil
			out[i].EnabledUntil = &t
		}
	}
	return out
}

func cloneRevision(r models.PolicyRevision) models.PolicyRevision {
	r.Manifest = append([]byte(nil), r.Manifest...)
	return r
}
