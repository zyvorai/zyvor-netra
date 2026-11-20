// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/zyvorai/netra/internal/flowlog"
	"github.com/zyvorai/netra/internal/flowlog/sqlitestore"
	"github.com/zyvorai/netra/internal/models"
)

const stateSchemaVersion = 1

type fileBackend struct {
	path string
	lock *os.File
}

type diskPreflight struct {
	Hash      []byte    `json:"hash"`
	ExpiresAt time.Time `json:"expiresAt"`
	Risk      string    `json:"risk"`
	Actor     string    `json:"actor,omitempty"`
}

type diskState struct {
	SchemaVersion         int                           `json:"schemaVersion"`
	SavedAt               time.Time                     `json:"savedAt"`
	Config                models.EBPFFastPathConfig     `json:"config"`
	Audit                 []models.AuditEvent           `json:"audit"`
	PolicyRevisions       []models.PolicyRevision       `json:"policyRevisions"`
	NextRevisionID        uint64                        `json:"nextRevisionId"`
	Preflights            map[string]diskPreflight      `json:"preflights,omitempty"`
	Baseline              models.BehaviorBaseline       `json:"baseline,omitempty"`
	RateBaseline          models.RateBaseline           `json:"rateBaseline,omitempty"`
	RuleIndex             map[string]firewallRuleIndex  `json:"ruleIndex,omitempty"`
	NextRuleSeq           map[string]uint64             `json:"nextRuleSeq,omitempty"`
	FirewallRuleRevisions []models.FirewallRuleRevision `json:"firewallRuleRevisions,omitempty"`
	NextFirewallRevID     uint64                        `json:"nextFirewallRevisionId,omitempty"`
	CaptureHistory        []models.CaptureHistoryEntry  `json:"captureHistory,omitempty"`
	NodeIsolation         []models.NodeIsolationSpec    `json:"nodeIsolation,omitempty"`
	NodeIsolationRevision uint64                        `json:"nodeIsolationRevision,omitempty"`
}

// Open returns a store backed by an atomically replaced JSON state file. The
// lock is intentionally process-exclusive. In v0.6 HA mode the elected Lease
// leader must also obtain this lock before it is allowed to become Ready.
func Open(path string) (*Store, error) {
	if path == "" {
		return New(), nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	lock, err := os.OpenFile(abs+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open state lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("state file is locked by another Netra controller: %w", err)
	}

	s := New()
	s.backend = &fileBackend{path: abs, lock: lock}
	if err := s.load(); err != nil {
		_ = s.Close()
		return nil, err
	}
	if err := s.configureFlowLog(abs); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// configureFlowLog selects JSON sidecar (default) or optional SQLite.
func (s *Store) configureFlowLog(stateAbs string) error {
	opts := flowlog.OptionsFromEnv()
	s.flowPath = stateAbs + ".flows"
	switch flowlog.BackendFromEnv() {
	case flowlog.BackendSQLite:
		dbPath := stateAbs + ".flows.db"
		backend, err := sqlitestore.Open(dbPath, opts)
		if err != nil {
			return fmt.Errorf("open sqlite flow store: %w", err)
		}
		if err := backend.ImportJSON(s.flowPath); err != nil {
			// Damaged JSON must not block sqlite; leave file renamed and start empty.
			_ = os.Rename(s.flowPath, s.flowPath+".bad")
		}
		s.flowLog = flowlog.NewWithBackend(backend, opts.Retain, opts.Max)
		return nil
	default:
		s.flowLog = flowlog.NewLimited(opts.Retain, opts.Max)
		if err := s.flowLog.Load(s.flowPath); err != nil {
			// A damaged flow sidecar must not stop the controller. History
			// starts empty; the next reports rebuild a baseline.
			_ = os.Rename(s.flowPath, s.flowPath+".bad")
		}
		return nil
	}
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.backend.path)
	if errors.Is(err, os.ErrNotExist) {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.persistLocked()
	}
	if err != nil {
		return fmt.Errorf("read state: %w", err)
	}
	var d diskState
	if err := json.Unmarshal(b, &d); err != nil {
		return fmt.Errorf("decode state: %w", err)
	}
	if d.SchemaVersion != stateSchemaVersion {
		return fmt.Errorf("unsupported state schema %d (expected %d)", d.SchemaVersion, stateSchemaVersion)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if d.Config.Revision == 0 {
		d.Config.Revision = 1
	}
	if d.Config.ScopeMode == "" {
		d.Config.ScopeMode = "all"
	}
	wasEnforcing := d.Config.Mode == "enforce"
	// A controller restart is a security boundary. Never resurrect an
	// emergency enforcement lease solely because it was present on disk.
	d.Config.Mode = "observe"
	d.Config.EnforceUntil = nil
	d.Config.LeaseSeconds = 0
	// Same invariant for NetPol v2 default-deny: it is the single
	// highest-blast-radius mutation in the firewall feature (a workload
	// only accepts explicitly allowed traffic), so a crashed/restarted
	// controller must never silently resume it — re-activation requires a
	// fresh, explicit plan/confirm from an operator.
	wasNetPolDefaultDenying := len(d.Config.NetPolDefaultDenies) > 0
	d.Config.NetPolDefaultDenies = nil
	d.Config = cloneConfig(d.Config)
	sort.Strings(d.Config.BlockedIPv4)
	sort.Strings(d.Config.BlockedIPv6)
	s.config = d.Config
	s.audit = append([]models.AuditEvent(nil), tailAudit(d.Audit, 1000)...)
	s.captureHistory = append([]models.CaptureHistoryEntry(nil), tailCaptureHistory(d.CaptureHistory, 500)...)
	s.policyRevisions = cloneRevisions(tailRevisions(d.PolicyRevisions, 1000))
	s.nextRevisionID = d.NextRevisionID
	s.preflights = map[string]preflight{}
	s.baseline = cloneBaseline(d.Baseline)
	s.rateBaseline = cloneRateBaseline(d.RateBaseline)
	if len(d.RuleIndex) == 0 && len(d.NextRuleSeq) == 0 {
		// First load after upgrading to a controller version with the
		// rule-ID system: synthesize an index for whatever rules already
		// exist so they immediately get stable IDs, but attribute them to
		// a migration actor rather than fabricating history/attribution
		// that was never actually recorded.
		s.ruleIndex = map[string]firewallRuleIndex{}
		s.ruleIndexByKey = map[string]string{}
		s.nextRuleSeq = map[string]uint64{}
		s.reconcileRuleIndexLocked("system:migration", d.SavedAt)
	} else {
		s.ruleIndex = make(map[string]firewallRuleIndex, len(d.RuleIndex))
		for id, e := range d.RuleIndex {
			s.ruleIndex[id] = e
		}
		s.ruleIndexByKey = make(map[string]string, len(d.RuleIndex))
		for id, e := range s.ruleIndex {
			s.ruleIndexByKey[e.Type+"|"+e.Key] = id
		}
		s.nextRuleSeq = make(map[string]uint64, len(d.NextRuleSeq))
		for typ, n := range d.NextRuleSeq {
			s.nextRuleSeq[typ] = n
		}
	}
	s.firewallRuleRevisions = append([]models.FirewallRuleRevision(nil), tailFirewallRevisions(d.FirewallRuleRevisions, 1000)...)
	s.nextFirewallRevID = d.NextFirewallRevID
	for _, r := range s.firewallRuleRevisions {
		if r.ID > s.nextFirewallRevID {
			s.nextFirewallRevID = r.ID
		}
	}
	for _, r := range s.config.NetPolRules {
		if n, ok := strings.CutPrefix(r.ID, "netpolrule-"); ok {
			if v, err := strconv.ParseUint(n, 10, 64); err == nil && v > s.nextNetPolRuleSeq {
				s.nextNetPolRuleSeq = v
			}
		}
	}
	now := time.Now().UTC()
	for token, item := range d.Preflights {
		if token == "" || len(item.Hash) != 32 || !now.Before(item.ExpiresAt) {
			continue
		}
		var hash [32]byte
		copy(hash[:], item.Hash)
		s.preflights[token] = preflight{hash: hash, expiresAt: item.ExpiresAt, risk: item.Risk, actor: item.Actor}
	}
	for _, r := range s.policyRevisions {
		if r.ID > s.nextRevisionID {
			s.nextRevisionID = r.ID
		}
	}
	// Node isolation: keep shadow policies (a review in progress), but never
	// resume enforce after a restart, for the same reason as Mode above.
	s.nodeIsolation = map[string]models.NodeIsolationSpec{}
	s.nodeIsolationRev = d.NodeIsolationRevision
	nodeIsoDemoted := false
	for _, spec := range d.NodeIsolation {
		if spec.Node == "" {
			continue
		}
		if spec.Revision > s.nodeIsolationRev {
			s.nodeIsolationRev = spec.Revision
		}
		if spec.Mode == models.NodeIsolationEnforce {
			s.nodeIsolationRev++
			spec.Mode, spec.LeaseUntil, spec.Revision = models.NodeIsolationShadow, nil, s.nodeIsolationRev
			s.appendAuditLocked(models.AuditEvent{At: now, Actor: "system", Action: "ebpf.node-isolation.restart-fail-open", Target: spec.Node, Details: map[string]any{"policyId": spec.PolicyID}})
			nodeIsoDemoted = true
		}
		s.nodeIsolation[spec.Node] = cloneNodeIsolation(spec)
	}
	if nodeIsoDemoted && !wasEnforcing && !wasNetPolDefaultDenying {
		if err := s.persistLocked(); err != nil {
			return fmt.Errorf("persist restart fail-open: %w", err)
		}
	}
	if wasEnforcing || wasNetPolDefaultDenying {
		s.config.Revision++
		if wasEnforcing {
			s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: "system", Action: "ebpf.restart.fail-open", Target: "fast-path"})
		}
		if wasNetPolDefaultDenying {
			s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: "system", Action: "ebpf.netpol.default-deny.restart-fail-open", Target: "netpol-v2"})
		}
		if err := s.persistLocked(); err != nil {
			return fmt.Errorf("persist restart fail-open: %w", err)
		}
	}
	return nil
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	if s.flowPath != "" && s.flowLog != nil {
		_ = s.flowLog.Save(s.flowPath)
		_ = s.flowLog.Close()
	}
	if s.backend == nil || s.backend.lock == nil {
		return nil
	}
	lock := s.backend.lock
	s.backend.lock = nil
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return lock.Close()
}

func (s *Store) Persistent() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.backend != nil
}

func (s *Store) StatePath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.backend == nil {
		return ""
	}
	return s.backend.path
}

func (s *Store) persistLocked() error {
	if s.backend == nil {
		return nil
	}
	cfg := cloneConfig(s.config)
	// Pod inventory is node-local, short-lived metadata supplied to agents. Never persist it.
	cfg.Workloads = nil
	ruleIndex := make(map[string]firewallRuleIndex, len(s.ruleIndex))
	for id, e := range s.ruleIndex {
		ruleIndex[id] = e
	}
	nextRuleSeq := make(map[string]uint64, len(s.nextRuleSeq))
	for typ, n := range s.nextRuleSeq {
		nextRuleSeq[typ] = n
	}
	d := diskState{
		SchemaVersion:         stateSchemaVersion,
		SavedAt:               time.Now().UTC(),
		Config:                cfg,
		Audit:                 append([]models.AuditEvent(nil), s.audit...),
		PolicyRevisions:       cloneRevisions(s.policyRevisions),
		NextRevisionID:        s.nextRevisionID,
		Preflights:            make(map[string]diskPreflight, len(s.preflights)),
		Baseline:              cloneBaseline(s.baseline),
		RateBaseline:          cloneRateBaseline(s.rateBaseline),
		RuleIndex:             ruleIndex,
		NextRuleSeq:           nextRuleSeq,
		FirewallRuleRevisions: append([]models.FirewallRuleRevision(nil), s.firewallRuleRevisions...),
		NextFirewallRevID:     s.nextFirewallRevID,
		CaptureHistory:        append([]models.CaptureHistoryEntry(nil), s.captureHistory...),
		NodeIsolationRevision: s.nodeIsolationRev,
	}
	for _, spec := range s.nodeIsolation {
		d.NodeIsolation = append(d.NodeIsolation, cloneNodeIsolation(spec))
	}
	sort.Slice(d.NodeIsolation, func(i, j int) bool { return d.NodeIsolation[i].Node < d.NodeIsolation[j].Node })
	now := time.Now().UTC()
	for token, item := range s.preflights {
		if !now.Before(item.expiresAt) {
			continue
		}
		d.Preflights[token] = diskPreflight{Hash: append([]byte(nil), item.hash[:]...), ExpiresAt: item.expiresAt, Risk: item.risk, Actor: item.actor}
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	dir := filepath.Dir(s.backend.path)
	f, err := os.CreateTemp(dir, ".netra-state-*")
	if err != nil {
		return fmt.Errorf("create temporary state: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync state: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close state: %w", err)
	}
	if err := os.Rename(tmp, s.backend.path); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	if dfd, err := os.Open(dir); err == nil {
		_ = dfd.Sync()
		_ = dfd.Close()
	}
	return nil
}

func tailAudit(in []models.AuditEvent, n int) []models.AuditEvent {
	if len(in) <= n {
		return in
	}
	return in[len(in)-n:]
}
func tailRevisions(in []models.PolicyRevision, n int) []models.PolicyRevision {
	if len(in) <= n {
		return in
	}
	return in[len(in)-n:]
}
func tailCaptureHistory(in []models.CaptureHistoryEntry, n int) []models.CaptureHistoryEntry {
	if len(in) <= n {
		return in
	}
	return in[len(in)-n:]
}
func tailFirewallRevisions(in []models.FirewallRuleRevision, n int) []models.FirewallRuleRevision {
	if len(in) <= n {
		return in
	}
	return in[len(in)-n:]
}
func cloneRevisions(in []models.PolicyRevision) []models.PolicyRevision {
	out := make([]models.PolicyRevision, len(in))
	for i := range in {
		out[i] = cloneRevision(in[i])
	}
	return out
}
