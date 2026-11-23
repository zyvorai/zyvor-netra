// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package store

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/denyset"
	"github.com/zyvorai/netra/internal/leaserails"
	"github.com/zyvorai/netra/internal/models"
)

const (
	maxDenyLeases  = 1000
	maxLeaseEvents = 1000
)

// ErrStale means rules or leases changed between planning and applying.
var ErrStale = errors.New("lease state changed since the plan was computed")

// RailsError carries the rail decision when a request is refused.
type RailsError struct{ Decision leaserails.Decision }

func (e *RailsError) Error() string {
	if len(e.Decision.Trips) == 0 {
		return "lease safety rail tripped"
	}
	return e.Decision.Trips[0].Code + ": " + e.Decision.Trips[0].Message
}

// StateToken identifies the rule and lease state a plan was computed against.
type StateToken struct {
	Revision uint64
	Lease    uint64
}

// LeaseStats feeds metrics and the console.
type LeaseStats struct {
	Active       int
	ExpiringSoon int // within soonWindow
	Created      uint64
	Extended     uint64
	Expired      uint64
	Revoked      uint64
	Rejected     uint64
	RailTrips    map[string]uint64
}

// SetLeaseRails installs the operator rail configuration.
func (s *Store) SetLeaseRails(c leaserails.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rails = c
}

// LeaseRails returns the rail configuration.
func (s *Store) LeaseRails() leaserails.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rails
}

// DenyLeases returns active denyset leases, soonest expiry first. owner
// filters when non-empty.
func (s *Store) DenyLeases(owner string) []models.DenyLease {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.normalizeLocked(time.Now())
	return s.denyLeasesLocked(owner)
}

func (s *Store) denyLeasesLocked(owner string) []models.DenyLease {
	out := make([]models.DenyLease, 0, len(s.denyLeases))
	for _, l := range s.denyLeases {
		if owner == "" || l.Owner == owner {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ExpiresAt.Equal(out[j].ExpiresAt) {
			return out[i].ExpiresAt.Before(out[j].ExpiresAt)
		}
		return out[i].Type+out[i].Key < out[j].Type+out[j].Key
	})
	return out
}

// LeaseStats summarises leases; soon is the "expiring soon" window.
func (s *Store) LeaseStats(soon time.Duration) LeaseStats {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.normalizeLocked(now)
	st := LeaseStats{Active: len(s.denyLeases), Created: s.leaseCounts["create"], Extended: s.leaseCounts["extend"], Expired: s.leaseCounts["expire"], Revoked: s.leaseCounts["revoke"], Rejected: s.leaseCounts["reject"], RailTrips: map[string]uint64{}}
	for _, l := range s.denyLeases {
		if l.ExpiresAt.Sub(now) <= soon {
			st.ExpiringSoon++
		}
	}
	for k, v := range s.railTrips {
		st.RailTrips[k] = v
	}
	return st
}

// LeaseHistory returns lease timeline events, newest first.
func (s *Store) LeaseHistory(owner string, since time.Time, limit int) []models.LeaseEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.normalizeLocked(time.Now())
	if limit <= 0 || limit > maxLeaseEvents {
		limit = 200
	}
	out := []models.LeaseEvent{}
	for i := len(s.leaseEvents) - 1; i >= 0 && len(out) < limit; i-- {
		e := s.leaseEvents[i]
		if owner != "" && e.Owner != owner {
			continue
		}
		if !since.IsZero() && e.At.Before(since) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// DenysetPlanState returns the data a plan is computed from: every denyset
// lease, the set of "type|key" for every deny rule currently configured, and
// a token to hand back to ApplyDenyset.
func (s *Store) DenysetPlanState() ([]denyset.Lease, map[string]bool, StateToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.normalizeLocked(time.Now())
	leases := make([]denyset.Lease, 0, len(s.denyLeases))
	for _, l := range s.denyLeasesLocked("") {
		leases = append(leases, denyset.Lease{Owner: l.Owner, Type: l.Type, Key: l.Key, Summary: l.Summary, LeaseSeconds: l.LeaseSeconds})
	}
	present := map[string]bool{}
	for _, r := range s.config.BlockedCIDRs {
		present["cidr|"+r.Direction+"|"+r.CIDR] = true
	}
	for _, r := range s.config.BlockedPorts {
		present["port|"+r.Direction+"|"+r.Protocol+"|"+strconv.FormatUint(uint64(r.Port), 10)] = true
	}
	return leases, present, StateToken{Revision: s.config.Revision, Lease: s.leaseRev}
}

func prefixOf(typ, key string) netip.Prefix {
	if typ != "cidr" {
		return netip.Prefix{}
	}
	if i := strings.LastIndex(key, "|"); i >= 0 {
		if p, err := netip.ParsePrefix(key[i+1:]); err == nil {
			return p
		}
	}
	return netip.Prefix{}
}

func (s *Store) railRequestLocked(owner, actor string, items []denyset.Item, protected map[string]bool, breakGlass string, now time.Time) leaserails.Request {
	removed := map[string]bool{}
	for _, it := range items {
		if it.Action == denyset.ActionRemove {
			removed[it.Type+"|"+it.Key] = true
		}
	}
	req := leaserails.Request{Actor: actor, BreakGlass: breakGlass}
	seen := map[string]bool{}
	for ck, l := range s.denyLeases {
		if removed[ck] {
			continue
		}
		seen[ck] = true
		req.Resulting = append(req.Resulting, leaserails.Held{Prefix: prefixOf(l.Type, l.Key)})
	}
	for _, it := range items {
		if it.Action != denyset.ActionAdd && it.Action != denyset.ActionExtend {
			continue
		}
		ck := it.Type + "|" + it.Key
		p := prefixOf(it.Type, it.Key)
		if it.Action == denyset.ActionAdd && !seen[ck] {
			req.Resulting = append(req.Resulting, leaserails.Held{Prefix: p})
		}
		req.Ops = append(req.Ops, leaserails.Op{Rule: it.Summary, Prefix: p, Seconds: it.LeaseSeconds, CatchAll: p.IsValid() && p.Bits() == 0, Protected: protected[ck]})
	}
	if s.rails.RateCount > 0 {
		cut := now.Add(-s.rails.RateWindow)
		for _, t := range s.actorOps[actor] {
			if t.After(cut) {
				req.ActorRecent++
			}
		}
	}
	return req
}

// EvaluateRails is the dry run: it reports which rails would trip for the
// items without changing anything or consuming rate budget.
func (s *Store) EvaluateRails(owner, actor string, items []denyset.Item, protected map[string]bool, breakGlass string) leaserails.Decision {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.normalizeLocked(now)
	return leaserails.Evaluate(s.rails, s.railRequestLocked(owner, actor, items, protected, breakGlass, now))
}

// RailsUsage reports current consumption for the console.
func (s *Store) RailsUsage() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.normalizeLocked(time.Now())
	ps := make([]netip.Prefix, 0, len(s.denyLeases))
	for _, l := range s.denyLeases {
		ps = append(ps, prefixOf(l.Type, l.Key))
	}
	v4, v6 := leaserails.Breadth(ps)
	return map[string]any{"activeLeases": len(s.denyLeases), "breadthV4": v4, "breadthV6": v6}
}

// ApplyRequest is a guarded denyset apply. Items come from a plan the caller
// has already verified against the plan hash and preflight receipt.
type ApplyRequest struct {
	Owner      string
	Actor      string
	Items      []denyset.Item
	Protected  map[string]bool
	BreakGlass string
	Token      StateToken
}

// ApplyResult counts what changed.
type ApplyResult struct {
	Added, Extended, Removed int
	Decision                 leaserails.Decision
	Revision                 uint64
}

func (s *Store) leaseEventLocked(e models.LeaseEvent) {
	s.leaseEvents = append(s.leaseEvents, e)
	if len(s.leaseEvents) > maxLeaseEvents {
		s.leaseEvents = append([]models.LeaseEvent(nil), s.leaseEvents[len(s.leaseEvents)-maxLeaseEvents:]...)
	}
	if s.leaseCounts == nil {
		s.leaseCounts = map[string]uint64{}
	}
	s.leaseCounts[e.Action]++
}

func parseRuleKey(typ, key string) (models.EBPFCIDRRule, models.EBPFPortRule, error) {
	parts := strings.Split(key, "|")
	switch {
	case typ == "cidr" && len(parts) == 2:
		return models.EBPFCIDRRule{Direction: parts[0], CIDR: parts[1]}, models.EBPFPortRule{}, nil
	case typ == "port" && len(parts) == 3:
		n, err := strconv.ParseUint(parts[2], 10, 16)
		if err == nil {
			return models.EBPFCIDRRule{}, models.EBPFPortRule{Direction: parts[0], Protocol: parts[1], Port: uint16(n)}, nil
		}
	}
	return models.EBPFCIDRRule{}, models.EBPFPortRule{}, fmt.Errorf("malformed rule key %q", key)
}

func (s *Store) insertDenyRuleLocked(typ, key string) (bool, error) {
	c, p, err := parseRuleKey(typ, key)
	if err != nil {
		return false, err
	}
	if typ == "cidr" {
		for _, x := range s.config.BlockedCIDRs {
			if x == c {
				return false, nil
			}
		}
		s.config.BlockedCIDRs = append(s.config.BlockedCIDRs, c)
		sort.Slice(s.config.BlockedCIDRs, func(i, j int) bool {
			a, b := s.config.BlockedCIDRs[i], s.config.BlockedCIDRs[j]
			if a.Direction == b.Direction {
				return a.CIDR < b.CIDR
			}
			return a.Direction < b.Direction
		})
		return true, nil
	}
	for _, x := range s.config.BlockedPorts {
		if x == p {
			return false, nil
		}
	}
	s.config.BlockedPorts = append(s.config.BlockedPorts, p)
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
	return true, nil
}

func (s *Store) removeDenyRuleLocked(typ, key string) bool {
	c, p, err := parseRuleKey(typ, key)
	if err != nil {
		return false
	}
	changed := false
	if typ == "cidr" {
		out := make([]models.EBPFCIDRRule, 0, len(s.config.BlockedCIDRs))
		for _, x := range s.config.BlockedCIDRs {
			if x == c {
				changed = true
				continue
			}
			out = append(out, x)
		}
		s.config.BlockedCIDRs = out
		return changed
	}
	out := make([]models.EBPFPortRule, 0, len(s.config.BlockedPorts))
	for _, x := range s.config.BlockedPorts {
		if x == p {
			changed = true
			continue
		}
		out = append(out, x)
	}
	s.config.BlockedPorts = out
	return changed
}

// expireDenyLeasesLocked removes rules whose lease ended, and drops leases
// whose rule was deleted or re-created outside the denyset (the lease then
// owns nothing; the rule, if any, is left alone).
func (s *Store) expireDenyLeasesLocked(now time.Time) {
	if len(s.denyLeases) == 0 {
		return
	}
	keys := make([]string, 0, len(s.denyLeases))
	for ck := range s.denyLeases {
		keys = append(keys, ck)
	}
	sort.Strings(keys)
	changed := false
	for _, ck := range keys {
		l := s.denyLeases[ck]
		id, ok := s.ruleIndexByKey[ck]
		idx := s.ruleIndex[id]
		ev := models.LeaseEvent{At: now.UTC(), Actor: "system", Owner: l.Owner, Rule: l.Summary}
		switch {
		case !ok:
			ev.Action, ev.Reason = "revoke", "rule was removed outside the denyset"
		case !idx.CreatedAt.Equal(l.RuleCreatedAt):
			ev.Action, ev.Reason = "revoke", "rule was re-created outside the denyset; the lease no longer owns it"
		case !now.Before(l.ExpiresAt):
			s.removeDenyRuleLocked(l.Type, l.Key)
			ev.Action, ev.Reason = "expire", "lease expired; rule removed"
			exp := l.ExpiresAt
			ev.ExpiresAt = &exp
			changed = true
		default:
			continue
		}
		delete(s.denyLeases, ck)
		s.leaseRev++
		s.leaseEventLocked(ev)
		s.appendAuditLocked(models.AuditEvent{At: now.UTC(), Actor: "system", Action: "ebpf.denyset.lease." + ev.Action, Target: l.Summary, Details: map[string]any{"owner": l.Owner, "reason": ev.Reason}})
	}
	if changed {
		s.config.Revision++
		s.reconcileRuleIndexLocked("system", now.UTC())
	}
}

// ApplyDenyset applies the add/extend/remove items of a plan. Removals only
// touch leases owned by req.Owner; additions fail rather than take over an
// existing rule; every rule gets a bounded lease.
func (s *Store) ApplyDenyset(req ApplyRequest) (ApplyResult, error) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.normalizeLocked(now)
	if req.Token != (StateToken{Revision: s.config.Revision, Lease: s.leaseRev}) {
		return ApplyResult{}, ErrStale
	}
	var res ApplyResult
	adds := 0
	for _, it := range req.Items {
		switch it.Action {
		case denyset.ActionAdd:
			adds++
		case denyset.ActionExtend:
		case denyset.ActionRemove:
		default:
			continue
		}
		if it.Action != denyset.ActionRemove && (it.LeaseSeconds < int64(denyset.MinLease/time.Second) || it.LeaseSeconds > int64(denyset.MaxLease/time.Second)) {
			return res, fmt.Errorf("lease for %s is outside %s-%s", it.Summary, denyset.MinLease, denyset.MaxLease)
		}
	}
	if len(s.denyLeases)+adds > maxDenyLeases {
		return res, fmt.Errorf("more than %d denyset leases", maxDenyLeases)
	}
	lreq := s.railRequestLocked(req.Owner, req.Actor, req.Items, req.Protected, req.BreakGlass, now)
	dec := leaserails.Evaluate(s.rails, lreq)
	if s.rails.RateCount > 0 && len(lreq.Ops) > 0 {
		cut := now.Add(-s.rails.RateWindow)
		kept := s.actorOps[req.Actor][:0:0]
		for _, t := range s.actorOps[req.Actor] {
			if t.After(cut) {
				kept = append(kept, t)
			}
		}
		for range lreq.Ops {
			kept = append(kept, now)
		}
		if len(kept) > 100000 {
			kept = kept[len(kept)-100000:]
		}
		if s.actorOps == nil {
			s.actorOps = map[string][]time.Time{}
		}
		s.actorOps[req.Actor] = kept
		if len(s.actorOps) > 1000 {
			for a, ts := range s.actorOps {
				if a != req.Actor && (len(ts) == 0 || !ts[len(ts)-1].After(cut)) {
					delete(s.actorOps, a)
				}
			}
		}
	}
	res.Decision = dec
	if !dec.Allowed() {
		codes := make([]string, 0, len(dec.Trips))
		if s.railTrips == nil {
			s.railTrips = map[string]uint64{}
		}
		for _, t := range dec.Trips {
			codes = append(codes, t.Code)
			s.railTrips[t.Code]++
		}
		s.leaseEventLocked(models.LeaseEvent{At: now, Action: "reject", Actor: req.Actor, Owner: req.Owner, Rails: codes, Reason: dec.Trips[0].Message})
		s.appendAuditLocked(models.AuditEvent{At: now, Actor: req.Actor, Action: "ebpf.denyset.rail.reject", Target: req.Owner, Details: map[string]any{"rails": codes}})
		_ = s.persistLocked()
		return res, &RailsError{Decision: dec}
	}

	before, auditLen := cloneConfig(s.config), len(s.audit)
	leasesBefore := make(map[string]models.DenyLease, len(s.denyLeases))
	for k, v := range s.denyLeases {
		leasesBefore[k] = v
	}
	eventsBefore := append([]models.LeaseEvent(nil), s.leaseEvents...)
	countsBefore := map[string]uint64{}
	for k, v := range s.leaseCounts {
		countsBefore[k] = v
	}
	revBefore := s.leaseRev
	rollback := func() {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.denyLeases = leasesBefore
		s.leaseEvents = eventsBefore
		s.leaseCounts = countsBefore
		s.leaseRev = revBefore
		s.reconcileRuleIndexLocked("system", now)
	}
	bgReason := ""
	if dec.BreakGlass {
		bgReason = strings.TrimSpace(req.BreakGlass)
	}
	codes := make([]string, 0, len(dec.Waived))
	for _, t := range dec.Waived {
		codes = append(codes, t.Code)
	}
	if s.denyLeases == nil {
		s.denyLeases = map[string]models.DenyLease{}
	}
	ruleChanged := false
	for _, it := range req.Items {
		ck := it.Type + "|" + it.Key
		switch it.Action {
		case denyset.ActionAdd:
			if _, held := s.denyLeases[ck]; held {
				rollback()
				return res, ErrStale
			}
			added, err := s.insertDenyRuleLocked(it.Type, it.Key)
			if err != nil || !added {
				rollback()
				if err == nil {
					err = ErrStale
				}
				return ApplyResult{}, err
			}
			ruleChanged = true
			s.reconcileRuleIndexLocked(req.Actor, now)
			exp := now.Add(time.Duration(it.LeaseSeconds) * time.Second)
			l := models.DenyLease{Owner: req.Owner, Type: it.Type, Key: it.Key, Summary: it.Summary, LeaseSeconds: it.LeaseSeconds, CreatedAt: now, CreatedBy: req.Actor, ExpiresAt: exp, RuleCreatedAt: s.ruleIndex[s.ruleIndexByKey[ck]].CreatedAt}
			s.denyLeases[ck] = l
			s.leaseEventLocked(models.LeaseEvent{At: now, Action: "create", Actor: req.Actor, Owner: req.Owner, Rule: it.Summary, LeaseSeconds: it.LeaseSeconds, ExpiresAt: &exp, Rails: codes, BreakGlass: dec.BreakGlass, Reason: bgReason})
			s.appendAuditLocked(models.AuditEvent{At: now, Actor: req.Actor, Action: "ebpf.denyset.lease.create", Target: it.Summary, Details: map[string]any{"owner": req.Owner, "leaseSeconds": it.LeaseSeconds}})
			res.Added++
		case denyset.ActionExtend:
			l, ok := s.denyLeases[ck]
			if !ok || l.Owner != req.Owner {
				rollback()
				return ApplyResult{}, ErrStale
			}
			l.LeaseSeconds = it.LeaseSeconds
			l.ExpiresAt = now.Add(time.Duration(it.LeaseSeconds) * time.Second)
			l.Extensions++
			s.denyLeases[ck] = l
			exp := l.ExpiresAt
			s.leaseEventLocked(models.LeaseEvent{At: now, Action: "extend", Actor: req.Actor, Owner: req.Owner, Rule: it.Summary, LeaseSeconds: it.LeaseSeconds, ExpiresAt: &exp, Rails: codes, BreakGlass: dec.BreakGlass, Reason: bgReason})
			s.appendAuditLocked(models.AuditEvent{At: now, Actor: req.Actor, Action: "ebpf.denyset.lease.extend", Target: it.Summary, Details: map[string]any{"owner": req.Owner, "leaseSeconds": it.LeaseSeconds}})
			res.Extended++
		case denyset.ActionRemove:
			l, ok := s.denyLeases[ck]
			if !ok || l.Owner != req.Owner {
				rollback()
				return ApplyResult{}, ErrStale
			}
			if s.removeDenyRuleLocked(l.Type, l.Key) {
				ruleChanged = true
			}
			delete(s.denyLeases, ck)
			s.leaseEventLocked(models.LeaseEvent{At: now, Action: "revoke", Actor: req.Actor, Owner: req.Owner, Rule: l.Summary, Reason: "removed from the denyset"})
			s.appendAuditLocked(models.AuditEvent{At: now, Actor: req.Actor, Action: "ebpf.denyset.lease.revoke", Target: l.Summary, Details: map[string]any{"owner": req.Owner}})
			res.Removed++
		}
	}
	if dec.BreakGlass {
		s.appendAuditLocked(models.AuditEvent{At: now, Actor: req.Actor, Action: "ebpf.denyset.breakglass", Target: req.Owner, Details: map[string]any{"rails": codes, "reason": bgReason}})
	}
	if res.Added+res.Extended+res.Removed == 0 {
		return res, nil
	}
	if ruleChanged {
		s.config.Revision++
		s.reconcileRuleIndexLocked(req.Actor, now)
	}
	s.leaseRev++
	if err := s.persistLocked(); err != nil {
		rollback()
		return ApplyResult{}, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	res.Revision = s.config.Revision
	return res, nil
}

// RecordRailReject records a refused lease request (caught before ApplyDenyset)
// on the timeline and audit log and counts its rail trips.
func (s *Store) RecordRailReject(actor, owner string, d leaserails.Decision) error {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.railTrips == nil {
		s.railTrips = map[string]uint64{}
	}
	codes := make([]string, 0, len(d.Trips))
	for _, t := range d.Trips {
		codes = append(codes, t.Code)
		s.railTrips[t.Code]++
	}
	reason := ""
	if len(d.Trips) > 0 {
		reason = d.Trips[0].Message
	}
	s.leaseEventLocked(models.LeaseEvent{At: now, Action: "reject", Actor: actor, Owner: owner, Rails: codes, Reason: reason})
	s.appendAuditLocked(models.AuditEvent{At: now, Actor: actor, Action: "ebpf.denyset.rail.reject", Target: owner, Details: map[string]any{"rails": codes}})
	if err := s.persistLocked(); err != nil {
		return fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return nil
}

// CountRailTrip counts a rail refusal that did not go through a denyset apply
// (the enforce-mode lease duration rail).
func (s *Store) CountRailTrip(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.railTrips == nil {
		s.railTrips = map[string]uint64{}
	}
	s.railTrips[code]++
}
