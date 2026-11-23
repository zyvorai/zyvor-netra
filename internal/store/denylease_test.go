// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package store

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/denyset"
	"github.com/zyvorai/netra/internal/leaserails"
	"github.com/zyvorai/netra/internal/models"
)

func parseSet(t *testing.T, body string) *denyset.File {
	t.Helper()
	f, errs := denyset.Parse([]byte("netra-denyset/1\n" + body))
	if errs != nil {
		t.Fatal(errs)
	}
	return f
}

func planApply(t *testing.T, s *Store, f *denyset.File, actor, bg string, protected map[string]bool) (ApplyResult, error) {
	t.Helper()
	leases, present, tok := s.DenysetPlanState()
	items := denyset.Diff(f, leases, present)
	return s.ApplyDenyset(ApplyRequest{Owner: f.Name, Actor: actor, Items: items, Protected: protected, BreakGlass: bg, Token: tok})
}

func TestDenysetApplyExtendRemoveOwnership(t *testing.T) {
	s := New()
	// A permanent operator rule and another denyset's rule must survive.
	if _, err := s.AddCIDR(models.EBPFCIDRRule{CIDR: "192.0.2.0/24", Direction: "egress"}, "ops"); err != nil {
		t.Fatal(err)
	}
	other := parseSet(t, "name: other\nlease: 1h\ndeny cidr 198.18.0.0/15 egress\n")
	if _, err := planApply(t, s, other, "a", "", nil); err != nil {
		t.Fatal(err)
	}
	f := parseSet(t, "name: inc\nlease: 10m\ndeny cidr 203.0.113.0/24 egress\ndeny port tcp 445 ingress\ndeny cidr 192.0.2.0/24 egress\n")
	r, err := planApply(t, s, f, "alice", "", nil)
	if err != nil || r.Added != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	cfg := s.Config()
	if len(cfg.BlockedCIDRs) != 3 || len(cfg.BlockedPorts) != 1 {
		t.Fatalf("%+v", cfg)
	}
	if len(s.DenyLeases("inc")) != 2 {
		t.Fatal("leases")
	}
	// Re-apply is a no-op.
	if r, err = planApply(t, s, f, "alice", "", nil); err != nil || r.Added+r.Extended+r.Removed != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	// Longer lease extends; dropping a rule removes only owned leases.
	f2 := parseSet(t, "name: inc\nlease: 20m\ndeny cidr 203.0.113.0/24 egress\n")
	r, err = planApply(t, s, f2, "alice", "", nil)
	if err != nil || r.Extended != 1 || r.Removed != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	cfg = s.Config()
	if len(cfg.BlockedPorts) != 0 || len(cfg.BlockedCIDRs) != 3 {
		t.Fatalf("removal reached outside the denyset: %+v", cfg)
	}
	// Empty file revokes everything inc owns and nothing else.
	if r, err = planApply(t, s, parseSet(t, "name: inc\nlease: 5m\n"), "alice", "", nil); err != nil || r.Removed != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	cfg = s.Config()
	if len(cfg.BlockedCIDRs) != 2 || len(s.DenyLeases("other")) != 1 {
		t.Fatalf("%+v", cfg)
	}
	var actions []string
	for _, e := range s.LeaseHistory("inc", time.Time{}, 50) {
		actions = append(actions, e.Action)
	}
	got := strings.Join(actions, ",")
	for _, want := range []string{"create", "extend", "revoke"} {
		if !strings.Contains(got, want) {
			t.Fatalf("timeline %s missing %s", got, want)
		}
	}
}

func TestDenysetExpiryRemovesRuleAndRecords(t *testing.T) {
	s := New()
	f := parseSet(t, "name: x\nlease: 1m\ndeny cidr 203.0.113.0/24 both\n")
	if _, err := planApply(t, s, f, "a", "", nil); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	for k, l := range s.denyLeases {
		l.ExpiresAt = time.Now().Add(-time.Second)
		s.denyLeases[k] = l
	}
	s.mu.Unlock()
	if cfg := s.Config(); len(cfg.BlockedCIDRs) != 0 {
		t.Fatalf("rule survived its lease: %+v", cfg.BlockedCIDRs)
	}
	if len(s.DenyLeases("")) != 0 {
		t.Fatal("lease survived")
	}
	h := s.LeaseHistory("x", time.Time{}, 10)
	if h[0].Action != "expire" || h[0].Actor != "system" {
		t.Fatalf("%+v", h)
	}
	if st := s.LeaseStats(time.Minute); st.Expired != 1 || st.Active != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestDenysetLeaseDroppedWhenRuleChangedOutside(t *testing.T) {
	s := New()
	if _, err := planApply(t, s, parseSet(t, "name: x\nlease: 5m\ndeny cidr 203.0.113.0/24 egress\n"), "a", "", nil); err != nil {
		t.Fatal(err)
	}
	// Operator deletes and re-creates the rule by hand: lease must not delete it later.
	if _, err := s.DelCIDR(models.EBPFCIDRRule{CIDR: "203.0.113.0/24", Direction: "egress"}, "ops"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := s.AddCIDR(models.EBPFCIDRRule{CIDR: "203.0.113.0/24", Direction: "egress"}, "ops"); err != nil {
		t.Fatal(err)
	}
	if len(s.DenyLeases("")) != 0 {
		t.Fatal("stale lease kept")
	}
	if len(s.Config().BlockedCIDRs) != 1 {
		t.Fatal("manual rule was removed")
	}
}

func TestDenysetStaleTokenAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	f := parseSet(t, "name: x\nlease: 1h\ndeny cidr 203.0.113.0/24 egress\n")
	leases, present, tok := s.DenysetPlanState()
	items := denyset.Diff(f, leases, present)
	if _, err := s.AddUID(5, "ops"); err != nil { // does not bump rule revision? it does; any change is stale
		t.Fatal(err)
	}
	if _, err := s.ApplyDenyset(ApplyRequest{Owner: "x", Actor: "a", Items: items, Token: tok}); !errors.Is(err, ErrStale) {
		t.Fatalf("want ErrStale, got %v", err)
	}
	if _, err := planApply(t, s, f, "a", "", nil); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if l := s2.DenyLeases("x"); len(l) != 1 || len(s2.LeaseHistory("x", time.Time{}, 5)) == 0 {
		t.Fatalf("leases not persisted: %+v", l)
	}
}

func TestDenysetRails(t *testing.T) {
	s := New()
	s.SetLeaseRails(leaserails.Config{MaxConcurrent: 2, MaxDuration: time.Hour, BreakGlass: true, RateCount: 4, RateWindow: time.Minute})
	// Duration rail.
	_, err := planApply(t, s, parseSet(t, "name: a\nlease: 2h\ndeny ip 198.51.100.1 egress\n"), "al", "", nil)
	var re *RailsError
	if !errors.As(err, &re) || re.Decision.Trips[0].Code != leaserails.CodeMaxDuration {
		t.Fatalf("%v", err)
	}
	if len(s.Config().BlockedCIDRs) != 0 {
		t.Fatal("rejected apply changed rules")
	}
	// Concurrent rail.
	_, err = planApply(t, s, parseSet(t, "name: a\nlease: 10m\ndeny ip 198.51.100.1 egress\ndeny ip 198.51.100.2 egress\ndeny ip 198.51.100.3 egress\n"), "bob", "", nil)
	if !errors.As(err, &re) || re.Decision.Trips[0].Code != leaserails.CodeMaxConcurrent {
		t.Fatalf("%v", err)
	}
	// Catch-all needs break-glass, and is audited when used.
	catch := parseSet(t, "name: c\nlease: 10m\ndeny cidr 0.0.0.0/0 egress\n")
	if _, err = planApply(t, s, catch, "carol", "", nil); !errors.As(err, &re) || !re.Decision.NeedsBreakGlass {
		t.Fatalf("%v", err)
	}
	if _, err = planApply(t, s, catch, "carol", "short", nil); err == nil {
		t.Fatal("invalid break-glass accepted")
	}
	r, err := planApply(t, s, catch, "carol2", "incident 4711 approved by oncall", nil)
	if err != nil || r.Added != 1 || !r.Decision.BreakGlass {
		t.Fatalf("%+v %v", r, err)
	}
	st := s.LeaseStats(time.Hour)
	if st.RailTrips[leaserails.CodeMaxDuration] != 1 || st.RailTrips[leaserails.CodeMaxConcurrent] != 1 || st.Rejected < 3 {
		t.Fatalf("%+v", st)
	}
	foundAudit := false
	for _, e := range s.Audit(100) {
		if e.Action == "ebpf.denyset.breakglass" && e.Actor == "carol2" {
			foundAudit = true
		}
	}
	if !foundAudit {
		t.Fatal("break-glass not audited")
	}
	// Protected destination is gated the same way.
	prot := parseSet(t, "name: p\nlease: 10m\ndeny ip 10.96.0.1 egress\n")
	if _, err = planApply(t, s, prot, "dave", "", map[string]bool{"cidr|egress|10.96.0.1/32": true}); !errors.As(err, &re) || re.Decision.Trips[0].Code != leaserails.CodeProtected {
		t.Fatalf("%v", err)
	}
	// Rate rail: erin makes 4 allowed changes then is refused.
	s2 := New()
	s2.SetLeaseRails(leaserails.Config{RateCount: 2, RateWindow: time.Hour})
	if _, err = planApply(t, s2, parseSet(t, "name: r\nlease: 5m\ndeny ip 1.1.1.1 egress\ndeny ip 1.1.1.2 egress\n"), "erin", "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err = planApply(t, s2, parseSet(t, "name: r\nlease: 5m\ndeny ip 1.1.1.1 egress\ndeny ip 1.1.1.2 egress\ndeny ip 1.1.1.3 egress\n"), "erin", "", nil); !errors.As(err, &re) || re.Decision.Trips[0].Code != leaserails.CodeActorRate {
		t.Fatalf("%v", err)
	}
	// Dry run does not consume budget.
	f := parseSet(t, "name: q\nlease: 5m\ndeny ip 2.2.2.2 egress\n")
	leases, present, _ := s2.DenysetPlanState()
	for i := 0; i < 5; i++ {
		_ = s2.EvaluateRails("q", "frank", denyset.Diff(f, leases, present), nil, "")
	}
	if _, err = planApply(t, s2, f, "frank", "", nil); err != nil {
		t.Fatalf("dry runs consumed rate budget: %v", err)
	}
}

func TestDenysetDefaultsPreserveBehaviour(t *testing.T) {
	s := New()
	big := "name: z\nlease: 24h\n"
	for i := 0; i < 50; i++ {
		big += "deny cidr 10." + string(rune('0'+i/10)) + "." + string(rune('0'+i%10)) + ".0/24 both\n"
	}
	big += "deny cidr 0.0.0.0/0 both\n"
	if r, err := planApply(t, s, parseSet(t, big), "a", "", map[string]bool{"cidr|both|0.0.0.0/0": true}); err != nil || r.Added != 51 {
		t.Fatalf("%+v %v", r, err)
	}
}
