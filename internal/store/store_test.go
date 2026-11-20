package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestConfigAndEvents(t *testing.T) {
	s := New()
	c, err := s.AddBlocked("203.0.113.10", "test")
	if err != nil {
		t.Fatal(err)
	}
	if c.Revision < 2 || len(c.BlockedIPv4) != 1 {
		t.Fatalf("bad config: %#v", c)
	}
	c, err = s.SetMode("enforce", 50*time.Millisecond, "test")
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != "enforce" || c.EnforceUntil == nil {
		t.Fatalf("lease missing: %#v", c)
	}
	time.Sleep(70 * time.Millisecond)
	if got := s.Config(); got.Mode != "observe" {
		t.Fatalf("lease should expire: %#v", got)
	}
	now := time.Now().UTC()
	for i := 0; i < 510; i++ {
		s.Report(models.AgentReport{Node: "n1", Events: []models.FastPathEvent{{ObservedAt: now}}})
	}
	if n := len(s.Agents()[0].Events); n != 500 {
		t.Fatalf("expected 500 events, got %d", n)
	}
}

func TestAgentStatusesMarkStale(t *testing.T) {
	s := New()
	now := time.Now().UTC()
	s.Report(models.AgentReport{Node: "fresh", ObservedAt: now.Add(-5 * time.Second)})
	s.Report(models.AgentReport{Node: "stale", ObservedAt: now.Add(-2 * time.Minute)})
	items := s.AgentStatuses(now, 45*time.Second)
	if len(items) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(items))
	}
	seen := map[string]bool{}
	for _, item := range items {
		seen[item.Node] = item.Stale
	}
	if seen["fresh"] || !seen["stale"] {
		t.Fatalf("unexpected stale map: %#v", seen)
	}
}

func TestPreflightReceiptsAreBoundAndOneShot(t *testing.T) {
	s := New()
	body := []byte(`{"kind":"CiliumNetworkPolicy"}`)
	r, err := s.IssuePreflight(body, "high", "test", time.Minute)
	if err != nil || r.Token == "" {
		t.Fatalf("receipt: %#v err=%v", r, err)
	}
	if _, ok, err := s.ConsumePreflight(r.Token, []byte(`{"changed":true}`)); err != nil || ok {
		t.Fatal("receipt must reject a modified body")
	}
	r, err = s.IssuePreflight(body, "high", "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if risk, ok, err := s.ConsumePreflight(r.Token, body); err != nil || !ok || risk != "high" {
		t.Fatalf("consume risk=%q ok=%v err=%v", risk, ok, err)
	}
	if _, ok, err := s.ConsumePreflight(r.Token, body); err != nil || ok {
		t.Fatal("receipt must be one-shot")
	}
}

func TestPersistentPreflightSurvivesLeaderRestartAndRemainsOneShot(t *testing.T) {
	path := t.TempDir() + "/state.json"
	body := []byte(`{"kind":"CiliumNetworkPolicy","metadata":{"name":"egress"}}`)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := s.IssuePreflight(body, "high", "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	risk, ok, err := s.ConsumePreflight(receipt.Token, body)
	if err != nil || !ok || risk != "high" {
		t.Fatalf("consume after restart risk=%q ok=%v err=%v", risk, ok, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, ok, err := s.ConsumePreflight(receipt.Token, body); err != nil || ok {
		t.Fatalf("consumed receipt must not replay after another restart: ok=%v err=%v", ok, err)
	}
}

func TestPreflightConsumePersistenceFailureKeepsReceipt(t *testing.T) {
	s := New()
	body := []byte(`{"kind":"CiliumNetworkPolicy"}`)
	receipt, err := s.IssuePreflight(body, "medium", "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s.backend = &fileBackend{path: t.TempDir()}
	if _, ok, err := s.ConsumePreflight(receipt.Token, body); err == nil || ok || !errors.Is(err, ErrPersistence) {
		t.Fatalf("expected persistence failure without consumption, ok=%v err=%v", ok, err)
	}
	s.backend = nil
	if risk, ok, err := s.ConsumePreflight(receipt.Token, body); err != nil || !ok || risk != "medium" {
		t.Fatalf("receipt should remain usable after failed persistence: risk=%q ok=%v err=%v", risk, ok, err)
	}
}

func TestPolicyHistoryAndRevisionLookup(t *testing.T) {
	s := New()
	first, err := s.RecordPolicyRevision("payments", "egress", "checkpoint", "test", []byte(`{"v":1}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.RecordPolicyRevision("payments", "egress", "apply", "test", []byte(`{"v":2}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.RecordPolicyRevision("other", "egress", "apply", "test", []byte(`{"v":3}`))
	if err != nil {
		t.Fatal(err)
	}
	items := s.PolicyHistory("payments", "egress", 10)
	if len(items) != 2 || items[0].ID != second.ID || items[1].ID != first.ID {
		t.Fatalf("history=%#v", items)
	}
	got, ok := s.PolicyRevision("payments", "egress", first.ID)
	if !ok || string(got.Manifest) != `{"v":1}` {
		t.Fatalf("revision=%#v ok=%v", got, ok)
	}
}

func TestPersistentStoreSurvivesRestartAndFailsOpen(t *testing.T) {
	path := t.TempDir() + "/state.json"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddBlocked("203.0.113.20", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddDNS("blocked.example", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddProcess("curl", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddSNI("blocked.example", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetMode("enforce", time.Hour, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordPolicyRevision("payments", "egress", "apply", "test", []byte(`{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy"}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := s.Config()
	if cfg.Mode != "observe" || len(cfg.BlockedIPv4) != 1 || cfg.BlockedIPv4[0] != "203.0.113.20" || len(cfg.BlockedDNS) != 1 || cfg.BlockedDNS[0] != "blocked.example" || len(cfg.BlockedProcesses) != 1 || cfg.BlockedProcesses[0] != "curl" || len(cfg.BlockedSNI) != 1 || cfg.BlockedSNI[0] != "blocked.example" {
		t.Fatalf("restart state=%#v", cfg)
	}
	if got := s.PolicyHistory("payments", "egress", 10); len(got) != 1 {
		t.Fatalf("expected durable policy history, got %#v", got)
	}
	foundFailOpen := false
	for _, e := range s.Audit(50) {
		if e.Action == "ebpf.restart.fail-open" {
			foundFailOpen = true
		}
	}
	if !foundFailOpen {
		t.Fatal("expected restart fail-open audit event")
	}
}

func TestPersistentStoreRejectsSecondWriter(t *testing.T) {
	path := t.TempDir() + "/state.json"
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := Open(path); err == nil {
		_ = second.Close()
		t.Fatal("expected second writer lock to fail")
	}
}

func TestPolicyArchiveRoundTrip(t *testing.T) {
	s := New()
	if _, err := s.RecordPolicyRevision("payments", "egress", "apply", "test", []byte(`{"kind":"CiliumNetworkPolicy"}`)); err != nil {
		t.Fatal(err)
	}
	archive := s.ExportPolicyArchive()
	dst := New()
	count, err := dst.ImportPolicyArchive(archive, "replace", "restore-test")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || len(dst.PolicyHistory("payments", "egress", 10)) != 1 {
		t.Fatalf("count=%d history=%#v", count, dst.PolicyHistory("payments", "egress", 10))
	}
}

func TestPersistentStoreRejectsCorruptState(t *testing.T) {
	path := t.TempDir() + "/state.json"
	if err := os.WriteFile(path, []byte(`{"schemaVersion":1,`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(path); err == nil {
		_ = s.Close()
		t.Fatal("expected corrupt state to reject startup")
	}
}

func TestPersistenceFailureRollsBackFastPathMutation(t *testing.T) {
	s := New()
	// Renaming a temporary file over an existing directory must fail. This gives
	// the mutator a deterministic persistence error without relying on chmod as root.
	s.backend = &fileBackend{path: t.TempDir()}
	before := s.Config()
	got, err := s.AddBlocked("203.0.113.30", "test")
	if err == nil || !errors.Is(err, ErrPersistence) {
		t.Fatalf("expected persistence error, got %v", err)
	}
	if got.Revision != before.Revision || len(got.BlockedIPv4) != 0 || len(s.Config().BlockedIPv4) != 0 {
		t.Fatalf("mutation was not rolled back: before=%#v got=%#v now=%#v", before, got, s.Config())
	}
}

func TestStandaloneEBPFRules(t *testing.T) {
	s := New()
	if _, err := s.AddBlockedIPv6("2001:db8::10", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddCIDR(models.EBPFCIDRRule{CIDR: "10.0.0.0/8", Direction: "egress"}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPortRule(models.EBPFPortRule{Protocol: "TCP", Port: 22, Direction: "both"}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddUID(1000, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddDNS("telemetry.example.com", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddProcess("curl", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddSNI("api.example.com", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetRateLimit(models.EBPFRateLimit{Destination: "203.0.113.8", PPS: 100}, "test"); err != nil {
		t.Fatal(err)
	}
	c := s.Config()
	if len(c.BlockedIPv6) != 1 || len(c.BlockedCIDRs) != 1 || len(c.BlockedPorts) != 1 || len(c.BlockedUIDs) != 1 || len(c.BlockedDNS) != 1 || len(c.BlockedProcesses) != 1 || len(c.BlockedSNI) != 1 || len(c.RateLimits) != 1 {
		t.Fatalf("rules missing: %#v", c)
	}
	// Config must be a deep copy.
	c.BlockedIPv6[0] = "mutated"
	c.BlockedUIDs[0] = 1
	c.BlockedDNS[0] = "mutated.example"
	c.BlockedProcesses[0] = "mutated"
	c.BlockedSNI[0] = "mutated.example"
	c2 := s.Config()
	if c2.BlockedIPv6[0] == "mutated" || c2.BlockedUIDs[0] == 1 || c2.BlockedDNS[0] == "mutated.example" || c2.BlockedProcesses[0] == "mutated" || c2.BlockedSNI[0] == "mutated.example" {
		t.Fatal("Config leaked mutable slices")
	}
}

func TestRuleIndexAssignsStableIDs(t *testing.T) {
	s := New()
	if _, err := s.AddCIDR(models.EBPFCIDRRule{CIDR: "10.0.0.0/8", Direction: "egress"}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddDNS("tracker.example.com", "test"); err != nil {
		t.Fatal(err)
	}
	rules := s.ListRules()
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d: %#v", len(rules), rules)
	}
	var cidrID, dnsID string
	for _, r := range rules {
		switch r.Type {
		case "cidr":
			cidrID = r.ID
			if r.CIDR != "10.0.0.0/8" || r.Direction != "egress" {
				t.Fatalf("cidr rule wrong: %#v", r)
			}
		case "dns":
			dnsID = r.ID
			if r.Value != "tracker.example.com" {
				t.Fatalf("dns rule wrong: %#v", r)
			}
		}
	}
	if cidrID == "" || dnsID == "" || cidrID == dnsID {
		t.Fatalf("expected distinct non-empty IDs, got cidr=%q dns=%q", cidrID, dnsID)
	}

	// Adding an unrelated rule must not disturb existing IDs.
	if _, err := s.AddUID(1000, "test"); err != nil {
		t.Fatal(err)
	}
	rules = s.ListRules()
	for _, r := range rules {
		if r.Type == "cidr" && r.ID != cidrID {
			t.Fatalf("cidr ID changed after unrelated mutation: was %s now %s", cidrID, r.ID)
		}
		if r.Type == "dns" && r.ID != dnsID {
			t.Fatalf("dns ID changed after unrelated mutation: was %s now %s", dnsID, r.ID)
		}
	}

	// Deleting removes the index entry.
	if _, err := s.DelDNS("tracker.example.com", "test"); err != nil {
		t.Fatal(err)
	}
	for _, r := range s.ListRules() {
		if r.Type == "dns" {
			t.Fatalf("dns rule should have been removed from the index: %#v", r)
		}
	}
	if typ, ok := s.RuleType(dnsID); ok {
		t.Fatalf("RuleType should report the deleted ID as gone, got type=%s", typ)
	}
}

func TestPatchRulePreservesIDAcrossKeyChange(t *testing.T) {
	s := New()
	if _, err := s.AddCIDR(models.EBPFCIDRRule{CIDR: "10.0.0.0/8", Direction: "egress"}, "test"); err != nil {
		t.Fatal(err)
	}
	rules := s.ListRules()
	if len(rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(rules))
	}
	id := rules[0].ID

	cfg, err := s.PatchRule(id, RuleEdit{CIDR: models.EBPFCIDRRule{CIDR: "10.0.0.0/16", Direction: "both"}}, "editor")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.BlockedCIDRs) != 1 || cfg.BlockedCIDRs[0].CIDR != "10.0.0.0/16" || cfg.BlockedCIDRs[0].Direction != "both" {
		t.Fatalf("config not updated: %#v", cfg.BlockedCIDRs)
	}

	rules = s.ListRules()
	if len(rules) != 1 {
		t.Fatalf("want 1 rule after edit, got %d", len(rules))
	}
	if rules[0].ID != id {
		t.Fatalf("ID changed across edit: was %s now %s", id, rules[0].ID)
	}
	if rules[0].CIDR != "10.0.0.0/16" || rules[0].Direction != "both" || rules[0].UpdatedBy != "editor" {
		t.Fatalf("rule not reflecting edit: %#v", rules[0])
	}

	hist := s.FirewallRuleHistory(id, 10)
	if len(hist) != 1 || hist[0].Action != "update" || hist[0].Actor != "editor" {
		t.Fatalf("expected one update revision, got %#v", hist)
	}
	var before, after models.EBPFCIDRRule
	if err := jsonUnmarshalRuleEditCIDR(hist[0].Before, &before); err != nil {
		t.Fatal(err)
	}
	if err := jsonUnmarshalRuleEditCIDR(hist[0].After, &after); err != nil {
		t.Fatal(err)
	}
	if before.CIDR != "10.0.0.0/8" || after.CIDR != "10.0.0.0/16" {
		t.Fatalf("before/after snapshot wrong: before=%#v after=%#v", before, after)
	}

	// Rollback should restore the original value under the same ID.
	cfg, err = s.RollbackFirewallRule(id, hist[0].ID, "reverter")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.BlockedCIDRs) != 1 || cfg.BlockedCIDRs[0].CIDR != "10.0.0.0/8" {
		t.Fatalf("rollback did not restore original value: %#v", cfg.BlockedCIDRs)
	}
	rules = s.ListRules()
	if rules[0].ID != id {
		t.Fatalf("rollback should preserve the ID: got %s want %s", rules[0].ID, id)
	}
}

func TestPatchRulePersistenceFailureRestoresIndex(t *testing.T) {
	s := New()
	if _, err := s.AddCIDR(models.EBPFCIDRRule{CIDR: "10.0.0.0/8", Direction: "egress"}, "test"); err != nil {
		t.Fatal(err)
	}
	id := s.ListRules()[0].ID

	// Same deterministic-failure trick as TestPersistenceFailureRollsBackFastPathMutation.
	s.backend = &fileBackend{path: t.TempDir()}
	_, err := s.PatchRule(id, RuleEdit{CIDR: models.EBPFCIDRRule{CIDR: "10.0.0.0/16", Direction: "both"}}, "editor")
	if err == nil || !errors.Is(err, ErrPersistence) {
		t.Fatalf("expected persistence error, got %v", err)
	}
	rules := s.ListRules()
	if len(rules) != 1 || rules[0].ID != id || rules[0].CIDR != "10.0.0.0/8" || rules[0].UpdatedBy != "" {
		t.Fatalf("index not rolled back after persistence failure: %#v", rules)
	}
	if len(s.FirewallRuleHistory(id, 10)) != 0 {
		t.Fatal("a revision should not have been recorded for a failed patch")
	}
}

func TestAllowCIDRAndIngressDeny(t *testing.T) {
	s := New()
	if _, err := s.AddAllowedCIDR(models.EBPFCIDRRule{CIDR: "10.1.0.0/16", Direction: "egress"}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddBlockedIngress("203.0.113.5", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddBlockedIngressIPv6("2001:db8::5", "test"); err != nil {
		t.Fatal(err)
	}
	c := s.Config()
	if len(c.AllowedCIDRs) != 1 || len(c.BlockedIngressIPv4) != 1 || len(c.BlockedIngressIPv6) != 1 {
		t.Fatalf("rules missing: %#v", c)
	}
	// Config must be a deep copy — the exact class of bug this project hit
	// for real in 0.25.0 (forgetting to clone Shield/NetPolDenies).
	c.AllowedCIDRs[0].CIDR = "mutated"
	c.BlockedIngressIPv4[0] = "mutated"
	c.BlockedIngressIPv6[0] = "mutated"
	c2 := s.Config()
	if c2.AllowedCIDRs[0].CIDR == "mutated" || c2.BlockedIngressIPv4[0] == "mutated" || c2.BlockedIngressIPv6[0] == "mutated" {
		t.Fatal("Config leaked mutable slices")
	}

	// Each new rule type must be independently reachable through the
	// unified rules table and deletable by stable ID.
	rules := s.ListRules()
	byType := map[string]models.FirewallRule{}
	for _, r := range rules {
		byType[r.Type] = r
	}
	for _, typ := range []string{"allow-cidr", "ip4-in", "ip6-in"} {
		r, ok := byType[typ]
		if !ok {
			t.Fatalf("rule type %s missing from ListRules: %#v", typ, rules)
		}
		if _, err := s.DeleteRule(r.ID, "test"); err != nil {
			t.Fatalf("DeleteRule(%s): %v", typ, err)
		}
	}
	final := s.Config()
	if len(final.AllowedCIDRs) != 0 || len(final.BlockedIngressIPv4) != 0 || len(final.BlockedIngressIPv6) != 0 {
		t.Fatalf("rules not removed via DeleteRule: %#v", final)
	}
}

func TestAllowedPort(t *testing.T) {
	s := New()
	rule := models.EBPFPortRule{Protocol: "TCP", Port: 8443, Direction: "egress"}
	if _, err := s.AddAllowedPort(rule, "test"); err != nil {
		t.Fatal(err)
	}
	c := s.Config()
	if len(c.AllowedPorts) != 1 || c.AllowedPorts[0] != rule {
		t.Fatalf("rule missing: %#v", c.AllowedPorts)
	}
	// Config must be a deep copy.
	c.AllowedPorts[0].Port = 1
	c2 := s.Config()
	if c2.AllowedPorts[0].Port == 1 {
		t.Fatal("Config leaked mutable slice")
	}

	rules := s.ListRules()
	var found *models.FirewallRule
	for i := range rules {
		if rules[i].Type == "allow-port" {
			found = &rules[i]
		}
	}
	if found == nil {
		t.Fatalf("allow-port missing from ListRules: %#v", rules)
	}
	if found.Protocol != "TCP" || found.Port != 8443 || found.Direction != "egress" {
		t.Fatalf("unexpected allow-port rule: %#v", found)
	}
	if _, err := s.DeleteRule(found.ID, "test"); err != nil {
		t.Fatalf("DeleteRule(allow-port): %v", err)
	}
	final := s.Config()
	if len(final.AllowedPorts) != 0 {
		t.Fatalf("rule not removed via DeleteRule: %#v", final)
	}
}

func TestAllowedUIDAndProcess(t *testing.T) {
	s := New()
	if _, err := s.AddAllowedUID(1000, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAllowedProcess("coredns", "test"); err != nil {
		t.Fatal(err)
	}
	c := s.Config()
	if len(c.AllowedUIDs) != 1 || c.AllowedUIDs[0] != 1000 || len(c.AllowedProcesses) != 1 || c.AllowedProcesses[0] != "coredns" {
		t.Fatalf("rules missing: %#v", c)
	}
	// Config must be a deep copy.
	c.AllowedUIDs[0] = 1
	c.AllowedProcesses[0] = "mutated"
	c2 := s.Config()
	if c2.AllowedUIDs[0] == 1 || c2.AllowedProcesses[0] == "mutated" {
		t.Fatal("Config leaked mutable slices")
	}

	rules := s.ListRules()
	byType := map[string]models.FirewallRule{}
	for _, r := range rules {
		byType[r.Type] = r
	}
	for _, typ := range []string{"allow-uid", "allow-process"} {
		r, ok := byType[typ]
		if !ok {
			t.Fatalf("rule type %s missing from ListRules: %#v", typ, rules)
		}
		if _, err := s.DeleteRule(r.ID, "test"); err != nil {
			t.Fatalf("DeleteRule(%s): %v", typ, err)
		}
	}
	final := s.Config()
	if len(final.AllowedUIDs) != 0 || len(final.AllowedProcesses) != 0 {
		t.Fatalf("rules not removed via DeleteRule: %#v", final)
	}
}

func TestDeleteRuleByID(t *testing.T) {
	s := New()
	if _, err := s.AddUID(1000, "test"); err != nil {
		t.Fatal(err)
	}
	rules := s.ListRules()
	if len(rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(rules))
	}
	cfg, err := s.DeleteRule(rules[0].ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.BlockedUIDs) != 0 {
		t.Fatalf("UID not removed: %#v", cfg.BlockedUIDs)
	}
	if _, err := s.DeleteRule("nonexistent-id", "test"); err == nil {
		t.Fatal("expected error deleting an unknown rule ID")
	}
}

func TestRuleIndexPersistsAndMigrationBackfillsLegacyState(t *testing.T) {
	path := t.TempDir() + "/state.json"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddDNS("tracker.example.com", "test"); err != nil {
		t.Fatal(err)
	}
	rules := s.ListRules()
	id := rules[0].ID
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Restart: the real ID/actor must survive since it was already indexed.
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	rules = s.ListRules()
	if len(rules) != 1 || rules[0].ID != id || rules[0].CreatedBy != "test" {
		t.Fatalf("rule index did not survive restart: %#v", rules)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a pre-rule-ID state file (no ruleIndex/nextRuleSeq keys at
	// all) by stripping them back out, then confirm load() backfills a
	// working index rather than erroring or leaving rules unindexed.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	delete(raw, "ruleIndex")
	delete(raw, "nextRuleSeq")
	b, err = json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rules = s.ListRules()
	if len(rules) != 1 || rules[0].Value != "tracker.example.com" {
		t.Fatalf("migration backfill failed: %#v", rules)
	}
	if rules[0].CreatedBy != "system:migration" {
		t.Fatalf("expected migration backfill actor, got %q", rules[0].CreatedBy)
	}
}

func jsonUnmarshalRuleEditCIDR(raw []byte, out *models.EBPFCIDRRule) error {
	var edit RuleEdit
	if err := json.Unmarshal(raw, &edit); err != nil {
		return err
	}
	*out = edit.CIDR
	return nil
}

func TestNetPolRuleCRUD(t *testing.T) {
	s := New()
	rule := models.NetPolRule{
		Selector: models.EBPFWorkloadScope{Namespace: "payments"},
		PeerIPv4: "10.0.0.5", Port: 5432, Protocol: "TCP", Direction: "egress", Action: "allow",
	}
	cfg, err := s.AddNetPolRule(rule, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.NetPolRules) != 1 {
		t.Fatalf("want 1 rule, got %#v", cfg.NetPolRules)
	}
	added := cfg.NetPolRules[0]
	if added.ID == "" || added.CreatedBy != "test" || added.CreatedAt.IsZero() {
		t.Fatalf("rule metadata not set: %#v", added)
	}
	if added.Selector.Namespace != "payments" {
		t.Fatalf("selector not preserved: %#v", added.Selector)
	}

	// A second rule must get a distinct, sequential ID.
	cfg, err = s.AddNetPolRule(models.NetPolRule{PeerIPv4: "10.0.0.6", Action: "deny"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.NetPolRules) != 2 || cfg.NetPolRules[0].ID == cfg.NetPolRules[1].ID {
		t.Fatalf("expected 2 distinct rule IDs: %#v", cfg.NetPolRules)
	}

	cfg, err = s.DelNetPolRule(added.ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.NetPolRules) != 1 || cfg.NetPolRules[0].PeerIPv4 != "10.0.0.6" {
		t.Fatalf("delete did not remove the right rule: %#v", cfg.NetPolRules)
	}
	if _, err := s.DelNetPolRule("nonexistent", "test"); err == nil {
		t.Fatal("expected error deleting an unknown netpol rule id")
	}
}

// TestSetRateLimitPPSAndBPSIndependent guards BPS being additive to the
// existing PPS-only rate-limit rule, not a replacement type: a rule can
// carry PPS, BPS, or both, and is only removed when both are zero.
func TestSetRateLimitPPSAndBPSIndependent(t *testing.T) {
	s := New()
	cfg, err := s.SetRateLimit(models.EBPFRateLimit{Destination: "10.0.0.5", PPS: 100, BPS: 5000}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RateLimits) != 1 || cfg.RateLimits[0].PPS != 100 || cfg.RateLimits[0].BPS != 5000 {
		t.Fatalf("expected both PPS and BPS set: %#v", cfg.RateLimits)
	}

	// BPS-only (PPS: 0) must survive — this is not delete semantics.
	cfg, err = s.SetRateLimit(models.EBPFRateLimit{Destination: "10.0.0.6", BPS: 2000}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RateLimits) != 2 {
		t.Fatalf("expected a BPS-only rule to be kept: %#v", cfg.RateLimits)
	}

	// All-zero (neither PPS nor BPS) is delete semantics.
	cfg, err = s.SetRateLimit(models.EBPFRateLimit{Destination: "10.0.0.5"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RateLimits) != 1 || cfg.RateLimits[0].Destination != "10.0.0.6" {
		t.Fatalf("expected the all-zero rule to be deleted: %#v", cfg.RateLimits)
	}
}

func TestDeniedCapabilityCRUD(t *testing.T) {
	s := New()
	cfg, err := s.AddDeniedCapability("CAP_NET_RAW", "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DeniedCapabilities) != 1 || cfg.DeniedCapabilities[0] != "CAP_NET_RAW" {
		t.Fatalf("unexpected denied capabilities: %#v", cfg.DeniedCapabilities)
	}

	// Adding the identical entry again must be a no-op, not a duplicate.
	cfg, err = s.AddDeniedCapability("CAP_NET_RAW", "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DeniedCapabilities) != 1 {
		t.Fatalf("expected no duplicate entry: %#v", cfg.DeniedCapabilities)
	}

	cfg, err = s.AddDeniedCapability("CAP_NET_ADMIN", "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DeniedCapabilities) != 2 {
		t.Fatalf("expected 2 distinct entries: %#v", cfg.DeniedCapabilities)
	}

	cfg, err = s.DelDeniedCapability("CAP_NET_RAW", "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DeniedCapabilities) != 1 || cfg.DeniedCapabilities[0] != "CAP_NET_ADMIN" {
		t.Fatalf("delete did not remove the right entry: %#v", cfg.DeniedCapabilities)
	}
}

func TestSynDropCRUD(t *testing.T) {
	s := New()
	entry := models.EBPFSynDropEntry{Address: "203.0.113.5", Direction: "egress"}
	cfg, err := s.AddSynDrop(entry, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SynDrop) != 1 || cfg.SynDrop[0] != entry {
		t.Fatalf("unexpected syndrop entries: %#v", cfg.SynDrop)
	}

	// Adding the identical entry again must be a no-op, not a duplicate.
	cfg, err = s.AddSynDrop(entry, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SynDrop) != 1 {
		t.Fatalf("expected no duplicate entry: %#v", cfg.SynDrop)
	}

	// Same address, different direction is a distinct entry.
	other := models.EBPFSynDropEntry{Address: "203.0.113.5", Direction: "ingress"}
	cfg, err = s.AddSynDrop(other, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SynDrop) != 2 {
		t.Fatalf("expected the ingress entry to be distinct: %#v", cfg.SynDrop)
	}

	cfg, err = s.DelSynDrop(entry, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SynDrop) != 1 || cfg.SynDrop[0] != other {
		t.Fatalf("delete did not remove the right entry: %#v", cfg.SynDrop)
	}
}

func TestSynDropCIDRCRUD(t *testing.T) {
	s := New()
	entry := models.EBPFSynDropCIDR{CIDR: "203.0.113.0/24", Direction: "egress"}
	cfg, err := s.AddSynDropCIDR(entry, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SynDropCIDR) != 1 || cfg.SynDropCIDR[0] != entry {
		t.Fatalf("unexpected syndrop-cidr entries: %#v", cfg.SynDropCIDR)
	}

	// Adding the identical entry again must be a no-op, not a duplicate.
	cfg, err = s.AddSynDropCIDR(entry, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SynDropCIDR) != 1 {
		t.Fatalf("expected no duplicate entry: %#v", cfg.SynDropCIDR)
	}

	// Same CIDR, different direction is a distinct entry.
	other := models.EBPFSynDropCIDR{CIDR: "203.0.113.0/24", Direction: "ingress"}
	cfg, err = s.AddSynDropCIDR(other, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SynDropCIDR) != 2 {
		t.Fatalf("expected the ingress entry to be distinct: %#v", cfg.SynDropCIDR)
	}

	cfg, err = s.DelSynDropCIDR(entry, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SynDropCIDR) != 1 || cfg.SynDropCIDR[0] != other {
		t.Fatalf("delete did not remove the right entry: %#v", cfg.SynDropCIDR)
	}
}

func TestConnRateLimitCRUD(t *testing.T) {
	s := New()
	rule := models.EBPFConnRateLimit{
		Selector:  models.EBPFWorkloadScope{Namespace: "payments"},
		PerSecond: 50,
	}
	cfg, err := s.AddConnRateLimit(rule, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.ConnRateLimits) != 1 {
		t.Fatalf("want 1 rule, got %#v", cfg.ConnRateLimits)
	}
	added := cfg.ConnRateLimits[0]
	if added.ID == "" || added.CreatedBy != "test" || added.CreatedAt.IsZero() {
		t.Fatalf("rule metadata not set: %#v", added)
	}
	if added.Selector.Namespace != "payments" || added.PerSecond != 50 {
		t.Fatalf("rule not preserved: %#v", added)
	}

	// A second rule must get a distinct, sequential ID.
	cfg, err = s.AddConnRateLimit(models.EBPFConnRateLimit{Selector: models.EBPFWorkloadScope{Namespace: "checkout"}, PerSecond: 10}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.ConnRateLimits) != 2 || cfg.ConnRateLimits[0].ID == cfg.ConnRateLimits[1].ID {
		t.Fatalf("expected 2 distinct rule IDs: %#v", cfg.ConnRateLimits)
	}

	if _, err := s.AddConnRateLimit(models.EBPFConnRateLimit{Selector: models.EBPFWorkloadScope{Namespace: "x"}, PerSecond: 0}, "test"); err == nil {
		t.Fatal("expected error adding a zero-PerSecond conn rate limit")
	}

	cfg, err = s.DelConnRateLimit(added.ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.ConnRateLimits) != 1 || cfg.ConnRateLimits[0].Selector.Namespace != "checkout" {
		t.Fatalf("delete did not remove the right rule: %#v", cfg.ConnRateLimits)
	}
	if _, err := s.DelConnRateLimit("nonexistent", "test"); err == nil {
		t.Fatal("expected error deleting an unknown conn rate limit id")
	}
}

func TestSetNetPolDefaultDenyActivateAndExpire(t *testing.T) {
	s := New()
	selector := models.EBPFWorkloadScope{Namespace: "payments", Pod: "api-1"}
	cfg, err := s.SetNetPolDefaultDeny(selector, true, 5*time.Minute, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.NetPolDefaultDenies) != 1 || cfg.NetPolDefaultDenies[0].LeaseSeconds != 300 || cfg.NetPolDefaultDenies[0].Actor != "operator" {
		t.Fatalf("activation not recorded: %#v", cfg.NetPolDefaultDenies)
	}

	// Re-activating the identical selector must replace, not duplicate.
	cfg, err = s.SetNetPolDefaultDeny(selector, true, 10*time.Minute, "operator2")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.NetPolDefaultDenies) != 1 || cfg.NetPolDefaultDenies[0].Actor != "operator2" {
		t.Fatalf("re-activation should replace the existing entry: %#v", cfg.NetPolDefaultDenies)
	}

	// Explicit deactivation.
	cfg, err = s.SetNetPolDefaultDeny(selector, false, 0, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.NetPolDefaultDenies) != 0 {
		t.Fatalf("expected deactivation to clear the entry: %#v", cfg.NetPolDefaultDenies)
	}

	// Lease self-revert: a negative lease sets EnabledUntil in the past, so
	// the very next Config() call (which normalizes) must expire it.
	if _, err := s.SetNetPolDefaultDeny(selector, true, -time.Second, "operator"); err != nil {
		t.Fatal(err)
	}
	cfg = s.Config()
	if len(cfg.NetPolDefaultDenies) != 0 {
		t.Fatalf("expected expired default-deny to self-revert, got %#v", cfg.NetPolDefaultDenies)
	}
	found := false
	for _, e := range s.Audit(20) {
		if e.Action == "ebpf.netpol.default-deny.expired" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected an ebpf.netpol.default-deny.expired audit event")
	}
}

func TestNetPolDefaultDenyNeverResurrectsAcrossRestart(t *testing.T) {
	path := t.TempDir() + "/state.json"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	selector := models.EBPFWorkloadScope{Namespace: "payments"}
	if _, err := s.SetNetPolDefaultDeny(selector, true, time.Hour, "operator"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := s.Config()
	if len(cfg.NetPolDefaultDenies) != 0 {
		t.Fatalf("default-deny must not resurrect across a restart, got %#v", cfg.NetPolDefaultDenies)
	}
	found := false
	for _, e := range s.Audit(20) {
		if e.Action == "ebpf.netpol.default-deny.restart-fail-open" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected an ebpf.netpol.default-deny.restart-fail-open audit event")
	}
}

func TestSetShieldBumpsGenerationLastAndDeepCopies(t *testing.T) {
	s := New()
	cfg, err := s.SetShield(models.ShieldConfig{Mode: "audit", ProtectedIPv4: []string{"203.0.113.9", "203.0.113.1"}, SynPPS: 5000}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Shield == nil || cfg.Shield.Mode != "audit" || cfg.Shield.Generation != 1 {
		t.Fatalf("cfg.Shield=%#v", cfg.Shield)
	}
	if len(cfg.Shield.ProtectedIPv4) != 2 || cfg.Shield.ProtectedIPv4[0] != "203.0.113.1" {
		t.Fatalf("protected IPs not sorted: %#v", cfg.Shield.ProtectedIPv4)
	}
	// A second SetShield call must bump the generation further, confirming
	// it's read from the prior stored config, not reset to a fixed value.
	cfg2, err := s.SetShield(models.ShieldConfig{Mode: "enforce"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Shield.Generation != 2 {
		t.Fatalf("expected generation 2, got %d", cfg2.Shield.Generation)
	}
	// Config() must be a deep copy — mutating the returned Shield pointer
	// or its slice must not corrupt the stored state.
	cfg2.Shield.Mode = "mutated"
	cfg3 := s.Config()
	if cfg3.Shield.Mode == "mutated" {
		t.Fatal("Config() leaked the Shield pointer")
	}
}

func TestSetNetPolEnabled(t *testing.T) {
	s := New()
	cfg, err := s.SetNetPolEnabled(true, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.NetPolEnabled {
		t.Fatal("expected NetPolEnabled=true")
	}
	cfg, err = s.SetNetPolEnabled(false, "test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NetPolEnabled {
		t.Fatal("expected NetPolEnabled=false")
	}
}

func TestWorkloadScopePersists(t *testing.T) {
	path := t.TempDir() + "/state.json"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := s.SetWorkloadScopes("selected", []models.EBPFWorkloadScope{{Namespace: "payments", Labels: map[string]string{"app": "api"}}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ScopeMode != "selected" || len(cfg.WorkloadScopes) != 1 {
		t.Fatalf("cfg=%#v", cfg)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg = s.Config()
	if cfg.ScopeMode != "selected" || cfg.WorkloadScopes[0].Labels["app"] != "api" {
		t.Fatalf("restart cfg=%#v", cfg)
	}
	if len(cfg.Workloads) != 0 {
		t.Fatal("ephemeral workload inventory must not persist")
	}
}

func TestBehaviorBaselinePersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	b := models.BehaviorBaseline{SchemaVersion: 1, CapturedAt: time.Unix(123, 0).UTC(), Entries: []models.BehaviorBaselineEntry{{Source: "pod:prod:api", Kind: "sni", Value: "api.example.com", Count: 3}}}
	if err := s.SetBaseline(b, "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got := s2.Baseline()
	if len(got.Entries) != 1 || got.Entries[0].Value != "api.example.com" {
		t.Fatalf("baseline=%#v", got)
	}
}

func TestCaptureLifecycle(t *testing.T) {
	s := New()
	if got := s.Capture("node-a"); got != nil {
		t.Fatalf("expected no active capture, got %#v", got)
	}
	spec := s.SetCapture(models.CaptureSpec{Node: "node-a", Protocol: "tcp", Port: 443, ExpiresAt: time.Now().Add(time.Hour)}, "alice")
	if spec.Requestor != "alice" || spec.StartedAt.IsZero() {
		t.Fatalf("SetCapture did not stamp requestor/startedAt: %#v", spec)
	}
	got := s.Capture("node-a")
	if got == nil || got.Protocol != "tcp" || got.Port != 443 {
		t.Fatalf("Capture(node-a) = %#v", got)
	}
	if all := s.Captures(); len(all) != 1 || all[0].Node != "node-a" {
		t.Fatalf("Captures() = %#v", all)
	}
	if s.Capture("node-b") != nil {
		t.Fatal("expected node-b to have no active capture")
	}
	auditBefore := len(s.audit)
	if !s.ClearCapture("node-a", "alice", "manual") {
		t.Fatal("ClearCapture on an active session should return true")
	}
	if s.ClearCapture("node-a", "alice", "manual") {
		t.Fatal("ClearCapture on an already-stopped session should return false")
	}
	if len(s.audit) != auditBefore+1 {
		t.Fatalf("expected exactly one new audit event for the real stop, got %d new", len(s.audit)-auditBefore)
	}
	if s.Capture("node-a") != nil {
		t.Fatal("expected no active capture after ClearCapture")
	}
}

func TestCaptureExpiry(t *testing.T) {
	s := New()
	s.SetCapture(models.CaptureSpec{Node: "node-a", Host: "10.0.0.1", ExpiresAt: time.Now().Add(20 * time.Millisecond)}, "bob")
	time.Sleep(40 * time.Millisecond)
	if got := s.Capture("node-a"); got != nil {
		t.Fatalf("expected expired capture to read back as nil, got %#v", got)
	}
	if all := s.Captures(); len(all) != 0 {
		t.Fatalf("expected Captures() to have expired the entry, got %#v", all)
	}
}
