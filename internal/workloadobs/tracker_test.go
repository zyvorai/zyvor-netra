// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package workloadobs

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

var t0 = time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

func agent(node string, mut func(*models.AgentReport)) models.AgentStatus {
	r := models.AgentReport{Node: node}
	if mut != nil {
		mut(&r)
	}
	return models.AgentStatus{AgentReport: r}
}

// cgroupOf gives each workload (or pod) its own cgroup id, as on a real node:
// agent entries are keyed by cgroup, so distinct workloads never share one.
func cgroupOf(name string) uint64 {
	var h uint64 = 14695981039346656037
	for _, c := range name {
		h = (h ^ uint64(c)) * 1099511628211
	}
	return h
}

func flow(ns, name string, dstPort uint16, packets, bytes, blocked uint64) models.DestinationStat {
	return models.DestinationStat{
		Namespace: ns, WorkloadKind: "Deployment", WorkloadName: name, CgroupID: cgroupOf(ns + "/" + name), Hook: "egress", Direction: "egress",
		Protocol: "tcp", SourceIP: "10.0.0.1", DestinationIP: "10.0.0.2", Port: dstPort,
		Packets: packets, Bytes: bytes, Blocked: blocked,
	}
}

func statsAgent(node string, fl ...models.DestinationStat) models.AgentStatus {
	return agent(node, func(r *models.AgentReport) { r.Stats = fl })
}

func find(s Snapshot, ns, wl string) (NamedTotals, bool) {
	for _, n := range s.Named {
		if n.Key.Namespace == ns && n.Key.Workload == wl {
			return n, true
		}
	}
	return NamedTotals{}, false
}

func TestFirstReportOnlyEstablishesABaseline(t *testing.T) {
	tr := NewTracker(TrackerConfig{})
	d := tr.Update([]models.AgentStatus{statsAgent("n1", flow("shop", "web", 80, 1_000_000, 9_000_000, 5))}, t0)
	if len(d) != 0 {
		t.Fatalf("first report produced deltas %v: lifetime history was booked as one tick's growth", d)
	}
	if s := tr.Snapshot(); len(s.Named) != 0 || s.Other[Packets] != 0 || s.Entries != 1 {
		t.Fatalf("snapshot after baseline = %+v", s)
	}
}

func TestGrowthAccumulatesPerWorkloadAndSumsAcrossFlows(t *testing.T) {
	tr := NewTracker(TrackerConfig{})
	tr.Update([]models.AgentStatus{statsAgent("n1", flow("shop", "web", 80, 100, 1000, 0), flow("shop", "web", 443, 50, 500, 0))}, t0)
	d := tr.Update([]models.AgentStatus{statsAgent("n1", flow("shop", "web", 80, 130, 1300, 2), flow("shop", "web", 443, 60, 600, 0))}, t0.Add(time.Minute))

	if len(d) != 1 || d[0].Key != (Key{"shop", "Deployment/web"}) {
		t.Fatalf("deltas = %+v", d)
	}
	if d[0].V[Packets] != 40 || d[0].V[Bytes] != 400 || d[0].V[BlockedPackets] != 2 {
		t.Fatalf("delta = %v, want packets 40 bytes 400 blocked 2 (two flows summed)", d[0].V)
	}
	n, ok := find(tr.Snapshot(), "shop", "Deployment/web")
	if !ok || n.V[Packets] != 40 {
		t.Fatalf("named totals = %+v ok=%v", n, ok)
	}
}

// The property the whole package exists for: a pod dying must not make a
// workload's counter fall, and a replacement pod's traffic must count.
func TestTotalsNeverDecreaseAcrossPodChurn(t *testing.T) {
	tr := NewTracker(TrackerConfig{})
	pod := func(name string, packets uint64) models.DestinationStat {
		f := flow("shop", "web", 80, packets, packets*10, 0)
		f.CgroupID = cgroupOf(name) // one cgroup per pod
		f.Pod = name
		return f
	}
	tr.Update([]models.AgentStatus{statsAgent("n1", pod("web-aaaaa", 100), pod("web-bbbbb", 100))}, t0)
	tr.Update([]models.AgentStatus{statsAgent("n1", pod("web-aaaaa", 150), pod("web-bbbbb", 130))}, t0.Add(1*time.Minute))
	before, _ := find(tr.Snapshot(), "shop", "Deployment/web")
	if before.V[Packets] != 80 {
		t.Fatalf("total = %d, want 80", before.V[Packets])
	}

	// web-bbbbb is gone (pod deleted); a new pod appears, with its own history.
	newPod := pod("web-cccccccc", 40)
	tr.Update([]models.AgentStatus{statsAgent("n1", pod("web-aaaaa", 160), newPod)}, t0.Add(2*time.Minute))
	after, _ := find(tr.Snapshot(), "shop", "Deployment/web")
	if after.V[Packets] < before.V[Packets] {
		t.Fatalf("total fell from %d to %d when a pod disappeared", before.V[Packets], after.V[Packets])
	}
	// +10 from the surviving pod, +40 from the brand-new pod (created since the last look).
	if after.V[Packets] != 80+10+40 {
		t.Fatalf("total = %d, want %d", after.V[Packets], 80+10+40)
	}
}

func TestCounterResetIsCountedAsRestartFromZeroNotNegativeGrowth(t *testing.T) {
	tr := NewTracker(TrackerConfig{})
	tr.Update([]models.AgentStatus{statsAgent("n1", flow("a", "x", 80, 1000, 1000, 0))}, t0)
	tr.Update([]models.AgentStatus{statsAgent("n1", flow("a", "x", 80, 1100, 1100, 0))}, t0.Add(time.Minute))
	// Agent restarted: the same flow now reports 30, far below 1100.
	tr.Update([]models.AgentStatus{statsAgent("n1", flow("a", "x", 80, 30, 30, 0))}, t0.Add(2*time.Minute))
	n, _ := find(tr.Snapshot(), "a", "Deployment/x")
	if n.V[Packets] != 100+30 {
		t.Fatalf("total = %d, want 130 (100 growth + 30 since the reset)", n.V[Packets])
	}
}

// A node that was stale (or gone) and returns holds lifetime totals; treating
// them as fresh growth would book days of traffic in one tick.
func TestReturningNodeReseedsInsteadOfSpiking(t *testing.T) {
	tr := NewTracker(TrackerConfig{})
	tr.Update([]models.AgentStatus{statsAgent("n1", flow("a", "x", 80, 100, 100, 0))}, t0)
	tr.Update([]models.AgentStatus{statsAgent("n1", flow("a", "x", 80, 110, 110, 0))}, t0.Add(time.Minute))

	stale := statsAgent("n1", flow("a", "x", 80, 110, 110, 0))
	stale.Stale = true
	tr.Update([]models.AgentStatus{stale}, t0.Add(2*time.Minute)) // node absent this round

	d := tr.Update([]models.AgentStatus{statsAgent("n1", flow("a", "x", 80, 9_000_000, 9_000_000, 0))}, t0.Add(3*time.Minute))
	if len(d) != 0 {
		t.Fatalf("a returning node produced deltas %v; it should only re-baseline", d)
	}
	n, _ := find(tr.Snapshot(), "a", "Deployment/x")
	if n.V[Packets] != 10 {
		t.Fatalf("total = %d, want 10 (only the growth seen before the outage)", n.V[Packets])
	}
	// And growth after the re-baseline counts normally.
	tr.Update([]models.AgentStatus{statsAgent("n1", flow("a", "x", 80, 9_000_005, 9_000_005, 0))}, t0.Add(4*time.Minute))
	if n, _ := find(tr.Snapshot(), "a", "Deployment/x"); n.V[Packets] != 15 {
		t.Fatalf("total = %d, want 15", n.V[Packets])
	}
}

func TestNewNodeJoiningLaterIsBaselinedNotBackfilled(t *testing.T) {
	tr := NewTracker(TrackerConfig{})
	tr.Update([]models.AgentStatus{statsAgent("n1", flow("a", "x", 80, 10, 10, 0))}, t0)
	tr.Update([]models.AgentStatus{
		statsAgent("n1", flow("a", "x", 80, 20, 20, 0)),
		statsAgent("n2", flow("a", "x", 80, 5_000, 5_000, 0)), // joins with history
	}, t0.Add(time.Minute))
	n, _ := find(tr.Snapshot(), "a", "Deployment/x")
	if n.V[Packets] != 10 {
		t.Fatalf("total = %d, want 10: the new node's history must not be counted", n.V[Packets])
	}
}

func TestCardinalityCapAdmitsBusiestFirstAndKeepsNamedStable(t *testing.T) {
	tr := NewTracker(TrackerConfig{MaxNamed: 2})
	mk := func(a, b, c, d uint64) models.AgentStatus {
		return statsAgent("n1", flow("ns", "a", 1, a, a, 0), flow("ns", "b", 1, b, b, 0), flow("ns", "c", 1, c, c, 0), flow("ns", "d", 1, d, d, 0))
	}
	tr.Update([]models.AgentStatus{mk(0, 0, 0, 0)}, t0)
	tr.Update([]models.AgentStatus{mk(5, 100, 50, 1)}, t0.Add(time.Minute))
	s := tr.Snapshot()
	if len(s.Named) != 2 {
		t.Fatalf("named = %d, want the cap of 2", len(s.Named))
	}
	if _, ok := find(s, "ns", "Deployment/b"); !ok {
		t.Fatal("busiest workload b must be named")
	}
	if _, ok := find(s, "ns", "Deployment/c"); !ok {
		t.Fatal("second busiest workload c must be named")
	}
	if s.Other[Packets] != 6 {
		t.Fatalf("__other__ = %d, want 6 (a=5 + d=1)", s.Other[Packets])
	}

	// a now becomes by far the busiest, but named series must stay put: series
	// that come and go break rate().
	tr.Update([]models.AgentStatus{mk(5000, 101, 51, 2)}, t0.Add(2*time.Minute))
	s = tr.Snapshot()
	if _, ok := find(s, "ns", "Deployment/a"); ok {
		t.Fatal("a workload must not displace an already-named one just by getting busy")
	}
	if b, _ := find(s, "ns", "Deployment/b"); b.V[Packets] != 101 {
		t.Fatalf("b total = %d, want 101", b.V[Packets])
	}
	if s.Other[Packets] != 6+4995+1 {
		t.Fatalf("__other__ = %d, want %d", s.Other[Packets], 6+4995+1)
	}

	// Conservation: nothing is lost or double counted.
	var sum uint64
	for _, n := range s.Named {
		sum += n.V[Packets]
	}
	if sum+s.Other[Packets] != (5000-5)+(101-100)+(51-50)+(2-1)+(5+100+50+1) {
		t.Fatalf("named %d + other %d does not equal total growth", sum, s.Other[Packets])
	}
}

func TestIdleWorkloadIsEvictedAndItsSlotReused(t *testing.T) {
	tr := NewTracker(TrackerConfig{MaxNamed: 1, IdleTimeout: 10 * time.Minute})
	mk := func(a, b uint64) models.AgentStatus {
		return statsAgent("n1", flow("ns", "a", 1, a, a, 0), flow("ns", "b", 1, b, b, 0))
	}
	tr.Update([]models.AgentStatus{mk(0, 0)}, t0)
	tr.Update([]models.AgentStatus{mk(10, 0)}, t0.Add(time.Minute)) // a named
	if _, ok := find(tr.Snapshot(), "ns", "Deployment/a"); !ok {
		t.Fatal("a should be named")
	}
	// b is active, a is silent; the slot is taken so b spills to __other__.
	tr.Update([]models.AgentStatus{mk(10, 5)}, t0.Add(5*time.Minute))
	if s := tr.Snapshot(); s.Other[Packets] != 5 {
		t.Fatalf("__other__ = %d, want 5", s.Other[Packets])
	}
	// 12 minutes after a's last activity it is idle: evicted, and b takes the slot.
	tr.Update([]models.AgentStatus{mk(10, 9)}, t0.Add(13*time.Minute))
	s := tr.Snapshot()
	if _, ok := find(s, "ns", "Deployment/a"); ok {
		t.Fatal("idle workload a should have been evicted")
	}
	if b, ok := find(s, "ns", "Deployment/b"); !ok || b.V[Packets] != 4 {
		t.Fatalf("b = %+v ok=%v, want named with the 4 packets since admission", b, ok)
	}
}

func TestHTTPStatusClassificationAndOtherSignals(t *testing.T) {
	tr := NewTracker(TrackerConfig{})
	rep := func(ok200, e503, e404 uint64, att, blk, dq, dfail uint64) models.AgentStatus {
		ns, kind, name := "shop", "Deployment", "web"
		return agent("n1", func(r *models.AgentReport) {
			r.HTTPStatus = []models.HTTPStatusStat{
				{CgroupID: 1, Status: 200, Count: ok200, Namespace: ns, WorkloadKind: kind, WorkloadName: name},
				{CgroupID: 1, Status: 503, Count: e503, Namespace: ns, WorkloadKind: kind, WorkloadName: name},
				{CgroupID: 1, Status: 404, Count: e404, Namespace: ns, WorkloadKind: kind, WorkloadName: name},
			}
			r.ConnectionAttempts = []models.ConnectionAttemptStat{{CgroupID: 1, Family: "ipv4", Protocol: "tcp", RemoteIP: "2", RemotePort: 2,
				Attempts: att, Blocked: blk, Namespace: ns, WorkloadKind: kind, WorkloadName: name}}
			r.DNSHealth = []models.DNSHealthStat{{CgroupID: 1, Name: "svc.local", Queries: dq, Failures: dfail, Namespace: ns, WorkloadKind: kind, WorkloadName: name}}
		})
	}
	tr.Update([]models.AgentStatus{rep(0, 0, 0, 0, 0, 0, 0)}, t0)
	tr.Update([]models.AgentStatus{rep(90, 7, 3, 20, 2, 50, 6)}, t0.Add(time.Minute))
	n, _ := find(tr.Snapshot(), "shop", "Deployment/web")
	want := map[Counter]uint64{
		HTTPResponses: 100, HTTP5xx: 7,
		ConnectionAttempts: 20, ConnectionsBlocked: 2, DNSQueries: 50, DNSFailures: 6,
	}
	for c, w := range want {
		if n.V[c] != w {
			t.Errorf("%s = %d, want %d", Counters[c].Name, n.V[c], w)
		}
	}
}

func TestEntriesWithoutAWorkloadAreIgnoredAndBarePodsGetAPodKey(t *testing.T) {
	tr := NewTracker(TrackerConfig{})
	host := models.DestinationStat{CgroupID: 1, DestinationIP: "1.1.1.1", Port: 53, Packets: 10}
	barePod := models.DestinationStat{CgroupID: 2, DestinationIP: "1.1.1.1", Port: 53, Packets: 10, Namespace: "kube-system", Pod: "debug-shell"}
	tr.Update([]models.AgentStatus{statsAgent("n1", host, barePod)}, t0)
	host.Packets, barePod.Packets = 20, 25
	d := tr.Update([]models.AgentStatus{statsAgent("n1", host, barePod)}, t0.Add(time.Minute))
	if len(d) != 1 || d[0].Key != (Key{"kube-system", "Pod/debug-shell"}) || d[0].V[Packets] != 15 {
		t.Fatalf("deltas = %+v: host traffic must be ignored, a bare pod keyed Pod/<name>", d)
	}
}

func TestEntryCapDropsNewEntriesAndCountsThem(t *testing.T) {
	tr := NewTracker(TrackerConfig{MaxEntries: 3})
	var fl []models.DestinationStat
	for i := range 10 {
		fl = append(fl, flow("ns", "w", uint16(1000+i), 1, 1, 0))
	}
	tr.Update([]models.AgentStatus{statsAgent("n1", fl...)}, t0)
	s := tr.Snapshot()
	if s.Entries != 3 || s.Dropped != 7 {
		t.Fatalf("entries=%d dropped=%d, want 3 and 7", s.Entries, s.Dropped)
	}
}

func TestEntriesUnseenForTooLongAreForgotten(t *testing.T) {
	tr := NewTracker(TrackerConfig{})
	tr.Update([]models.AgentStatus{statsAgent("n1", flow("ns", "w", 1, 1, 1, 0), flow("ns", "w", 2, 1, 1, 0))}, t0)
	// Only one flow keeps reporting.
	for i := 1; i <= keepGens+2; i++ {
		tr.Update([]models.AgentStatus{statsAgent("n1", flow("ns", "w", 1, uint64(1+i), 1, 0))}, t0.Add(time.Duration(i)*time.Minute))
	}
	if e := tr.Snapshot().Entries; e != 1 {
		t.Fatalf("entries = %d, want 1: the silent flow's state should have been pruned", e)
	}
}

func TestConcurrentUpdateAndSnapshotAreRaceFree(t *testing.T) {
	tr := NewTracker(TrackerConfig{MaxNamed: 5})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 200 {
			var fl []models.DestinationStat
			for w := range 20 {
				fl = append(fl, flow("ns", fmt.Sprintf("w%d", w), 1, uint64(i*w), 1, 0))
			}
			tr.Update([]models.AgentStatus{statsAgent("n1", fl...)}, t0.Add(time.Duration(i)*time.Second))
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			s := tr.Snapshot()
			if len(s.Named) > 5 {
				t.Errorf("named = %d exceeds the cap", len(s.Named))
				return
			}
		}
	}()
	wg.Wait()
}

// Real names captured from a live node (80.79.5.173): agents resolve a pod's
// direct controller, so Deployments show up as ReplicaSets with a hash suffix.
func TestCanonicalOwnerMapsRealAgentNamesToTheWorkloadOperatorsMean(t *testing.T) {
	for _, tc := range []struct{ kind, name, wantKind, wantName string }{
		{"ReplicaSet", "cdi-apiserver-6c4b4dfd7c", "Deployment", "cdi-apiserver"},
		{"ReplicaSet", "cdi-uploadproxy-7f59bd6994", "Deployment", "cdi-uploadproxy"},
		{"ReplicaSet", "cert-manager-689c4c5575", "Deployment", "cert-manager"},
		{"ReplicaSet", "cert-manager-cainjector-6fbb9c8cd6", "Deployment", "cert-manager-cainjector"},
		{"ReplicaSet", "netra-69b5dd578d", "Deployment", "netra"},
		{"Job", "nightly-backup-29234567", "CronJob", "nightly-backup"},
		{"Job", "db-migrate-20260919", "CronJob", "db-migrate"},
		// Not generated names: left exactly as reported.
		{"ReplicaSet", "handmade", "ReplicaSet", "handmade"},
		{"ReplicaSet", "web-abc", "ReplicaSet", "web-abc"},
		{"Job", "one-off-import", "Job", "one-off-import"},
		{"StatefulSet", "postgres-0", "StatefulSet", "postgres-0"},
		{"DaemonSet", "cilium", "DaemonSet", "cilium"},
		{"Deployment", "already-canonical", "Deployment", "already-canonical"},
		{"", "no-kind", "", "no-kind"},
	} {
		if k, n := canonicalOwner(tc.kind, tc.name); k != tc.wantKind || n != tc.wantName {
			t.Errorf("%s/%s -> %s/%s, want %s/%s", tc.kind, tc.name, k, n, tc.wantKind, tc.wantName)
		}
	}
}

// A rollout replaces the ReplicaSet (new hash). The workload's series must
// carry on instead of a new one starting.
func TestARolloutDoesNotFragmentTheWorkloadSeries(t *testing.T) {
	tr := NewTracker(TrackerConfig{})
	rs := func(name string, packets uint64) models.AgentStatus {
		return statsAgent("n1", models.DestinationStat{
			CgroupID: cgroupOf(name), Namespace: "shop", WorkloadKind: "ReplicaSet", WorkloadName: name,
			Hook: "egress", Direction: "egress", Protocol: "tcp", DestinationIP: "10.0.0.2", Port: 80, Packets: packets, Bytes: packets,
		})
	}
	tr.Update([]models.AgentStatus{rs("checkout-6c4b4dfd7c", 100)}, t0)
	tr.Update([]models.AgentStatus{rs("checkout-6c4b4dfd7c", 150)}, t0.Add(time.Minute))
	// Rollout: the old ReplicaSet's pods go away, the new one's appear.
	tr.Update([]models.AgentStatus{rs("checkout-7f59bd6994", 30)}, t0.Add(2*time.Minute))
	s := tr.Snapshot()
	if len(s.Named) != 1 || s.Named[0].Key != (Key{"shop", "Deployment/checkout"}) {
		t.Fatalf("named = %+v, want exactly Deployment/checkout across the rollout", s.Named)
	}
	if got := s.Named[0].V[Packets]; got != 50+30 {
		t.Fatalf("total = %d, want 80 (50 before the rollout + the new ReplicaSet's 30)", got)
	}
}

// Agents send top-N snapshots. A flow that merely climbs into the top N must
// not have its lifetime counted as one tick's growth.
func TestFirstSightingIsOnlyABaselineWhenTheReportIsCapped(t *testing.T) {
	capped := func(extra ...models.DestinationStat) models.AgentStatus {
		fl := make([]models.DestinationStat, 0, models.ReportCapFlows)
		for i := range models.ReportCapFlows - len(extra) {
			f := flow("filler", fmt.Sprintf("f%04d", i), 1, 1_000_000, 1, 0) // big flows that stay in the top N
			fl = append(fl, f)
		}
		return statsAgent("n1", append(fl, extra...)...)
	}
	tr := NewTracker(TrackerConfig{MaxNamed: 2000})
	tr.Update([]models.AgentStatus{capped()}, t0)

	// A long-lived flow (5,000,000 packets of history) enters the top N.
	climber := flow("shop", "web", 80, 5_000_000, 1, 0)
	tr.Update([]models.AgentStatus{capped(climber)}, t0.Add(time.Minute))
	if n, ok := find(tr.Snapshot(), "shop", "Deployment/web"); ok && n.V[Packets] != 0 {
		t.Fatalf("a flow that climbed into a capped report was booked with %d packets of history", n.V[Packets])
	}
	if !tr.Snapshot().Truncated[SourceFlows] {
		t.Fatal("the capped source must be flagged truncated")
	}
	// Once baselined, its real growth counts.
	climber.Packets += 250
	tr.Update([]models.AgentStatus{capped(climber)}, t0.Add(2*time.Minute))
	if n, _ := find(tr.Snapshot(), "shop", "Deployment/web"); n.V[Packets] != 250 {
		t.Fatalf("growth after the baseline = %d, want 250", n.V[Packets])
	}
}

func TestFirstSightingStillCountsInFullWhenTheReportIsNotCapped(t *testing.T) {
	tr := NewTracker(TrackerConfig{})
	tr.Update([]models.AgentStatus{statsAgent("n1", flow("a", "x", 80, 10, 10, 0))}, t0)
	tr.Update([]models.AgentStatus{statsAgent("n1", flow("a", "x", 80, 10, 10, 0), flow("a", "x", 443, 40, 40, 0))}, t0.Add(time.Minute))
	if n, _ := find(tr.Snapshot(), "a", "Deployment/x"); n.V[Packets] != 40 {
		t.Fatalf("total = %d, want 40: a new flow in an uncapped report is genuinely new", n.V[Packets])
	}
	s := tr.Snapshot()
	for _, src := range Sources {
		if s.Truncated[src] {
			t.Errorf("source %s reported truncated for a tiny report", src)
		}
	}
}

func TestTruncationFlagsAreTrackedPerSource(t *testing.T) {
	tr := NewTracker(TrackerConfig{})
	dns := make([]models.DNSHealthStat, models.ReportCapDNS)
	for i := range dns {
		dns[i] = models.DNSHealthStat{CgroupID: uint64(i), Name: fmt.Sprintf("n%d", i), Queries: 1}
	}
	tr.Update([]models.AgentStatus{agent("n1", func(r *models.AgentReport) { r.DNSHealth = dns })}, t0)
	s := tr.Snapshot()
	if !s.Truncated[SourceDNS] || s.Truncated[SourceFlows] || s.Truncated[SourceHTTP] || s.Truncated[SourceConnections] {
		t.Fatalf("flags = %v, want only dns", s.Truncated)
	}
	// A later, smaller report clears the flag.
	tr.Update([]models.AgentStatus{agent("n1", func(r *models.AgentReport) { r.DNSHealth = dns[:3] })}, t0.Add(time.Minute))
	if tr.Snapshot().Truncated[SourceDNS] {
		t.Fatal("the flag must clear once the report is under its cap")
	}
}
