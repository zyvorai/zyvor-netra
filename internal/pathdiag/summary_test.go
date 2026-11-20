package pathdiag

import (
	"github.com/zyvorai/netra/internal/models"
	"testing"
	"time"
)

func TestBuild(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{ObservedAt: time.Now(), TCPPressure: []models.TCPPressureStat{{CgroupID: 1, RemoteIP: "10.0.0.2", RemotePort: 443, SendCWND: 10, PacketsOut: 9, LostOut: 2, RetransOut: 1, RateDelivered: 100, RateIntervalUS: 100000}}, ConnectLatency: []models.ConnectLatencyStat{{CgroupID: 1, RemoteIP: "10.0.0.2", RemotePort: 443, Established: 2, TotalLatencyUS: 600000, MaxLatencyUS: 500000}}}}
	got := Build([]models.AgentStatus{a}, 10)
	if got.Summary.ConnectionsMeasured != 2 || got.Summary.AverageConnectUS != 300000 {
		t.Fatalf("bad connect summary: %#v", got.Summary)
	}
	if got.Summary.CongestedFlows != 1 || got.Summary.LostOut != 2 {
		t.Fatalf("bad pressure summary: %#v", got.Summary)
	}
	if len(got.Summary.Anomalies) == 0 {
		t.Fatal("expected anomalies")
	}
}

func TestStaleIgnored(t *testing.T) {
	a := models.AgentStatus{Stale: true, AgentReport: models.AgentReport{TCPPressure: []models.TCPPressureStat{{LostOut: 99}}}}
	if got := Build([]models.AgentStatus{a}, 10); got.Summary.LostOut != 0 {
		t.Fatal("stale agent should be ignored")
	}
}

func TestBuildMergesEdgeIntelAcrossNodes(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{EdgeIntel: &models.EdgeIntelSummary{
		Handshake: []models.EdgeIntelBucket{{Count: 2, TotalNS: 200, MaxNS: 150}},
		Counts:    map[string]uint64{"syn": 5, "rst": 1},
	}}}
	b := models.AgentStatus{AgentReport: models.AgentReport{EdgeIntel: &models.EdgeIntelSummary{
		Handshake: []models.EdgeIntelBucket{{Count: 3, TotalNS: 300, MaxNS: 200}},
		Counts:    map[string]uint64{"syn": 4, "fin": 2},
	}}}
	// A node without edge intel attached (nil) must contribute nothing,
	// not panic or zero out the totals.
	c := models.AgentStatus{AgentReport: models.AgentReport{}}
	// A stale node's edge intel must not be counted either.
	stale := models.AgentStatus{Stale: true, AgentReport: models.AgentReport{EdgeIntel: &models.EdgeIntelSummary{Counts: map[string]uint64{"syn": 1000}}}}

	got := Build([]models.AgentStatus{a, b, c, stale}, 10)
	if len(got.EdgeIntel.Handshake) != 1 || got.EdgeIntel.Handshake[0].Count != 5 || got.EdgeIntel.Handshake[0].TotalNS != 500 || got.EdgeIntel.Handshake[0].MaxNS != 200 {
		t.Fatalf("handshake histogram not merged correctly: %#v", got.EdgeIntel.Handshake)
	}
	if got.EdgeIntel.Counts["syn"] != 9 || got.EdgeIntel.Counts["rst"] != 1 || got.EdgeIntel.Counts["fin"] != 2 {
		t.Fatalf("counts not merged correctly: %#v", got.EdgeIntel.Counts)
	}
}
