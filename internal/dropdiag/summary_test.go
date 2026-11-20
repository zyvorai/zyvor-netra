package dropdiag

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuild(t *testing.T) {
	r := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", KernelDrops: []models.KernelDropStat{{Reason: 5, Count: 7}}, Stack: models.NodeStackStat{SoftnetProcessed: 100, SoftnetDropped: 2, SoftnetTimeSqueeze: 1, Interfaces: []models.InterfaceStackStat{{Name: "eth0", RXDropped: 3}}}}}}, 10)
	if r.Summary.KernelDropEvents != 7 || r.Summary.SoftnetDropped != 2 || r.Summary.RXDropped != 3 {
		t.Fatalf("unexpected summary: %#v", r.Summary)
	}
	if len(r.Summary.Anomalies) == 0 {
		t.Fatal("expected anomalies")
	}
}

func TestBuildQdiscDrops(t *testing.T) {
	r := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", QdiscStats: []models.QdiscStat{{Interface: "eth0", Kind: "fq_codel", Drops: 12}}}}}, 10)
	if r.Summary.QdiscDrops != 12 {
		t.Fatalf("expected QdiscDrops=12, got %#v", r.Summary)
	}
	found := false
	for _, an := range r.Summary.Anomalies {
		if an.Kind == "qdisc-drop" && an.Subject == "n1/eth0/fq_codel" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a qdisc-drop anomaly, got %#v", r.Summary.Anomalies)
	}
}

func TestBuildSkipsStale(t *testing.T) {
	r := Build([]models.AgentStatus{{Stale: true, AgentReport: models.AgentReport{Node: "n1", KernelDrops: []models.KernelDropStat{{Count: 99}}}}}, 10)
	if r.Summary.KernelDropEvents != 0 || len(r.Nodes) != 0 {
		t.Fatalf("stale agent included: %#v", r)
	}
}
