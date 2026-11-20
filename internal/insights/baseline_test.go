package insights

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestCaptureAndDrift(t *testing.T) {
	baseAgents := []models.AgentStatus{{AgentReport: models.AgentReport{Stats: []models.DestinationStat{{Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api", DestinationIP: "10.0.0.10", Port: 443, Protocol: "TCP", Packets: 20}}, TLSMetadata: []models.TLSMetadataStat{{Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api", SNI: "old.example.com", Handshakes: 5}}}}}
	b := CaptureBaseline(baseAgents, time.Unix(100, 0))
	if len(b.Entries) != 2 {
		t.Fatalf("entries=%d", len(b.Entries))
	}
	current := append([]models.AgentStatus(nil), baseAgents...)
	current[0].TLSMetadata = append(current[0].TLSMetadata, models.TLSMetadataStat{Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api", SNI: "new.example.com", Handshakes: 3})
	d := Drift(b, current)
	if len(d.Findings) != 1 || d.Findings[0].Kind != "sni" {
		t.Fatalf("unexpected drift: %#v", d.Findings)
	}
}

func TestDriftNoiseThreshold(t *testing.T) {
	b := BehaviorBaselineForTest(time.Unix(1, 0))
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{DNSHealth: []models.DNSHealthStat{{Namespace: "n", Pod: "p", Name: "one.example", Queries: 1}}}}}
	d := Drift(b, agents)
	if len(d.Findings) != 0 {
		t.Fatalf("single DNS query should be below threshold: %#v", d.Findings)
	}
}

func BehaviorBaselineForTest(at time.Time) models.BehaviorBaseline {
	return models.BehaviorBaseline{SchemaVersion: BaselineSchemaVersion, CapturedAt: at, Entries: []models.BehaviorBaselineEntry{{Source: "pod:n:p", Kind: "dns", Value: "known.example", Count: 2}}}
}

func TestCaptureSkipsStaleAgents(t *testing.T) {
	agents := []models.AgentStatus{
		{AgentReport: models.AgentReport{TLSMetadata: []models.TLSMetadataStat{{Namespace: "prod", Pod: "api", SNI: "fresh.example", Handshakes: 2}}}},
		{AgentReport: models.AgentReport{TLSMetadata: []models.TLSMetadataStat{{Namespace: "prod", Pod: "old", SNI: "stale.example", Handshakes: 9}}}, Stale: true},
	}
	b := CaptureBaseline(agents, time.Unix(10, 0))
	for _, e := range b.Entries {
		if e.Value == "stale.example" {
			t.Fatalf("stale agent entered baseline: %#v", b)
		}
	}
}
