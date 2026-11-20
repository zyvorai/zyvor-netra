package health

import (
	"github.com/zyvorai/netra/internal/models"
	"testing"
)

func TestBuildFindsTCPAndDNSProblems(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{
		TCPHealth:          []models.TCPHealthStat{{CgroupID: 7, Namespace: "payments", Pod: "api-1", RemoteIP: "10.0.0.8", RemotePort: 443, ActiveEstablished: 2, Retransmissions: 22, RTOs: 1, RTTSamples: 2, SRTTUS: 300000}},
		TCPSignals:         []models.TCPSignalStat{{Namespace: "payments", Pod: "api-1", Packets: 200, RST: 8}},
		DNSHealth:          []models.DNSHealthStat{{Namespace: "payments", Pod: "api-1", Name: "db.example", Queries: 10, Responses: 10, Failures: 2, TotalLatencyUS: 3000000, MaxLatencyUS: 1200000}},
		ConnectionAttempts: []models.ConnectionAttemptStat{{CgroupID: 7, Namespace: "payments", Pod: "api-1", Protocol: "TCP", RemoteIP: "10.0.0.9", RemotePort: 443, Attempts: 30}},
	}}
	r := Build([]models.AgentStatus{a}, 10)
	if r.Summary.TCPConnections != 2 || r.Summary.TCPRetransmissions != 22 || r.Summary.DNSFailures != 2 || r.Summary.ConnectionAttempts != 30 || r.Summary.EstimatedConnectFailures != 28 {
		t.Fatalf("bad summary: %+v", r.Summary)
	}
	if r.Summary.HealthScore >= 100 {
		t.Fatalf("expected degraded score: %+v", r.Summary)
	}
	if len(r.Summary.Anomalies) < 5 {
		t.Fatalf("expected anomalies: %+v", r.Summary.Anomalies)
	}
}

func TestBuildFindsICMPAnomalies(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{
		Node:       "node-1",
		ICMPTypes:  []models.NamedCount{{Name: "echo-request", Count: 6000}, {Name: "dest-unreach", Count: 600}},
		ICMP6Types: []models.NamedCount{{Name: "echo-request", Count: 5000}, {Name: "dest-unreach", Count: 500}},
	}}
	r := Build([]models.AgentStatus{a}, 10)

	var gotEcho, gotUnreach bool
	for _, an := range r.Summary.Anomalies {
		if an.Kind == "icmp-echo" {
			gotEcho = true
			if an.Subject != "node-1" || an.Value != 11000 {
				t.Fatalf("unexpected icmp-echo anomaly: %+v", an)
			}
		}
		if an.Kind == "icmp-unreach" {
			gotUnreach = true
			if an.Subject != "node-1" || an.Value != 1100 {
				t.Fatalf("unexpected icmp-unreach anomaly: %+v", an)
			}
		}
	}
	if !gotEcho || !gotUnreach {
		t.Fatalf("expected icmp-echo and icmp-unreach anomalies: %+v", r.Summary.Anomalies)
	}
}

func TestBuildIgnoresICMPBelowThreshold(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{
		Node:       "node-1",
		ICMPTypes:  []models.NamedCount{{Name: "echo-request", Count: 9999}, {Name: "dest-unreach", Count: 999}},
		ICMP6Types: []models.NamedCount{{Name: "echo-request", Count: 0}, {Name: "dest-unreach", Count: 0}},
	}}
	r := Build([]models.AgentStatus{a}, 10)

	for _, an := range r.Summary.Anomalies {
		if an.Kind == "icmp-echo" || an.Kind == "icmp-unreach" {
			t.Fatalf("unexpected icmp anomaly below threshold: %+v", an)
		}
	}
}

func TestBuildFindsBPFMapsMissingAnomaly(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{
		Node:        "node-1",
		MissingMaps: []string{"allowed_ports", "rate_v6"},
	}}
	r := Build([]models.AgentStatus{a}, 10)

	var got *models.NetworkHealthAnomaly
	for i, an := range r.Summary.Anomalies {
		if an.Kind == "bpf-maps-missing" {
			got = &r.Summary.Anomalies[i]
		}
	}
	if got == nil {
		t.Fatalf("expected bpf-maps-missing anomaly: %+v", r.Summary.Anomalies)
	}
	if got.Subject != "node-1" || got.Severity != "warning" || got.Value != 2 {
		t.Fatalf("unexpected bpf-maps-missing anomaly: %+v", got)
	}
}

func TestBuildIgnoresBPFMapsMissingWhenComplete(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{Node: "node-1"}}
	r := Build([]models.AgentStatus{a}, 10)

	for _, an := range r.Summary.Anomalies {
		if an.Kind == "bpf-maps-missing" {
			t.Fatalf("unexpected bpf-maps-missing anomaly: %+v", an)
		}
	}
}

func TestAnomaliesPopulateSourceKeyWithoutChangingSubject(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{
		Node:      "node-1",
		TCPHealth: []models.TCPHealthStat{{CgroupID: 7, Namespace: "payments", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api", RemoteIP: "10.0.0.8", RemotePort: 443, ActiveEstablished: 2, SRTTUS: 800000}},
	}}
	r := Build([]models.AgentStatus{a}, 10)
	var got *models.NetworkHealthAnomaly
	for i, an := range r.Summary.Anomalies {
		if an.Kind == "tcp-latency" {
			got = &r.Summary.Anomalies[i]
		}
	}
	if got == nil {
		t.Fatalf("expected a tcp-latency anomaly: %+v", r.Summary.Anomalies)
	}
	if got.SourceKey != "workload:payments:deployment:api" {
		t.Fatalf("sourceKey=%q, want workload:payments:deployment:api", got.SourceKey)
	}
	if got.Subject != "payments/api-1 → 10.0.0.8:443" {
		t.Fatalf("Subject must stay unchanged for existing consumers (netractl explain, alert dedup), got %q", got.Subject)
	}
}

func TestAnomalySourceKeyFallsBackToNodeForNodeLevelFindings(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{Node: "node-7", MissingMaps: []string{"shield_source_hits"}}}
	r := Build([]models.AgentStatus{a}, 10)
	var got *models.NetworkHealthAnomaly
	for i, an := range r.Summary.Anomalies {
		if an.Kind == "bpf-maps-missing" {
			got = &r.Summary.Anomalies[i]
		}
	}
	if got == nil {
		t.Fatalf("expected bpf-maps-missing anomaly: %+v", r.Summary.Anomalies)
	}
	if got.SourceKey != "node:node-7" {
		t.Fatalf("sourceKey=%q, want node:node-7", got.SourceKey)
	}
}
