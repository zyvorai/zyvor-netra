package insights

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestRateDriftAndExposure(t *testing.T) {
	now := time.Now()
	b := models.RateBaseline{
		SchemaVersion: 1,
		CapturedAt:    now,
		Entries: []models.RateBaselineEntry{{
			Source: "workload:prod:deployment:api",
			Metric: "connections",
			Rate:   1,
		}},
	}
	w := models.RateWindow{
		Metrics:                []models.RateMetric{{Source: "workload:prod:deployment:api", ConnectionsPerSecond: 12}},
		RequestedWindowSeconds: 60,
	}
	d := RateDrift(b, w)
	if len(d.Findings) != 1 || d.Findings[0].Severity != "critical" {
		t.Fatalf("%#v", d)
	}
	ex := Exposure(models.DependencyGraph{Edges: []models.DependencyEdge{{Source: "workload:prod:deployment:api", External: true}}}, models.DriftResponse{}, d)
	if len(ex) != 1 || ex[0].Score < 30 {
		t.Fatalf("%#v", ex)
	}
}

func TestRemediationExternalDestination(t *testing.T) {
	g := models.DependencyGraph{
		Nodes: []models.DependencyNode{{ID: "external:203.0.113.10", Kind: "external", IP: "203.0.113.10"}},
		Edges: []models.DependencyEdge{{Source: "workload:prod:deployment:api", Target: "external:203.0.113.10", External: true}},
	}
	d := models.DriftResponse{Findings: []models.DriftFinding{{
		Severity: "warning", Kind: "destination", Source: "workload:prod:deployment:api", Value: "203.0.113.10", Message: "new destination",
	}}}
	p := Remediations(g, d, models.RateDriftResponse{}, 10)
	if len(p) != 1 || p[0].Action["operation"] != "ebpf.deny.add" {
		t.Fatalf("%#v", p)
	}
}
