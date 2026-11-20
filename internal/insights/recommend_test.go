package insights

import (
	"bytes"
	"github.com/zyvorai/netra/internal/models"
	"testing"
)

func TestRecommendationsContainServiceAndReviewMarker(t *testing.T) {
	g := models.DependencyGraph{Nodes: []models.DependencyNode{
		{ID: "workload:prod:deployment:api", Kind: "workload", Namespace: "prod", Name: "api", WorkloadKind: "Deployment"},
		{ID: "service:prod:redis", Kind: "service", Namespace: "prod", Name: "redis", IP: "10.96.0.20"},
	}, Edges: []models.DependencyEdge{{Source: "workload:prod:deployment:api", Target: "service:prod:redis", Protocol: "TCP", Port: 6379, Packets: 100}}}
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{Workloads: []models.WorkloadIdentity{{Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api", Labels: map[string]string{"app": "api"}}}}}}
	recs := Recommendations(g, agents, "prod", "api", 10)
	if len(recs) != 1 {
		t.Fatalf("recs=%d", len(recs))
	}
	if !bytes.Contains(recs[0].Manifest, []byte(`"toServices"`)) || !bytes.Contains(recs[0].Manifest, []byte(`review-required`)) {
		t.Fatalf("manifest=%s", recs[0].Manifest)
	}
}
