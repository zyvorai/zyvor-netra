package insights

import (
	"github.com/zyvorai/netra/internal/models"
	"testing"
)

func TestDependenciesResolveServiceAndExternal(t *testing.T) {
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{Stats: []models.DestinationStat{
		{Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api", DestinationIP: "10.96.0.20", Port: 6379, Protocol: "TCP", Direction: "egress", Packets: 10},
		{Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api", DestinationIP: "203.0.113.10", Port: 443, Protocol: "TCP", Direction: "egress", Packets: 3},
	}}}}
	g := Dependencies(agents, nil, []models.ServiceInfo{{Name: "redis", Namespace: "prod", ClusterIP: "10.96.0.20"}}, 100)
	if len(g.Edges) != 2 {
		t.Fatalf("edges=%d", len(g.Edges))
	}
	foundSvc, foundExternal := false, false
	for _, e := range g.Edges {
		if e.Target == "service:prod:redis" {
			foundSvc = true
		}
		if e.External {
			foundExternal = true
		}
	}
	if !foundSvc || !foundExternal {
		t.Fatalf("service=%v external=%v graph=%#v", foundSvc, foundExternal, g)
	}
}
