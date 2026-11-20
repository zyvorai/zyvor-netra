package l7

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildAggregatesMetadata(t *testing.T) {
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{
		TLSMetadata:        []models.TLSMetadataStat{{SNI: "api.example.com", Handshakes: 3, Blocked: 1}},
		HTTPMetadata:       []models.HTTPMetadataStat{{Host: "plain.example.com", Method: "GET", Requests: 2}},
		HTTPStatus:         []models.HTTPStatusStat{{Status: 200, Count: 5}, {Status: 503, Count: 1}},
		ConnectionAttempts: []models.ConnectionAttemptStat{{Protocol: "TCP", RemotePort: 443, Attempts: 4, Blocked: 1}},
	}}}
	x := Build(agents, 10)
	if x.Summary.TLSHandshakes != 3 || x.Summary.TLSBlocked != 1 || x.Summary.HTTPRequests != 2 || x.Summary.HTTP5xx != 1 || x.Summary.ConnectAttempts != 4 {
		t.Fatalf("unexpected summary: %+v", x.Summary)
	}
	if len(x.Summary.TopSNI) != 1 || x.Summary.TopSNI[0].Name != "api.example.com" {
		t.Fatalf("unexpected SNI: %+v", x.Summary.TopSNI)
	}
}
