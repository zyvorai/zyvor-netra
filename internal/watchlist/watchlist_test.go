package watchlist

import (
	"testing"

	"github.com/zyvorai/netra/internal/intel"
	"github.com/zyvorai/netra/internal/models"
)

func TestMatchIPAndDNS(t *testing.T) {
	r := Match([]models.AgentStatus{{AgentReport: models.AgentReport{
		Node:      "n1",
		Stats:     []models.DestinationStat{{DestinationIP: "203.0.113.9", Packets: 4, Namespace: "prod", Pod: "api"}},
		DNSHealth: []models.DNSHealthStat{{Name: "bad.example.", Queries: 2}},
	}}}, []intel.Entry{{Type: "ip", Value: "203.0.113.9"}, {Type: "dns", Value: "bad.example"}, {Type: "ip", Value: "192.0.2.1"}}, 50)
	if r.Count != 2 {
		t.Fatalf("%#v", r)
	}
}
