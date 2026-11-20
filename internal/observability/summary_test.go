package observability

import (
	"github.com/zyvorai/netra/internal/models"
	"testing"
)

func TestSummarize(t *testing.T) {
	a := []models.AgentStatus{{AgentReport: models.AgentReport{Stats: []models.DestinationStat{{DestinationIP: "1.1.1.1", Port: 443, Protocol: "TCP", Direction: "egress", Hook: "cgroup", Packets: 10, Bytes: 1000, Blocked: 2}}, Events: []models.FastPathEvent{{Type: "dns", DNSQuery: "example.com", Protocol: "UDP", Direction: "egress", Hook: "cgroup", Comm: "curl"}, {Type: "block", Action: "blocked", Reason: "cidr", Protocol: "TCP", Direction: "egress", Hook: "socket", Comm: "curl"}}}}}
	s := Summarize(a, 10)
	if s.Packets != 10 || s.Bytes != 1000 || s.Blocked != 2 || s.DNSQueries != 1 {
		t.Fatalf("bad summary: %#v", s)
	}
	if len(s.TopDNS) != 1 || s.TopDNS[0].Name != "example.com" {
		t.Fatalf("dns: %#v", s.TopDNS)
	}
	if s.Protocols["TCP"] != 10 || s.Directions["egress"] != 10 || s.Hooks["cgroup"] != 10 {
		t.Fatalf("exact packet dimensions: protocols=%#v directions=%#v hooks=%#v", s.Protocols, s.Directions, s.Hooks)
	}
}
