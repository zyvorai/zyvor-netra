package flowstats

import "testing"

func TestCollectorSummarizesHubbleFlow(t *testing.T) {
	c := New()
	flows := [][]byte{
		[]byte(`{"verdict":"FORWARDED","IP":{"source":"10.0.0.1","destination":"203.0.113.10"},"l4":{"TCP":{"sourcePort":43000,"destinationPort":443}}}`),
		[]byte(`{"verdict":"DROPPED","dropReasonDesc":"POLICY_DENIED","IP":{"source":"10.0.0.1","destination":"203.0.113.20"},"l4":{"TCP":{"sourcePort":43001,"destinationPort":443}}}`),
		[]byte(`{"verdict":"DROPPED","dropReasonDesc":"POLICY_DENIED","ip":{"source":"10.0.0.2","destination":"203.0.113.20"},"l4":{"UDP":{"sourcePort":53000,"destinationPort":53}}}`),
	}
	for _, flow := range flows {
		if !c.Add(flow) {
			t.Fatal("flow was not accepted")
		}
	}
	s := c.Summary(5)
	if s.Total != 3 || s.Verdicts["DROPPED"] != 2 || s.Protocols["TCP"] != 2 || s.Protocols["UDP"] != 1 {
		t.Fatalf("summary=%#v", s)
	}
	if len(s.TopDestinations) == 0 || s.TopDestinations[0].Name != "203.0.113.20" || s.TopDestinations[0].Count != 2 {
		t.Fatalf("destinations=%#v", s.TopDestinations)
	}
	if len(s.DropReasons) != 1 || s.DropReasons[0].Name != "POLICY_DENIED" || s.DropReasons[0].Count != 2 {
		t.Fatalf("dropReasons=%#v", s.DropReasons)
	}
}
