package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAnalyzeChangeDetectsSelectorAndRemovedDestination(t *testing.T) {
	current := []byte(`{"metadata":{"name":"eg","namespace":"payments"},"spec":{"endpointSelector":{"matchLabels":{"app":"api"}},"egress":[{"toFQDNs":[{"matchName":"old.example.com"}],"toCIDR":["10.0.0.0/8"]}]}}`)
	candidate := []byte(`{"metadata":{"name":"eg","namespace":"payments"},"spec":{"endpointSelector":{"matchLabels":{"app":"worker"}},"egress":[{"toFQDNs":[{"matchName":"new.example.com"}]}]}}`)
	p, err := AnalyzeChange(current, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if p.Risk != "high" || !p.SelectorChanged {
		t.Fatalf("unexpected plan: %#v", p)
	}
	if len(p.RemovedDestinations) != 2 || len(p.AddedDestinations) != 1 {
		t.Fatalf("destinations: %#v", p)
	}
}

func TestAnalyzeChangeFlagsEmptySelector(t *testing.T) {
	candidate := []byte(`{"metadata":{"name":"eg"},"spec":{"endpointSelector":{},"egress":[{"toEntities":["world"]}]}}`)
	p, err := AnalyzeChange(nil, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if p.Risk != "critical" {
		t.Fatalf("risk=%s", p.Risk)
	}
}

// TestAnalyzeChangeNewPolicyHasNoNullSlices guards against a real crash: the
// dashboard's Policies page unconditionally reads .length/.map on
// changes/warnings/addedDestinations/removedDestinations. A nil Go slice
// still satisfies len(x)==0 in a Go test, but marshals to JSON "null"
// instead of "[]", which crashed the frontend. Only a JSON-level check
// catches this class of bug.
func TestAnalyzeChangeNewPolicyHasNoNullSlices(t *testing.T) {
	candidate := []byte(`{"metadata":{"name":"eg","namespace":"payments"},"spec":{"endpointSelector":{"matchLabels":{"app":"api"}},"egress":[{"toFQDNs":[{"matchName":"api.example.com"}]}]}}`)
	p, err := AnalyzeChange(nil, candidate)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"changes":null`, `"warnings":null`, `"addedDestinations":null`, `"removedDestinations":null`} {
		if strings.Contains(string(b), field) {
			t.Fatalf("field serialized as null, would crash the dashboard's .length/.map reads: %s\nfull json: %s", field, b)
		}
	}
}

func TestAnalyzeChangeSupportsSpecsAndExpressions(t *testing.T) {
	candidate := []byte(`{"metadata":{"name":"eg","namespace":"payments"},"specs":[{"endpointSelector":{"matchExpressions":[{"key":"tier","operator":"In","values":["api"]}]},"egress":[{"toCIDR":["192.0.2.0/24"]}]}]}`)
	p, err := AnalyzeChange(nil, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if p.Risk == "critical" || p.ProposedEgressRules != 1 || len(p.AddedDestinations) != 1 {
		t.Fatalf("unexpected plan: %#v", p)
	}
}
