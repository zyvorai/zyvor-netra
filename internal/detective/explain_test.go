// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package detective

import (
	"errors"
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildUnified_NilHubbleFn(t *testing.T) {
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{
		Node:        "n1",
		PolicyDrops: []models.PolicyDropStat{{Reason: 1, Packets: 5}},
	}}}
	out, err := BuildUnified(agents, models.EBPFFastPathConfig{}, 10, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.Sources) != 1 || out.Sources[0] != "netra" {
		t.Fatalf("expected only netra source, got %v", out.Sources)
	}
	if len(out.Findings) != 1 || out.Findings[0].Source != "netra" {
		t.Fatalf("expected 1 netra finding, got %#v", out.Findings)
	}
}

func TestBuildUnified_HubbleAppended(t *testing.T) {
	out, err := BuildUnified(nil, models.EBPFFastPathConfig{}, 10, func() ([]UnifiedFinding, error) {
		return []UnifiedFinding{{Source: "hubble", Code: "hubble-drop", Explanation: "dropped"}}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.Sources) != 2 || out.Sources[1] != "hubble" {
		t.Fatalf("expected netra+hubble sources, got %v", out.Sources)
	}
	if len(out.Findings) != 1 || out.Findings[0].Source != "hubble" {
		t.Fatalf("expected 1 hubble finding, got %#v", out.Findings)
	}
}

func TestBuildUnified_HubbleErrorDoesNotFailRequest(t *testing.T) {
	out, err := BuildUnified(nil, models.EBPFFastPathConfig{}, 10, func() ([]UnifiedFinding, error) {
		return nil, errors.New("hubble unreachable")
	})
	if err == nil {
		t.Fatal("expected the hubble error to be returned to the caller for logging")
	}
	if len(out.Sources) != 1 || out.Sources[0] != "netra" {
		t.Fatalf("expected standalone findings to still be usable despite hubble error, got %v", out.Sources)
	}
}

func TestHubbleFindingsFromExplain(t *testing.T) {
	items := []map[string]any{
		{
			"dropReason":  "POLICY_DENIED",
			"summary":     "Cilium policy enforcement denied this flow.",
			"suggestions": []string{"Check egress policy."},
			"flow": map[string]any{
				"source":      map[string]any{"namespace": "ns1", "podName": "pod-a"},
				"destination": map[string]any{"podName": "pod-b"},
				"verdict":     "DROPPED",
			},
		},
	}
	out := HubbleFindingsFromExplain(items)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	f := out[0]
	if f.Source != "hubble" || f.Pod != "pod-a" || f.Namespace != "ns1" || f.Dst != "pod-b" {
		t.Fatalf("unexpected adapted finding: %#v", f)
	}
	if f.Suggestion != "Check egress policy." {
		t.Fatalf("expected suggestion carried through, got %q", f.Suggestion)
	}
}
