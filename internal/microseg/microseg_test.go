// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package microseg

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestPreferPacketWolfWhenCilium(t *testing.T) {
	g := Build(models.DependencyGraph{}, nil, true, 10)
	if !g.PreferPacketWolf || len(g.LeaseDrafts) != 0 {
		t.Fatalf("%+v", g)
	}
}

func TestNetraDraftsWithoutCilium(t *testing.T) {
	g := Build(models.DependencyGraph{
		Edges: []models.DependencyEdge{
			{Source: "w1", Target: "e1", Protocol: "TCP", Port: 80, Packets: 3, External: false},
		},
	}, nil, false, 10)
	if g.PreferPacketWolf {
		t.Fatal("expected Netra-leaning guidance")
	}
	if g.Recommendation == "" {
		t.Fatal("empty recommendation")
	}
}
