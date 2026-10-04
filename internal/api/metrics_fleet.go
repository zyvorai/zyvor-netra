// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/anomaly"
	"github.com/zyvorai/netra/internal/fleet"
	"github.com/zyvorai/netra/internal/metricalert"
)

// metricsStaleAfter marks a node whose stream stopped.
const metricsStaleAfter = 2 * time.Minute

// localMetricsSummary is this cluster's metrics platform at a glance.
func (s *Server) localMetricsSummary(now time.Time) fleet.MetricsSummary {
	out := fleet.MetricsSummary{TopAlerts: []fleet.MetricAlertRef{}, TopAnomalous: []fleet.MetricRef{}}
	if s.metricsHub == nil {
		return out
	}
	out.Available = true
	for _, n := range s.metricsHub.Nodes() {
		out.Nodes++
		out.Series += n.Stats.Series
		if now.Sub(n.LastIngest) > metricsStaleAfter {
			out.StaleNodes++
		}
	}
	sum := anomaly.Summarize(s.metricsHub.Sources(), nil, now.Add(-15*time.Minute).Unix(), now.Unix(), 5, now)
	var weighted float64
	var dims int
	for _, n := range sum.Nodes {
		weighted += n.AnomalyRate * float64(n.Dimensions)
		dims += n.Dimensions
	}
	if dims > 0 {
		out.AnomalyRate = weighted / float64(dims)
	}
	for _, r := range sum.Ranked {
		if r.AnomalyRate > 0 {
			out.TopAnomalous = append(out.TopAnomalous, fleet.MetricRef{Node: r.Node, Chart: r.Chart, Dimension: r.Dimension, AnomalyRate: r.AnomalyRate})
		}
	}
	if s.metricAlerts != nil {
		for _, a := range s.metricAlerts.Active() {
			if a.Status == metricalert.StatusCritical {
				out.AlertsCritical++
			} else {
				out.AlertsWarning++
			}
			if len(out.TopAlerts) < 5 {
				out.TopAlerts = append(out.TopAlerts, fleet.MetricAlertRef{Rule: a.Rule, Status: string(a.Status), Node: a.Node, Chart: a.Chart})
			}
		}
	}
	return out
}

func (s *Server) metricsSummary(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.localMetricsSummary(time.Now()))
}

// metricsFleet rolls up this cluster and every NETRA_FLEET_PEERS peer.
func (s *Server) metricsFleet(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, fleet.AggregateMetrics(ctx,
		strings.TrimSpace(os.Getenv("NETRA_CLUSTER_NAME")),
		strings.TrimSpace(os.Getenv("NETRA_CLUSTER_TENANT")),
		s.localMetricsSummary(now),
		fleet.ParsePeers(os.Getenv("NETRA_FLEET_PEERS")), nil))
}
