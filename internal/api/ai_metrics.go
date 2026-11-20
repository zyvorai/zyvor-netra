// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/ai"
	"github.com/zyvorai/netra/internal/anomaly"
	"github.com/zyvorai/netra/internal/metricalert"
)

// minAnomalyRate is the share of flagged samples (percent, last 15 minutes)
// before a metric is cited in AI briefs; lower rates are model noise.
const minAnomalyRate = 10

// metricFindings summarizes raised metric alerts and the most anomalous
// metrics for the AI snapshot. Read-only: it never acks, silences or
// changes a rule.
func (s *Server) metricFindings(now time.Time) []ai.Finding {
	var out []ai.Finding
	if s.metricAlerts != nil {
		for _, a := range s.metricAlerts.Active() {
			if len(out) >= 6 {
				break
			}
			if a.Silenced {
				continue
			}
			val := "n/a"
			if v := float64(a.Value); !math.IsNaN(v) && !math.IsInf(v, 0) {
				val = strings.TrimSpace(fmt.Sprintf("%.4g %s", v, a.Units))
			}
			where := a.Node + " " + a.Chart
			if a.Dimension != "" {
				where += "/" + a.Dimension
			}
			out = append(out, ai.Finding{
				Severity: alertSeverity(a.Status),
				Kind:     "metric-alert",
				Subject:  a.Rule,
				Message:  fmt.Sprintf("%s %s on %s = %s (%s)", a.Rule, a.Status, where, val, a.Info),
			})
		}
	}
	if s.metricsHub != nil {
		sum := anomaly.Summarize(s.metricsHub.Sources(), nil, now.Add(-15*time.Minute).Unix(), now.Unix(), 5, now)
		for _, r := range sum.Ranked {
			if r.AnomalyRate < minAnomalyRate {
				continue
			}
			out = append(out, ai.Finding{
				Severity: "info",
				Kind:     "metric-anomaly",
				Subject:  r.Node + " " + r.Chart + "/" + r.Dimension,
				Message:  fmt.Sprintf("%s %s/%s anomalous %.0f%% of the last 15m (%s)", r.Node, r.Chart, r.Dimension, r.AnomalyRate, r.Context),
			})
		}
	}
	return out
}

func alertSeverity(s metricalert.Status) string {
	if s == metricalert.StatusCritical {
		return "critical"
	}
	return "warning"
}
