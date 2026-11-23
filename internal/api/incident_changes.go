// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package api

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/anomaly"
	"github.com/zyvorai/netra/internal/bpfattachdiag"
	"github.com/zyvorai/netra/internal/changeline"
	"github.com/zyvorai/netra/internal/detective"
	"github.com/zyvorai/netra/internal/models"
)

const (
	changesDefaultSince = time.Hour
	changesMaxSince     = 24 * time.Hour
)

// incidentChanges serves GET /api/v1/incidents/changes?since=1h&lead=10m&node=NAME:
// the ordered "what changed, then what broke" timeline joining the audit log,
// netlink recorder, BPF attachment inventory, drop attribution, metric anomaly
// bursts and metric alert transitions. Read-only: it never acks or silences an
// alert and never touches a route, program or rule.
func (s *Server) incidentChanges(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	now := time.Now()
	since := changesDefaultSince
	if raw := strings.TrimSpace(q.Get("since")); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 || d > changesMaxSince {
			errorJSON(w, http.StatusBadRequest, "since must be a duration between 1s and 24h, e.g. 30m")
			return
		}
		since = d
	}
	lead := time.Duration(0)
	if raw := strings.TrimSpace(q.Get("lead")); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			errorJSON(w, http.StatusBadRequest, "lead must be a positive duration such as 10m (capped at 6h)")
			return
		}
		lead = d
	}
	node := strings.TrimSpace(q.Get("node"))
	start := now.Add(-since)

	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	if node != "" {
		agents = slices.DeleteFunc(agents, func(a models.AgentStatus) bool { return a.Node != node })
	}
	in := changeline.Inputs{Now: now, Since: start, Lead: lead, Node: node}
	in.Audit = s.store.Audit(0)
	in.Netlink = netlinkEvents(agents, "", start, netlinkMaxLimit)
	in.Attach = bpfattachdiag.Build(agents, now).Findings
	in.Drops = detective.Build(agents, s.store.Config(), 100).Findings

	for _, a := range agents {
		switch {
		case a.Netlink == nil || !a.Netlink.Available:
			in.Gaps = append(in.Gaps, fmt.Sprintf("netlink recorder not reporting on %s: route/link/address changes there are invisible", a.Node))
		case a.Netlink.Overruns > 0 || a.Netlink.Missed > 0:
			in.Gaps = append(in.Gaps, fmt.Sprintf("netlink recorder on %s lost events (overruns=%d missed=%d since agent start)", a.Node, a.Netlink.Overruns, a.Netlink.Missed))
		}
		if a.BPFAttach == nil || !a.BPFAttach.Available {
			in.Gaps = append(in.Gaps, fmt.Sprintf("BPF attachment inventory not available on %s", a.Node))
		}
		if a.Stale {
			in.Gaps = append(in.Gaps, fmt.Sprintf("agent %s is stale: its data may be out of date", a.Node))
		}
	}
	if len(agents) == 0 {
		in.Gaps = append(in.Gaps, "no fresh agents reported: only the audit log and metric alerts can contribute")
	}
	if s.metricsHub != nil {
		sum := anomaly.Summarize(s.metricsHub.Sources(), nil, start.Unix(), now.Unix(), 1, now)
		for _, n := range sum.Nodes {
			if node != "" && n.Node != node {
				continue
			}
			for _, p := range n.Timeline {
				if p.Rate == p.Rate { // skip NaN buckets
					in.Anomaly = append(in.Anomaly, changeline.AnomalyPoint{Node: n.Node, At: time.Unix(p.T, 0), Rate: float64(p.Rate)})
				}
			}
		}
	} else {
		in.Gaps = append(in.Gaps, "metrics platform disabled: anomaly bursts are not part of this timeline")
	}
	if s.metricAlerts != nil {
		for _, t := range s.metricAlerts.Snapshot(true, 1000).History {
			in.Alerts = append(in.Alerts, changeline.AlertChange{At: t.Time, Rule: t.Rule, Node: t.Node, From: string(t.From), To: string(t.To), Info: t.Info, Silenced: t.Silenced})
		}
	} else {
		in.Gaps = append(in.Gaps, "metric alerts disabled: alert transitions are not part of this timeline")
	}
	writeJSON(w, http.StatusOK, changeline.Build(in))
}
