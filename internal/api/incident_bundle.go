// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package api

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/anomaly"
	"github.com/zyvorai/netra/internal/bpfattachdiag"
	"github.com/zyvorai/netra/internal/detective"
	"github.com/zyvorai/netra/internal/flowlog"
	"github.com/zyvorai/netra/internal/incidentbundle"
	"github.com/zyvorai/netra/internal/tsdb"
)

// controllerVersion is the version recorded in an incident bundle. It must
// move with the release (scripts/check-version-sync.sh reads it).
const controllerVersion = "0.32.0"

// bundleSignals are the metric contexts a bundle carries. Key signals only.
var bundleSignals = []string{
	"ebpf.packets", "ebpf.bandwidth", "ebpf.kernel_drops", "ebpf.policy_drops", "ebpf.tcp_events",
	"ebpf.conntrack_entries", "net.ephemeral_utilization", "system.cpu", "mem.used_percent",
}

var bundleNodeRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$`)

// incidentBundle serves GET /api/v1/incident/bundle?minutes=N&node=NAME
// &exclude=a,b&mask_ips=ips|prefix. It is a read-only view over stores Netra
// already keeps (docs/incident-bundle.md): no new collector, no payload, no
// mutation. An optional X-Netra-Mask-Key header (at most 128 bytes) makes the IP
// pseudonyms reproducible across bundles so a before/after diff lines up.
func (s *Server) incidentBundle(w http.ResponseWriter, r *http.Request) {
	if p, ok := principalFrom(r.Context()); ok && !p.Unrestricted() {
		s.metricsData.rbacDenied.Add(1)
		errorJSON(w, http.StatusForbidden, "an incident bundle spans every namespace on the node and needs an unscoped role")
		return
	}
	q := r.URL.Query()
	window := incidentbundle.DefaultWindow
	if raw := strings.TrimSpace(q.Get("minutes")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > int(incidentbundle.MaxWindow/time.Minute) {
			errorJSON(w, http.StatusBadRequest, "minutes must be a whole number from 1 to 1440")
			return
		}
		window = time.Duration(n) * time.Minute
	}
	node := strings.TrimSpace(q.Get("node"))
	if node != "" && !bundleNodeRe.MatchString(node) {
		errorJSON(w, http.StatusBadRequest, "node must be a node name (letters, digits, . _ : -)")
		return
	}
	var exclude []string
	for _, e := range strings.Split(q.Get("exclude"), ",") {
		if e = strings.TrimSpace(e); e != "" {
			if !incidentbundle.ValidSection(e) {
				errorJSON(w, http.StatusBadRequest, "unknown section "+strconv.Quote(e)+" (sections: "+strings.Join(incidentbundle.SectionNames, ", ")+")")
				return
			}
			exclude = append(exclude, e)
		}
	}
	mask, ok := incidentbundle.ParseMask(q.Get("mask_ips"))
	if !ok {
		errorJSON(w, http.StatusBadRequest, "mask_ips must be ips or prefix (or omitted)")
		return
	}
	var maskKey []byte
	if k := r.Header.Get("X-Netra-Mask-Key"); k != "" {
		if len(k) > 128 {
			errorJSON(w, http.StatusBadRequest, "X-Netra-Mask-Key is limited to 128 bytes")
			return
		}
		maskKey = []byte(k)
	}

	now := time.Now().UTC()
	start := now.Add(-window)
	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	if node != "" {
		kept := agents[:0:0]
		for _, a := range agents {
			if a.Node == node {
				kept = append(kept, a)
			}
		}
		agents = kept
	}
	cfg := s.store.Config()
	in := incidentbundle.Inputs{
		Now: now, Window: window, Node: node, Version: controllerVersion, Mode: cfg.Mode, Agents: agents, Config: cfg,
		Opts: incidentbundle.Options{Exclude: exclude, Mask: mask, MaskKey: maskKey},
	}
	in.Audit = s.store.Audit(0)
	in.Leases = s.store.DenyLeases("")
	in.LeaseHistory = s.store.LeaseHistory("", start, incidentbundle.MaxLeaseEvents*2)
	in.Netlink = netlinkEvents(agents, "", start, netlinkMaxLimit)
	in.Attach = bpfattachdiag.Build(agents, now).Findings
	in.Drops = detective.Build(agents, cfg, incidentbundle.MaxDrops).Findings
	in.FlowsOK = true
	in.Flows = s.store.FlowQuery(flowlog.Query{Since: start, Node: node, Limit: flowlog.DefaultMax}).Records
	if s.dnsDetector != nil {
		in.DNSOK = true
		in.DNSFindings = s.dnsDetector.Findings()
	}

	if s.metricsHub != nil {
		srcs := s.metricsHub.Sources()
		scope := "all"
		var nodes []string
		if node != "" {
			scope, nodes = node, []string{node}
		}
		for _, ctx := range bundleSignals {
			res, err := tsdb.Run(srcs, tsdb.Query{Context: ctx, Nodes: nodes, After: -int64(window / time.Second), Points: incidentbundle.MaxPoints, GroupBy: "dimension"}, now)
			if err != nil {
				continue
			}
			for _, d := range res.Dimensions {
				ml := incidentbundle.MetricLine{Context: ctx, Dimension: d.Name, Units: res.Units, Title: res.Title, Scope: scope, Step: res.Interval}
				if len(res.Timestamps) > 0 {
					ml.Start = res.Timestamps[0]
				}
				for _, v := range d.Values {
					ml.Values = append(ml.Values, float64(v))
				}
				in.Metrics = append(in.Metrics, ml)
			}
		}
		if len(in.Metrics) == 0 {
			in.MetricsNote = "the metrics platform has no series for the key signals in this window"
		}
		sum := anomaly.Summarize(srcs, nil, start.Unix(), now.Unix(), 1, now)
		for _, n := range sum.Nodes {
			for _, p := range n.Timeline {
				if p.Rate == p.Rate {
					in.Anomalies = append(in.Anomalies, incidentbundle.AnomalyIn{Node: n.Node, At: time.Unix(p.T, 0), Rate: float64(p.Rate)})
				}
			}
		}
	} else {
		in.MetricsNote = "metrics platform disabled: no metric series, no anomaly buckets"
	}
	if s.metricAlerts != nil {
		in.AlertsOK = true
		snap := s.metricAlerts.Snapshot(false, 1000)
		for _, a := range snap.Active {
			in.Alerts = append(in.Alerts, incidentbundle.AlertIn{Rule: a.Rule, Node: a.Node, Context: a.Context, Chart: a.Chart, Dimension: a.Dimension,
				Status: string(a.Status), Value: float64(a.Value), Units: a.Units, Since: a.Since, Info: a.Info, Silenced: a.Silenced, Acked: a.Acked})
		}
		for _, t := range snap.History {
			in.Transitions = append(in.Transitions, incidentbundle.TransitionIn{At: t.Time, Rule: t.Rule, Node: t.Node, Chart: t.Chart,
				From: string(t.From), To: string(t.To), Info: t.Info, Silenced: t.Silenced})
		}
	}

	out, _, err := incidentbundle.Build(in)
	if err != nil {
		s.log.Warn("incident bundle build failed", "err", err)
		errorJSON(w, http.StatusInternalServerError, "could not build the bundle: "+err.Error())
		return
	}
	if q.Get("seal") == "true" {
		if msg, ok := sealHeader(w, out); !ok {
			errorJSON(w, http.StatusBadRequest, msg)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeRawJSON(w, http.StatusOK, out)
}
