// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/workloadobs"
)

// WithWorkloadObs attaches the per-workload counter tracker and SLO registry.
// A nil Observer leaves both features off.
func (s *Server) WithWorkloadObs(o *workloadobs.Observer) *Server {
	s.wobs = o
	return s
}

// promLabel escapes a label value for the Prometheus text format, which only
// defines \\, \" and \n (Go's %q also emits \t and \x.. escapes that the format
// does not know).
func promLabel(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
}

// writeWorkloadMetrics appends the opt-in per-workload series and SLO gauges
// to /metrics. Series carry namespace and workload labels only, are capped at
// NETRA_METRICS_WORKLOAD_MAX named workloads plus one __other__ bucket, and
// are true counters (see internal/workloadobs).
func (s *Server) writeWorkloadMetrics(w http.ResponseWriter) {
	o := s.wobs
	if o == nil {
		return
	}
	if o.PromSeriesEnabled() {
		snap := o.Snapshot()
		for c := workloadobs.Counter(0); c < workloadobs.NumCounters; c++ {
			name := "netra_workload_" + workloadobs.Counters[c].Name + "_total"
			fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, workloadobs.Counters[c].Help, name)
			for _, n := range snap.Named {
				fmt.Fprintf(w, "%s{namespace=\"%s\",workload=\"%s\"} %d\n", name, promLabel(n.Key.Namespace), promLabel(n.Key.Workload), n.V[c])
			}
			fmt.Fprintf(w, "%s{namespace=\"%s\",workload=\"%s\"} %d\n", name, workloadobs.OtherLabel, workloadobs.OtherLabel, snap.Other[c])
		}
		fmt.Fprint(w, "# HELP netra_workload_report_truncated 1 when a node agent's latest report for this source hit its entry cap. Agents send top-N snapshots, so per-workload counts for a capped source are lower bounds.\n# TYPE netra_workload_report_truncated gauge\n")
		for _, src := range workloadobs.Sources {
			v := 0
			if snap.Truncated[src] {
				v = 1
			}
			fmt.Fprintf(w, "netra_workload_report_truncated{source=\"%s\"} %d\n", src, v)
		}
		metricGauge(w, "netra_workload_series_named", "Workloads currently exported with their own series (excludes __other__).", float64(len(snap.Named)))
		metricGauge(w, "netra_workload_series_max", "Cap on named workloads (NETRA_METRICS_WORKLOAD_MAX).", float64(snap.MaxNamed))
		metricGauge(w, "netra_workload_tracker_entries", "Raw agent counter entries the workload tracker holds state for.", float64(snap.Entries))
		metricCounter(w, "netra_workload_tracker_dropped_total", "Agent entries ignored because the tracker's entry cap was reached.", snap.Dropped)
	}
	if !o.HasSLOs() {
		return
	}
	sts := o.SLOStatus(time.Now())
	fmt.Fprint(w, "# HELP netra_slo_target_ratio Target good-event ratio of the SLO (0..1).\n# TYPE netra_slo_target_ratio gauge\n")
	for _, st := range sts {
		fmt.Fprintf(w, "netra_slo_target_ratio{slo=\"%s\"} %.6f\n", promLabel(st.Definition.Name), st.Definition.TargetPct/100)
	}
	fmt.Fprint(w, "# HELP netra_slo_compliance_ratio Observed good-event ratio over the SLO window (1 when there is no data; see netra_slo_has_data).\n# TYPE netra_slo_compliance_ratio gauge\n")
	for _, st := range sts {
		fmt.Fprintf(w, "netra_slo_compliance_ratio{slo=\"%s\"} %.6f\n", promLabel(st.Definition.Name), st.CompliancePct/100)
	}
	fmt.Fprint(w, "# HELP netra_slo_budget_remaining Fraction of the error budget left over the SLO window (0..1).\n# TYPE netra_slo_budget_remaining gauge\n")
	for _, st := range sts {
		fmt.Fprintf(w, "netra_slo_budget_remaining{slo=\"%s\"} %.6f\n", promLabel(st.Definition.Name), st.BudgetRemaining)
	}
	fmt.Fprint(w, "# HELP netra_slo_has_data Whether any events have been observed in the SLO window (1 yes).\n# TYPE netra_slo_has_data gauge\n")
	for _, st := range sts {
		v := 0
		if st.HasData {
			v = 1
		}
		fmt.Fprintf(w, "netra_slo_has_data{slo=\"%s\"} %d\n", promLabel(st.Definition.Name), v)
	}
	fmt.Fprint(w, "# HELP netra_slo_alert_state Multi-window burn-rate alert state: 0 ok, 1 ticket, 2 page.\n# TYPE netra_slo_alert_state gauge\n")
	for _, st := range sts {
		state := 0
		switch st.Severity {
		case "ticket":
			state = 1
		case "page":
			state = 2
		}
		fmt.Fprintf(w, "netra_slo_alert_state{slo=\"%s\"} %d\n", promLabel(st.Definition.Name), state)
	}
	fmt.Fprint(w, "# HELP netra_slo_burn_rate Error-budget burn rate over a window (1 = spending exactly the budget).\n# TYPE netra_slo_burn_rate gauge\n")
	for _, st := range sts {
		seen := map[string]bool{}
		for _, win := range st.Windows {
			for _, p := range []struct {
				d time.Duration
				v float64
			}{{win.Long, win.LongBurn}, {win.Short, win.ShortBurn}} {
				label := durLabel(p.d)
				if seen[label] {
					continue
				}
				seen[label] = true
				fmt.Fprintf(w, "netra_slo_burn_rate{slo=\"%s\",window=\"%s\"} %.4f\n", promLabel(st.Definition.Name), label, p.v)
			}
		}
	}
}

// durLabel renders a duration compactly and stably: 5m, 1h, 3d.
func durLabel(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	default:
		return d.String()
	}
}

type sloWindowView struct {
	Kind      string  `json:"kind"`
	Long      string  `json:"long"`
	Short     string  `json:"short"`
	LongBurn  float64 `json:"longBurn"`
	ShortBurn float64 `json:"shortBurn"`
	Threshold float64 `json:"threshold"`
	Firing    bool    `json:"firing"`
}

type sloView struct {
	Name            string          `json:"name"`
	SLI             string          `json:"sli"`
	Namespace       string          `json:"namespace,omitempty"`
	Workload        string          `json:"workload,omitempty"`
	TargetPct       float64         `json:"targetPct"`
	Window          string          `json:"window"`
	Severity        string          `json:"severity"`
	HasData         bool            `json:"hasData"`
	Total           uint64          `json:"total"`
	Errors          uint64          `json:"errors"`
	CompliancePct   float64         `json:"compliancePct"`
	BudgetRemaining float64         `json:"budgetRemaining"`
	Windows         []sloWindowView `json:"windows"`
}

// sloStatus serves GET /api/v1/slo.
func (s *Server) sloStatus(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{
		"enabled":               s.wobs.HasSLOs(),
		"workloadSeriesEnabled": s.wobs.PromSeriesEnabled(),
		"items":                 []sloView{},
	}
	if s.wobs.HasSLOs() {
		items := make([]sloView, 0)
		for _, st := range s.wobs.SLOStatus(time.Now()) {
			v := sloView{
				Name: st.Definition.Name, SLI: st.Definition.SLI, Namespace: st.Definition.Namespace, Workload: st.Definition.Workload,
				TargetPct: st.Definition.TargetPct, Window: durLabel(st.Definition.Window), Severity: string(st.Severity),
				HasData: st.HasData, Total: st.Total, Errors: st.Errors, CompliancePct: st.CompliancePct, BudgetRemaining: st.BudgetRemaining,
			}
			for _, win := range st.Windows {
				v.Windows = append(v.Windows, sloWindowView{
					Kind: win.Kind, Long: durLabel(win.Long), Short: durLabel(win.Short),
					LongBurn: win.LongBurn, ShortBurn: win.ShortBurn, Threshold: win.Threshold, Firing: win.Firing,
				})
			}
			items = append(items, v)
		}
		out["items"] = items
	}
	writeJSON(w, http.StatusOK, out)
}
