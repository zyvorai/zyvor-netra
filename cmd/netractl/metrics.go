// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
)

const metricsUsage = `metrics nodes|contexts|query|top|anomalies|evidence|alerts|fleet [flags]
  metrics nodes [--json]
  metrics contexts [--node N] [--family F] [--json]
  metrics query CONTEXT [--node N] [--after -600] [--before 0] [--points 60]
                [--group avg|min|max|sum|last|p95] [--group-by dimension|chart|node|label:KEY]
                [--labels k:v,...] [--json]
  metrics top [--node N] [--after -60] [--json]
  metrics anomalies [--node N] [--after -900] [--highlight-after T --highlight-before T] [--json]
  metrics evidence CONTEXT [--node N] [--labels namespace:NS,workload:W] [--after -900] [--before 0] [--json]
  metrics alerts [--all] [--json]
  metrics fleet [--json]        this cluster plus NETRA_FLEET_PEERS peers
  metrics ack ALERT_ID
  metrics silence [--rule GLOB] [--node GLOB] [--chart GLOB] --for 2h [--comment TEXT]
  metrics unsilence SILENCE_ID`

// metricsCmd reads the per-second metrics platform. Only ack, silence and
// unsilence change state, and only the alert engine's notification state.
func metricsCmd(args []string, w io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(w, metricsUsage)
		return nil
	}
	sub := args[0]
	pos, flags, err := parseMetricFlags(args[1:])
	if err != nil {
		return err
	}
	_, asJSON := flags["json"]
	switch sub {
	case "nodes":
		return metricsGet("/api/v1/metrics/nodes", asJSON, w, printNodes)
	case "contexts":
		q := url.Values{}
		setIf(q, "nodes", flags["node"])
		setIf(q, "family", flags["family"])
		return metricsGet("/api/v1/metrics/contexts?"+q.Encode(), asJSON, w, printContexts)
	case "query":
		if len(pos) == 0 {
			return fmt.Errorf("metrics query needs a CONTEXT, for example: netractl metrics query system.cpu")
		}
		q := url.Values{}
		q.Set("context", pos[0])
		setIf(q, "nodes", flags["node"])
		setIf(q, "after", flags["after"])
		setIf(q, "before", flags["before"])
		setIf(q, "points", flags["points"])
		setIf(q, "group", flags["group"])
		setIf(q, "group_by", flags["group-by"])
		setIf(q, "labels", flags["labels"])
		setIf(q, "dimensions", flags["dimensions"])
		return metricsGet("/api/v1/metrics/data?"+q.Encode(), asJSON, w, printQuery)
	case "top":
		return metricsTop(flags, asJSON, w)
	case "anomalies":
		q := url.Values{}
		setIf(q, "nodes", flags["node"])
		setIf(q, "after", flags["after"])
		setIf(q, "before", flags["before"])
		setIf(q, "highlight_after", flags["highlight-after"])
		setIf(q, "highlight_before", flags["highlight-before"])
		setIf(q, "top", flags["top"])
		return metricsGet("/api/v1/metrics/anomalies?"+q.Encode(), asJSON, w, printAnomalies)
	case "evidence":
		if len(pos) == 0 {
			return fmt.Errorf("metrics evidence needs a CONTEXT, for example: netractl metrics evidence ebpf.kernel_drops --node n1")
		}
		q := url.Values{}
		q.Set("context", pos[0])
		setIf(q, "node", flags["node"])
		setIf(q, "labels", flags["labels"])
		setIf(q, "after", flags["after"])
		setIf(q, "before", flags["before"])
		return metricsGet("/api/v1/metrics/evidence?"+q.Encode(), asJSON, w, printEvidence)
	case "fleet":
		return metricsGet("/api/v1/metrics/fleet", asJSON, w, printMetricsFleet)
	case "alerts":
		p := "/api/v1/metrics/alerts"
		if _, all := flags["all"]; all {
			p += "?all=true"
		}
		return metricsGet(p, asJSON, w, printAlerts)
	case "ack":
		if len(pos) != 1 {
			return fmt.Errorf("metrics ack needs one ALERT_ID (see netractl metrics alerts --json)")
		}
		return metricsSend(http.MethodPost, "/api/v1/metrics/alerts/"+url.PathEscape(pos[0])+"/ack", nil, w)
	case "silence":
		if flags["for"] == "" {
			return fmt.Errorf("metrics silence needs --for, for example --for 2h")
		}
		body, _ := json.Marshal(map[string]string{"rule": flags["rule"], "node": flags["node"], "chart": flags["chart"], "duration": flags["for"], "comment": flags["comment"]})
		return metricsSend(http.MethodPost, "/api/v1/metrics/alerts/silences", body, w)
	case "unsilence":
		if len(pos) != 1 {
			return fmt.Errorf("metrics unsilence needs one SILENCE_ID")
		}
		return metricsSend(http.MethodDelete, "/api/v1/metrics/alerts/silences/"+url.PathEscape(pos[0]), nil, w)
	default:
		return fmt.Errorf("%s", metricsUsage)
	}
}

var metricFlagNames = map[string]bool{
	"node": true, "family": true, "after": true, "before": true, "points": true, "group": true,
	"group-by": true, "labels": true, "dimensions": true, "highlight-after": true, "highlight-before": true, "top": true,
	"rule": true, "chart": true, "for": true, "comment": true,
}

func metricsSend(method, p string, body []byte, w io.Writer) error {
	out, status, err := doRequest(method, p, body, nil)
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("%s: %s", http.StatusText(status), strings.TrimSpace(string(out)))
	}
	if len(out) > 0 {
		fmt.Fprintln(w, strings.TrimSpace(string(out)))
	} else {
		fmt.Fprintln(w, "ok")
	}
	return nil
}

func parseMetricFlags(args []string) ([]string, map[string]string, error) {
	flags := map[string]string{}
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			pos = append(pos, a)
			continue
		}
		name := strings.TrimPrefix(a, "--")
		if name == "json" || name == "all" {
			flags[name] = "true"
			continue
		}
		if k, v, ok := strings.Cut(name, "="); ok {
			if !metricFlagNames[k] {
				return nil, nil, fmt.Errorf("unknown metrics flag --%s", k)
			}
			flags[k] = v
			continue
		}
		if !metricFlagNames[name] {
			return nil, nil, fmt.Errorf("unknown metrics flag --%s", name)
		}
		if i+1 >= len(args) {
			return nil, nil, fmt.Errorf("--%s needs a value", name)
		}
		flags[name] = args[i+1]
		i++
	}
	return pos, flags, nil
}

func setIf(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

func metricsFetch(p string) (map[string]any, error) {
	out, status, err := doRequest(http.MethodGet, p, nil, nil)
	if err != nil {
		return nil, err
	}
	if status >= 300 {
		return nil, fmt.Errorf("%s: %s", http.StatusText(status), strings.TrimSpace(string(out)))
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		return nil, err
	}
	return v, nil
}

func metricsGet(p string, asJSON bool, w io.Writer, pretty func(map[string]any, io.Writer)) error {
	v, err := metricsFetch(p)
	if err != nil {
		return err
	}
	if asJSON || os.Getenv("NETRA_OUTPUT") == "json" {
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Fprintln(w, string(b))
		return nil
	}
	pretty(v, w)
	return nil
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func num(v any) float64 {
	f, ok := v.(float64)
	if !ok {
		return math.NaN()
	}
	return f
}

func fmtNum(f float64) string {
	switch {
	case math.IsNaN(f):
		return "-"
	case math.Abs(f) >= 1e6:
		return fmt.Sprintf("%.3gM", f/1e6)
	case math.Abs(f) >= 1e4:
		return fmt.Sprintf("%.1fk", f/1e3)
	case math.Abs(f) >= 100:
		return fmt.Sprintf("%.0f", f)
	default:
		return fmt.Sprintf("%.2f", f)
	}
}

func printNodes(v map[string]any, w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NODE\tSERIES\tMEMORY\tDISK\tLAST INGEST")
	for _, n := range list(v["nodes"]) {
		m := obj(n)
		st := obj(m["stats"])
		fmt.Fprintf(tw, "%s\t%.0f\t%s\t%s\t%s\n", str(m["node"]), num(st["series"]), bytesHuman(num(st["memoryBytes"])), bytesHuman(num(st["diskBytes"])), str(m["lastIngest"]))
	}
	tw.Flush()
}

func bytesHuman(b float64) string {
	if math.IsNaN(b) {
		return "-"
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	i := 0
	for b >= 1024 && i < len(units)-1 {
		b /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", b, units[i])
}

func printContexts(v map[string]any, w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "CONTEXT\tFAMILY\tUNITS\tCHARTS\tTITLE")
	for _, c := range list(v["contexts"]) {
		m := obj(c)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", str(m["context"]), str(m["family"]), str(m["units"]), len(list(m["charts"])), str(m["title"]))
	}
	tw.Flush()
}

// summarize returns last, min, max and avg of a value array, skipping nulls.
func summarize(vals []any) (last, lo, hi, avg float64) {
	last, lo, hi = math.NaN(), math.Inf(1), math.Inf(-1)
	var sum float64
	var n int
	for _, x := range vals {
		f := num(x)
		if math.IsNaN(f) {
			continue
		}
		last = f
		lo, hi = math.Min(lo, f), math.Max(hi, f)
		sum += f
		n++
	}
	if n == 0 {
		return math.NaN(), math.NaN(), math.NaN(), math.NaN()
	}
	return last, lo, hi, sum / float64(n)
}

func printQuery(v map[string]any, w io.Writer) {
	fmt.Fprintf(w, "%s (%s) tier %.0f, %.0fs per point, %.0f series\n", str(v["context"]), str(v["units"]), num(v["tier"]), num(v["interval"]), num(v["matched"]))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "DIMENSION\tLAST\tMIN\tAVG\tMAX\tANOMALY%")
	for _, d := range list(v["dimensions"]) {
		m := obj(d)
		last, lo, hi, avg := summarize(list(m["values"]))
		_, _, _, ar := summarize(list(m["anomalyRate"]))
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", str(m["name"]), fmtNum(last), fmtNum(lo), fmtNum(avg), fmtNum(hi), fmtNum(ar))
	}
	tw.Flush()
}

// metricsTop prints a per-node summary like top: CPU, RAM, load, network
// and anomaly rate.
func metricsTop(flags map[string]string, asJSON bool, w io.Writer) error {
	after := flags["after"]
	if after == "" {
		after = "-60"
	}
	type col struct {
		name, context, dims, agg string
	}
	cols := []col{
		{"CPU%", "system.cpu", "", "sum"},
		{"RAM%", "mem.used_percent", "", "avg"},
		{"LOAD1", "system.load", "load1", "avg"},
		{"NET IN kb/s", "system.net", "received", "sum"},
		{"NET OUT kb/s", "system.net", "sent", "sum"},
		{"DISK IN KiB/s", "system.io", "in", "sum"},
		{"DISK OUT KiB/s", "system.io", "out", "sum"},
	}
	rows := map[string]map[string]float64{}
	for _, c := range cols {
		q := url.Values{}
		q.Set("context", c.context)
		q.Set("after", after)
		q.Set("points", "1")
		q.Set("group_by", "node")
		setIf(q, "nodes", flags["node"])
		setIf(q, "dimensions", c.dims)
		if c.context == "system.cpu" {
			q.Set("aggregate", "sum")
		}
		v, err := metricsFetch("/api/v1/metrics/data?" + q.Encode())
		if err != nil {
			return err
		}
		for _, d := range list(v["dimensions"]) {
			m := obj(d)
			node := str(m["name"])
			if rows[node] == nil {
				rows[node] = map[string]float64{}
			}
			_, _, _, avg := summarize(list(m["values"]))
			rows[node][c.name] = avg
		}
	}
	if an, err := metricsFetch("/api/v1/metrics/anomalies?after=" + url.QueryEscape(after)); err == nil {
		for _, n := range list(an["nodes"]) {
			m := obj(n)
			if rows[str(m["node"])] != nil {
				rows[str(m["node"])]["ANOMALY%"] = num(m["anomalyRate"])
			}
		}
	}
	if asJSON {
		b, _ := json.MarshalIndent(rows, "", "  ")
		fmt.Fprintln(w, string(b))
		return nil
	}
	nodes := make([]string, 0, len(rows))
	for n := range rows {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	hdr := []string{"NODE"}
	for _, c := range cols {
		hdr = append(hdr, c.name)
	}
	hdr = append(hdr, "ANOMALY%")
	fmt.Fprintln(tw, strings.Join(hdr, "\t"))
	for _, n := range nodes {
		line := []string{n}
		for _, h := range hdr[1:] {
			v, ok := rows[n][h]
			if !ok {
				v = math.NaN()
			}
			line = append(line, fmtNum(v))
		}
		fmt.Fprintln(tw, strings.Join(line, "\t"))
	}
	return tw.Flush()
}

func printAnomalies(v map[string]any, w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NODE\tANOMALY%\tDIMENSIONS")
	for _, n := range list(v["nodes"]) {
		m := obj(n)
		fmt.Fprintf(tw, "%s\t%s\t%.0f\n", str(m["node"]), fmtNum(num(m["anomalyRate"])), num(m["dimensions"]))
	}
	tw.Flush()
	fmt.Fprintln(w)
	tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "RANK\tNODE\tCHART\tDIMENSION\tANOMALY%\tSCORE")
	for i, r := range list(v["ranked"]) {
		m := obj(r)
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", i+1, str(m["node"]), str(m["chart"]), str(m["dimension"]), fmtNum(num(m["anomalyRate"])), fmtNum(num(m["score"])))
	}
	tw.Flush()
}

func printEvidence(v map[string]any, w io.Writer) {
	fmt.Fprintf(w, "%s on %s: %.0f flow records, evidence: %s\n\n", str(v["context"]), firstStr(str(v["node"]), "all nodes"), num(v["flowRecords"]), joinStrs(list(v["kinds"])))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "WORKLOAD\tPEER\tPORT\tBYTES\tBLOCKED\tRETRANS")
	for _, p := range list(v["topPeers"]) {
		m := obj(p)
		wl := str(m["workload"])
		if ns := str(m["namespace"]); ns != "" {
			wl = ns + "/" + wl
		}
		fmt.Fprintf(tw, "%s\t%s\t%.0f/%s\t%s\t%.0f\t%.0f\n", firstStr(wl, "-"), str(m["peer"]), num(m["port"]), str(m["protocol"]), fmtNum(num(m["bytes"])), num(m["blocked"]), num(m["retransmissions"]))
	}
	tw.Flush()
	if drops := list(v["kernelDrops"]); len(drops) > 0 {
		fmt.Fprintln(w, "\nKernel drop reasons (cumulative):")
		for _, d := range drops {
			fmt.Fprintf(w, "  %s  %.0f\n", str(obj(d)["name"]), num(obj(d)["count"]))
		}
	}
	if caps := list(v["captures"]); len(caps) > 0 {
		fmt.Fprintf(w, "\n%d capture session(s) overlap this window (netractl capture history).\n", len(caps))
	}
	if an := list(v["anomalous"]); len(an) > 0 {
		fmt.Fprintln(w, "\nAnomalous at the same time:")
		for _, a := range an {
			m := obj(a)
			fmt.Fprintf(w, "  %s %s/%s  %s%%\n", str(m["node"]), str(m["chart"]), str(m["dimension"]), fmtNum(num(m["anomalyRate"])))
		}
	}
	fmt.Fprintln(w, "\nFollow up:")
	for _, l := range list(v["links"]) {
		m := obj(l)
		fmt.Fprintf(w, "  %-28s %s\n", str(m["title"]), str(m["href"]))
	}
}

func printMetricsFleet(v map[string]any, w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "CLUSTER\tOK\tNODES\tSERIES\tANOMALY%\tCRIT\tWARN\tERROR")
	for _, c := range list(v["clusters"]) {
		m := obj(c)
		sm := obj(m["summary"])
		fmt.Fprintf(tw, "%s\t%v\t%.0f\t%.0f\t%s\t%.0f\t%.0f\t%s\n", str(m["name"]), m["ok"], num(sm["nodes"]), num(sm["series"]), fmtNum(num(sm["anomalyRate"])), num(sm["alertsCritical"]), num(sm["alertsWarning"]), str(m["error"]))
	}
	t := obj(v["totals"])
	fmt.Fprintf(tw, "TOTAL\t%.0f/%.0f\t%.0f\t%.0f\t%s\t%.0f\t%.0f\t\n", num(t["okClusters"]), num(t["clusters"]), num(t["nodes"]), num(t["series"]), fmtNum(num(t["anomalyRate"])), num(t["alertsCritical"]), num(t["alertsWarning"]))
	tw.Flush()
}

func firstStr(v, d string) string {
	if v != "" {
		return v
	}
	return d
}

func joinStrs(vs []any) string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, str(v))
	}
	return strings.Join(out, ", ")
}

func printAlerts(v map[string]any, w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tALERT\tNODE\tCHART\tVALUE\tSINCE\tINFO")
	for _, a := range list(v["active"]) {
		m := obj(a)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s %s\t%s\t%s\n", str(m["status"]), str(m["rule"]), str(m["node"]), str(m["chart"]), fmtNum(num(m["value"])), str(m["units"]), str(m["since"]), str(m["info"]))
	}
	tw.Flush()
}
