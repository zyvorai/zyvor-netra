// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/zyvorai/netra/internal/metricstream"
	"github.com/zyvorai/netra/internal/tsdb"
)

// WithMetrics attaches the per-node metrics hub fed by agents over
// POST /api/v1/agents/metrics. Nil disables the /api/v1/metrics/* surface.
func (s *Server) WithMetrics(h *metricstream.Hub) *Server {
	s.metricsHub = h
	return s
}

func (s *Server) requireMetrics(w http.ResponseWriter) bool {
	if s.metricsHub == nil {
		errorJSON(w, http.StatusServiceUnavailable, "per-second metrics are disabled on this controller; set NETRA_METRICS_ENABLED=true")
		return false
	}
	return true
}

func (s *Server) agentMetricsIngest(w http.ResponseWriter, r *http.Request) {
	if !s.requireMetrics(w) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
	s.metricsHub.ServeHTTP(w, r)
}

func splitList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseLabels reads "k:v,k2:v2" (values may use '*').
func parseLabels(v string) map[string]string {
	items := splitList(v)
	if len(items) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, it := range items {
		k, val, ok := strings.Cut(it, ":")
		if !ok {
			k, val, ok = strings.Cut(it, "=")
		}
		if ok && k != "" {
			out[strings.TrimSpace(k)] = strings.TrimSpace(val)
		}
	}
	return out
}

func queryInt(q url.Values, key string, d int64) int64 {
	if v := q.Get(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return d
}

var allowedGroups = map[string]bool{"": true, "avg": true, "min": true, "max": true, "sum": true, "last": true, "p50": true, "p90": true, "p95": true, "p99": true}
var allowedAggregates = map[string]bool{"": true, "sum": true, "avg": true, "min": true, "max": true}

// parseMetricQuery builds a tsdb.Query from URL parameters. after and before
// accept unix seconds or negative seconds relative to now, like Netdata.
func parseMetricQuery(q url.Values) (tsdb.Query, string) {
	mq := tsdb.Query{
		Context:    strings.TrimSpace(q.Get("context")),
		Charts:     splitList(q.Get("charts")),
		Dimensions: splitList(q.Get("dimensions")),
		Nodes:      splitList(q.Get("nodes")),
		Labels:     parseLabels(q.Get("labels")),
		After:      queryInt(q, "after", -600),
		Before:     queryInt(q, "before", 0),
		Points:     int(queryInt(q, "points", 0)),
		Group:      q.Get("group"),
		GroupBy:    q.Get("group_by"),
		Aggregate:  q.Get("aggregate"),
	}
	if mq.Context == "" {
		return mq, "context is required"
	}
	if !allowedGroups[mq.Group] {
		return mq, "group must be one of avg, min, max, sum, last, p50, p90, p95, p99"
	}
	if !allowedAggregates[mq.Aggregate] {
		return mq, "aggregate must be one of sum, avg, min, max"
	}
	switch {
	case mq.GroupBy == "", mq.GroupBy == "dimension", mq.GroupBy == "chart", mq.GroupBy == "node", mq.GroupBy == "instance", mq.GroupBy == "all", strings.HasPrefix(mq.GroupBy, "label:"):
	default:
		return mq, "group_by must be dimension, chart, node, instance, all or label:<key>"
	}
	if t := q.Get("tier"); t != "" {
		n, err := strconv.Atoi(t)
		if err != nil || n < 0 || n > 2 {
			return mq, "tier must be 0, 1 or 2"
		}
		mq.Tier = &n
	}
	return mq, ""
}

func (s *Server) metricsNodes(w http.ResponseWriter, _ *http.Request) {
	if !s.requireMetrics(w) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": s.metricsHub.Nodes()})
}

func (s *Server) metricsContexts(w http.ResponseWriter, r *http.Request) {
	if !s.requireMetrics(w) {
		return
	}
	ctxs := tsdb.Contexts(s.metricsHub.Sources(), splitList(r.URL.Query().Get("nodes")))
	if fam := r.URL.Query().Get("family"); fam != "" {
		kept := ctxs[:0]
		for _, c := range ctxs {
			if tsdb.MatchGlob(fam, c.Family) {
				kept = append(kept, c)
			}
		}
		ctxs = kept
	}
	writeJSON(w, http.StatusOK, map[string]any{"contexts": ctxs, "count": len(ctxs)})
}

func (s *Server) metricsQuery(w http.ResponseWriter, r *http.Request) {
	if !s.requireMetrics(w) {
		return
	}
	mq, msg := parseMetricQuery(r.URL.Query())
	if msg != "" {
		errorJSON(w, http.StatusBadRequest, msg)
		return
	}
	res, err := tsdb.Run(s.metricsHub.Sources(), mq, time.Now())
	if err != nil {
		errorJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

var metricsUpgrader = websocket.Upgrader{HandshakeTimeout: 10 * time.Second}

// streamQuery is one subscription on the metrics WebSocket.
type streamQuery struct {
	ID        string            `json:"id"`
	Context   string            `json:"context"`
	Charts    []string          `json:"charts,omitempty"`
	Nodes     []string          `json:"nodes,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Window    int64             `json:"window"` // seconds, default 300
	Points    int               `json:"points"`
	GroupBy   string            `json:"groupBy,omitempty"`
	Group     string            `json:"group,omitempty"`
	Aggregate string            `json:"aggregate,omitempty"`
}

// metricsStream pushes the latest window of every subscribed query once per
// second. The client sends {"subscribe":[...]} to replace its subscriptions.
// The origin must match the host because the session cookie authenticates
// the handshake.
func (s *Server) metricsStream(w http.ResponseWriter, r *http.Request) {
	if !s.requireMetrics(w) {
		return
	}
	conn, err := metricsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetReadLimit(64 << 10)
	subs := make(chan []streamQuery, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			var msg struct {
				Subscribe []streamQuery `json:"subscribe"`
			}
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			if len(msg.Subscribe) > 50 {
				msg.Subscribe = msg.Subscribe[:50]
			}
			select {
			case <-subs:
			default:
			}
			subs <- msg.Subscribe
		}
	}()
	var cur []streamQuery
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-r.Context().Done():
			return
		case cur = <-subs:
		case now := <-t.C:
			if len(cur) == 0 {
				continue
			}
			out := make(map[string]tsdb.Result, len(cur))
			for _, sq := range cur {
				win := sq.Window
				if win <= 0 || win > 86400 {
					win = 300
				}
				if !allowedGroups[sq.Group] || !allowedAggregates[sq.Aggregate] {
					continue
				}
				res, err := tsdb.Run(s.metricsHub.Sources(), tsdb.Query{
					Context: sq.Context, Charts: sq.Charts, Nodes: sq.Nodes, Labels: sq.Labels,
					After: -win, Points: sq.Points, GroupBy: sq.GroupBy, Group: sq.Group, Aggregate: sq.Aggregate,
				}, now)
				if err == nil {
					out[sq.ID] = res
				}
			}
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := conn.WriteJSON(map[string]any{"t": now.Unix(), "results": out}); err != nil {
				return
			}
		}
	}
}
