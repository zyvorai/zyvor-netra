// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/zyvorai/netra/internal/coverage"
	"github.com/zyvorai/netra/internal/detective"
	"github.com/zyvorai/netra/internal/dnsboard"
	"github.com/zyvorai/netra/internal/flowlog"
	"github.com/zyvorai/netra/internal/investigate"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/pathdiag"
)

type investigateConnectionBody struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Peer      string `json:"peer"`
	Port      uint16 `json:"port"`
	Node      string `json:"node"`
	Since     string `json:"since"`
	Until     string `json:"until"`
	Window    string `json:"window"`
}

func (s *Server) investigateConnection(w http.ResponseWriter, r *http.Request) {
	var body investigateConnectionBody
	if r.Body != nil && r.ContentLength != 0 {
		if err := decodeJSON(r, &body, 1<<20); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
	}
	// Also accept query params for netractl convenience.
	q := r.URL.Query()
	if body.Namespace == "" {
		body.Namespace = q.Get("namespace")
	}
	if body.Pod == "" {
		body.Pod = q.Get("pod")
	}
	if body.Peer == "" {
		body.Peer = q.Get("peer")
	}
	if body.Node == "" {
		body.Node = q.Get("node")
	}
	if body.Port == 0 {
		if n, err := strconv.Atoi(q.Get("port")); err == nil && n > 0 && n < 65536 {
			body.Port = uint16(n)
		}
	}
	if body.Window == "" {
		body.Window = q.Get("window")
	}
	if body.Since == "" {
		body.Since = q.Get("since")
	}

	if p, ok := principalFrom(r.Context()); ok && !p.Unrestricted() {
		if body.Namespace != "" && !p.AllowsNamespace(body.Namespace) {
			s.metricsData.rbacDenied.Add(1)
			errorJSON(w, http.StatusForbidden, "scope does not allow this namespace")
			return
		}
		if len(p.Clusters) > 0 && !p.allowsDim(p.Clusters, localCluster()) {
			s.metricsData.rbacDenied.Add(1)
			errorJSON(w, http.StatusForbidden, "scope does not allow this cluster")
			return
		}
	}

	now := time.Now().UTC()
	until := now
	since := now.Add(-15 * time.Minute)
	if body.Window != "" {
		if d, err := time.ParseDuration(body.Window); err == nil && d > 0 && d <= flowlog.DefaultRetain {
			since = now.Add(-d)
		} else {
			errorJSON(w, 400, "window must be a duration within flow retention")
			return
		}
	}
	if body.Since != "" {
		if d, err := time.ParseDuration(body.Since); err == nil && d > 0 {
			since = now.Add(-d)
		} else if t, err := time.Parse(time.RFC3339, body.Since); err == nil {
			since = t.UTC()
		}
	}
	if body.Until != "" {
		if t, err := time.Parse(time.RFC3339, body.Until); err == nil {
			until = t.UTC()
		}
	}

	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	hist := s.store.FlowQuery(flowlog.Query{
		Since: since, Until: until,
		Namespace: body.Namespace, Pod: body.Pod, Peer: body.Peer, Node: body.Node,
		Limit: flowlog.DefaultMax,
	})
	if body.Port != 0 {
		var filtered []flowlog.Record
		for _, rec := range hist.Records {
			if rec.Port == body.Port {
				filtered = append(filtered, rec)
			}
		}
		hist.Records = filtered
		hist.Matched = len(filtered)
	}

	board := dnsboard.Build(agents, now, 50)
	var dnsRows []investigate.DNSRow
	for _, row := range board.Rows {
		dnsRows = append(dnsRows, investigate.DNSRow{Name: row.Name, Failures: row.Failures, Queries: row.Queries})
	}

	var hits []investigate.DetectiveHit
	if unified, err := detective.BuildUnified(agents, s.store.Config(), 20, nil); err == nil {
		for _, f := range unified.Findings {
			hits = append(hits, investigate.DetectiveHit{
				Summary: f.Explanation, Confidence: f.Confidence,
				Namespace: f.Namespace, Pod: f.Pod, Peer: f.Dst,
			})
		}
	}

	var pathNotes []string
	path := pathdiag.Build(agents, 10)
	if path.Summary.TotalRetrans > 0 || path.Summary.LostOut > 0 {
		pathNotes = append(pathNotes, "path retrans="+strconv.FormatUint(path.Summary.TotalRetrans, 10)+
			" lost="+strconv.FormatUint(path.Summary.LostOut, 10)+
			" congestedFlows="+strconv.FormatUint(path.Summary.CongestedFlows, 10))
	}
	for _, row := range path.Pressure {
		if body.Peer != "" && row.RemoteIP != body.Peer {
			continue
		}
		if row.RetransOut == 0 && row.TotalRetrans == 0 {
			continue
		}
		pathNotes = append(pathNotes, "pressure "+row.RemoteIP+":"+strconv.Itoa(int(row.RemotePort))+
			" retransOut="+strconv.FormatUint(row.RetransOut, 10))
		if len(pathNotes) >= 5 {
			break
		}
	}

	var dropNotes []string
	for _, a := range agents {
		if a.DropInfo == nil {
			continue
		}
		for _, f := range a.DropInfo.Flows {
			if body.Peer != "" && f.Dst != body.Peer && f.Src != body.Peer {
				continue
			}
			dropNotes = append(dropNotes, "drop-info "+a.Node+" "+f.Dst+":"+strconv.Itoa(int(f.DstPort))+" "+f.Reason)
			if len(dropNotes) >= 5 {
				break
			}
		}
	}

	var netlink []models.NetlinkEvent
	for _, a := range agents {
		if a.Netlink == nil {
			continue
		}
		for _, ev := range a.Netlink.Events {
			ev.Node = a.Node
			netlink = append(netlink, ev)
		}
	}

	var captures []models.CaptureHistoryEntry
	for _, c := range s.store.CaptureHistory(100) {
		if c.EndedAt.Before(since) || c.StartedAt.After(until) {
			continue
		}
		captures = append(captures, c)
	}

	out := investigate.Compose(investigate.Request{
		Namespace: body.Namespace, Pod: body.Pod, Peer: body.Peer,
		Port: body.Port, Node: body.Node, Since: since, Until: until,
	}, investigate.Input{
		Now: now, Agents: agents,
		FlowRecords: hist.Records, FlowLimitations: hist.Limitations,
		Coverage: coverage.Build(agents, now),
		Captures: captures, DNSRows: dnsRows, Detective: hits,
		PathNotes: pathNotes, DropNotes: dropNotes, NetlinkEvents: netlink,
	})
	writeJSON(w, 200, out)
}
