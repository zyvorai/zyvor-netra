// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/ai"
	"github.com/zyvorai/netra/internal/denysim"
	"github.com/zyvorai/netra/internal/health"
	"github.com/zyvorai/netra/internal/insights"
	"github.com/zyvorai/netra/internal/kerneldiag"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/observability"
)

var errAIStoreUnavailable = errors.New("controller store is not initialised")

func (s *Server) aiStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, ai.CurrentStatus())
}

func (s *Server) aiBrief(w http.ResponseWriter, r *http.Request) {
	snap, err := s.aiSnapshot(r)
	if err != nil {
		errorJSON(w, 503, err.Error())
		return
	}
	brief := ai.BuildBrief(snap)
	s.recordHealthSample(snap, brief.Severity, brief.Fingerprint)
	writeJSON(w, 200, brief)
}

// aiCongestionBrief builds a plain-English brief scoped to kernel-network
// (Congestion Map) findings. It reuses aiSnapshot(r) for cluster context
// exactly like aiBrief, then augments a LOCAL COPY of snap.Anomalies from
// kerneldiag.BuildWindow — the same engine and default window
// ebpfKernelNetworkDiagnostics already uses — so /api/v1/ai/digest, /ask
// and /agent (which call aiSnapshot independently) are entirely unaffected;
// kernel-network findings only ever influence this one endpoint's severity
// and summary.
func (s *Server) aiCongestionBrief(w http.ResponseWriter, r *http.Request) {
	snap, err := s.aiSnapshot(r)
	if err != nil {
		errorJSON(w, 503, err.Error())
		return
	}
	window := 5 * time.Minute
	if raw := strings.TrimSpace(r.URL.Query().Get("window")); raw != "" {
		parsed, perr := time.ParseDuration(raw)
		if perr != nil || parsed <= 0 {
			errorJSON(w, http.StatusBadRequest, "window must be a positive duration such as 5m or 1h")
			return
		}
		window = parsed
	}
	if s.store != nil {
		agents := s.store.AgentStatuses(time.Now(), s.agentStaleAfter)
		diag := kerneldiag.BuildWindow(agents, s.store.KernelNetworkWindows(window))
		snap.KernelCritical = diag.Summary.Critical
		snap.KernelWarnings = diag.Summary.Warnings
		for _, n := range diag.Nodes {
			for _, f := range n.Findings {
				if len(snap.Anomalies) >= 12 {
					break
				}
				snap.Anomalies = append(snap.Anomalies, ai.Finding{
					Severity: f.Severity,
					Kind:     "kernel-network/" + f.Layer,
					Subject:  n.Node,
					Message:  f.Explanation,
				})
			}
		}
	}
	writeJSON(w, 200, ai.CongestionBrief(snap))
}

func (s *Server) aiAsk(w http.ResponseWriter, r *http.Request) {
	var req ai.AskRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		errorJSON(w, 400, "unable to read request body")
		return
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			errorJSON(w, 400, "invalid JSON body")
			return
		}
	}
	snap, err := s.aiSnapshot(r)
	if err != nil {
		errorJSON(w, 503, err.Error())
		return
	}
	snap = scopeAISnapshot(snap, req.Namespace)
	// Use the provider whenever NETRA_AI_API_KEY is set. Heuristic-only
	// operators leave the key unset. preferLlm is accepted for forward
	// compatibility and is not a hard switch.
	_ = req.PreferLLM
	writeJSON(w, 200, ai.Answer(r.Context(), snap, req.Question, ai.ProviderFromEnv(), req.ConversationID))
}

// aiAgent runs the in-process NL graph (classify → optional draft →
// synthesize). Same snapshot and safety contract as aiAsk; the extra
// payload is the step trace plus a preview-only draft when the question
// looks like deny/rate/allow. The optional Python LangGraph companion
// calls this endpoint as one of its tools.
func (s *Server) aiAgent(w http.ResponseWriter, r *http.Request) {
	var req ai.AskRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		errorJSON(w, 400, "unable to read request body")
		return
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			errorJSON(w, 400, "invalid JSON body")
			return
		}
	}
	snap, err := s.aiSnapshot(r)
	if err != nil {
		errorJSON(w, 503, err.Error())
		return
	}
	snap = scopeAISnapshot(snap, req.Namespace)
	_ = req.PreferLLM
	res := ai.Run(r.Context(), snap, req.Question, ai.ProviderFromEnv(), req.ConversationID)
	if res.Draft != nil {
		s.attachDraftBlastRadius(res.Draft)
	}
	writeJSON(w, 200, res)
}

// aiForget clears any stored conversation memory (conversation.go) for
// the given id — used by the web "New conversation" reset and ChatOps's
// /netra forget, both of which only ever reach conversation state through
// this HTTP seam, never internal/ai directly.
func (s *Server) aiForget(w http.ResponseWriter, r *http.Request) {
	var req ai.ForgetRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		errorJSON(w, 400, "unable to read request body")
		return
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			errorJSON(w, 400, "invalid JSON body")
			return
		}
	}
	ai.ClearConversation(req.ConversationID)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) aiDraft(w http.ResponseWriter, r *http.Request) {
	var req ai.AskRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		errorJSON(w, 400, "unable to read request body")
		return
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			errorJSON(w, 400, "invalid JSON body")
			return
		}
	}
	if strings.TrimSpace(req.Question) == "" {
		errorJSON(w, 400, "question is required")
		return
	}
	draft := ai.DraftRule(req.Question)
	s.attachDraftBlastRadius(&draft)
	writeJSON(w, 200, draft)
}

func (s *Server) aiDigest(w http.ResponseWriter, r *http.Request) {
	snap, err := s.aiSnapshot(r)
	if err != nil {
		errorJSON(w, 503, err.Error())
		return
	}
	brief := ai.BuildBrief(snap)
	peek := r.URL.Query().Get("peek") == "1" || strings.EqualFold(r.Header.Get("X-Netra-Digest-Peek"), "1")
	var digest ai.Digest
	if peek {
		digest = ai.BuildDigestPeek(brief)
	} else {
		digest = ai.BuildDigest(brief)
	}
	digest = ai.NarrateWhyChanged(r.Context(), digest, ai.ProviderFromEnv())
	if !peek {
		s.recordHealthSample(snap, digest.Severity, digest.Fingerprint)
	}
	writeJSON(w, 200, digest)
}

// recordHealthSample feeds the shared bounded health-history (see
// internal/store/history.go) from an already-computed ai.Snapshot plus the
// overall severity/fingerprint its caller (aiBrief or aiDigest) derived from
// it, rather than recomputing either here.
func (s *Server) recordHealthSample(snap ai.Snapshot, severity, fingerprint string) {
	s.store.RecordHealthSample(models.ClusterHealthSample{
		HealthScore: snap.HealthScore,
		AgentsStale: snap.AgentsStale,
		Mode:        snap.Mode,
		Severity:    severity,
		Fingerprint: fingerprint,
	}, time.Now())
}

func (s *Server) aiSuggestions(w http.ResponseWriter, r *http.Request) {
	snap, err := s.aiSnapshot(r)
	if err != nil {
		errorJSON(w, 503, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": ai.Suggestions(snap)})
}

func (s *Server) aiExplain(w http.ResponseWriter, r *http.Request) {
	var req ai.ExplainRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		errorJSON(w, 400, "unable to read request body")
		return
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			errorJSON(w, 400, "invalid JSON body")
			return
		}
	}
	snap, err := s.aiSnapshot(r)
	if err != nil {
		errorJSON(w, 503, err.Error())
		return
	}
	// Explain popovers narrate one independent finding, not a thread —
	// they never opt into conversation memory.
	writeJSON(w, 200, ai.ExplainFinding(r.Context(), snap, req, ai.ProviderFromEnv()))
}

func (s *Server) aiSnapshot(r *http.Request) (ai.Snapshot, error) {
	if s.store == nil {
		return ai.Snapshot{}, errAIStoreUnavailable
	}
	now := time.Now().UTC()
	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	obs := observability.Summarize(agents, 8)
	hs := health.Build(agents, 8)

	stale := 0
	workloads := 0
	for _, a := range agents {
		if a.Stale {
			stale++
		}
		workloads += len(a.Workloads)
	}

	cfg := s.store.Config()
	snap := ai.Snapshot{
		GeneratedAt:     now,
		AgentsTotal:     len(agents),
		AgentsStale:     stale,
		Workloads:       workloads,
		Mode:            cfg.Mode,
		LeaseSeconds:    cfg.LeaseSeconds,
		Packets:         obs.Packets,
		Bytes:           obs.Bytes,
		Blocked:         obs.Blocked,
		HealthScore:     hs.Summary.HealthScore,
		TopDestinations: toAICounts(obs.TopDestinations, 8),
		TopDNS:          toAICounts(obs.TopDNS, 8),
		TopProcesses:    toAICounts(obs.TopProcesses, 8),
		BlockReasons:    toAICounts(obs.BlockReasons, 8),
	}
	for _, a := range agents {
		for _, c := range a.ICMPTypes {
			snap.TopICMP = append(snap.TopICMP, ai.NamedCount{Name: c.Name, Count: c.Count})
		}
		for _, c := range a.ICMP6Types {
			snap.TopICMP = append(snap.TopICMP, ai.NamedCount{Name: "v6:" + c.Name, Count: c.Count})
		}
	}
	if len(snap.TopICMP) > 8 {
		snap.TopICMP = snap.TopICMP[:8]
	}
	for _, a := range hs.Summary.Anomalies {
		if len(snap.Anomalies) >= 8 {
			break
		}
		snap.Anomalies = append(snap.Anomalies, ai.Finding{
			Severity: a.Severity,
			Kind:     a.Kind,
			Subject:  a.Subject,
			Message:  a.Message,
		})
	}

	snap.Metrics = s.metricFindings(now)
	if s.tlsFP != nil {
		risk := s.tlsFP.Risk(100, 2)
		snap.TLSRare = risk.Rare
		snap.ECHSightings = risk.ECHSightings
	}

	graph, err := s.dependencyGraph(r, 2000)
	if err == nil {
		external := 0
		for _, e := range graph.Edges {
			if e.External {
				external++
			}
		}
		drift := insights.Drift(s.store.Baseline(), agents)
		rateDrift := s.rateDrift(r)
		exposure := insights.Exposure(graph, drift, rateDrift)
		nsHint := strings.TrimSpace(r.URL.Query().Get("namespace"))
		recs := insights.Recommendations(graph, agents, nsHint, "", 50)
		high := 0
		for _, item := range exposure {
			if nsHint != "" && !sourceInNamespace(item.Source, nsHint) {
				continue
			}
			if item.Severity == "high" || item.Severity == "critical" {
				high++
			}
			if len(snap.Exposure) < 6 {
				msg := item.Source
				if len(item.Reasons) > 0 {
					msg = item.Reasons[0]
				}
				snap.Exposure = append(snap.Exposure, ai.Finding{
					Severity: item.Severity,
					Kind:     "exposure",
					Subject:  item.Source,
					Message:  msg,
				})
			}
		}
		for _, f := range drift.Findings {
			if nsHint != "" && !sourceInNamespace(f.Source, nsHint) {
				continue
			}
			if len(snap.Drift) >= 6 {
				break
			}
			snap.Drift = append(snap.Drift, ai.Finding{
				Severity: f.Severity,
				Kind:     f.Kind,
				Subject:  f.Source,
				Message:  f.Message,
			})
		}
		if nsHint != "" {
			external = 0
			edges := 0
			for _, e := range graph.Edges {
				if sourceInNamespace(e.Source, nsHint) || sourceInNamespace(e.Target, nsHint) {
					edges++
					if e.External {
						external++
					}
				}
			}
			snap.DependencyEdges = edges
			snap.ExternalEdges = external
		} else {
			snap.DependencyEdges = len(graph.Edges)
			snap.ExternalEdges = external
		}
		snap.DriftFindings = len(snap.Drift)
		if nsHint == "" {
			snap.DriftFindings = len(drift.Findings)
		}
		snap.HighExposure = high
		snap.Recommendations = len(recs)
	}
	return snap, nil
}

// scopeAISnapshot post-filters findings when the ask/agent body carries a
// namespace. AgentsTotal/Mode stay cluster-wide so the brief still says how
// many nodes are reporting.
func scopeAISnapshot(snap ai.Snapshot, namespace string) ai.Snapshot {
	ns := strings.TrimSpace(namespace)
	if ns == "" {
		return snap
	}
	filter := func(in []ai.Finding) []ai.Finding {
		out := make([]ai.Finding, 0, len(in))
		for _, f := range in {
			if sourceInNamespace(f.Subject, ns) || strings.Contains(strings.ToLower(f.Message), strings.ToLower(ns)) {
				out = append(out, f)
			}
		}
		return out
	}
	snap.Exposure = filter(snap.Exposure)
	snap.Drift = filter(snap.Drift)
	snap.Anomalies = filter(snap.Anomalies)
	snap.HighExposure = 0
	for _, f := range snap.Exposure {
		if f.Severity == "high" || f.Severity == "critical" {
			snap.HighExposure++
		}
	}
	snap.DriftFindings = len(snap.Drift)
	snap.SuggestedNext = append([]string{"Scoped to namespace " + ns + "."}, snap.SuggestedNext...)
	return snap
}

func sourceInNamespace(source, ns string) bool {
	if ns == "" || source == "" {
		return ns == ""
	}
	// Canonical forms: workload:ns:kind:name, pod:ns:pod, ns/pod, bare ns token.
	parts := strings.Split(source, ":")
	if len(parts) >= 2 && (parts[0] == "workload" || parts[0] == "pod" || parts[0] == "service") {
		return parts[1] == ns
	}
	if i := strings.IndexByte(source, '/'); i > 0 {
		return source[:i] == ns
	}
	return source == ns || strings.Contains(source, ":"+ns+":")
}

func toAICounts(in []models.NamedCount, n int) []ai.NamedCount {
	if n <= 0 || n > len(in) {
		n = len(in)
	}
	out := make([]ai.NamedCount, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, ai.NamedCount{Name: in[i].Name, Count: in[i].Count})
	}
	return out
}

// attachDraftBlastRadius runs an observe-only deny-preview against live
// counters when the draft targets an IP/CIDR/port/DNS/SNI/process. Failures
// are ignored so drafting never 503s on a preview miss.
func (s *Server) attachDraftBlastRadius(d *ai.RuleDraft) {
	if d == nil || !d.Understood || s.store == nil {
		return
	}
	kind, value := draftPreviewTarget(*d)
	if kind == "" || value == "" {
		return
	}
	p := denysim.Proposal{Kind: kind, Value: value, Limit: 20}
	if dir, ok := d.Body["direction"].(string); ok {
		p.Direction = dir
	}
	if proto, ok := d.Body["protocol"].(string); ok {
		p.Protocol = proto
	}
	if kind == denysim.KindPort {
		if n, err := strconv.ParseUint(value, 10, 16); err == nil {
			p.Port = uint16(n)
		}
	}
	res, err := denysim.Preview(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), p)
	if err != nil || res == nil {
		return
	}
	d.BlastRadius = map[string]any{
		"hitCount":     res.HitCount,
		"workloads":    res.Workloads,
		"totalPackets": res.TotalPackets,
		"agentsSeen":   res.AgentsSeen,
		"agentsStale":  res.AgentsStale,
		"caveat":       res.Caveat,
		"note":         "Observe-only counterfactual from deny-preview. Nothing was applied.",
	}
	if res.HitCount > 0 {
		d.Warnings = append(d.Warnings, "deny-preview would match "+strconv.Itoa(res.HitCount)+" observed counter group(s) / "+strconv.Itoa(res.Workloads)+" workload(s)")
	}
}

func draftPreviewTarget(d ai.RuleDraft) (kind, value string) {
	switch d.Kind {
	case "deny", "allow":
		if ip, ok := d.Body["ip"].(string); ok {
			return denysim.KindIP, ip
		}
		if ip, ok := d.Body["address"].(string); ok {
			return denysim.KindIP, ip
		}
	case "cidr-deny", "cidr-allow", "cidr":
		if c, ok := d.Body["cidr"].(string); ok {
			return denysim.KindCIDR, c
		}
	case "port-deny", "port-allow", "port":
		if p, ok := d.Body["port"]; ok {
			return denysim.KindPort, formatDraftPort(p)
		}
	case "dns", "dns-deny":
		if n, ok := d.Body["name"].(string); ok {
			return denysim.KindDNS, n
		}
		if n, ok := d.Body["domain"].(string); ok {
			return denysim.KindDNS, n
		}
	case "sni", "sni-deny":
		if n, ok := d.Body["sni"].(string); ok {
			return denysim.KindSNI, n
		}
		if n, ok := d.Body["name"].(string); ok {
			return denysim.KindSNI, n
		}
	case "process", "process-deny", "process-allow":
		if n, ok := d.Body["name"].(string); ok {
			return denysim.KindProcess, n
		}
	}
	return "", ""
}

func formatDraftPort(v any) string {
	switch t := v.(type) {
	case float64:
		return strconv.Itoa(int(t))
	case int:
		return strconv.Itoa(t)
	case uint16:
		return strconv.Itoa(int(t))
	case string:
		return t
	default:
		return ""
	}
}
