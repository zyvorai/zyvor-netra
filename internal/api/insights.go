// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/ai"
	"github.com/zyvorai/netra/internal/forecast"
	"github.com/zyvorai/netra/internal/insights"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/policy"
	"github.com/zyvorai/netra/internal/store"
)

var errKubeUnavailable = errors.New("kubernetes client unavailable")

func (s *Server) dependencyGraph(r *http.Request, limit int) (models.DependencyGraph, error) {
	if s.kube == nil {
		return models.DependencyGraph{}, errKubeUnavailable
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	pods, err := s.kube.ListPods(ctx, "")
	if err != nil {
		return models.DependencyGraph{}, err
	}
	services, err := s.kube.ListServices(ctx, "")
	if err != nil {
		return models.DependencyGraph{}, err
	}
	return insights.Dependencies(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), pods, services, limit), nil
}

func (s *Server) insightsDependencies(w http.ResponseWriter, r *http.Request) {
	limit := 500
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 5000 {
		limit = n
	}
	graph, err := s.dependencyGraph(r, limit)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, graph)
}

func (s *Server) insightsBaselineGet(w http.ResponseWriter, _ *http.Request) {
	b := s.store.Baseline()
	if b.CapturedAt.IsZero() {
		writeJSON(w, 200, map[string]any{"captured": false, "baseline": nil})
		return
	}
	writeJSON(w, 200, map[string]any{"captured": true, "baseline": b})
}

func (s *Server) insightsBaselineCapture(w http.ResponseWriter, r *http.Request) {
	b := insights.CaptureBaseline(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), time.Now())
	if err := s.store.SetBaseline(b, actor(r)); err != nil {
		if errors.Is(err, store.ErrPersistence) {
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
		} else {
			errorJSON(w, 500, err.Error())
		}
		return
	}
	writeJSON(w, 201, map[string]any{"captured": true, "baseline": b})
}

func (s *Server) insightsBaselineClear(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Netra-Confirm-Baseline-Clear")), "clear") {
		errorJSON(w, 409, "clearing the behavior baseline requires X-Netra-Confirm-Baseline-Clear: clear")
		return
	}
	if err := s.store.ClearBaseline(actor(r)); err != nil {
		if errors.Is(err, store.ErrPersistence) {
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
		} else {
			errorJSON(w, 500, err.Error())
		}
		return
	}
	writeJSON(w, 200, map[string]any{"cleared": true})
}

func (s *Server) insightsDrift(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, insights.Drift(s.store.Baseline(), s.store.AgentStatuses(time.Now(), s.agentStaleAfter)))
}

func (s *Server) insightsRecommendations(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	graph, err := s.dependencyGraph(r, 5000)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	recs := insights.Recommendations(graph, s.store.AgentStatuses(time.Now(), s.agentStaleAfter), strings.TrimSpace(r.URL.Query().Get("namespace")), strings.TrimSpace(r.URL.Query().Get("workload")), limit)
	writeJSON(w, 200, map[string]any{"items": recs, "count": len(recs), "ciliumEnabled": s.ciliumEnabled, "applyRequiresReview": true})
}

func (s *Server) insightsSummary(w http.ResponseWriter, r *http.Request) {
	graph, err := s.dependencyGraph(r, 5000)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	agents := s.store.AgentStatuses(time.Now(), s.agentStaleAfter)
	drift := insights.Drift(s.store.Baseline(), agents)
	recs := insights.Recommendations(graph, agents, "", "", 200)
	external := 0
	for _, e := range graph.Edges {
		if e.External {
			external++
		}
	}
	b := s.store.Baseline()
	rateBaseline := s.store.RateBaseline()
	rateDrift := s.rateDrift(r)
	exposure := insights.Exposure(graph, drift, rateDrift)
	remediations := insights.Remediations(graph, drift, rateDrift, 200)
	highExposure := 0
	for _, item := range exposure {
		if item.Severity == "high" || item.Severity == "critical" {
			highExposure++
		}
	}
	writeJSON(w, 200, models.InsightSummary{DependencyEdges: len(graph.Edges), ExternalEdges: external, BaselineEntries: len(b.Entries), DriftFindings: len(drift.Findings), Recommendations: len(recs), RateBaselineEntries: len(rateBaseline.Entries), RateDriftFindings: len(rateDrift.Findings), HighExposure: highExposure, RemediationProposals: len(remediations), RateWarming: rateDrift.Window.Warming})
}

func insightRateWindow(r *http.Request) time.Duration {
	window := 5 * time.Minute
	if raw := strings.TrimSpace(r.URL.Query().Get("window")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d >= 30*time.Second && d <= 2*time.Hour {
			window = d
		}
	}
	return window
}

func (s *Server) insightsRates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.store.RateWindow(insightRateWindow(r), time.Now()))
}

func (s *Server) insightsRateBaselineGet(w http.ResponseWriter, _ *http.Request) {
	b := s.store.RateBaseline()
	if b.CapturedAt.IsZero() {
		writeJSON(w, 200, map[string]any{"captured": false, "baseline": nil})
		return
	}
	writeJSON(w, 200, map[string]any{"captured": true, "baseline": b})
}

func (s *Server) insightsRateBaselineCapture(w http.ResponseWriter, r *http.Request) {
	b, err := s.store.CaptureRateBaseline(insightRateWindow(r), actor(r))
	if err != nil {
		if errors.Is(err, store.ErrPersistence) {
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
		} else {
			errorJSON(w, http.StatusConflict, err.Error())
		}
		return
	}
	writeJSON(w, 201, map[string]any{"captured": true, "baseline": b})
}

func (s *Server) insightsRateBaselineClear(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Netra-Confirm-Rate-Baseline-Clear")), "clear") {
		errorJSON(w, 409, "clearing the traffic-rate baseline requires X-Netra-Confirm-Rate-Baseline-Clear: clear")
		return
	}
	if err := s.store.ClearRateBaseline(actor(r)); err != nil {
		if errors.Is(err, store.ErrPersistence) {
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
		} else {
			errorJSON(w, 500, err.Error())
		}
		return
	}
	writeJSON(w, 200, map[string]any{"cleared": true})
}

func (s *Server) rateDrift(r *http.Request) models.RateDriftResponse {
	return insights.RateDrift(s.store.RateBaseline(), s.store.RateWindow(insightRateWindow(r), time.Now()))
}

func (s *Server) insightsRateDrift(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.rateDrift(r))
}

func (s *Server) insightsExposure(w http.ResponseWriter, r *http.Request) {
	graph, err := s.dependencyGraph(r, 5000)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	behavior := insights.Drift(s.store.Baseline(), s.store.AgentStatuses(time.Now(), s.agentStaleAfter))
	rates := s.rateDrift(r)
	writeJSON(w, 200, map[string]any{"items": insights.Exposure(graph, behavior, rates), "rateWarming": rates.Window.Warming})
}

func (s *Server) insightsHealthTrend(w http.ResponseWriter, r *http.Request) {
	threshold := forecast.DefaultBreachThreshold
	if raw := r.URL.Query().Get("threshold"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > 99 {
			errorJSON(w, 400, "threshold must be an integer between 0 and 99")
			return
		}
		threshold = n
	}
	now := time.Now()
	// HealthHistory retains at most 2h (internal/store/history.go), well
	// inside forecast.MaxHorizon, so a zero `since` already returns
	// everything usable — no separate window computation needed here.
	history := s.store.HealthHistory(time.Time{})
	writeJSON(w, 200, forecast.Project(history, threshold, now))
}

func (s *Server) insightsBlastRadius(w http.ResponseWriter, r *http.Request) {
	root := strings.TrimSpace(r.URL.Query().Get("root"))
	if root == "" {
		errorJSON(w, 400, "root query parameter is required")
		return
	}
	hops := insights.DefaultBlastRadiusHops
	if raw := r.URL.Query().Get("hops"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			errorJSON(w, 400, "hops must be a positive integer")
			return
		}
		hops = n
	}
	graph, err := s.dependencyGraph(r, 5000)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	resp, err := insights.BlastRadius(graph, root, hops)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, resp)
}

func (s *Server) insightsRemediations(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	graph, err := s.dependencyGraph(r, 5000)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	behavior := insights.Drift(s.store.Baseline(), s.store.AgentStatuses(time.Now(), s.agentStaleAfter))
	rates := s.rateDrift(r)
	items := insights.Remediations(graph, behavior, rates, limit)
	writeJSON(w, 200, map[string]any{"items": items, "count": len(items), "reviewRequired": true, "autoApply": false})
}

type policyReviewResponse struct {
	GeneratedAt      time.Time                   `json:"generatedAt"`
	Recommendation   models.PolicyRecommendation `json:"recommendation"`
	MatchingPolicies []models.PolicyRef          `json:"matchingPolicies"`
	// AmbiguousMatch is true when more than one existing CiliumNetworkPolicy
	// matches this workload's labels — Plan below is analyzed against only
	// the first match (best-effort; resolving true precedence between
	// several matching CNPs is out of scope here, same as
	// WorkloadDetail.Policies which lists all matches without ranking them).
	AmbiguousMatch bool                     `json:"ambiguousMatch,omitempty"`
	Plan           policy.ChangePlan        `json:"plan"`
	BlastRadius    []models.BlastRadiusItem `json:"blastRadius"`
	History        []models.PolicyRevision  `json:"history"`
	Prose          string                   `json:"prose,omitempty"`
	Engine         string                   `json:"engine"`
}

func (s *Server) insightsPolicyReview(w http.ResponseWriter, r *http.Request) {
	recID := strings.TrimSpace(r.URL.Query().Get("recommendationId"))
	if recID == "" {
		errorJSON(w, 400, "recommendationId is required (see GET /api/v1/insights/recommendations for ids)")
		return
	}
	if s.kube == nil {
		errorJSON(w, 502, errKubeUnavailable.Error())
		return
	}
	graph, err := s.dependencyGraph(r, 5000)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	agents := s.store.AgentStatuses(time.Now(), s.agentStaleAfter)
	// Recommendations don't persist their own store — IDs are a stable hash
	// of the source workload (internal/insights/recommend.go), so looking
	// one up again is the same recompute-on-request style every other
	// insights/* read handler already uses.
	recs := insights.Recommendations(graph, agents, "", "", 500)
	var rec *models.PolicyRecommendation
	for i := range recs {
		if recs[i].ID == recID {
			rec = &recs[i]
			break
		}
	}
	if rec == nil {
		errorJSON(w, 404, "recommendation not found; recommendation ids can shift as observed traffic changes — recompute /api/v1/insights/recommendations and retry with a current id")
		return
	}

	pods, err := s.kube.ListPods(r.Context(), rec.Namespace)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	var labels map[string]string
	for _, p := range pods {
		if strings.EqualFold(p.OwnerKind, rec.WorkloadKind) && p.OwnerName == rec.WorkloadName {
			labels = p.Labels
			break
		}
	}
	listJSON, err := s.kube.ListPolicies(r.Context(), rec.Namespace)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	matches := policy.SummarizeMatchingPolicies(listJSON, rec.Namespace, labels)

	var currentJSON []byte
	if len(matches) > 0 {
		currentJSON, _, err = s.kube.GetPolicy(r.Context(), matches[0].Namespace, matches[0].Name)
		if err != nil {
			errorJSON(w, 502, err.Error())
			return
		}
	}
	plan, err := policy.AnalyzeChange(currentJSON, rec.Manifest)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}

	sourceID := models.CanonicalSource(rec.Namespace, "", rec.WorkloadKind, rec.WorkloadName, 0)
	blast := insights.PolicyBlastRadius(plan, sourceID, graph)

	var history []models.PolicyRevision
	if len(matches) > 0 {
		history = s.store.PolicyHistory(matches[0].Namespace, matches[0].Name, 20)
	}

	resp := policyReviewResponse{
		GeneratedAt:      time.Now().UTC(),
		Recommendation:   *rec,
		MatchingPolicies: matches,
		AmbiguousMatch:   len(matches) > 1,
		Plan:             plan,
		BlastRadius:      blast,
		History:          history,
		Engine:           "heuristic",
	}
	resp.Prose = narratePolicyReview(r.Context(), resp)
	if resp.Prose != "" {
		resp.Engine = "llm"
	}
	writeJSON(w, 200, resp)
}

// narratePolicyReview asks the optional LLM provider to summarize the
// review's aggregate fields — never the full candidate manifest, which
// could be large and isn't needed to explain risk/blast-radius in prose.
// Returns "" (leaving the heuristic-only response as a complete answer on
// its own) when no provider is configured or the call fails.
func narratePolicyReview(ctx context.Context, resp policyReviewResponse) string {
	p := ai.ProviderFromEnv()
	if p == nil || !p.Enabled() {
		return ""
	}
	sys := strings.Join([]string{
		"You are Netra's read-only network observability assistant.",
		"Summarize this CiliumNetworkPolicy change review in a short paragraph for an operator about to decide whether to apply it.",
		"Use only the facts given; never invent a destination, a rule, or a cause not stated.",
		"Never recommend applying the policy without human review — this tool is read-only, never mutates.",
		"Keep the answer under 180 words.",
	}, " ")
	var b strings.Builder
	fmt.Fprintf(&b, "Workload: %s/%s (%s)\n", resp.Recommendation.Namespace, resp.Recommendation.WorkloadName, resp.Recommendation.WorkloadKind)
	fmt.Fprintf(&b, "Matching existing policies: %d (ambiguous=%v)\n", len(resp.MatchingPolicies), resp.AmbiguousMatch)
	fmt.Fprintf(&b, "Risk: %s\n", resp.Plan.Risk)
	fmt.Fprintf(&b, "Changes: %v\n", resp.Plan.Changes)
	fmt.Fprintf(&b, "Warnings: %v\n", resp.Plan.Warnings)
	fmt.Fprintf(&b, "Added destinations: %v\n", resp.Plan.AddedDestinations)
	fmt.Fprintf(&b, "Removed destinations: %v\n", resp.Plan.RemovedDestinations)
	for _, item := range resp.BlastRadius {
		fmt.Fprintf(&b, "- %s (%s): correlated=%v active=%v — %s\n", item.Destination, item.Kind, item.Correlated, item.ActiveTraffic, item.Note)
	}
	rewritten, err := p.RewriteText(ctx, sys, b.String())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(rewritten)
}

func (s *Server) insightsNewSinceStart(w http.ResponseWriter, r *http.Request) {
	maxRestarts := 5
	if raw := r.URL.Query().Get("maxRestarts"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			errorJSON(w, 400, "maxRestarts must be a non-negative integer (0 disables the restart-count filter)")
			return
		}
		maxRestarts = n
	}
	if s.kube == nil {
		errorJSON(w, 502, errKubeUnavailable.Error())
		return
	}
	pods, err := s.kube.ListPods(r.Context(), "")
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	agents := s.store.AgentStatuses(time.Now(), s.agentStaleAfter)
	findings := insights.NewSinceStart(s.store.Baseline(), agents, pods, maxRestarts)
	writeJSON(w, 200, map[string]any{
		"findings":    findings,
		"count":       len(findings),
		"limitation":  insights.NewSinceStartLimitation,
		"maxRestarts": maxRestarts,
		// Unlike internal/alert's poller-driven equivalent, this stateless,
		// on-demand endpoint carries no memory of the previous poll, so it
		// cannot detect "this pod just restarted between two polls" — a
		// finding here may legitimately repeat across a pod's crash loop.
		"note": "on-demand and stateless: may repeat the same finding across a pod's crash loop, unlike the alert-poller path which suppresses that for one cycle",
	})
}

func (s *Server) insightsProtocolDowngrades(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, insights.ProtocolDowngrades(s.store.Baseline(), s.store.AgentStatuses(time.Now(), s.agentStaleAfter)))
}
