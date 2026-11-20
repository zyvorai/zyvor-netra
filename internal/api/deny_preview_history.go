// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/counterfactual"
	"github.com/zyvorai/netra/internal/denysim"
	"github.com/zyvorai/netra/internal/flowlog"
)

var errBadSince = errors.New("since must be a duration up to 168h (e.g. 1h) or an RFC3339 timestamp within the last 7 days")

const historyPreviewCaveat = "Historical flow-delta preview only — not a policy determination and not an apply. Hits come from the controller's bounded flowlog (default 7 days / 100000 records), not live agent counters. DNS/SNI matches need those fields on retained rows (often empty today). Absence of a hit means Netra did not retain a matching flow delta in the window, not that enforce would be a no-op."

type denyHistoryBody struct {
	denysim.Proposal
	Since string `json:"since,omitempty"` // duration (1h) or RFC3339; default 1h, max 168h
}

type denyHistoryResponse struct {
	Proposal    denysim.Proposal       `json:"proposal"`
	Since       string                 `json:"since"`
	WindowStart time.Time              `json:"windowStart"`
	WindowEnd   time.Time              `json:"windowEnd"`
	Result      *counterfactual.Result `json:"result"`
	Caveat      string                 `json:"caveat"`
	Limitations []string               `json:"limitations"`
}

func (s *Server) ebpfDenyPreviewHistory(w http.ResponseWriter, r *http.Request) {
	var body denyHistoryBody
	if err := decodeJSON(r, &body, 1<<16); err != nil {
		errorJSON(w, 400, "invalid deny-preview-history body: "+err.Error())
		return
	}
	pol, err := counterfactual.PolicyFromEmergencyDeny(body.Kind, body.Value, body.Direction, body.Protocol, body.Port)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	now := time.Now().UTC()
	start, sinceLabel, err := parseHistorySince(body.Since, now)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	limit := body.Limit
	if limit <= 0 {
		limit = 2000
	}
	if limit > flowlog.DefaultMax {
		limit = flowlog.DefaultMax
	}
	q := counterfactual.Query{Start: start, End: now, Limit: limit}
	if ns := strings.TrimSpace(body.Namespace); ns != "" {
		if pod := strings.TrimSpace(body.Pod); pod != "" {
			q.Workload = "pod/" + ns + "/" + pod
		} else if wn := strings.TrimSpace(body.WorkloadName); wn != "" {
			kind := strings.TrimSpace(body.WorkloadKind)
			if kind == "" {
				kind = "pod"
			}
			q.Workload = kind + "/" + ns + "/" + wn
		}
	}
	store := counterfactual.FlowLogStore{Log: flowQuerier{s: s}}
	res, err := counterfactual.NewEvaluator(store).Evaluate(r.Context(), pol, q)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, denyHistoryResponse{
		Proposal:    body.Proposal,
		Since:       sinceLabel,
		WindowStart: start,
		WindowEnd:   now,
		Result:      res,
		Caveat:      historyPreviewCaveat,
		Limitations: flowlog.Limitations(),
	})
}

type flowQuerier struct{ s *Server }

func (f flowQuerier) Query(q flowlog.Query) flowlog.Result {
	if f.s == nil || f.s.store == nil {
		return flowlog.Result{Records: []flowlog.Record{}, Limitations: flowlog.Limitations()}
	}
	return f.s.store.FlowQuery(q)
}

func parseHistorySince(raw string, now time.Time) (time.Time, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "1h"
	}
	if d, err := time.ParseDuration(raw); err == nil {
		if d <= 0 || d > flowlog.DefaultRetain {
			return time.Time{}, "", errBadSince
		}
		return now.Add(-d), raw, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, "", errBadSince
	}
	if t.After(now) || now.Sub(t) > flowlog.DefaultRetain {
		return time.Time{}, "", errBadSince
	}
	return t.UTC(), raw, nil
}
