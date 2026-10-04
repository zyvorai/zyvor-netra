// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"net/http"
	"time"

	"github.com/zyvorai/netra/internal/anomaly"
)

// metricsAnomalies reports the anomaly rate per node, a 60-bucket timeline,
// the most anomalous dimensions and, with highlight_after/highlight_before,
// the dimensions whose distribution changed most versus the baseline.
func (s *Server) metricsAnomalies(w http.ResponseWriter, r *http.Request) {
	if !s.requireMetrics(w) {
		return
	}
	q := r.URL.Query()
	now := time.Now()
	resolve := func(v int64) int64 {
		if v <= 0 {
			return now.Unix() + v
		}
		return v
	}
	after, before := resolve(queryInt(q, "after", -900)), resolve(queryInt(q, "before", 0))
	if after >= before {
		errorJSON(w, http.StatusBadRequest, "after must be before before")
		return
	}
	if before-after > 31*86400 {
		errorJSON(w, http.StatusBadRequest, "window is limited to 31 days")
		return
	}
	top := int(queryInt(q, "top", 30))
	if top <= 0 || top > 500 {
		top = 30
	}
	nodes := splitList(q.Get("nodes"))
	sum := anomaly.Summarize(s.metricsHub.Sources(), nodes, after, before, top, now)
	if q.Has("highlight_after") {
		ha, hb := resolve(queryInt(q, "highlight_after", 0)), resolve(queryInt(q, "highlight_before", 0))
		if ha >= hb {
			errorJSON(w, http.StatusBadRequest, "highlight_after must be before highlight_before")
			return
		}
		sum.HighlightAfter, sum.HighlightBefore = ha, hb
		sum.Correlated = anomaly.Correlate(s.metricsHub.Sources(), nodes, ha, hb, top, now)
	}
	writeJSON(w, http.StatusOK, sum)
}
