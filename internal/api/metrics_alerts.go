// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/zyvorai/netra/internal/metricalert"
	"github.com/zyvorai/netra/internal/metricexport"
)

// WithMetricAlerts exposes the metric alert engine (see docs/metric-alerts.md).
func (s *Server) WithMetricAlerts(e *metricalert.Engine) *Server {
	s.metricAlerts = e
	return s
}

// WithMetricExporters reports exporter status on GET /api/v1/metrics/exporters.
func (s *Server) WithMetricExporters(status func() []metricexport.Status) *Server {
	s.metricExporters = status
	return s
}

func (s *Server) metricsExporters(w http.ResponseWriter, _ *http.Request) {
	if !s.requireMetrics(w) {
		return
	}
	out := []metricexport.Status{}
	if s.metricExporters != nil {
		out = append(out, s.metricExporters()...)
	}
	writeJSON(w, http.StatusOK, map[string]any{"exporters": out})
}

func (s *Server) requireMetricAlerts(w http.ResponseWriter) bool {
	if s.metricAlerts == nil {
		errorJSON(w, http.StatusServiceUnavailable, "metric alerts are disabled (NETRA_METRICS_ENABLED / NETRA_METRICALERT_ENABLED)")
		return false
	}
	return true
}

func (s *Server) metricsAlerts(w http.ResponseWriter, r *http.Request) {
	if !s.requireMetricAlerts(w) {
		return
	}
	q := r.URL.Query()
	writeJSON(w, http.StatusOK, s.metricAlerts.Snapshot(q.Get("all") == "true" || q.Get("all") == "1", int(queryInt(q, "history", 200))))
}

func requestActor(r *http.Request) string {
	if who, ok := verifiedActor(r); ok {
		return who
	}
	if p, ok := principalFrom(r.Context()); ok {
		return p.kind
	}
	return "anonymous"
}

type silenceRequest struct {
	Rule     string    `json:"rule"`
	Node     string    `json:"node"`
	Chart    string    `json:"chart"`
	Duration string    `json:"duration"`
	Until    time.Time `json:"until"`
	Comment  string    `json:"comment"`
}

func (s *Server) metricsAlertSilence(w http.ResponseWriter, r *http.Request) {
	if !s.requireMetricAlerts(w) {
		return
	}
	var req silenceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		errorJSON(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	now := time.Now()
	until := req.Until
	if req.Duration != "" {
		d, err := time.ParseDuration(req.Duration)
		if err != nil {
			errorJSON(w, http.StatusBadRequest, "duration must be a Go duration such as 2h")
			return
		}
		until = now.Add(d)
	}
	if len(req.Comment) > 500 {
		req.Comment = req.Comment[:500]
	}
	sil, err := s.metricAlerts.AddSilence(metricalert.Silence{Rule: req.Rule, Node: req.Node, Chart: req.Chart, Until: until, Comment: req.Comment, CreatedBy: requestActor(r)}, now)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, sil)
}

func (s *Server) metricsAlertUnsilence(w http.ResponseWriter, r *http.Request) {
	if !s.requireMetricAlerts(w) {
		return
	}
	if err := s.metricAlerts.DeleteSilence(r.PathValue("id")); err != nil {
		errorJSON(w, http.StatusNotFound, "silence not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) metricsAlertAck(w http.ResponseWriter, r *http.Request) {
	if !s.requireMetricAlerts(w) {
		return
	}
	if err := s.metricAlerts.Ack(r.PathValue("id"), requestActor(r)); err != nil {
		if errors.Is(err, metricalert.ErrNotFound) {
			errorJSON(w, http.StatusNotFound, "no raised alert with that id")
			return
		}
		errorJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "acknowledged"})
}
