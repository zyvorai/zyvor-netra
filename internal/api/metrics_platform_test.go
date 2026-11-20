// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/zyvorai/netra/internal/metricstream"
	"github.com/zyvorai/netra/internal/store"
	"github.com/zyvorai/netra/internal/tsdb"
)

func metricsTestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	t.Setenv("NETRA_API_KEY", "api-secret")
	t.Setenv("NETRA_AGENT_KEY", "agent-secret")
	hub, err := metricstream.OpenHub(metricstream.HubOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, store.New()).WithMetrics(hub)
	return s, s.Handler()
}

func ingestBatch(t *testing.T, h http.Handler, key string, b *metricstream.Batch) *httptest.ResponseRecorder {
	t.Helper()
	body, err := metricstream.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/metrics", bytes.NewReader(body))
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("X-Netra-Agent-Key", key)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func authedGet(t *testing.T, h http.Handler, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer api-secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var v map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &v)
	return rr.Code, v
}

func cpuBatch(node string, from, to int64) *metricstream.Batch {
	ws := metricstream.WireSeries{Series: tsdb.Series{Context: "system.cpu", Chart: "system.cpu", Dimension: "user", Units: "%", Family: "cpu"}}
	for ts := from; ts <= to; ts++ {
		ws.Points = append(ws.Points, [3]float64{float64(ts), 40, 0})
	}
	return &metricstream.Batch{Node: node, From: 0, To: to, Series: []metricstream.WireSeries{ws}}
}

func TestMetricsIngestRequiresAgentKeyAndQueryRequiresAPIKey(t *testing.T) {
	_, h := metricsTestServer(t)
	now := time.Now().Unix()
	if rr := ingestBatch(t, h, "wrong", cpuBatch("n1", now-60, now)); rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad agent key accepted: %d", rr.Code)
	}
	rr := ingestBatch(t, h, "agent-secret", cpuBatch("n1", now-60, now))
	if rr.Code != http.StatusOK {
		t.Fatalf("ingest %d %s", rr.Code, rr.Body)
	}
	var resp metricstream.Response
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Stored != 61 || resp.LastT != now {
		t.Fatalf("ingest response %+v", resp)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/data?context=system.cpu", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated query allowed: %d", rec.Code)
	}

	code, body := authedGet(t, h, "/api/v1/metrics/data?context=system.cpu&after=-30&points=3")
	if code != 200 {
		t.Fatalf("query %d %v", code, body)
	}
	dims := body["dimensions"].([]any)
	if len(dims) != 1 || dims[0].(map[string]any)["name"] != "user" {
		t.Fatalf("dimensions %v", dims)
	}
	code, body = authedGet(t, h, "/api/v1/metrics/contexts")
	if code != 200 || body["count"].(float64) != 1 {
		t.Fatalf("contexts %d %v", code, body)
	}
	code, body = authedGet(t, h, "/api/v1/metrics/nodes")
	if code != 200 || len(body["nodes"].([]any)) != 1 {
		t.Fatalf("nodes %d %v", code, body)
	}
}

func TestMetricsQueryValidation(t *testing.T) {
	_, h := metricsTestServer(t)
	for _, q := range []string{
		"",
		"?context=x&group=median",
		"?context=x&group_by=random",
		"?context=x&aggregate=p99",
		"?context=x&tier=7",
	} {
		if code, _ := authedGet(t, h, "/api/v1/metrics/data"+q); code != http.StatusBadRequest {
			t.Errorf("%q: code %d, want 400", q, code)
		}
	}
}

func TestMetricsDisabledAnswers503(t *testing.T) {
	t.Setenv("NETRA_API_KEY", "")
	t.Setenv("NETRA_AGENT_KEY", "")
	t.Setenv("NETRA_ALLOW_UNAUTHENTICATED", "true")
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, store.New())
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/metrics/contexts", nil))
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "NETRA_METRICS_ENABLED") {
		t.Fatalf("got %d %s", rr.Code, rr.Body)
	}
}

func TestMetricsStreamPushesSubscribedQueries(t *testing.T) {
	s, _ := metricsTestServer(t)
	now := time.Now().Unix()
	if _, err := s.metricsHub.Ingest(cpuBatch("n1", now-30, now)); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(s.metricsStream))
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.WriteJSON(map[string]any{"subscribe": []streamQuery{{ID: "cpu", Context: "system.cpu", Window: 60, Points: 10}}}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var msg struct {
		Results map[string]tsdb.Result `json:"results"`
	}
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatal(err)
	}
	if r, ok := msg.Results["cpu"]; !ok || len(r.Dimensions) != 1 {
		t.Fatalf("stream payload %+v", msg)
	}
}

func TestMetricsStreamRejectsCrossOrigin(t *testing.T) {
	s, _ := metricsTestServer(t)
	srv := httptest.NewServer(http.HandlerFunc(s.metricsStream))
	defer srv.Close()
	hdr := http.Header{"Origin": []string{"https://evil.example"}}
	if _, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), hdr); err == nil {
		t.Fatal("cross-origin WebSocket handshake accepted")
	}
}
