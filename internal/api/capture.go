// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/zyvorai/netra/internal/alert"
	"github.com/zyvorai/netra/internal/capture"
	"github.com/zyvorai/netra/internal/models"
)

const (
	defaultCaptureDuration = 60 * time.Second
	maxCaptureDuration     = 5 * time.Minute
	// maxConcurrentCaptures is a soft, cluster-wide in-memory guard, not a
	// hard resource limit — raised from the original 5 so a multi-node bulk
	// start (captureBulkStart) doesn't immediately trip it.
	maxConcurrentCaptures = 25
	defaultCaptureMaxPPS  = 2000
)

// captureHub fans agent-pushed capture frames out to every browser watching
// that node, without ever decoding a frame itself — see
// internal/capture.Frame's doc comment for the wire format both ends
// already agree on. One captureSession exists per node with at least one
// live agent or browser connection; it's dropped once both are gone.
type captureHub struct {
	mu       sync.Mutex
	sessions map[string]*captureSession
}

func newCaptureHub() *captureHub { return &captureHub{sessions: map[string]*captureSession{}} }

type captureSession struct {
	mu       sync.Mutex
	browsers map[*websocket.Conn]struct{}
	// Metadata-only counters for MCP/agent summaries — never stores payloads.
	frames      uint64
	bytes       uint64
	protoCounts map[string]uint64
	startedAt   time.Time
}

func (h *captureHub) session(node string) *captureSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.sessions[node]
	if !ok {
		s = &captureSession{browsers: map[*websocket.Conn]struct{}{}, protoCounts: map[string]uint64{}, startedAt: time.Now().UTC()}
		h.sessions[node] = s
	}
	return s
}

func (s *captureSession) observeMeta(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.frames++
	s.bytes += uint64(len(data))
	// Wire frame: capture package prefixes a small header; protocol byte is
	// best-effort. Unknown buckets as "other".
	proto := "other"
	if len(data) > 22 {
		switch data[22] {
		case 6:
			proto = "tcp"
		case 17:
			proto = "udp"
		case 1:
			proto = "icmp"
		}
	}
	if s.protoCounts == nil {
		s.protoCounts = map[string]uint64{}
	}
	s.protoCounts[proto]++
}

func (s *captureSession) summary() models.CaptureSessionSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	dur := 0.0
	if !s.startedAt.IsZero() {
		dur = time.Since(s.startedAt).Seconds()
	}
	pc := make(map[string]uint64, len(s.protoCounts))
	for k, v := range s.protoCounts {
		pc[k] = v
	}
	return models.CaptureSessionSummary{
		Frames: s.frames, Bytes: s.bytes, DurationSeconds: dur,
		ProtocolCounts: pc,
		Note:           "Metadata only — no packet payloads. Live bytes stay on the Capture dashboard.",
	}
}

func (h *captureHub) drop(node string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.sessions, node)
}

func (s *captureSession) subscribe(c *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.browsers[c] = struct{}{}
}

func (s *captureSession) unsubscribe(c *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.browsers, c)
}

// broadcast relays one agent-pushed frame to every subscribed browser.
// A browser whose write fails (slow consumer, closed tab) is dropped from
// the session rather than blocking or slowing down the rest — a live
// packet feed has no retry story for a lagging reader.
func (s *captureSession) broadcast(data []byte) {
	s.mu.Lock()
	conns := make([]*websocket.Conn, 0, len(s.browsers))
	for c := range s.browsers {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		if err := c.WriteMessage(websocket.BinaryMessage, data); err != nil {
			s.unsubscribe(c)
			_ = c.Close()
		}
	}
}

// captureRequestBody is the shared request shape for starting a capture,
// used by both the single-node PUT and the multi-node bulk POST below.
type captureRequestBody struct {
	Backend         string `json:"backend"`
	Protocol        string `json:"protocol"`
	Host            string `json:"host"`
	Port            uint16 `json:"port"`
	SnapLen         uint16 `json:"snapLen"`
	MaxPPS          uint32 `json:"maxPps"`
	DurationSeconds int    `json:"durationSeconds"`
}

// validateCaptureRequest normalizes and validates a capture request body
// for one node — shared by captureStart and captureBulkStart so the two
// can never disagree about what counts as a legal capture spec. A non-zero
// status return means validation failed and msg is the error to report;
// the cluster-wide concurrency cap is still checked separately by each
// caller, since captureBulkStart must recheck it fresh for every node in
// the batch.
func validateCaptureRequest(node string, x captureRequestBody) (spec models.CaptureSpec, status int, msg string) {
	backend, err := models.NormalizeCaptureBackend(strings.ToLower(strings.TrimSpace(x.Backend)))
	if err != nil {
		return models.CaptureSpec{}, 400, err.Error()
	}
	protocol := strings.ToLower(strings.TrimSpace(x.Protocol))
	host := strings.TrimSpace(x.Host)
	// Applies identically to both backends: a promiscuous raw-socket
	// AF_PACKET capture has the same "sees all host-visible traffic on the
	// interface" blast radius as the eBPF path, so this rule is not
	// eBPF-specific and must never become so.
	if protocol == "" && host == "" && x.Port == 0 {
		return models.CaptureSpec{}, 400, "at least one of protocol, host, or port is required — unfiltered whole-interface captures are not allowed"
	}
	duration := defaultCaptureDuration
	if x.DurationSeconds > 0 {
		duration = time.Duration(x.DurationSeconds) * time.Second
	}
	if duration > maxCaptureDuration {
		return models.CaptureSpec{}, 400, "durationSeconds cannot exceed " + maxCaptureDuration.String()
	}
	maxPPS := x.MaxPPS
	if maxPPS == 0 {
		maxPPS = defaultCaptureMaxPPS
	}
	return models.CaptureSpec{
		Node: node, Backend: backend, Protocol: protocol, Host: host, Port: x.Port, SnapLen: x.SnapLen, MaxPPS: maxPPS,
		ExpiresAt: time.Now().UTC().Add(duration),
	}, 0, ""
}

// captureStart handles PUT /api/v1/vms/{node}/capture — an operator
// starting a new packet-capture session on one node. See
// bpf/netra_capture.c and internal/agent's applyCapture for how this
// desired state is reconciled down to the node within one 3s tick.
func (s *Server) captureStart(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimSpace(r.PathValue("node"))
	if node == "" {
		errorJSON(w, 400, "node is required")
		return
	}
	var x captureRequestBody
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	spec, status, msg := validateCaptureRequest(node, x)
	if status != 0 {
		errorJSON(w, status, msg)
		return
	}
	if len(s.store.Captures()) >= maxConcurrentCaptures {
		if existing := s.store.Capture(node); existing == nil {
			errorJSON(w, http.StatusTooManyRequests, "too many concurrent captures already active cluster-wide")
			return
		}
	}
	spec = s.store.SetCapture(spec, actor(r))
	writeJSON(w, 200, spec)
}

// captureBulkStart handles POST /api/v1/capture/bulk — start the same
// filtered capture across many nodes at once. Capture is already a
// per-node, pull-based primitive (each agent independently reconciles its
// own DesiredCapture, see internal/agent's applyCapture), so "many nodes"
// needs no new coordination — just N independent calls to
// Store.SetCapture. A cap hit or validation failure partway through the
// batch fails only that node, not the whole request.
func (s *Server) captureBulkStart(w http.ResponseWriter, r *http.Request) {
	var x struct {
		Nodes []string `json:"nodes"`
		captureRequestBody
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if len(x.Nodes) == 0 {
		errorJSON(w, 400, "nodes is required")
		return
	}
	type nodeResult struct {
		Node  string              `json:"node"`
		OK    bool                `json:"ok"`
		Spec  *models.CaptureSpec `json:"spec,omitempty"`
		Error string              `json:"error,omitempty"`
	}
	results := make([]nodeResult, 0, len(x.Nodes))
	for _, node := range x.Nodes {
		node = strings.TrimSpace(node)
		if node == "" {
			continue
		}
		spec, status, msg := validateCaptureRequest(node, x.captureRequestBody)
		if status != 0 {
			results = append(results, nodeResult{Node: node, Error: msg})
			continue
		}
		if len(s.store.Captures()) >= maxConcurrentCaptures {
			if existing := s.store.Capture(node); existing == nil {
				results = append(results, nodeResult{Node: node, Error: "too many concurrent captures already active cluster-wide"})
				continue
			}
		}
		started := s.store.SetCapture(spec, actor(r))
		results = append(results, nodeResult{Node: node, OK: true, Spec: &started})
	}
	writeJSON(w, 200, map[string]any{"results": results})
}

// captureStop handles DELETE /api/v1/vms/{node}/capture.
func (s *Server) captureStop(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimSpace(r.PathValue("node"))
	if node == "" {
		errorJSON(w, 400, "node is required")
		return
	}
	if !s.store.ClearCapture(node, actor(r), "manual") {
		errorJSON(w, 404, "no active capture on "+node)
		return
	}
	writeJSON(w, 200, map[string]any{"stopped": node})
}

// captureStatus handles GET /api/v1/capture/status.
func (s *Server) captureStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, models.CaptureStatusResponse{Active: s.store.Captures()})
}

// captureHistory handles GET /api/v1/capture/history?limit=N — metadata
// for already-ended sessions; see models.CaptureHistoryEntry's doc comment
// for why packet bytes are never included.
func (s *Server) captureHistory(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	writeJSON(w, 200, models.CaptureHistoryResponse{Entries: s.store.CaptureHistory(limit)})
}

// agentCaptureStream handles GET /api/v1/agents/capture/stream?node=X — the
// agent-initiated leg of the relay, authenticated the same way
// POST /api/v1/agents/report already is (agentAuth). Every frame this
// connection receives is broadcast to that node's captureSession verbatim;
// when the active session is an auto-capture, frames are also appended to
// a classic PCAP under the configured artifact store.
func (s *Server) agentCaptureStream(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimSpace(r.URL.Query().Get("node"))
	if node == "" {
		errorJSON(w, 400, "node is required")
		return
	}
	if !s.requireAgentNode(w, r, node) {
		return
	}
	conn, err := consoleUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	defer s.captureHub.drop(node)

	var startedAt time.Time
	if spec := s.store.Capture(node); spec != nil && alert.IsAutoCaptureRequestor(spec.Requestor) {
		startedAt = spec.StartedAt
		if s.artifacts != nil && s.artifacts.Enabled() {
			src, kind, _ := capture.ParseAutoRequestor(spec.Requestor)
			if _, err := s.artifacts.Begin(node, src, kind, "", startedAt); err != nil {
				s.log.Warn("auto-capture artifact begin", "node", node, "error", err)
			}
		}
	}
	defer s.finalizeAutoArtifact(node, startedAt)

	sess := s.captureHub.session(node)
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if mt == websocket.BinaryMessage {
			sess.observeMeta(data)
			sess.broadcast(data)
			if s.tlsFP != nil {
				s.tlsFP.ObserveFrame(node, data)
			}
			if s.artifacts != nil && !startedAt.IsZero() {
				s.artifacts.WriteFrame(node, data)
			}
		}
	}
}

func (s *Server) finalizeAutoArtifact(node string, startedAt time.Time) {
	if s.artifacts == nil || !s.artifacts.Enabled() || startedAt.IsZero() {
		return
	}
	meta, ok := s.artifacts.Finalize(node, time.Now().UTC())
	if !ok || meta.ID == "" || meta.Frames == 0 {
		return
	}
	sum := s.captureHub.session(node).summary()
	if sum.Frames == 0 && meta.Frames > 0 {
		sum.Frames = uint64(meta.Frames)
		sum.Bytes = uint64(meta.Bytes)
	}
	s.store.PatchCaptureHistory(node, startedAt, func(e *models.CaptureHistoryEntry) {
		e.ArtifactID = meta.ID
		e.ArtifactBytes = meta.Bytes
		e.ArtifactFrames = meta.Frames
		e.TriggerSource = meta.TriggerSource
		e.TriggerKind = meta.TriggerKind
		e.ContextAvailable = meta.ContextPath != ""
		if e.TriggerSubject == "" {
			e.TriggerSubject = meta.TriggerSubject
		}
		cp := sum
		e.Summary = &cp
	})
}

// captureSummaries handles GET /api/v1/capture/summaries — metadata for
// active + recent sessions without packet bytes (MCP-safe).
func (s *Server) captureSummaries(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	active := []map[string]any{}
	for _, spec := range s.store.Captures() {
		sum := s.captureHub.session(spec.Node).summary()
		active = append(active, map[string]any{
			"node": spec.Node, "backend": spec.Backend, "protocol": spec.Protocol,
			"host": spec.Host, "port": spec.Port, "requestor": spec.Requestor,
			"startedAt": spec.StartedAt, "summary": sum, "active": true,
		})
	}
	hist := s.store.CaptureHistory(limit)
	writeJSON(w, 200, map[string]any{
		"active":  active,
		"history": hist,
		"note":    "Bounded capture session summaries — no PCAP bytes. Use the Capture UI for live frames.",
	})
}

// captureArtifactDownload handles GET /api/v1/capture/artifacts/{id}.
func (s *Server) captureArtifactDownload(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" || s.artifacts == nil {
		errorJSON(w, 404, "artifact not found")
		return
	}
	f, meta, err := s.artifacts.Open(id)
	if err != nil {
		errorJSON(w, 404, "artifact not found")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.pcap"`, meta.ID))
	http.ServeContent(w, r, meta.ID+".pcap", meta.EndedAt, f)
}

// captureArtifactContext handles GET /api/v1/capture/artifacts/{id}/context.
func (s *Server) captureArtifactContext(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" || s.artifacts == nil {
		errorJSON(w, 404, "artifact not found")
		return
	}
	f, meta, err := s.artifacts.OpenContext(id)
	if err != nil {
		errorJSON(w, 404, "artifact not found")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.context.json"`, meta.ID))
	http.ServeContent(w, r, meta.ID+".context.json", meta.EndedAt, f)
}

// proxyCaptureStream handles GET /api/v1/vms/{node}/capture/ws — the
// browser-facing leg, mirroring proxyPodExec's Upgrade-then-relay shape
// (console.go) except the relay direction is one-way (agent to browser
// only; a capture viewer never sends packet data back).
func (s *Server) proxyCaptureStream(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimSpace(r.PathValue("node"))
	if node == "" {
		errorJSON(w, 400, "node is required")
		return
	}
	conn, err := consoleUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	sess := s.captureHub.session(node)
	sess.subscribe(conn)
	defer sess.unsubscribe(conn)
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}
