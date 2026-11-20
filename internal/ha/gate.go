// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package ha

import (
	"encoding/json"
	"net/http"
	"sync"
)

// Gate keeps follower replicas alive without allowing them to serve mutable API
// traffic. Kubernetes readiness targets /readyz, so only the elected leader is
// selected by the Service.
type Gate struct {
	mu       sync.Mutex
	wg       sync.WaitGroup
	leader   bool
	identity string
	handler  http.Handler
	version  string
}

func NewGate(identity, version string) *Gate {
	return &Gate{identity: identity, version: version}
}

func (g *Gate) Promote(h http.Handler) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.handler = h
	g.leader = true
}

// Demote prevents new requests before waiting for in-flight leader requests to
// finish. Callers can then safely close the persistent store and release locks.
func (g *Gate) Demote() {
	g.mu.Lock()
	g.leader = false
	g.handler = nil
	g.mu.Unlock()
	g.wg.Wait()
}

func (g *Gate) IsLeader() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.leader
}

func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/livez", "/healthz":
		g.mu.Lock()
		leader := g.leader
		g.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "leader": leader, "identity": g.identity, "version": g.version})
		return
	case "/readyz":
		g.mu.Lock()
		leader := g.leader
		g.mu.Unlock()
		if !leader {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "leader": false, "identity": g.identity})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "leader": true, "identity": g.identity})
		return
	}

	g.mu.Lock()
	if !g.leader || g.handler == nil {
		g.mu.Unlock()
		w.Header().Set("Retry-After", "2")
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "netra controller is a standby replica; retry against the elected leader", "leader": false})
		return
	}
	h := g.handler
	g.wg.Add(1)
	g.mu.Unlock()
	defer g.wg.Done()
	h.ServeHTTP(w, r)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
