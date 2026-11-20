// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package metricstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/tsdb"
)

var nodeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)

// ErrNodeLimit is returned when a batch arrives from a node beyond MaxNodes.
var ErrNodeLimit = errors.New("metrics node limit reached")

// HubOptions configures the parent store.
type HubOptions struct {
	// Dir holds one tsdb directory per node. Empty keeps everything in memory.
	Dir      string
	DB       tsdb.Options // Dir inside is ignored and set per node
	MaxNodes int          // default 2000
	Log      *slog.Logger
}

// Hub is the parent's set of per-node stores.
type Hub struct {
	opts HubOptions
	mu   sync.RWMutex
	dbs  map[string]*tsdb.DB
	seen map[string]time.Time
	// Annotate, when set, may mark samples anomalous before they are stored.
	Annotate func(node string, samples []tsdb.Sample)
	// OnIngest, when set, runs after each stored batch. It must not block.
	OnIngest func(node string, samples []tsdb.Sample)
}

// NodeInfo describes one node's store.
type NodeInfo struct {
	Node       string     `json:"node"`
	LastIngest time.Time  `json:"lastIngest"`
	Stats      tsdb.Stats `json:"stats"`
}

// OpenHub opens existing node stores under opts.Dir.
func OpenHub(opts HubOptions) (*Hub, error) {
	if opts.MaxNodes <= 0 {
		opts.MaxNodes = 2000
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	h := &Hub{opts: opts, dbs: map[string]*tsdb.DB{}, seen: map[string]time.Time{}}
	if opts.Dir == "" {
		return h, nil
	}
	if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(opts.Dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() || !nodeName.MatchString(e.Name()) {
			continue
		}
		if _, err := h.open(e.Name()); err != nil {
			return nil, fmt.Errorf("open metrics for node %s: %w", e.Name(), err)
		}
	}
	return h, nil
}

func (h *Hub) open(node string) (*tsdb.DB, error) {
	o := h.opts.DB
	o.Dir = ""
	if h.opts.Dir != "" {
		o.Dir = filepath.Join(h.opts.Dir, node)
	}
	db, err := tsdb.Open(o)
	if err != nil {
		return nil, err
	}
	h.dbs[node] = db
	return db, nil
}

func (h *Hub) dbFor(node string) (*tsdb.DB, error) {
	h.mu.RLock()
	db := h.dbs[node]
	h.mu.RUnlock()
	if db != nil {
		return db, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if db = h.dbs[node]; db != nil {
		return db, nil
	}
	if len(h.dbs) >= h.opts.MaxNodes {
		return nil, ErrNodeLimit
	}
	return h.open(node)
}

// ValidNode reports whether node is usable as a store name.
func ValidNode(node string) bool { return nodeName.MatchString(node) && !strings.Contains(node, "..") }

// Ingest stores a batch and returns the node's newest stored second.
func (h *Hub) Ingest(b *Batch) (Response, error) {
	if !ValidNode(b.Node) {
		return Response{}, fmt.Errorf("invalid node name %q", b.Node)
	}
	db, err := h.dbFor(b.Node)
	if err != nil {
		return Response{}, err
	}
	prev := db.LastT()
	if b.From > prev && len(b.Series) > 0 {
		return Response{PrevLastT: prev, LastT: prev, Gap: true}, nil
	}
	samples := b.Samples()
	if h.Annotate != nil {
		h.Annotate(b.Node, samples)
	}
	n, err := db.AppendBatch(samples)
	h.mu.Lock()
	h.seen[b.Node] = time.Now()
	h.mu.Unlock()
	if err != nil && !errors.Is(err, tsdb.ErrSeriesLimit) {
		return Response{}, err
	}
	if n > 0 && h.OnIngest != nil {
		h.OnIngest(b.Node, samples)
	}
	return Response{PrevLastT: prev, LastT: db.LastT(), Stored: n}, nil
}

// ServeHTTP is the ingest endpoint. Callers wrap it in agent authentication.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	b, err := Decode(r.Body, strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	resp, err := h.Ingest(b)
	switch {
	case errors.Is(err, ErrNodeLimit):
		writeErr(w, http.StatusTooManyRequests, err.Error())
		return
	case err != nil:
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// Sources returns every node store for tsdb.Run.
func (h *Hub) Sources() []tsdb.Source {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]tsdb.Source, 0, len(h.dbs))
	for n, db := range h.dbs {
		out = append(out, tsdb.Source{Node: n, DB: db})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

// DB returns one node's store or nil.
func (h *Hub) DB(node string) *tsdb.DB {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.dbs[node]
}

// Nodes lists node stores with their stats.
func (h *Hub) Nodes() []NodeInfo {
	h.mu.RLock()
	type pair struct {
		n  string
		db *tsdb.DB
		t  time.Time
	}
	ps := make([]pair, 0, len(h.dbs))
	for n, db := range h.dbs {
		ps = append(ps, pair{n, db, h.seen[n]})
	}
	h.mu.RUnlock()
	out := make([]NodeInfo, 0, len(ps))
	for _, p := range ps {
		out = append(out, NodeInfo{Node: p.n, LastIngest: p.t, Stats: p.db.Stats()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

// Run maintains every store each interval until ctx ends.
func (h *Hub) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			for _, src := range h.Sources() {
				if err := src.DB.Maintain(now); err != nil {
					h.opts.Log.Warn("metrics maintenance", "node", src.Node, "error", err)
				}
			}
		}
	}
}

// Close flushes and closes every store.
func (h *Hub) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	var errs []error
	for _, db := range h.dbs {
		errs = append(errs, db.Close())
	}
	h.dbs = map[string]*tsdb.DB{}
	return errors.Join(errs...)
}
