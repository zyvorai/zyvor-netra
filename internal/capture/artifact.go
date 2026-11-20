// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package capture

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

const (
	DefaultArtifactDir     = "/var/lib/netra/auto-capture"
	DefaultMaxArtifacts    = 50
	DefaultMaxTotalBytes   = 1 << 30  // 1 GiB
	DefaultMaxSessionBytes = 50 << 20 // 50 MiB per session
	artifactFileSuffix     = ".pcap"
	contextFileSuffix      = ".context.json"
)

// ArtifactMeta describes one finalized auto-capture PCAP on disk.
type ArtifactMeta struct {
	ID             string
	Node           string
	Path           string
	Bytes          int64
	Frames         int64
	TriggerSource  string
	TriggerKind    string
	TriggerSubject string
	StartedAt      time.Time
	EndedAt        time.Time
	// ContextPath is the sibling drop-incident JSON, empty when none was staged.
	ContextPath string
}

// ArtifactStore writes auto-capture PCAPs under Dir and prunes by count/size.
type ArtifactStore struct {
	Dir             string
	MaxArtifacts    int
	MaxTotalBytes   int64
	MaxSessionBytes int64

	mu      sync.Mutex
	active  map[string]*activeRecording // keyed by node
	index   map[string]ArtifactMeta     // keyed by id
	pending map[string]models.DropIncidentContext
}

type activeRecording struct {
	meta   ArtifactMeta
	file   *os.File
	bytes  int64
	frames int64
	header bool
}

// NewArtifactStore prepares Dir and returns a store. Empty Dir disables recording.
func NewArtifactStore(dir string, maxArtifacts int, maxTotal, maxSession int64) (*ArtifactStore, error) {
	if strings.TrimSpace(dir) == "" {
		return &ArtifactStore{active: map[string]*activeRecording{}, index: map[string]ArtifactMeta{}, pending: map[string]models.DropIncidentContext{}}, nil
	}
	if maxArtifacts <= 0 {
		maxArtifacts = DefaultMaxArtifacts
	}
	if maxTotal <= 0 {
		maxTotal = DefaultMaxTotalBytes
	}
	if maxSession <= 0 {
		maxSession = DefaultMaxSessionBytes
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("auto-capture dir: %w", err)
	}
	s := &ArtifactStore{
		Dir:             dir,
		MaxArtifacts:    maxArtifacts,
		MaxTotalBytes:   maxTotal,
		MaxSessionBytes: maxSession,
		active:          map[string]*activeRecording{},
		index:           map[string]ArtifactMeta{},
		pending:         map[string]models.DropIncidentContext{},
	}
	_ = s.scanExisting()
	return s, nil
}

func (s *ArtifactStore) Enabled() bool {
	return s != nil && s.Dir != ""
}

func (s *ArtifactStore) scanExisting() error {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), artifactFileSuffix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		id := strings.TrimSuffix(e.Name(), artifactFileSuffix)
		// Prefer id from filename: {unix}-{node}-{hex}.pcap → use full stem as id
		meta := ArtifactMeta{
			ID:    id,
			Path:  filepath.Join(s.Dir, e.Name()),
			Bytes: info.Size(),
		}
		if cpath := contextPathBeside(meta.Path); cpath != "" {
			if st, err := os.Stat(cpath); err == nil && !st.IsDir() {
				meta.ContextPath = cpath
			}
		}
		s.index[id] = meta
	}
	return nil
}

// Begin opens a PCAP for node. Trigger fields are recorded into the meta.
// If a recording is already active for node, it is finalized first.
func (s *ArtifactStore) Begin(node, triggerSource, triggerKind, triggerSubject string, startedAt time.Time) (string, error) {
	if !s.Enabled() {
		return "", nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.active[node]; ok {
		s.finalizeLocked(node, prev, time.Now().UTC())
	}
	id, err := newArtifactID(node, startedAt)
	if err != nil {
		return "", err
	}
	if !filepath.IsLocal(id) {
		return "", fmt.Errorf("refusing artifact id %q", id)
	}
	path := filepath.Join(s.Dir, id+artifactFileSuffix)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return "", err
	}
	if err := WritePCAPHeader(f); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}
	s.active[node] = &activeRecording{
		meta: ArtifactMeta{
			ID:             id,
			Node:           node,
			Path:           path,
			TriggerSource:  triggerSource,
			TriggerKind:    triggerKind,
			TriggerSubject: triggerSubject,
			StartedAt:      startedAt,
		},
		file:   f,
		bytes:  24, // global header
		header: true,
	}
	s.attachPendingContextLocked(node)
	return id, nil
}

// StageContext keeps ctx until Begin writes {id}.context.json beside the PCAP.
// A later StageContext for the same node replaces the previous one.
func (s *ArtifactStore) StageContext(node string, ctx models.DropIncidentContext) {
	if !s.Enabled() || strings.TrimSpace(node) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		s.pending = map[string]models.DropIncidentContext{}
	}
	s.pending[node] = ctx
}

func (s *ArtifactStore) attachPendingContextLocked(node string) {
	rec := s.active[node]
	if rec == nil {
		return
	}
	ctx, ok := s.pending[node]
	if !ok {
		return
	}
	delete(s.pending, node)
	cpath := contextPathBeside(rec.meta.Path)
	if cpath == "" {
		return
	}
	if err := writeContextFile(cpath, ctx); err != nil {
		return
	}
	rec.meta.ContextPath = cpath
}

// WriteFrame appends one WS capture frame to node's active recording.
func (s *ArtifactStore) WriteFrame(node string, raw []byte) {
	if !s.Enabled() {
		return
	}
	f, err := DecodeFrame(raw)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.active[node]
	if !ok || rec.file == nil {
		return
	}
	if rec.bytes >= s.MaxSessionBytes {
		return
	}
	before := rec.bytes
	if err := WritePCAPRecord(rec.file, f); err != nil {
		return
	}
	// approximate: record header 16 + data
	rec.bytes = before + int64(16+len(f.Data))
	rec.frames++
}

// Finalize closes node's recording and returns its meta (ok=false if none).
func (s *ArtifactStore) Finalize(node string, endedAt time.Time) (ArtifactMeta, bool) {
	if !s.Enabled() {
		return ArtifactMeta{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.active[node]
	if !ok {
		return ArtifactMeta{}, false
	}
	return s.finalizeLocked(node, rec, endedAt), true
}

func (s *ArtifactStore) finalizeLocked(node string, rec *activeRecording, endedAt time.Time) ArtifactMeta {
	delete(s.active, node)
	if rec.file != nil {
		_ = rec.file.Sync()
		_ = rec.file.Close()
		rec.file = nil
	}
	meta := rec.meta
	meta.Bytes = rec.bytes
	meta.Frames = rec.frames
	meta.EndedAt = endedAt
	if meta.Frames == 0 && meta.Bytes <= 24 {
		// Empty capture — drop the file rather than keep a header-only pcap.
		_ = os.Remove(meta.Path)
		removeContext(meta)
		meta.ContextPath = ""
		return meta
	}
	s.index[meta.ID] = meta
	s.pruneLocked()
	return meta
}

// Get returns finalized artifact metadata by id.
func (s *ArtifactStore) Get(id string) (ArtifactMeta, bool) {
	if s == nil {
		return ArtifactMeta{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.index[id]
	return m, ok
}

// Open returns a read-only file handle for a finalized artifact.
func (s *ArtifactStore) Open(id string) (*os.File, ArtifactMeta, error) {
	m, ok := s.Get(id)
	if !ok || m.Path == "" {
		return nil, ArtifactMeta{}, fmt.Errorf("artifact %q not found", id)
	}
	f, err := os.Open(m.Path)
	if err != nil {
		return nil, ArtifactMeta{}, err
	}
	return f, m, nil
}

// OpenContext returns a read-only handle for the drop-incident JSON
// stored beside a finalized PCAP.
func (s *ArtifactStore) OpenContext(id string) (*os.File, ArtifactMeta, error) {
	m, ok := s.Get(id)
	if !ok {
		return nil, ArtifactMeta{}, fmt.Errorf("artifact %q not found", id)
	}
	path := m.ContextPath
	if path == "" {
		path = contextPathBeside(m.Path)
	}
	if path == "" {
		return nil, ArtifactMeta{}, fmt.Errorf("artifact %q has no context", id)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ArtifactMeta{}, err
	}
	m.ContextPath = path
	return f, m, nil
}

func (s *ArtifactStore) pruneLocked() {
	type item struct {
		id    string
		meta  ArtifactMeta
		mtime time.Time
	}
	items := make([]item, 0, len(s.index))
	var total int64
	for id, m := range s.index {
		st, err := os.Stat(m.Path)
		if err != nil {
			removeContext(m)
			delete(s.index, id)
			continue
		}
		total += st.Size()
		items = append(items, item{id: id, meta: m, mtime: st.ModTime()})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].mtime.Before(items[j].mtime) })
	for len(items) > s.MaxArtifacts || total > s.MaxTotalBytes {
		if len(items) == 0 {
			break
		}
		old := items[0]
		items = items[1:]
		_ = os.Remove(old.meta.Path)
		removeContext(old.meta)
		delete(s.index, old.id)
		total -= old.meta.Bytes
	}
}

func newArtifactID(node string, startedAt time.Time) (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, node)
	return fmt.Sprintf("%d-%s-%s", startedAt.UTC().Unix(), safe, hex.EncodeToString(b[:])), nil
}

func contextPathBeside(pcapPath string) string {
	if !strings.HasSuffix(pcapPath, artifactFileSuffix) {
		return ""
	}
	return strings.TrimSuffix(pcapPath, artifactFileSuffix) + contextFileSuffix
}

func writeContextFile(path string, ctx models.DropIncidentContext) error {
	b, err := json.MarshalIndent(ctx, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o640)
}

func removeContext(meta ArtifactMeta) {
	path := meta.ContextPath
	if path == "" {
		path = contextPathBeside(meta.Path)
	}
	if path != "" {
		_ = os.Remove(path)
	}
}

// ParseAutoRequestor extracts trigger source/kind from "auto-capture:source/kind".
func ParseAutoRequestor(requestor string) (source, kind string, ok bool) {
	const prefix = "auto-capture:"
	if !strings.HasPrefix(requestor, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(requestor, prefix)
	i := strings.IndexByte(rest, '/')
	if i <= 0 {
		return rest, "", true
	}
	return rest[:i], rest[i+1:], true
}
