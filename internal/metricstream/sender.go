// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package metricstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/tsdb"
)

// Sender streams an agent's DB to the parent.
type Sender struct {
	DB     *tsdb.DB
	Server string // base URL, no trailing slash
	Node   string
	Key    string // X-Netra-Agent-Key
	Client *http.Client
	Log    *slog.Logger
	// MaxPoints bounds one POST, default 150000. A batch always spans at
	// least one second; while catching up it spans MaxPoints/series seconds,
	// so per-series metadata is sent once for several seconds of points.
	// Keep it well inside MaxDecoded.
	MaxPoints int
	// CatchUp is the number of extra POSTs per tick while replaying a
	// backlog, default 5.
	CatchUp int

	mu     sync.Mutex
	cursor int64
	synced bool
	st     SenderStatus
}

// SenderStatus is exported for diagnostics.
type SenderStatus struct {
	Cursor     int64     `json:"cursor"`
	Sent       uint64    `json:"sentBatches"`
	Points     uint64    `json:"sentPoints"`
	Failures   uint64    `json:"failures"`
	Replays    uint64    `json:"replays"`
	LastError  string    `json:"lastError,omitempty"`
	LastSentAt time.Time `json:"lastSentAt"`
}

// Status returns a snapshot of the sender's state.
func (s *Sender) Status() SenderStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.st
	st.Cursor = s.cursor
	return st
}

// Run streams once per second until ctx ends.
func (s *Sender) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			catch := s.CatchUp
			if catch <= 0 {
				catch = 5
			}
			for i := 0; i <= catch; i++ {
				more, err := s.Once(ctx)
				if err != nil {
					if s.Log != nil && ctx.Err() == nil {
						s.Log.Debug("metrics stream", "error", err)
					}
					break
				}
				if !more {
					break
				}
			}
		}
	}
}

// Once sends one batch. more reports that a backlog remains.
func (s *Sender) Once(ctx context.Context) (more bool, err error) {
	s.mu.Lock()
	cursor, synced := s.cursor, s.synced
	s.mu.Unlock()
	maxPts := s.MaxPoints
	if maxPts <= 0 {
		maxPts = 150000
	}
	b := &Batch{Node: s.Node, From: cursor, To: cursor}
	var npts int
	if synced {
		sp, to := s.DB.Since(cursor, maxPts)
		b.Series, b.To = FromSeriesPoints(sp), to
		for _, ws := range b.Series {
			npts += len(ws.Points)
		}
		if to == cursor {
			return false, nil
		}
	}
	resp, err := s.post(ctx, b)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.st.Failures++
		s.st.LastError = err.Error()
		return false, err
	}
	s.st.LastError = ""
	if !synced {
		// First contact: resume after whatever the parent already holds.
		s.cursor, s.synced = resp.LastT, true
		return true, nil
	}
	if resp.Gap {
		// The parent is missing seconds before this batch (it restarted
		// with an empty store): replay from what it has.
		s.cursor = resp.PrevLastT
		s.st.Replays++
		return true, nil
	}
	s.st.Sent++
	s.st.Points += uint64(npts)
	s.st.LastSentAt = time.Now()
	s.cursor = b.To
	return s.DB.LastT() > b.To, nil
}

func (s *Sender) post(ctx context.Context, b *Batch) (Response, error) {
	body, err := Encode(b)
	if err != nil {
		return Response{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Server+Path, bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	if s.Key != "" {
		req.Header.Set("X-Netra-Agent-Key", s.Key)
	}
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	res, err := client.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 {
		return Response{}, fmt.Errorf("metrics ingest: %s %s", res.Status, bytes.TrimSpace(raw))
	}
	var out Response
	if err := json.Unmarshal(raw, &out); err != nil {
		return Response{}, fmt.Errorf("metrics ingest response: %w", err)
	}
	return out, nil
}
