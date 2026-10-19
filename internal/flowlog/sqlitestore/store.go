// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package sqlitestore is an optional indexed backend for flowlog deltas.
// It uses modernc.org/sqlite (pure Go, no CGO). Observe-only: no payloads.
package sqlitestore

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/flowlog"
	_ "modernc.org/sqlite"
)

// Store implements flowlog.Backend with incremental SQLite writes.
type Store struct {
	mu       sync.Mutex
	db       *sql.DB
	path     string
	retain   time.Duration
	max      int
	maxBytes int64
	count    int
}

// Open creates or opens a WAL SQLite database at path.
func Open(path string, opts flowlog.Options) (*Store, error) {
	opts = opts.Normalize()
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("sqlite flow path is empty")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, path: path, retain: opts.Retain, max: opts.Max, maxBytes: opts.MaxBytes}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.refreshCount(); err != nil {
		_ = db.Close()
		return nil, err
	}
	_ = s.prune(time.Now().UTC())
	return s, nil
}

func (s *Store) migrate() error {
	stmts := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA synchronous=NORMAL`,
		`CREATE TABLE IF NOT EXISTS flows (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			observed_at INTEGER NOT NULL,
			node TEXT,
			namespace TEXT,
			pod TEXT,
			workload_kind TEXT,
			workload_name TEXT,
			peer TEXT NOT NULL,
			port INTEGER NOT NULL,
			protocol TEXT,
			direction TEXT,
			app_protocol TEXT,
			packets INTEGER,
			bytes INTEGER,
			blocked INTEGER,
			retrans INTEGER,
			rtos INTEGER,
			srtt_us INTEGER,
			pid INTEGER,
			comm TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_flows_observed ON flows(observed_at)`,
		`CREATE INDEX IF NOT EXISTS idx_flows_ns_pod ON flows(namespace, pod, observed_at)`,
		`CREATE INDEX IF NOT EXISTS idx_flows_peer ON flows(peer, port, observed_at)`,
		`CREATE INDEX IF NOT EXISTS idx_flows_node ON flows(node, observed_at)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("sqlite migrate: %w", err)
		}
	}
	return nil
}

func (s *Store) refreshCount() error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM flows`).Scan(&n); err != nil {
		return err
	}
	s.count = n
	return nil
}

// ImportJSON loads a legacy `<state>.flows` sidecar once, then renames it to `.migrated`.
func (s *Store) ImportJSON(jsonPath string) error {
	if s == nil || jsonPath == "" {
		return nil
	}
	b, err := os.ReadFile(jsonPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var disk struct {
		Version int              `json:"version"`
		Records []flowlog.Record `json:"records"`
	}
	if err := json.Unmarshal(b, &disk); err != nil {
		return err
	}
	if len(disk.Records) > 0 {
		if err := s.Append(disk.Records); err != nil {
			return err
		}
	}
	return os.Rename(jsonPath, jsonPath+".migrated")
}

func (s *Store) Append(recs []flowlog.Record) error {
	if s == nil || len(recs) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO flows (
		observed_at, node, namespace, pod, workload_kind, workload_name,
		peer, port, protocol, direction, app_protocol,
		packets, bytes, blocked, retrans, rtos, srtt_us, pid, comm
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range recs {
		_, err := stmt.Exec(
			r.ObservedAt.UTC().UnixNano(),
			r.Node, r.Namespace, r.Pod, r.WorkloadKind, r.WorkloadName,
			r.Peer, int(r.Port), r.Protocol, r.Direction, r.AppProtocol,
			r.Packets, r.Bytes, r.Blocked, r.Retrans, r.RTOs, r.SRTTUS, r.PID, r.Comm,
		)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		s.count++
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.prune(time.Now().UTC())
}

func (s *Store) prune(now time.Time) error {
	cut := now.Add(-s.retain).UTC().UnixNano()
	if _, err := s.db.Exec(`DELETE FROM flows WHERE observed_at < ?`, cut); err != nil {
		return err
	}
	if s.max > 0 {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM flows`).Scan(&n); err != nil {
			return err
		}
		if n > s.max {
			drop := n - s.max
			if _, err := s.db.Exec(`DELETE FROM flows WHERE id IN (SELECT id FROM flows ORDER BY observed_at ASC, id ASC LIMIT ?)`, drop); err != nil {
				return err
			}
		}
	}
	if s.maxBytes > 0 {
		pruned := false
		for {
			size, err := s.dbFileBytes()
			if err != nil || size <= s.maxBytes {
				break
			}
			var n int
			_ = s.db.QueryRow(`SELECT COUNT(*) FROM flows`).Scan(&n)
			if n == 0 {
				break
			}
			drop := n / 10
			if drop < 1 {
				drop = 1
			}
			if _, err := s.db.Exec(`DELETE FROM flows WHERE id IN (SELECT id FROM flows ORDER BY observed_at ASC, id ASC LIMIT ?)`, drop); err != nil {
				return err
			}
			pruned = true
		}
		if pruned {
			// Reclaim pages after a byte-budget prune. Ignore errors: retention
			// already dropped rows; a failed vacuum only leaves file headroom.
			_, _ = s.db.Exec(`VACUUM`)
		}
	}
	return s.refreshCount()
}

func (s *Store) Query(q flowlog.Query) flowlog.Result {
	res := flowlog.Result{Records: []flowlog.Record{}, Limitations: s.Limitations()}
	if s == nil {
		return res
	}
	if q.Limit <= 0 {
		q.Limit = 200
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.prune(time.Now().UTC())

	var where []string
	var args []any
	if !q.Since.IsZero() {
		where = append(where, "observed_at >= ?")
		args = append(args, q.Since.UTC().UnixNano())
	}
	if !q.Until.IsZero() {
		where = append(where, "observed_at <= ?")
		args = append(args, q.Until.UTC().UnixNano())
	}
	if q.Node != "" {
		where = append(where, "node = ?")
		args = append(args, q.Node)
	}
	if q.Namespace != "" {
		where = append(where, "namespace = ?")
		args = append(args, q.Namespace)
	}
	if q.Pod != "" {
		where = append(where, "pod = ?")
		args = append(args, q.Pod)
	}
	if q.Peer != "" {
		where = append(where, "peer = ?")
		args = append(args, q.Peer)
	}
	if q.Protocol != "" {
		where = append(where, "LOWER(protocol) = LOWER(?)")
		args = append(args, q.Protocol)
	}
	if q.AppProtocol != "" {
		where = append(where, "LOWER(app_protocol) = LOWER(?)")
		args = append(args, q.AppProtocol)
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	countQ := "SELECT COUNT(*) FROM flows" + clause
	var matched int
	if err := s.db.QueryRow(countQ, args...).Scan(&matched); err != nil {
		return res
	}
	res.Matched = matched
	res.Truncated = matched > q.Limit

	selectQ := `SELECT observed_at, node, namespace, pod, workload_kind, workload_name,
		peer, port, protocol, direction, app_protocol,
		packets, bytes, blocked, retrans, rtos, srtt_us, pid, comm
		FROM flows` + clause + ` ORDER BY observed_at DESC, id DESC LIMIT ?`
	args = append(args, q.Limit)
	rows, err := s.db.Query(selectQ, args...)
	if err != nil {
		return res
	}
	defer rows.Close()
	for rows.Next() {
		var rec flowlog.Record
		var ts int64
		var port int
		var pid int64
		if err := rows.Scan(
			&ts, &rec.Node, &rec.Namespace, &rec.Pod, &rec.WorkloadKind, &rec.WorkloadName,
			&rec.Peer, &port, &rec.Protocol, &rec.Direction, &rec.AppProtocol,
			&rec.Packets, &rec.Bytes, &rec.Blocked, &rec.Retrans, &rec.RTOs, &rec.SRTTUS, &pid, &rec.Comm,
		); err != nil {
			continue
		}
		rec.ObservedAt = time.Unix(0, ts).UTC()
		rec.Port = uint16(port)
		rec.PID = uint32(pid)
		res.Records = append(res.Records, rec)
	}
	return res
}

func (s *Store) Limitations() []string {
	if s == nil {
		return flowlog.SQLiteLimitations(flowlog.DefaultRetain, flowlog.DefaultMax, 0)
	}
	return flowlog.SQLiteLimitations(s.retain, s.max, s.maxBytes)
}

func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

func (s *Store) dbFileBytes() (int64, error) {
	var pages, pageSize int64
	if err := s.db.QueryRow(`PRAGMA page_count`).Scan(&pages); err != nil {
		return 0, err
	}
	if err := s.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		return 0, err
	}
	return pages * pageSize, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.db.Close()
	s.db = nil
	return err
}
