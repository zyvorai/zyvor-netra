// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package snowflakesink

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	sf "github.com/snowflakedb/gosnowflake"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/siem"
)

// Sink batches audit events and loads them into a Snowflake table.
// Best-effort, like internal/siem.Forwarder: a failed flush is logged
// and dropped, never retried from this package — the store still has
// the audit events for a pull export or the syslog forwarder. This
// trades durability for availability rather than risking a slow or
// unreachable warehouse backing up the audit path.
type Sink struct {
	cfg Config
	log *slog.Logger
	db  *sql.DB

	mu      sync.Mutex
	lastAt  time.Time
	started bool
}

// New parses the private key, opens a pooled Snowflake connection, and
// ensures the target table exists. It does not start polling — call
// Run for that.
func New(ctx context.Context, cfg Config, log *slog.Logger) (*Sink, error) {
	return newWithDialTarget(ctx, cfg, log, dialTarget{})
}

// dialTarget overrides the real Snowflake account host with a fake REST
// server, letting tests exercise the actual gosnowflake DSN/JWT/HTTP
// path end to end without a live Snowflake account. The zero value
// (every field empty) means "use the real Snowflake host," exactly as
// gosnowflake itself defaults when sf.Config's Host/Port/Protocol are
// unset — so New (the only production caller) is unaffected.
type dialTarget struct {
	host     string
	port     int
	protocol string
}

func newWithDialTarget(ctx context.Context, cfg Config, log *slog.Logger, dial dialTarget) (*Sink, error) {
	if err := cfg.applyDefaults(); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	key, err := loadPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("snowflakesink: %w", err)
	}
	dsn, err := sf.DSN(&sf.Config{
		Account:       cfg.Account,
		User:          cfg.User,
		Authenticator: sf.AuthTypeJwt,
		PrivateKey:    key,
		Warehouse:     cfg.Warehouse,
		Database:      cfg.Database,
		Schema:        cfg.Schema,
		Host:          dial.host,
		Port:          dial.port,
		Protocol:      dial.protocol,
	})
	if err != nil {
		return nil, fmt.Errorf("snowflakesink: build dsn: %w", err)
	}
	db, err := sql.Open("snowflake", dsn)
	if err != nil {
		return nil, fmt.Errorf("snowflakesink: open: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("snowflakesink: connect: %w", err)
	}
	s := newSink(db, cfg, log)
	if err := s.ensureTable(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("snowflakesink: %w", err)
	}
	return s, nil
}

// newSink wires a Sink around an already-open *sql.DB, skipping key
// parsing, DSN construction, and the connectivity ping. Tests use this
// with a sqlmock DB to exercise batching/watermark logic without a
// real Snowflake account; New is the only other caller.
func newSink(db *sql.DB, cfg Config, log *slog.Logger) *Sink {
	if log == nil {
		log = slog.Default()
	}
	return &Sink{cfg: cfg, log: log, db: db}
}

// Close releases the underlying connection pool.
func (s *Sink) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Sink) ensureTable(ctx context.Context) error {
	ddl := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		at TIMESTAMP_NTZ NOT NULL,
		actor STRING,
		action STRING,
		target STRING,
		message STRING,
		details VARIANT
	)`, s.cfg.Table)
	if _, err := s.db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("create table %s: %w", s.cfg.Table, err)
	}
	// The base table always has exactly the 6 fixed columns above, so
	// this CREATE stays stable and idempotent regardless of config; any
	// operator-configured extra columns are added on top of it here,
	// letting a column added to config after the table already exists
	// widen it in place with no separate migration step.
	for _, ec := range s.cfg.ExtraColumns {
		alter := fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s STRING", s.cfg.Table, ec.Name)
		if _, err := s.db.ExecContext(ctx, alter); err != nil {
			return fmt.Errorf("add column %s.%s: %w", s.cfg.Table, ec.Name, err)
		}
	}
	return nil
}

// maxImmediateRedrainsPerTick bounds how many times Run will call drain
// back-to-back (instead of waiting for the next ticker fire) when a
// drain fully flushes a batch as large as cfg.BatchSize — a signal there
// may be more backlog immediately behind it. This is netra's substitute
// for genuine Snowpipe Streaming: gosnowflake has no Streaming Ingest
// API to build on, so instead of waiting out the rest of interval when
// there's evident backlog, Run drains again right away, bounded so a
// permanently busy audit stream can't turn this into a tight loop.
const maxImmediateRedrainsPerTick = 4

// Run polls fetch() on interval and loads audit events newer than the
// last successful flush, batching up to cfg.BatchSize rows per insert.
// First tick is a catch-up, matching Forwarder.Run.
func (s *Sink) Run(ctx context.Context, interval time.Duration, fetch func() []models.AuditEvent) {
	if s == nil || fetch == nil {
		return
	}
	if interval <= 0 {
		interval = 15 * time.Second
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.mu.Unlock()
	if interval < time.Second {
		s.log.Warn("snowflake interval below recommended floor", "interval", interval, "recommendedMinimum", time.Second)
	}

	drainUntilCaughtUp := func() {
		for i := 0; i < maxImmediateRedrainsPerTick; i++ {
			if !s.drain(ctx, fetch) {
				return
			}
		}
	}

	tick := time.NewTicker(interval)
	defer tick.Stop()
	drainUntilCaughtUp()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			drainUntilCaughtUp()
		}
	}
}

// drain returns true when a full cfg.BatchSize batch of fresh events was
// found and successfully flushed — a signal there may be more backlog
// worth draining immediately, since fetch() (typically st.Audit(200)) is
// a capped snapshot. It returns false otherwise, including after any
// flush error, so a struggling warehouse gets backed off to the normal
// ticker cadence instead of being hammered immediately.
func (s *Sink) drain(ctx context.Context, fetch func() []models.AuditEvent) bool {
	events := fetch()
	if len(events) == 0 {
		return false
	}
	s.mu.Lock()
	cutoff := s.lastAt
	s.mu.Unlock()

	fresh, _ := siem.NewSince(events, cutoff)
	if len(fresh) == 0 {
		return false
	}
	hadFullBatch := len(fresh) >= s.cfg.BatchSize
	succeeded := true
	// Track the newest timestamp actually committed, batch by batch, so
	// a failure partway through still advances the watermark past what
	// landed instead of re-sending already-committed rows next tick.
	var committed time.Time
	for len(fresh) > 0 {
		n := s.cfg.BatchSize
		if n > len(fresh) {
			n = len(fresh)
		}
		batch := fresh[:n]
		fresh = fresh[n:]
		if err := s.flush(ctx, batch); err != nil {
			s.log.Warn("snowflake flush failed", "error", err, "count", len(batch), "table", s.cfg.Table)
			succeeded = false
			break
		}
		for _, e := range batch {
			if e.At.After(committed) {
				committed = e.At
			}
		}
	}
	if !committed.IsZero() {
		s.mu.Lock()
		if committed.After(s.lastAt) {
			s.lastAt = committed
		}
		s.mu.Unlock()
	}
	return hadFullBatch && succeeded
}

func (s *Sink) flush(ctx context.Context, events []models.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	cols := "at, actor, action, target, message, details"
	rowPlaceholder := "?, ?, ?, ?, ?, PARSE_JSON(?)"
	for _, ec := range s.cfg.ExtraColumns {
		cols += ", " + ec.Name
		rowPlaceholder += ", ?"
	}
	placeholders := make([]string, 0, len(events))
	args := make([]any, 0, len(events)*(6+len(s.cfg.ExtraColumns)))
	for _, e := range events {
		details := "{}"
		if len(e.Details) > 0 {
			b, err := json.Marshal(e.Details)
			if err != nil {
				return fmt.Errorf("marshal details: %w", err)
			}
			details = string(b)
		}
		args = append(args, e.At.UTC(), e.Actor, e.Action, e.Target, auditMessage(e), details)
		for _, ec := range s.cfg.ExtraColumns {
			v, err := extraColumnValue(ec, e)
			if err != nil {
				return fmt.Errorf("extra column %s: %w", ec.Name, err)
			}
			args = append(args, v)
		}
		placeholders = append(placeholders, "("+rowPlaceholder+")")
	}
	stmt := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES %s",
		s.cfg.Table, cols, strings.Join(placeholders, ", "),
	)
	_, err := s.db.ExecContext(ctx, stmt, args...)
	return err
}

// extraColumnValue resolves one configured ExtraColumn against one
// event. Extra columns are always STRING-typed by design — non-string
// Details values are JSON-encoded into the string rather than attempting
// type inference, so typed/queryable JSON still goes through the
// existing details VARIANT column; extra columns exist for fast
// equality/ILIKE filtering and joins on one hot key. Source's shape is
// already validated by Config.applyDefaults, so the default branch below
// is unreachable in practice — it returns an error rather than panicking
// only as defense in depth.
func extraColumnValue(ec ExtraColumn, e models.AuditEvent) (any, error) {
	switch {
	case strings.HasPrefix(ec.Source, extraColumnStaticPrefix):
		return strings.TrimPrefix(ec.Source, extraColumnStaticPrefix), nil
	case strings.HasPrefix(ec.Source, extraColumnDetailsPrefix):
		key := strings.TrimPrefix(ec.Source, extraColumnDetailsPrefix)
		v, ok := e.Details[key]
		if !ok || v == nil {
			return nil, nil
		}
		if str, ok := v.(string); ok {
			return str, nil
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		return string(b), nil
	default:
		return nil, fmt.Errorf("unrecognized source %q", ec.Source)
	}
}

// auditMessage mirrors internal/siem's unexported helper of the same
// name (record.go) so Snowflake's message column reads the same as the
// pull export's and syslog forwarder's Record.Message for the same
// event — duplicated rather than imported because that helper isn't
// exported across the package boundary.
func auditMessage(e models.AuditEvent) string {
	if e.Target == "" {
		return e.Action
	}
	return e.Action + " " + e.Target
}

// loadPrivateKey reads an unencrypted PEM-encoded RSA key (PKCS#8 or
// PKCS#1 — Snowflake's own key-pair setup docs generate PKCS#8) for JWT
// authentication.
func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("private key %s: no PEM block found", path)
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key %s: not an RSA key", path)
		}
		return rsaKey, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("private key %s: unsupported format (want unencrypted PKCS#8 or PKCS#1 PEM)", path)
}
