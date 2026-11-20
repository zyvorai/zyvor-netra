// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package snowflakesink

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// SysctlConfig configures the sysctl-audit findings export table.
type SysctlConfig struct {
	Table     string
	BatchSize int
}

func (c *SysctlConfig) applyDefaults() error {
	c.Table = strings.ToUpper(strings.TrimSpace(c.Table))
	if c.Table == "" {
		c.Table = "NETRA_SYSCTL_AUDIT"
	}
	if !isValidIdentifier(c.Table) {
		return fmt.Errorf("snowflake sysctl table %q is not a valid unquoted identifier", c.Table)
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 50
	}
	return nil
}

// SysctlSink exports the FULL current sysctl-audit findings snapshot on
// every tick, stamped with a single time.Now() per tick as the
// observation timestamp. Unlike Sink, it carries no watermark: sysctl
// findings have no timestamp of their own (models.SysctlAuditFinding has
// none) and sysctlaudit.Build recomputes the entire current cluster
// state from scratch on every call — there is no "new since last tick"
// concept for current-state data, so this deliberately does not reuse
// siem.NewSince/Sink's watermark machinery. Every tick re-exports
// everything; a Snowflake-side dedup view (see docs/snowflake-export.md)
// collapses to latest-per-key for consumers who want current-state-only,
// the same way NETRA_AUDIT_DEDUP does for the audit table. Shares its
// parent Sink's *sql.DB — does not own it and never closes it.
type SysctlSink struct {
	cfg SysctlConfig
	log *slog.Logger
	db  *sql.DB

	mu      sync.Mutex
	started bool
}

// NewSysctlSink builds a second export target that writes sysctl-audit
// findings snapshots into their own table, reusing this Sink's
// already-open *sql.DB connection pool rather than dialing Snowflake a
// second time. Call only after New has already succeeded for the parent
// Sink.
func (s *Sink) NewSysctlSink(ctx context.Context, cfg SysctlConfig) (*SysctlSink, error) {
	if err := cfg.applyDefaults(); err != nil {
		return nil, err
	}
	log := s.log
	if log == nil {
		log = slog.Default()
	}
	ss := &SysctlSink{cfg: cfg, log: log, db: s.db}
	if err := ss.ensureTable(ctx); err != nil {
		return nil, fmt.Errorf("snowflakesink: sysctl: %w", err)
	}
	return ss, nil
}

func (ss *SysctlSink) ensureTable(ctx context.Context) error {
	ddl := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		at             TIMESTAMP_NTZ NOT NULL,
		node           STRING,
		severity       STRING,
		category       STRING,
		name           STRING,
		interface      STRING,
		current_value  STRING,
		expected_value STRING,
		rationale      STRING,
		informational  BOOLEAN
	)`, ss.cfg.Table)
	if _, err := ss.db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("create table %s: %w", ss.cfg.Table, err)
	}
	return nil
}

// Run polls fetch() on interval and re-exports the full current findings
// snapshot every tick — no watermark, no "fresh since last time" filter.
// First tick is an immediate catch-up, matching Sink.Run.
func (ss *SysctlSink) Run(ctx context.Context, interval time.Duration, fetch func() models.SysctlAuditResponse) {
	if ss == nil || fetch == nil {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ss.mu.Lock()
	if ss.started {
		ss.mu.Unlock()
		return
	}
	ss.started = true
	ss.mu.Unlock()

	tick := time.NewTicker(interval)
	defer tick.Stop()
	ss.drain(ctx, fetch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			ss.drain(ctx, fetch)
		}
	}
}

type sysctlRow struct {
	at      time.Time
	node    string
	finding models.SysctlAuditFinding
}

// flattenSysctlFindings stamps every row from one fetch() call with the
// same observation instant, so a single export tick reads as one
// consistent snapshot in Snowflake rather than a smear of timestamps
// across whatever wall-clock time each row happened to be flushed at.
func flattenSysctlFindings(resp models.SysctlAuditResponse, at time.Time) []sysctlRow {
	var rows []sysctlRow
	for _, n := range resp.Nodes {
		for _, f := range n.Findings {
			rows = append(rows, sysctlRow{at: at, node: n.Node, finding: f})
		}
	}
	return rows
}

func (ss *SysctlSink) drain(ctx context.Context, fetch func() models.SysctlAuditResponse) {
	rows := flattenSysctlFindings(fetch(), time.Now().UTC())
	if len(rows) == 0 {
		return
	}
	for len(rows) > 0 {
		n := ss.cfg.BatchSize
		if n > len(rows) {
			n = len(rows)
		}
		batch := rows[:n]
		rows = rows[n:]
		if err := ss.flush(ctx, batch); err != nil {
			ss.log.Warn("snowflake sysctl flush failed", "error", err, "count", len(batch), "table", ss.cfg.Table)
			// No watermark to preserve here on purpose: every tick
			// re-exports the full current snapshot, so a batch dropped
			// mid-tick is not permanently lost — it reappears on the
			// very next successful tick along with everything else.
			break
		}
	}
}

func (ss *SysctlSink) flush(ctx context.Context, rows []sysctlRow) error {
	if len(rows) == 0 {
		return nil
	}
	placeholders := make([]string, 0, len(rows))
	args := make([]any, 0, len(rows)*10)
	for _, r := range rows {
		f := r.finding
		placeholders = append(placeholders, "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
		args = append(args, r.at, r.node, f.Severity, f.Category, f.Name, f.Interface, f.CurrentValue, f.ExpectedValue, f.Rationale, f.Informational)
	}
	stmt := fmt.Sprintf(
		"INSERT INTO %s (at, node, severity, category, name, interface, current_value, expected_value, rationale, informational) VALUES %s",
		ss.cfg.Table, strings.Join(placeholders, ", "),
	)
	_, err := ss.db.ExecContext(ctx, stmt, args...)
	return err
}
