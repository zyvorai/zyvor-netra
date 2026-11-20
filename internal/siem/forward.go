// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package siem

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// ForwardConfig is the optional syslog/CEF/JSONL push sink. Off unless
// Addr is set. Network is udp (default) or tcp. Format is syslog
// (default), cef, or jsonl.
type ForwardConfig struct {
	Network string
	Addr    string
	Format  string
	Timeout time.Duration
}

func (c *ForwardConfig) applyDefaults() error {
	c.Network = strings.ToLower(strings.TrimSpace(c.Network))
	if c.Network == "" {
		c.Network = "udp"
	}
	if c.Network != "udp" && c.Network != "tcp" {
		return fmt.Errorf("syslog network must be udp or tcp")
	}
	c.Addr = strings.TrimSpace(c.Addr)
	if c.Addr == "" {
		return fmt.Errorf("syslog addr is required")
	}
	f, err := NormalizeFormat(c.Format)
	if err != nil {
		return err
	}
	if f == FormatJSON || f == FormatOTLP {
		// Line-oriented sinks cannot take a wrapped JSON document.
		f = FormatSyslog
	}
	c.Format = f
	if c.Timeout <= 0 {
		c.Timeout = 3 * time.Second
	}
	return nil
}

// Forwarder dials Addr per batch (no long-lived connection) so a
// collector restart does not require bouncing netrad. Best-effort:
// a full send failure is logged and dropped, never retried from this
// package — the store still has the audit events for a pull export.
type Forwarder struct {
	cfg ForwardConfig
	log *slog.Logger
	now func() time.Time

	mu      sync.Mutex
	lastAt  time.Time
	started bool
}

func NewForwarder(cfg ForwardConfig, log *slog.Logger) (*Forwarder, error) {
	if err := cfg.applyDefaults(); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	return &Forwarder{cfg: cfg, log: log, now: time.Now}, nil
}

// Send encodes records and writes them to the collector.
func (f *Forwarder) Send(records []Record) error {
	if f == nil || len(records) == 0 {
		return nil
	}
	body, err := Encode(f.cfg.Format, records)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	d := net.Dialer{Timeout: f.cfg.Timeout}
	conn, err := d.Dial(f.cfg.Network, f.cfg.Addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(f.cfg.Timeout))
	_, err = conn.Write(body)
	return err
}

// Run polls fetch() on interval and forwards audit events newer than the
// last successful send. First tick is a catch-up of at most 100 events.
func (f *Forwarder) Run(ctx context.Context, interval time.Duration, fetch func() []models.AuditEvent) {
	if f == nil || fetch == nil {
		return
	}
	if interval <= 0 {
		interval = 15 * time.Second
	}
	f.mu.Lock()
	if f.started {
		f.mu.Unlock()
		return
	}
	f.started = true
	f.mu.Unlock()

	tick := time.NewTicker(interval)
	defer tick.Stop()
	f.drain(fetch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			f.drain(fetch)
		}
	}
}

func (f *Forwarder) drain(fetch func() []models.AuditEvent) {
	events := fetch()
	if len(events) == 0 {
		return
	}
	f.mu.Lock()
	cutoff := f.lastAt
	f.mu.Unlock()

	fresh, newest := NewSince(events, cutoff)
	if len(fresh) == 0 {
		return
	}
	recs := make([]Record, len(fresh))
	for i, e := range fresh {
		recs[i] = FromAudit(e)
	}
	if err := f.Send(recs); err != nil {
		f.log.Warn("syslog forward failed", "error", err, "count", len(recs), "addr", f.cfg.Addr)
		return
	}
	if !newest.IsZero() {
		f.mu.Lock()
		if newest.After(f.lastAt) {
			f.lastAt = newest
		}
		f.mu.Unlock()
	}
}

// NewSince filters a newest-first audit event snapshot (as returned by
// store.Audit) down to events strictly after cutoff, returning them
// oldest-first alongside the newest timestamp seen — so a caller can
// advance its own watermark monotonically even on a partial send. A
// zero cutoff means "everything" (first-tick catch-up). Shared between
// Forwarder and any other push sink (e.g. internal/snowflakesink) so
// every consumer of the audit stream agrees on what "new" means.
func NewSince(events []models.AuditEvent, cutoff time.Time) (fresh []models.AuditEvent, newest time.Time) {
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if e.At.IsZero() {
			continue
		}
		if !cutoff.IsZero() && !e.At.After(cutoff) {
			continue
		}
		fresh = append(fresh, e)
		if e.At.After(newest) {
			newest = e.At
		}
	}
	return fresh, newest
}

// Configured reports whether a forwarder would start from env-style fields.
func (c ForwardConfig) Enabled() bool {
	return strings.TrimSpace(c.Addr) != ""
}
