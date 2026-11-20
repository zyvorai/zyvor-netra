// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package snowflakesink

import (
	"context"
	"log/slog"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/zyvorai/netra/internal/models"
)

// failOnWarnHandler fails the test if anything Warn-or-above is logged
// — used to prove a code path never attempts (and then swallows the
// error from) an unexpected database call.
type failOnWarnHandler struct{ t *testing.T }

func (h failOnWarnHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h failOnWarnHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		h.t.Errorf("unexpected log at %s: %s", r.Level, r.Message)
	}
	return nil
}
func (h failOnWarnHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h failOnWarnHandler) WithGroup(string) slog.Handler      { return h }

func newTestSink(t *testing.T, cfg Config) (*Sink, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if cfg.Table == "" {
		cfg.Table = "NETRA_AUDIT"
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	return newSink(db, cfg, nil), mock
}

func auditAt(offset time.Duration, base time.Time, actor string) models.AuditEvent {
	return models.AuditEvent{At: base.Add(offset), Actor: actor, Action: "mode.set", Target: "enforce"}
}

// store.Audit returns newest-first; tests build fixtures the same way
// so drain's oldest-first reordering (via siem.NewSince) is exercised.
func newestFirst(events []models.AuditEvent) []models.AuditEvent {
	out := make([]models.AuditEvent, len(events))
	for i, e := range events {
		out[len(events)-1-i] = e
	}
	return out
}

func TestDrainBatchesInConfiguredSizeAndAdvancesWatermark(t *testing.T) {
	base := time.Now().UTC()
	oldestFirst := []models.AuditEvent{
		auditAt(1*time.Second, base, "alice"),
		auditAt(2*time.Second, base, "bob"),
		auditAt(3*time.Second, base, "carol"),
	}
	sink, mock := newTestSink(t, Config{BatchSize: 2})

	mock.ExpectExec("INSERT INTO NETRA_AUDIT").WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec("INSERT INTO NETRA_AUDIT").WillReturnResult(sqlmock.NewResult(0, 1))

	sink.drain(context.Background(), func() []models.AuditEvent { return newestFirst(oldestFirst) })

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
	if got := sink.lastAt; !got.Equal(oldestFirst[2].At) {
		t.Fatalf("lastAt = %v, want %v", got, oldestFirst[2].At)
	}
}

func TestDrainSkipsEventsAtOrBeforeWatermark(t *testing.T) {
	base := time.Now().UTC()
	e1 := auditAt(1*time.Second, base, "alice")
	e2 := auditAt(2*time.Second, base, "bob")
	sink, mock := newTestSink(t, Config{})
	sink.lastAt = e1.At // simulate e1 already committed on a prior tick

	mock.ExpectExec("INSERT INTO NETRA_AUDIT").WithArgs(e2.At, e2.Actor, e2.Action, e2.Target, auditMessage(e2), "{}").
		WillReturnResult(sqlmock.NewResult(0, 1))

	sink.drain(context.Background(), func() []models.AuditEvent { return newestFirst([]models.AuditEvent{e1, e2}) })

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (e1 should not have been re-sent): %v", err)
	}
}

func TestDrainStopsAtFirstFailedBatchButKeepsPriorProgress(t *testing.T) {
	base := time.Now().UTC()
	events := []models.AuditEvent{
		auditAt(1*time.Second, base, "alice"),
		auditAt(2*time.Second, base, "bob"),
		auditAt(3*time.Second, base, "carol"),
	}
	sink, mock := newTestSink(t, Config{BatchSize: 1})

	mock.ExpectExec("INSERT INTO NETRA_AUDIT").WillReturnResult(sqlmock.NewResult(0, 1)) // batch 1: alice, succeeds
	mock.ExpectExec("INSERT INTO NETRA_AUDIT").WillReturnError(context.DeadlineExceeded) // batch 2: bob, fails
	// batch 3 (carol) must never be attempted once batch 2 fails.

	sink.drain(context.Background(), func() []models.AuditEvent { return newestFirst(events) })

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
	if got := sink.lastAt; !got.Equal(events[0].At) {
		t.Fatalf("lastAt = %v, want %v (only the first, successful batch)", got, events[0].At)
	}
}

func TestDrainWithNoNewEventsSkipsFlush(t *testing.T) {
	base := time.Now().UTC()
	e1 := auditAt(1*time.Second, base, "alice")
	sink, mock := newTestSink(t, Config{})
	sink.lastAt = e1.At
	sink.log = slog.New(failOnWarnHandler{t: t})

	// No mock.ExpectExec set up at all — an unexpected Exec call would
	// surface as a flush error, which would log a Warn and fail the test.
	sink.drain(context.Background(), func() []models.AuditEvent { return []models.AuditEvent{e1} })

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestEnsureTableAddsConfiguredExtraColumnsViaAlterTable(t *testing.T) {
	sink, mock := newTestSink(t, Config{ExtraColumns: []ExtraColumn{
		{Name: "REASON", Source: "details:reason"},
		{Name: "ENVIRONMENT", Source: "static:prod"},
	}})

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS NETRA_AUDIT").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("ALTER TABLE NETRA_AUDIT ADD COLUMN IF NOT EXISTS REASON STRING").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("ALTER TABLE NETRA_AUDIT ADD COLUMN IF NOT EXISTS ENVIRONMENT STRING").WillReturnResult(sqlmock.NewResult(0, 0))

	if err := sink.ensureTable(context.Background()); err != nil {
		t.Fatalf("ensureTable: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestFlushIncludesConfiguredExtraColumnsFromDetailsAndStatic(t *testing.T) {
	base := time.Now().UTC()
	e := models.AuditEvent{At: base, Actor: "alice", Action: "mode.set", Target: "enforce", Details: map[string]any{"reason": "drift"}}
	sink, mock := newTestSink(t, Config{ExtraColumns: []ExtraColumn{
		{Name: "REASON", Source: "details:reason"},
		{Name: "ENV", Source: "static:prod"},
	}})

	mock.ExpectExec("INSERT INTO NETRA_AUDIT").
		WithArgs(e.At, e.Actor, e.Action, e.Target, auditMessage(e), `{"reason":"drift"}`, "drift", "prod").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := sink.flush(context.Background(), []models.AuditEvent{e}); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestFlushExtraColumnDetailsKeyMissingBindsNull(t *testing.T) {
	base := time.Now().UTC()
	e := models.AuditEvent{At: base, Actor: "alice", Action: "mode.set"}
	sink, mock := newTestSink(t, Config{ExtraColumns: []ExtraColumn{{Name: "REASON", Source: "details:reason"}}})

	mock.ExpectExec("INSERT INTO NETRA_AUDIT").
		WithArgs(e.At, e.Actor, e.Action, e.Target, auditMessage(e), "{}", nil).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := sink.flush(context.Background(), []models.AuditEvent{e}); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestFlushExtraColumnNonStringDetailsValueIsJSONEncoded(t *testing.T) {
	base := time.Now().UTC()
	e := models.AuditEvent{At: base, Actor: "alice", Action: "mode.set", Details: map[string]any{"count": 3}}
	sink, mock := newTestSink(t, Config{ExtraColumns: []ExtraColumn{{Name: "COUNT", Source: "details:count"}}})

	mock.ExpectExec("INSERT INTO NETRA_AUDIT").
		WithArgs(e.At, e.Actor, e.Action, e.Target, auditMessage(e), `{"count":3}`, "3").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := sink.flush(context.Background(), []models.AuditEvent{e}); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestParseExtraColumnsValidatesShapeAndRejectsBadSources(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    []ExtraColumn
		wantErr bool
	}{
		{"empty", "", nil, false},
		{"single details", "REASON=details:reason", []ExtraColumn{{Name: "REASON", Source: "details:reason"}}, false},
		{"single static", "ENV=static:prod", []ExtraColumn{{Name: "ENV", Source: "static:prod"}}, false},
		{"multiple", "REASON=details:reason,ENV=static:prod", []ExtraColumn{{Name: "REASON", Source: "details:reason"}, {Name: "ENV", Source: "static:prod"}}, false},
		{"missing equals", "REASON", nil, true},
		{"empty name", "=details:reason", nil, true},
		{"empty source", "REASON=", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseExtraColumns(tc.raw)
			if tc.wantErr != (err != nil) {
				t.Fatalf("ParseExtraColumns(%q) err = %v, wantErr %v", tc.raw, err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ParseExtraColumns(%q) = %+v, want %+v", tc.raw, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("ParseExtraColumns(%q)[%d] = %+v, want %+v", tc.raw, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestConfigApplyDefaultsRejectsReservedOrDuplicateExtraColumnNames(t *testing.T) {
	base := func() Config {
		return Config{Account: "acct", User: "u", PrivateKeyPath: "/tmp/key", Warehouse: "wh", Database: "db", Schema: "sch"}
	}
	cases := []struct {
		name string
		cols []ExtraColumn
	}{
		{"reserved name", []ExtraColumn{{Name: "ACTOR", Source: "static:x"}}},
		{"duplicate name", []ExtraColumn{{Name: "REASON", Source: "details:a"}, {Name: "REASON", Source: "details:b"}}},
		{"invalid identifier", []ExtraColumn{{Name: "1BAD", Source: "details:a"}}},
		{"unknown source prefix", []ExtraColumn{{Name: "REASON", Source: "env:a"}}},
		{"empty details key", []ExtraColumn{{Name: "REASON", Source: "details:"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			cfg.ExtraColumns = tc.cols
			if err := cfg.applyDefaults(); err == nil {
				t.Fatalf("applyDefaults() with %+v: want error, got nil", tc.cols)
			}
		})
	}
}

func TestDrainReturnsTrueOnlyAfterFullSuccessfulBatch(t *testing.T) {
	base := time.Now().UTC()

	t.Run("full batch succeeds", func(t *testing.T) {
		events := []models.AuditEvent{auditAt(1*time.Second, base, "alice"), auditAt(2*time.Second, base, "bob")}
		sink, mock := newTestSink(t, Config{BatchSize: 1})
		mock.ExpectExec("INSERT INTO NETRA_AUDIT").WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec("INSERT INTO NETRA_AUDIT").WillReturnResult(sqlmock.NewResult(0, 1))

		if got := sink.drain(context.Background(), func() []models.AuditEvent { return newestFirst(events) }); !got {
			t.Fatalf("drain() = false, want true (a full batch flushed successfully)")
		}
	})

	t.Run("partial batch", func(t *testing.T) {
		events := []models.AuditEvent{auditAt(1*time.Second, base, "alice")}
		sink, mock := newTestSink(t, Config{BatchSize: 5})
		mock.ExpectExec("INSERT INTO NETRA_AUDIT").WillReturnResult(sqlmock.NewResult(0, 1))

		if got := sink.drain(context.Background(), func() []models.AuditEvent { return newestFirst(events) }); got {
			t.Fatalf("drain() = true, want false (fewer events than BatchSize)")
		}
	})
}

func TestDrainReturnsFalseAfterFlushError(t *testing.T) {
	base := time.Now().UTC()
	events := []models.AuditEvent{
		auditAt(1*time.Second, base, "alice"),
		auditAt(2*time.Second, base, "bob"),
	}
	sink, mock := newTestSink(t, Config{BatchSize: 1})
	mock.ExpectExec("INSERT INTO NETRA_AUDIT").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO NETRA_AUDIT").WillReturnError(context.DeadlineExceeded)

	if got := sink.drain(context.Background(), func() []models.AuditEvent { return newestFirst(events) }); got {
		t.Fatalf("drain() = true, want false (second batch failed, so Run must not tight-loop-retry)")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRunRedrainsImmediatelyWithoutWaitingForNextTick(t *testing.T) {
	sink, mock := newTestSink(t, Config{BatchSize: 1})
	base := time.Now().UTC()
	events := []models.AuditEvent{
		auditAt(1*time.Second, base, "alice"),
		auditAt(2*time.Second, base, "bob"),
		auditAt(3*time.Second, base, "carol"),
	}
	for range events {
		mock.ExpectExec("INSERT INTO NETRA_AUDIT").WillReturnResult(sqlmock.NewResult(0, 1))
	}

	var calls int
	fetch := func() []models.AuditEvent {
		calls++
		if calls == 1 {
			return newestFirst(events)
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	sink.Run(ctx, 5*time.Second, fetch)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (redrain should have delivered all 3 events well before the 5s ticker fired): %v", err)
	}
}

func TestRunLogsWarnWhenIntervalBelowRecommendedFloor(t *testing.T) {
	sink, _ := newTestSink(t, Config{})
	var records []slog.Record
	sink.log = slog.New(&recordingHandler{records: &records})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	sink.Run(ctx, 100*time.Millisecond, func() []models.AuditEvent { return nil })

	var warns int
	for _, r := range records {
		if r.Level == slog.LevelWarn && r.Message == "snowflake interval below recommended floor" {
			warns++
		}
	}
	if warns != 1 {
		t.Fatalf("got %d 'interval below recommended floor' warnings, want exactly 1", warns)
	}
}

// recordingHandler captures every log record for later assertions.
type recordingHandler struct{ records *[]slog.Record }

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	*h.records = append(*h.records, r)
	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func TestAuditMessage(t *testing.T) {
	cases := []struct {
		name string
		e    models.AuditEvent
		want string
	}{
		{"with target", models.AuditEvent{Action: "mode.set", Target: "enforce"}, "mode.set enforce"},
		{"without target", models.AuditEvent{Action: "lease.renew"}, "lease.renew"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := auditMessage(tc.e); got != tc.want {
				t.Fatalf("auditMessage(%+v) = %q, want %q", tc.e, got, tc.want)
			}
		})
	}
}
