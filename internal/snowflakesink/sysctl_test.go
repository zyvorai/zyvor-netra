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

func newTestSysctlSink(t *testing.T, cfg SysctlConfig) (*SysctlSink, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if cfg.Table == "" {
		cfg.Table = "NETRA_SYSCTL_AUDIT"
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	return &SysctlSink{cfg: cfg, log: slog.Default(), db: db}, mock
}

func finding(name, node string) (models.SysctlAuditFinding, string) {
	return models.SysctlAuditFinding{
		Severity:      "warning",
		Category:      "network",
		Name:          name,
		Interface:     "eth0",
		CurrentValue:  "1",
		ExpectedValue: "0",
		Rationale:     "test",
	}, node
}

func TestSysctlEnsureTableCreatesExpectedDDL(t *testing.T) {
	sink, mock := newTestSysctlSink(t, SysctlConfig{})
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS NETRA_SYSCTL_AUDIT").WillReturnResult(sqlmock.NewResult(0, 0))

	if err := sink.ensureTable(context.Background()); err != nil {
		t.Fatalf("ensureTable: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestFlattenSysctlFindingsStampsSingleTimestampAcrossAllRows(t *testing.T) {
	f1, n1 := finding("net.ipv4.ip_forward", "node-a")
	f2, _ := finding("net.ipv4.tcp_syncookies", "node-a")
	f3, n3 := finding("net.ipv6.conf.all.disable_ipv6", "node-b")
	resp := models.SysctlAuditResponse{Nodes: []models.NodeSysctlAudit{
		{Node: n1, Findings: []models.SysctlAuditFinding{f1, f2}},
		{Node: n3, Findings: []models.SysctlAuditFinding{f3}},
	}}
	at := time.Now().UTC()

	rows := flattenSysctlFindings(resp, at)
	if len(rows) != 3 {
		t.Fatalf("len(rows) = %d, want 3", len(rows))
	}
	for _, r := range rows {
		if !r.at.Equal(at) {
			t.Fatalf("row.at = %v, want %v (every row from one fetch must share one observation instant)", r.at, at)
		}
	}
}

func TestSysctlDrainInsertsOneRowPerFindingAcrossNodes(t *testing.T) {
	f1, n1 := finding("net.ipv4.ip_forward", "node-a")
	f2, n2 := finding("net.ipv6.conf.all.disable_ipv6", "node-b")
	resp := models.SysctlAuditResponse{Nodes: []models.NodeSysctlAudit{
		{Node: n1, Findings: []models.SysctlAuditFinding{f1}},
		{Node: n2, Findings: []models.SysctlAuditFinding{f2}},
	}}
	sink, mock := newTestSysctlSink(t, SysctlConfig{BatchSize: 50})

	mock.ExpectExec("INSERT INTO NETRA_SYSCTL_AUDIT").
		WithArgs(sqlmock.AnyArg(), n1, f1.Severity, f1.Category, f1.Name, f1.Interface, f1.CurrentValue, f1.ExpectedValue, f1.Rationale, f1.Informational,
			sqlmock.AnyArg(), n2, f2.Severity, f2.Category, f2.Name, f2.Interface, f2.CurrentValue, f2.ExpectedValue, f2.Rationale, f2.Informational).
		WillReturnResult(sqlmock.NewResult(0, 2))

	sink.drain(context.Background(), func() models.SysctlAuditResponse { return resp })

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSysctlDrainWithNoFindingsSkipsFlush(t *testing.T) {
	sink, mock := newTestSysctlSink(t, SysctlConfig{})
	sink.log = slog.New(failOnWarnHandler{t: t})

	// No mock.ExpectExec set up at all — an unexpected Exec call would
	// surface as a flush error, which would log a Warn and fail the test.
	sink.drain(context.Background(), func() models.SysctlAuditResponse { return models.SysctlAuditResponse{} })

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSysctlDrainStopsAtFirstFailedBatchNoWatermarkToPreserve(t *testing.T) {
	f1, n1 := finding("a", "node-a")
	f2, n2 := finding("b", "node-b")
	f3, n3 := finding("c", "node-c")
	resp := models.SysctlAuditResponse{Nodes: []models.NodeSysctlAudit{
		{Node: n1, Findings: []models.SysctlAuditFinding{f1}},
		{Node: n2, Findings: []models.SysctlAuditFinding{f2}},
		{Node: n3, Findings: []models.SysctlAuditFinding{f3}},
	}}
	sink, mock := newTestSysctlSink(t, SysctlConfig{BatchSize: 1})

	mock.ExpectExec("INSERT INTO NETRA_SYSCTL_AUDIT").WillReturnResult(sqlmock.NewResult(0, 1)) // batch 1 succeeds
	mock.ExpectExec("INSERT INTO NETRA_SYSCTL_AUDIT").WillReturnError(context.DeadlineExceeded) // batch 2 fails
	// batch 3 must never be attempted once batch 2 fails.

	// Unlike the audit sink's equivalent test, there is no lastAt-style
	// watermark field to assert on afterward: the sysctl sink carries no
	// watermark at all, since every tick re-exports the full current
	// snapshot regardless of what a prior tick did or didn't commit.
	sink.drain(context.Background(), func() models.SysctlAuditResponse { return resp })

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestNewSysctlSinkReusesParentSinkConnection(t *testing.T) {
	parent, mock := newTestSink(t, Config{})
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS NETRA_SYSCTL_AUDIT").WillReturnResult(sqlmock.NewResult(0, 0))

	ss, err := parent.NewSysctlSink(context.Background(), SysctlConfig{})
	if err != nil {
		t.Fatalf("NewSysctlSink: %v", err)
	}
	if ss.db != parent.db {
		t.Fatalf("SysctlSink.db does not match parent Sink.db — a second connection must never be opened")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (only the sysctl CREATE TABLE should have run against the shared connection): %v", err)
	}
}

func TestSysctlConfigApplyDefaultsRejectsInvalidTableName(t *testing.T) {
	cfg := SysctlConfig{Table: "1BAD"}
	if err := cfg.applyDefaults(); err == nil {
		t.Fatalf("applyDefaults() with table %q: want error, got nil", cfg.Table)
	}
}
