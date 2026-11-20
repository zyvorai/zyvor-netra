// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package snowflakesink is the optional Snowflake export sink for the
// audit stream. Off unless Account is set. Auth is key-pair (JWT) only
// — no password field — matching Snowflake's recommended service
// account authentication.
package snowflakesink

import (
	"fmt"
	"strings"
)

// Config configures the sink. Every field except Table, BatchSize, and
// ExtraColumns is required once Account is set.
type Config struct {
	Account        string
	User           string
	PrivateKeyPath string
	Warehouse      string
	Database       string
	Schema         string
	Table          string
	BatchSize      int
	ExtraColumns   []ExtraColumn
}

// ExtraColumn maps one additional, operator-configured Snowflake column
// onto either a key inside models.AuditEvent.Details or a fixed value
// supplied at startup. Column names reach raw DDL/DML unquoted exactly
// like Table, so Name is validated with the same isValidIdentifier used
// for Table.
type ExtraColumn struct {
	Name   string // uppercased, validated identifier
	Source string // "details:<key>" or "static:<value>"
}

// reservedColumns are the fixed columns every table already has; an
// ExtraColumn may not reuse one of these names.
var reservedColumns = map[string]bool{
	"AT": true, "ACTOR": true, "ACTION": true, "TARGET": true, "MESSAGE": true, "DETAILS": true,
}

const (
	extraColumnDetailsPrefix = "details:"
	extraColumnStaticPrefix  = "static:"
)

func (c *Config) applyDefaults() error {
	c.Account = strings.TrimSpace(c.Account)
	if c.Account == "" {
		return fmt.Errorf("snowflake account is required")
	}
	c.User = strings.TrimSpace(c.User)
	if c.User == "" {
		return fmt.Errorf("snowflake user is required")
	}
	c.PrivateKeyPath = strings.TrimSpace(c.PrivateKeyPath)
	if c.PrivateKeyPath == "" {
		return fmt.Errorf("snowflake private key path is required")
	}
	c.Warehouse = strings.TrimSpace(c.Warehouse)
	if c.Warehouse == "" {
		return fmt.Errorf("snowflake warehouse is required")
	}
	c.Database = strings.TrimSpace(c.Database)
	if c.Database == "" {
		return fmt.Errorf("snowflake database is required")
	}
	c.Schema = strings.TrimSpace(c.Schema)
	if c.Schema == "" {
		return fmt.Errorf("snowflake schema is required")
	}
	c.Table = strings.ToUpper(strings.TrimSpace(c.Table))
	if c.Table == "" {
		c.Table = "NETRA_AUDIT"
	}
	if !isValidIdentifier(c.Table) {
		return fmt.Errorf("snowflake table %q is not a valid unquoted identifier", c.Table)
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 50
	}
	if err := c.applyExtraColumnDefaults(); err != nil {
		return err
	}
	return nil
}

// applyExtraColumnDefaults uppercases and validates every configured
// ExtraColumn in place. This is the one place ExtraColumn safety is
// enforced, regardless of whether a Config was built from env vars (via
// ParseExtraColumns) or directly in a test — the same guarantee Table
// already gets from applyDefaults.
func (c *Config) applyExtraColumnDefaults() error {
	seen := make(map[string]bool, len(c.ExtraColumns))
	for i := range c.ExtraColumns {
		ec := &c.ExtraColumns[i]
		ec.Name = strings.ToUpper(strings.TrimSpace(ec.Name))
		if !isValidIdentifier(ec.Name) {
			return fmt.Errorf("snowflake extra column %q is not a valid unquoted identifier", ec.Name)
		}
		if reservedColumns[ec.Name] {
			return fmt.Errorf("snowflake extra column %q collides with a fixed column", ec.Name)
		}
		if seen[ec.Name] {
			return fmt.Errorf("snowflake extra column %q is configured more than once", ec.Name)
		}
		seen[ec.Name] = true
		switch {
		case strings.HasPrefix(ec.Source, extraColumnDetailsPrefix):
			if strings.TrimPrefix(ec.Source, extraColumnDetailsPrefix) == "" {
				return fmt.Errorf("snowflake extra column %q: %q source has an empty key", ec.Name, ec.Source)
			}
		case strings.HasPrefix(ec.Source, extraColumnStaticPrefix):
			// A static value may legitimately be empty (e.g. an
			// intentionally blank tag), so no further check here.
		default:
			return fmt.Errorf("snowflake extra column %q: source %q must start with %q or %q", ec.Name, ec.Source, extraColumnDetailsPrefix, extraColumnStaticPrefix)
		}
	}
	return nil
}

// ParseExtraColumns parses NETRA_SNOWFLAKE_EXTRA_COLUMNS: a comma-separated
// list of NAME=SOURCE pairs, e.g.
// "REASON=details:reason,ENVIRONMENT=static:prod". SOURCE is
// "details:<key>" (project models.AuditEvent.Details[key] into the
// column, JSON-encoding non-string values) or "static:<value>" (a fixed
// value repeated on every row). This only checks the NAME=SOURCE shape;
// identifier safety, reserved-name, and duplicate checks happen in
// Config.applyDefaults, the same place Table's safety check lives.
func ParseExtraColumns(raw string) ([]ExtraColumn, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	cols := make([]ExtraColumn, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, source, ok := strings.Cut(part, "=")
		if !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(source) == "" {
			return nil, fmt.Errorf("snowflake extra column %q: want NAME=SOURCE", part)
		}
		cols = append(cols, ExtraColumn{Name: strings.TrimSpace(name), Source: strings.TrimSpace(source)})
	}
	return cols, nil
}

// isValidIdentifier reports whether s is safe to interpolate unquoted
// into DDL/DML as a Snowflake object name (letters, digits, underscore,
// not leading with a digit). The table name is the only sink-config
// value that ever reaches raw SQL text instead of a bind parameter, so
// it is validated eagerly at startup rather than escaped later.
func isValidIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r == '_':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// Enabled reports whether a sink would start from env-style fields.
func (c Config) Enabled() bool {
	return strings.TrimSpace(c.Account) != ""
}
