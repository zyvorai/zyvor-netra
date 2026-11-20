// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"context"
	"github.com/zyvorai/netra/internal/intel"
	"os"
	"strings"
	"time"
)

// RunIntelRefresh is owned by the controller leader's lifetime. API reads
// never start background work and feed refresh never applies deny entries.
func (s *Server) RunIntelRefresh(ctx context.Context) {
	raw := strings.TrimSpace(os.Getenv("NETRA_INTEL_SOURCE_URL"))
	if raw == "" {
		return
	}
	interval, ttl := 15*time.Minute, time.Hour
	var err error
	if v := os.Getenv("NETRA_INTEL_REFRESH_INTERVAL"); v != "" {
		interval, err = time.ParseDuration(v)
		if err != nil {
			s.log.Warn("invalid intel refresh interval")
			return
		}
	}
	if v := os.Getenv("NETRA_INTEL_TTL"); v != "" {
		ttl, err = time.ParseDuration(v)
		if err != nil {
			s.log.Warn("invalid intel TTL")
			return
		}
	}
	c := intel.RefreshConfig{URL: raw, Interval: interval, TTL: ttl}
	if err = c.Validate(); err != nil {
		s.log.Warn("invalid intel refresh configuration", "error", err)
		return
	}
	s.intelFeed.RunRefresh(ctx, c)
}
