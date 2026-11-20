// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package webhook

import (
	"encoding/json"
	"fmt"
	"time"
)

// configJSON mirrors Config but with Timeout as a Go duration string
// ("5s"), matching this repo's envDuration convention rather than a
// bare-integer-seconds encoding.
type configJSON struct {
	Name        string            `json:"name"`
	URL         string            `json:"url"`
	Secret      string            `json:"secret,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	MinSeverity string            `json:"minSeverity,omitempty"`
	Timeout     string            `json:"timeout,omitempty"`
	MaxAttempts int               `json:"maxAttempts,omitempty"`
}

// ParseConfigs decodes the JSON array format used by NETRA_ALERT_WEBHOOKS,
// e.g.:
//
//	[{"name":"slack","url":"https://hooks.example/...","minSeverity":"warning","timeout":"5s","maxAttempts":3}]
func ParseConfigs(raw string) ([]Config, error) {
	var in []configJSON
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return nil, fmt.Errorf("webhook: parse NETRA_ALERT_WEBHOOKS: %w", err)
	}
	out := make([]Config, 0, len(in))
	for _, c := range in {
		cfg := Config{Name: c.Name, URL: c.URL, Secret: c.Secret, Headers: c.Headers, MinSeverity: c.MinSeverity, MaxAttempts: c.MaxAttempts}
		if c.Timeout != "" {
			d, err := time.ParseDuration(c.Timeout)
			if err != nil {
				return nil, fmt.Errorf("webhook: sink %q: invalid timeout %q: %w", c.Name, c.Timeout, err)
			}
			cfg.Timeout = d
		}
		out = append(out, cfg)
	}
	return out, nil
}
