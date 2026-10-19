// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package flowlog

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// OptionsFromEnv reads NETRA_FLOW_* retention knobs.
func OptionsFromEnv() Options {
	o := Options{Retain: DefaultRetain, Max: DefaultMax}
	if v := strings.TrimSpace(os.Getenv("NETRA_FLOW_RETAIN")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			o.Retain = d
		}
	}
	if v := strings.TrimSpace(os.Getenv("NETRA_FLOW_MAX")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			o.Max = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("NETRA_FLOW_MAX_BYTES")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			o.MaxBytes = n
		}
	}
	return o.Normalize()
}

// BackendFromEnv returns NETRA_FLOW_BACKEND (default json).
func BackendFromEnv() BackendName {
	return ParseBackend(os.Getenv("NETRA_FLOW_BACKEND"))
}
