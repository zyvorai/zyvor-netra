// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package models

import "time"

// ProtocolDowngradeFinding flags a workload/host pair that had TLS
// handshake history to Host at baseline capture time and now also shows
// cleartext HTTP to that same host. This is coexistence-tolerant
// correlation, not a verdict — never a "downgrade attack"/"MITM"/"stripped"
// claim. Severity is "warning" when no concurrent TLS activity to Host is
// currently observed (the stronger signal: TLS presence has disappeared)
// and "info" when TLS is still concurrently active (weaker — likely
// coexistence, e.g. a secondary client path) — the weaker case is still
// always surfaced, per this project's non-suppression convention, just
// honestly labeled lower-confidence.
type ProtocolDowngradeFinding struct {
	Source         string `json:"source"`
	Host           string `json:"host"`
	Severity       string `json:"severity"`
	TLSStillActive bool   `json:"tlsStillActive"`
	Message        string `json:"message"`
}

// ProtocolDowngradeResponse is internal/insights.ProtocolDowngrades' result.
// L7Degraded/L7DegradedNodes must gate how an empty Findings list is read:
// when true, a quiet result may only mean Netra's L7 (TLS SNI / HTTP Host)
// visibility is currently incomplete on those nodes, never "confirmed no
// downgrades."
type ProtocolDowngradeResponse struct {
	BaselineCapturedAt *time.Time                 `json:"baselineCapturedAt,omitempty"`
	Findings           []ProtocolDowngradeFinding `json:"findings"`
	L7Degraded         bool                       `json:"l7Degraded"`
	L7DegradedNodes    []string                   `json:"l7DegradedNodes,omitempty"`
}
