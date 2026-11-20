// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package models

// Node agents do not report whole BPF maps: each list in an AgentReport is a
// top-N snapshot, sorted before it is cut. Consumers that difference these
// lists over time (internal/workloadobs) must know the cap, because an entry
// that first appears may simply have climbed into the top N rather than been
// created since the last report.
//
// These are the single source of truth: internal/agent truncates to them and
// internal/workloadobs detects truncation against them. The ordering is part of
// the contract:
//
//	flows              by cumulative packets, descending
//	connection sources by cumulative attempts, descending
//	DNS names          (see readDNSHealth)
//	HTTP status        (see readHTTPStatus)
//
// TCPHealth is capped by a retransmission/RTT score, not by traffic, so it is a
// biased sample of sockets and unsuitable for ratios; it is not exported here.
const (
	ReportCapFlows        = 1000
	ReportCapConnAttempts = 2000
	ReportCapDNS          = 500
	ReportCapHTTPStatus   = 1000
)
