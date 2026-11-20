// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package models

// SysctlAuditEntry is a read-only snapshot of one network hardening/tuning
// sysctl. Unlike KernelTunable, entries are pre-tagged with a Category and,
// for per-interface sysctls, an Interface — the grouping keys the audit's
// baseline classification and cluster-outlier detection use.
type SysctlAuditEntry struct {
	Name      string `json:"name"`
	Interface string `json:"interface,omitempty"`
	Category  string `json:"category"`
	Value     string `json:"value"`
	Source    string `json:"source"`
}

type SysctlAuditSnapshot struct {
	Entries []SysctlAuditEntry `json:"entries,omitempty"`
}

// SysctlAuditFinding is one sysctl classified against the baseline. Most
// entries in scope are deliberately Informational (no universally "correct"
// value exists — e.g. ip_forward, disable_ipv6, tcp_congestion_control):
// they are still reported, with Severity "info" and no ExpectedValue verdict,
// rather than silently omitted or forced into a false pass/fail.
type SysctlAuditFinding struct {
	Severity      string `json:"severity"`
	Category      string `json:"category"`
	Name          string `json:"name"`
	Interface     string `json:"interface,omitempty"`
	CurrentValue  string `json:"currentValue"`
	ExpectedValue string `json:"expectedValue,omitempty"`
	Rationale     string `json:"rationale"`
	Informational bool   `json:"informational,omitempty"`
}

type NodeSysctlAudit struct {
	Node     string               `json:"node"`
	Snapshot SysctlAuditSnapshot  `json:"snapshot"`
	Findings []SysctlAuditFinding `json:"findings,omitempty"`
}

type SysctlAuditSummary struct {
	Nodes         int `json:"nodes"`
	Findings      int `json:"findings"`
	Critical      int `json:"critical"`
	Warnings      int `json:"warnings"`
	Informational int `json:"informational"`
	Outliers      int `json:"outliers"`
}

// SysctlAuditOutlier flags one (name, interface) pair where nodes disagree.
// This is the cluster-summary mechanism that lets the API/web avoid dumping
// every value for every node up front — an operator scans Outliers first.
type SysctlAuditOutlier struct {
	Name          string   `json:"name"`
	Interface     string   `json:"interface,omitempty"`
	Category      string   `json:"category"`
	MajorityValue string   `json:"majorityValue"`
	OutlierNodes  []string `json:"outlierNodes"`
}

type SysctlAuditResponse struct {
	Summary     SysctlAuditSummary   `json:"summary"`
	Nodes       []NodeSysctlAudit    `json:"nodes"`
	Outliers    []SysctlAuditOutlier `json:"outliers,omitempty"`
	Limitations []string             `json:"limitations"`
}
