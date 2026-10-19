// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package counterfactual evaluates a network policy against observed flow
// history and returns what the policy would have denied, what it would
// have broken, and when the affected patterns first appeared.
//
// # What this package is
//
// A retrospective policy evaluator. Given a policy P and a time window
// over stored flows, it answers: which observed flows would P have
// denied, which workloads would have lost which dependencies, and when
// did each affected pattern first appear. The output is a Receipt: a
// signed, timestamped artifact that can be attached to a change request
// or a postmortem.
//
// # What this package is not
//
// It is not a policy engine — it does not enforce anything and does not
// touch the datapath. Its only input is stored Flow records and a Policy
// description; its only output is a report. It is not a simulator either:
// it evaluates flows as atomic records (was this observed flow allowed or
// denied), not TCP state or timing. This is a deliberate simplification,
// disclosed in every receipt.
//
// # Where flows come from
//
// This package defines its own narrow Store interface and ships an
// in-memory reference implementation (MemoryStore). The production
// adapter is FlowLogStore, which reads the controller's bounded flow
// history (internal/flowlog: 7 days / 100000 deltas by default) used by
// GET /api/v1/flows/history and POST /api/v1/ebpf/deny/preview-history.
// Live agent-counter deny preview remains in internal/denysim.
package counterfactual
