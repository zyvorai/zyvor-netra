// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package models

import "time"

// DenyLease bounds one deny rule created by a declarative denyset. The rule
// itself lives in EBPFFastPathConfig; the lease says who owns it and when the
// controller removes it again. A rule without a DenyLease is never touched by
// a denyset.
type DenyLease struct {
	Owner         string    `json:"owner"`        // denyset name (ownership label)
	Type          string    `json:"type"`         // cidr or port (rule index type)
	Key           string    `json:"key"`          // rule index key, e.g. "egress|203.0.113.0/24"
	Summary       string    `json:"summary"`      // human readable rule
	LeaseSeconds  int64     `json:"leaseSeconds"` // duration granted at the last create/extend
	CreatedAt     time.Time `json:"createdAt"`
	CreatedBy     string    `json:"createdBy"`
	ExpiresAt     time.Time `json:"expiresAt"`
	Extensions    int       `json:"extensions,omitempty"`
	RuleCreatedAt time.Time `json:"ruleCreatedAt"` // identity of the rule instance the lease owns
}

// LeaseEvent is one entry of the read-only lease timeline.
type LeaseEvent struct {
	At           time.Time  `json:"at"`
	Action       string     `json:"action"` // create, extend, expire, revoke, reject
	Actor        string     `json:"actor"`
	Owner        string     `json:"owner,omitempty"`
	Rule         string     `json:"rule,omitempty"`
	LeaseSeconds int64      `json:"leaseSeconds,omitempty"`
	ExpiresAt    *time.Time `json:"expiresAt,omitempty"`
	Rails        []string   `json:"rails,omitempty"` // rail codes that tripped (reject) or were waived (break-glass)
	BreakGlass   bool       `json:"breakGlass,omitempty"`
	Reason       string     `json:"reason,omitempty"`
}
