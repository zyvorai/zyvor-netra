// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package models

import "time"

// BPF program owners. Netra names every program it loads "netra_*"; Cilium's
// start with "cil_". Anything else is reported as "other", never guessed at.
const (
	BPFOwnerNetra  = "netra"
	BPFOwnerCilium = "cilium"
	BPFOwnerOther  = "other"
)

// BPFProgram is one program attached to an interface, as the kernel reports it.
// Only the id, the (15-character, kernel-truncated) name and an owner class are
// kept: no bytecode, no maps, nothing that could reach into a program.
type BPFProgram struct {
	ID    uint32 `json:"id"`
	Name  string `json:"name,omitempty"`
	Owner string `json:"owner"`
	// Mode is set for XDP only: native, generic, offload or multi.
	Mode string `json:"mode,omitempty"`
}

// BPFInterfaceAttach is what the kernel says is attached to one interface.
// TCX lists are in execution order (the first runs first); classic cls_bpf
// filters are listed separately because they are a different attach mechanism.
type BPFInterfaceAttach struct {
	Name       string       `json:"name"`
	Index      int          `json:"index"`
	Type       string       `json:"type,omitempty"`
	State      string       `json:"state,omitempty"`
	XDP        *BPFProgram  `json:"xdp,omitempty"`
	TCXIngress []BPFProgram `json:"tcxIngress,omitempty"`
	TCXEgress  []BPFProgram `json:"tcxEgress,omitempty"`
	TCIngress  []BPFProgram `json:"tcIngress,omitempty"`
	TCEgress   []BPFProgram `json:"tcEgress,omitempty"`
}

// BPFAttachReport is one agent's read-only inventory of the BPF programs
// attached to its interfaces. It observes; it never attaches, detaches or
// replaces anything, and it never touches a Cilium-owned program or map.
//
// A nil report means the inventory is off. Unchanged means the agent did not
// re-send the interface list because it is identical to the one with this Hash;
// the controller carries the previous list forward.
type BPFAttachReport struct {
	Available   bool      `json:"available"`
	Unavailable string    `json:"unavailable,omitempty"`
	Error       string    `json:"error,omitempty"`
	ObservedAt  time.Time `json:"observedAt,omitzero"`
	Hash        string    `json:"hash,omitempty"`
	Unchanged   bool      `json:"unchanged,omitempty"`
	// TCXSupported is false when the kernel cannot list TCX programs (before 6.6),
	// so an empty TCX list there means "cannot tell", not "nothing attached".
	TCXSupported bool `json:"tcxSupported"`
	// Interfaces are only those with at least one program attached, capped;
	// Total is how many there were before the cap and Truncated how many were cut.
	Interfaces []BPFInterfaceAttach `json:"interfaces,omitempty"`
	Total      int                  `json:"total"`
	Truncated  int                  `json:"truncated,omitempty"`
	// Failed names interfaces whose programs could not be read, so an absent
	// program there is "unknown", never "detached".
	Failed []string `json:"failed,omitempty"`
}

// BPFAttachFinding is one evidence-backed observation about attachments. Like a
// netlink finding it is level-triggered (it clears when the kernel shows the
// programs attached again) and its subject is the node.
type BPFAttachFinding struct {
	Severity   string   `json:"severity"` // critical|warning|info
	Kind       string   `json:"kind"`
	Node       string   `json:"node"`
	Subject    string   `json:"subject"`
	Message    string   `json:"message"`
	Value      float64  `json:"value,omitempty"`
	Interfaces []string `json:"interfaces,omitempty"`
}

// BPFAttachFindingsResponse is the findings half of GET /api/v1/ebpf/attachments.
type BPFAttachFindingsResponse struct {
	ObservedAt time.Time `json:"observedAt"`
	// Evaluated is the number of fresh nodes whose inventory was read; Skipped
	// counts the rest (stale, inventory off or unavailable), so "no findings"
	// cannot be mistaken for "nothing was looked at".
	Evaluated int                `json:"evaluated"`
	Skipped   int                `json:"skipped"`
	Findings  []BPFAttachFinding `json:"findings"`
}
