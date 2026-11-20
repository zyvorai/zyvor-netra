// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package models

import "time"

// HostProcessStat is one host process in a drop-incident snapshot.
// Comm is the kernel task name only — never argv, cmdline, or environment.
type HostProcessStat struct {
	PID        uint32  `json:"pid"`
	Comm       string  `json:"comm,omitempty"`
	CPUPercent float64 `json:"cpuPercent"`
	RSSBytes   uint64  `json:"rssBytes"`
}

// HostProcessTops is the bounded comm-only process sample carried on an
// agent report so a later drop can freeze it. It is not part of
// GET /api/v1/node-resources.
type HostProcessTops struct {
	ByCPU    []HostProcessStat `json:"byCpu,omitempty"`
	ByMemory []HostProcessStat `json:"byMemory,omitempty"`
}

// StackSample is a bounded kernel stack for one hot host process.
// Folded is comm plus kernel frames from /proc/<pid>/stack. No argv,
// no user-space flame graph, and nothing is read if the file is absent.
type StackSample struct {
	Node   string `json:"node,omitempty"`
	PID    uint32 `json:"pid"`
	Comm   string `json:"comm,omitempty"`
	Folded string `json:"folded,omitempty"`
	Frames int    `json:"frames,omitempty"`
	// Wchan is the kernel wait channel (/proc/<pid>/wchan), a single
	// symbol for where a sleeping process sits. Not a user-space stack.
	Wchan string `json:"wchan,omitempty"`
}

// KernelNote is one scrubbed kernel-log line about the network stack
// or an OOM kill. Application journal lines are not collected.
type KernelNote struct {
	Node string `json:"node,omitempty"`
	Text string `json:"text"`
}

// DropIncidentTrigger is the alert that caused the capture.
type DropIncidentTrigger struct {
	Source    string    `json:"source"`
	Kind      string    `json:"kind"`
	Severity  string    `json:"severity,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	Message   string    `json:"message,omitempty"`
	Value     float64   `json:"value,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// DropIncidentNode is which machine the drop was observed on.
type DropIncidentNode struct {
	Name          string `json:"name"`
	Hostname      string `json:"hostname,omitempty"`
	KernelRelease string `json:"kernelRelease,omitempty"`
	Stale         bool   `json:"stale"`
	AgeSeconds    int64  `json:"ageSeconds"`
}

// DropIncidentContext is the sos-style snapshot frozen when auto-capture
// starts. It is not a Red Hat sosreport: no dmesg, journal, package
// inventory, argv, or Secret contents.
type DropIncidentContext struct {
	CapturedAt           time.Time              `json:"capturedAt"`
	Trigger              DropIncidentTrigger    `json:"trigger"`
	Node                 DropIncidentNode       `json:"node"`
	Host                 HostResourceSnapshot   `json:"host"`
	CPUHot               bool                   `json:"cpuHot"`
	MemoryHot            bool                   `json:"memoryHot"`
	TopWorkloadsByCPU    []WorkloadResourceStat `json:"topWorkloadsByCpu,omitempty"`
	TopWorkloadsByMemory []WorkloadResourceStat `json:"topWorkloadsByMemory,omitempty"`
	PolicyDropProcesses  []PolicyDropStat       `json:"policyDropProcesses,omitempty"`
	TopProcessesByCPU    []HostProcessStat      `json:"topProcessesByCpu,omitempty"`
	TopProcessesByMemory []HostProcessStat      `json:"topProcessesByMemory,omitempty"`
	Stack                NodeStackStat          `json:"stack"`
	QdiscStats           []QdiscStat            `json:"qdiscStats,omitempty"`
	KernelDrops          []KernelDropStat       `json:"kernelDrops,omitempty"`
	Limitations          []string               `json:"limitations,omitempty"`
}
