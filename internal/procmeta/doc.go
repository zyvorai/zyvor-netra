// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package procmeta reads process metadata from /proc for attribution of
// network observations. It is meant to be called from the privileged
// per-node agent (cmd/netra-agent), which is the only process with a
// meaningful view of a given PID's /proc entry — the controller aggregates
// AgentReport from potentially many remote nodes and has no relationship to
// any specific node's process tree, so it must never call this package.
//
// The package is Linux-only and has no dependencies outside the standard
// library.
//
// # Identity and PID reuse
//
// A bare PID is not a stable identifier. The kernel reuses PIDs once they
// are freed, so a cache or an event stream keyed on PID alone will
// misattribute a new process to an old one. Every Meta returned by this
// package carries an Identity{PID, StartTime}. Callers that store or
// compare process references MUST use Identity, not PID.
//
// # Field sources
//
//   - /proc/PID/stat          PID, comm, PPID, StartTime (jiffies since boot)
//   - /proc/PID/status        UID/GID sets, capabilities, NSpid, NoNewPrivs, Seccomp
//   - /proc/PID/cgroup        cgroup v2 path, pod UID, container ID, QoS class
//   - /proc/PID/attr/current  LSM label (may not exist)
//   - /proc/PID/exe           executable path (may not exist for kernel threads)
//   - /proc/PID/cmdline       used only to help classify kernel threads; argv
//     content itself is never retained (it can carry secrets passed as
//     command-line arguments) — see Meta.KernelThread
//   - /proc/stat              host boot time (read once, see BootTime)
//
// # What this package does not do
//
// It does not read task_struct from eBPF. On kernels without
// bpf_get_current_task_btf (pre-5.11) that path is either unavailable or
// requires embedding vmlinux BTF. Reading the same fields from /proc is
// portable, testable, and cheap enough for per-connection enrichment when a
// small cache is used. See Cache.
//
// It does not retain process argv/cmdline content, matching this project's
// existing narrow, privacy-conscious observability boundary (process
// identity elsewhere in this codebase is limited to Linux `comm`, and no
// feature collects arbitrary payload/argument content).
//
// It does not resolve a PodUID to a Kubernetes Pod name, namespace, owner,
// or labels. That requires an API server and belongs in whatever layer
// already talks to Kubernetes (see internal/cgroupmeta, internal/workload).
// This package hands over identifiers; the caller joins them.
//
// # Deployment requirement
//
// Reading a workload's /proc/PID from inside the agent container requires
// either hostPID: true or a host /proc bind-mount on the agent DaemonSet;
// neither is present by default. This is a real expansion of what the
// already-privileged agent can see (every host process's /proc, not just
// what eBPF hooks already surface), so callers should gate use of this
// package behind an explicit opt-in rather than enabling it unconditionally
// whenever the agent is deployed.
package procmeta
