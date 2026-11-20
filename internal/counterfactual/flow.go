// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package counterfactual

import (
	"net/netip"
	"time"
)

// Direction is the direction of a flow relative to the attributed workload.
type Direction string

const (
	DirectionIngress Direction = "ingress"
	DirectionEgress  Direction = "egress"
)

// String returns the direction as a plain string.
func (d Direction) String() string { return string(d) }

// Protocol is the transport protocol of a flow.
type Protocol string

const (
	ProtocolTCP  Protocol = "tcp"
	ProtocolUDP  Protocol = "udp"
	ProtocolICMP Protocol = "icmp"
	ProtocolAny  Protocol = "any"
)

// WorkloadRef identifies the workload a flow is attributed to. It is
// deliberately stable and self-contained: two flows with the same
// WorkloadRef refer to the same workload even if the pod IP changed
// between them.
type WorkloadRef struct {
	// Kind is "pod", "vm", or "host".
	Kind string `json:"kind"`
	// Namespace is empty for host workloads.
	Namespace string `json:"namespace,omitempty"`
	// Name is the pod or VM name.
	Name string `json:"name"`
	// Owner is the immediate controller (Deployment, StatefulSet,
	// VirtualMachine). Empty when the workload is unmanaged.
	Owner string `json:"owner,omitempty"`
	// UID is the stable identity from the Kubernetes API. Empty for host
	// workloads.
	UID string `json:"uid,omitempty"`
}

// Key returns a stable string form of the workload reference, suitable
// for use as a map key.
func (w WorkloadRef) Key() string {
	if w.Namespace == "" {
		return w.Kind + "//" + w.Name
	}
	return w.Kind + "/" + w.Namespace + "/" + w.Name
}

// String returns a human-readable form.
func (w WorkloadRef) String() string {
	if w.Namespace == "" {
		return w.Kind + " " + w.Name
	}
	return w.Kind + " " + w.Namespace + "/" + w.Name
}

// Flow is one observed network flow, attributed to a workload.
//
// A Flow is a summary of what happened, not a packet: one record per
// five-tuple plus metadata, with the counts of packets and bytes observed
// over the flow's lifetime.
type Flow struct {
	// Timestamp is the first time this flow was observed.
	Timestamp time.Time `json:"ts"`

	// Src and Dst are the five-tuple. For an egress flow attributed to
	// Workload, Workload is the source. For an ingress flow, Workload is
	// the destination.
	SrcIP   netip.Addr `json:"srcIp"`
	DstIP   netip.Addr `json:"dstIp"`
	SrcPort uint16     `json:"srcPort"`
	DstPort uint16     `json:"dstPort"`

	Protocol  Protocol  `json:"proto"`
	Direction Direction `json:"direction"`

	// Workload is the attributed workload. Empty when attribution failed.
	Workload WorkloadRef `json:"workload"`

	// L7 metadata. Best-effort; empty when not observed.
	DNSName string `json:"dnsName,omitempty"`
	TLSSNI  string `json:"tlsSni,omitempty"`

	// Counters over the flow's lifetime.
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`

	// Duration is LastSeen - Timestamp. Zero for a single-packet flow.
	Duration time.Duration `json:"duration,omitempty"`
}

// RemoteIP returns the IP at the far end of the flow from the attributed
// workload's perspective.
func (f Flow) RemoteIP() netip.Addr {
	if f.Direction == DirectionEgress {
		return f.DstIP
	}
	return f.SrcIP
}

// RemotePort returns the port at the far end of the flow from the
// attributed workload's perspective.
func (f Flow) RemotePort() uint16 {
	if f.Direction == DirectionEgress {
		return f.DstPort
	}
	return f.SrcPort
}

// RemoteString returns "ip:port" for the far end of the flow.
func (f Flow) RemoteString() string {
	return netip.AddrPortFrom(f.RemoteIP(), f.RemotePort()).String()
}

// DestinationString returns the best available name for the far end: the
// TLS SNI if present, else the DNS name, else "ip:port".
func (f Flow) DestinationString() string {
	if f.TLSSNI != "" {
		return f.TLSSNI
	}
	if f.DNSName != "" {
		return f.DNSName
	}
	return f.RemoteString()
}
