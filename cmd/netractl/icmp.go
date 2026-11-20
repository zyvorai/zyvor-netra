// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import "fmt"

type explainICMP struct {
	InterfaceName  string `json:"interfaceName"`
	InterfaceIndex uint32 `json:"interfaceIndex"`
	Family         string `json:"family"`
	Type           uint8  `json:"type"`
	Code           uint8  `json:"code"`
	Direction      string `json:"direction"`
	Hook           string `json:"hook"`
	Packets        uint64 `json:"packets"`
	AdvertisedMTU  uint32 `json:"advertisedMtu"`
}

func (o explainOptions) includesNodeICMP() bool {
	return o.Namespace == "" && o.Pod == "" && o.PID == 0 && o.Container == "" &&
		o.Docker == "" && o.Destination == "" && o.DNS == ""
}

func icmpFinding(e explainICMP) (kind, evidence, next string) {
	if e.Packets == 0 || e.Hook != "tc" {
		return
	}
	v4, v6 := e.Family == "IPv4", e.Family == "IPv6"
	switch {
	case (v4 && e.Type == 3 && e.Code == 4) || (v6 && e.Type == 2 && e.Code == 0):
		kind = "icmp-pmtu"
		next = "Check interface and tunnel MTUs and whether ICMP errors reach the sender. The advertised MTU is a peer claim, not a verified path MTU."
	case (v4 && e.Type == 3) || (v6 && e.Type == 1):
		kind = "icmp-unreachable"
		next = "Inspect the ICMP type/code, destination listener, routes, and firewall rejects. This node-level signal does not identify the failing workload or connection."
	case (v4 && e.Type == 11) || (v6 && e.Type == 3):
		kind = "icmp-time-exceeded"
		next = "Check routing loops, hop limits, and fragment reassembly timeouts using the reported ICMP code."
	case (v4 && e.Type == 12) || (v6 && e.Type == 4):
		kind = "icmp-parameter-problem"
		next = "Check IP header and tunnel configuration; peers reported a packet parameter problem."
	default:
		return
	}
	evidence = fmt.Sprintf("interface-index=%d family=%s direction=%q hook=tc type=%d code=%d observations=%d", e.InterfaceIndex, e.Family, e.Direction, e.Type, e.Code, e.Packets)
	if e.InterfaceName != "" {
		evidence += fmt.Sprintf(" interface-name=%q", e.InterfaceName)
	}
	if e.AdvertisedMTU != 0 {
		evidence += fmt.Sprintf(" last-advertised-mtu=%d", e.AdvertisedMTU)
	}
	return
}
