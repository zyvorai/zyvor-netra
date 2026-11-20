// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package flowstats

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

type Collector struct {
	total        uint64
	verdicts     map[string]uint64
	protocols    map[string]uint64
	dropReasons  map[string]uint64
	destinations map[string]uint64
}

func New() *Collector {
	return &Collector{
		verdicts:     map[string]uint64{},
		protocols:    map[string]uint64{},
		dropReasons:  map[string]uint64{},
		destinations: map[string]uint64{},
	}
}

func (c *Collector) Add(raw []byte) bool {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	c.total++
	if verdict := normalized(m["verdict"]); verdict != "" {
		c.verdicts[verdict]++
	}
	if reason := normalized(m["dropReasonDesc"]); reason != "" && reason != "0" {
		c.dropReasons[reason]++
	}
	if proto := flowProtocol(m); proto != "" {
		c.protocols[proto]++
	}
	if dst := destinationIP(m); dst != "" {
		c.destinations[dst]++
	}
	return true
}

func (c *Collector) Summary(limit int) models.FlowSummary {
	if limit <= 0 {
		limit = 10
	}
	return models.FlowSummary{
		Total:           c.total,
		Verdicts:        cloneMap(c.verdicts),
		Protocols:       cloneMap(c.protocols),
		DropReasons:     top(c.dropReasons, limit),
		TopDestinations: top(c.destinations, limit),
	}
}

func destinationIP(m map[string]any) string {
	for _, key := range []string{"IP", "ip"} {
		if ip, ok := m[key].(map[string]any); ok {
			if v := strings.TrimSpace(fmt.Sprint(ip["destination"])); v != "" && v != "<nil>" {
				return v
			}
		}
	}
	return ""
}

func flowProtocol(m map[string]any) string {
	l4, _ := m["l4"].(map[string]any)
	if l4 == nil {
		return ""
	}
	for _, p := range []string{"TCP", "tcp", "UDP", "udp", "ICMPv4", "icmpv4", "ICMPv6", "icmpv6", "SCTP", "sctp"} {
		if _, ok := l4[p]; ok {
			return strings.ToUpper(p)
		}
	}
	return ""
}

func normalized(v any) string {
	x := strings.TrimSpace(fmt.Sprint(v))
	if x == "" || x == "<nil>" {
		return ""
	}
	return strings.ToUpper(x)
}

func top(m map[string]uint64, limit int) []models.NamedCount {
	out := make([]models.NamedCount, 0, len(m))
	for name, count := range m {
		out = append(out, models.NamedCount{Name: name, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Name < out[j].Name
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func cloneMap(in map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
