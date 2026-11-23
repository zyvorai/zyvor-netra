// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package flooddetect finds inbound volumetric floods (SYN, UDP, ICMP and
// fragment) from data Netra already collects, and suggests a deny for the
// public sources that drive one. It is detection and suggestion only: it
// reads kernel counters stored by the metrics platform and the per-source
// counters the XDP shield already reports, and never applies a rule, flips
// a mode or touches a map. Any deny it suggests goes through the existing
// preview, the self-lockout check, the leased enforce mode and fails open.
//
// Per-vector rates are compared with a robust baseline (median and median
// absolute deviation over the lookback window) rather than a fixed rate, in
// the spirit of the behavioural, per-vector DoS vectors of commercial DDoS
// appliances, but with absolute floors so a quiet node does not alarm on a
// small relative change.
package flooddetect

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
)

// Vector names a flood class.
type Vector string

const (
	VectorSYN      Vector = "syn"
	VectorUDP      Vector = "udp"
	VectorICMP     Vector = "icmp"
	VectorFragment Vector = "fragment"
)

const (
	// MaxValues bounds how many points of one signal are examined.
	MaxValues = 5000
	// MinBaseline is the fewest valid baseline points needed to judge.
	MinBaseline = 20
	// TailPoints is how many of the newest points form the current level.
	TailPoints = 3
	// MaxFindings bounds the findings returned for node signals.
	MaxFindings = 200
	// minZ is the robust z-score a rate must clear above the baseline.
	minZ = 6.0
)

// Severity values.
const (
	SeverityWarning  = "warning"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Signal is one evenly spaced rate series (events per second) for a node.
type Signal struct {
	Node   string
	Vector Vector
	Name   string // the kernel signal, for example "syn queue drops and cookies"
	// Floor is the absolute rate below which nothing is reported.
	Floor float64
	// MinRatio is the least multiple of the baseline that is reported.
	MinRatio float64
	// Values are oldest first. NaN, Inf and negative values count as missing.
	Values []float64
}

// NodeFinding is a vector whose current rate is far above its own baseline.
type NodeFinding struct {
	Node     string  `json:"node"`
	Vector   Vector  `json:"vector"`
	Signal   string  `json:"signal"`
	Current  float64 `json:"currentPerSecond"`
	Baseline float64 `json:"baselinePerSecond"`
	Ratio    float64 `json:"ratio"`
	Z        float64 `json:"robustZ"`
	Floor    float64 `json:"floorPerSecond"`
	Severity string  `json:"severity"`
	Message  string  `json:"message"`
}

func clean(v []float64) []float64 {
	if len(v) > MaxValues {
		v = v[len(v)-MaxValues:]
	}
	return v
}

func valid(x float64) bool { return !math.IsNaN(x) && !math.IsInf(x, 0) && x >= 0 }

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	c := append([]float64(nil), v...)
	sort.Float64s(c)
	n := len(c)
	if n%2 == 1 {
		return c[n/2]
	}
	return (c[n/2-1] + c[n/2]) / 2
}

// AnalyzeSignal judges one signal. The newest TailPoints points give the
// current level (their median, so one spiky bucket cannot fire); everything
// before them is the baseline.
func AnalyzeSignal(s Signal) (NodeFinding, bool) {
	vals := clean(s.Values)
	if len(vals) < MinBaseline+TailPoints || s.Floor <= 0 || math.IsNaN(s.Floor) || math.IsInf(s.Floor, 0) {
		return NodeFinding{}, false
	}
	tail := vals[len(vals)-TailPoints:]
	var tv []float64
	for _, x := range tail {
		if valid(x) {
			tv = append(tv, x)
		}
	}
	if len(tv) < 2 { // need most of the tail present
		return NodeFinding{}, false
	}
	var base []float64
	for _, x := range vals[:len(vals)-TailPoints] {
		if valid(x) {
			base = append(base, x)
		}
	}
	if len(base) < MinBaseline {
		return NodeFinding{}, false
	}
	cur := median(tv)
	b := median(base)
	dev := make([]float64, len(base))
	for i, x := range base {
		dev[i] = math.Abs(x - b)
	}
	spread := math.Max(1.4826*median(dev), math.Max(0.1*b, 0.01*s.Floor))
	z := (cur - b) / spread
	minRatio := s.MinRatio
	if !(minRatio >= 1) {
		minRatio = 3
	}
	if cur < s.Floor || z < minZ || cur < minRatio*b {
		return NodeFinding{}, false
	}
	x := cur / math.Max(b, s.Floor)
	sev := SeverityWarning
	switch {
	case x >= 10:
		sev = SeverityCritical
	case x >= 4:
		sev = SeverityHigh
	}
	ratio := math.Inf(1)
	if b > 0 {
		ratio = cur / b
	}
	f := NodeFinding{Node: s.Node, Vector: s.Vector, Signal: s.Name, Current: round2(cur), Baseline: round2(b), Z: round2(z), Floor: s.Floor, Severity: sev}
	if !math.IsInf(ratio, 0) {
		f.Ratio = round2(ratio)
	}
	f.Message = fmt.Sprintf("%s on %s is %.1f/s against a baseline of %.1f/s", s.Name, s.Node, cur, b)
	return f, true
}

func round2(x float64) float64 { return math.Round(x*100) / 100 }

func sevRank(s string) int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityHigh:
		return 2
	}
	return 1
}

// Analyze judges every signal and returns findings worst first, bounded.
func Analyze(signals []Signal) []NodeFinding {
	var out []NodeFinding
	for _, s := range signals {
		if f, ok := AnalyzeSignal(s); ok {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if sevRank(out[i].Severity) != sevRank(out[j].Severity) {
			return sevRank(out[i].Severity) > sevRank(out[j].Severity)
		}
		if out[i].Z != out[j].Z {
			return out[i].Z > out[j].Z
		}
		if out[i].Node != out[j].Node {
			return out[i].Node < out[j].Node
		}
		return out[i].Signal < out[j].Signal
	})
	if len(out) > MaxFindings {
		out = out[:MaxFindings]
	}
	return out
}

// Suggestion is a SUGGESTED leased deny for a flooding source. It is text
// and a request body for the existing review-only preview. Nothing here
// applies it.
type Suggestion struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Direction string `json:"direction"`
	Protocol  string `json:"protocol,omitempty"`
	// PreviewRequest is the body for POST /api/v1/ebpf/deny/preview.
	PreviewRequest map[string]any `json:"previewRequest"`
	Steps          []string       `json:"steps"`
}

// Suggest returns a deny suggestion for source, or a reason it is not
// suggested. Only a public unicast address is ever suggested: a private,
// loopback, link-local, multicast, unspecified or malformed address is a
// workload or node to investigate, not something to deny at the edge.
func Suggest(address, class string) (*Suggestion, string) {
	a, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return nil, "address is not a valid IP; nothing suggested"
	}
	a = a.Unmap()
	switch {
	case a.IsUnspecified(), a.IsLoopback(), a.IsMulticast(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(), a.IsInterfaceLocalMulticast():
		return nil, "address is not a routable unicast address; nothing suggested"
	case a.IsPrivate():
		return nil, "address is private (a cluster, node or internal host); investigate the workload or node instead of denying it"
	case !a.IsGlobalUnicast():
		return nil, "address is not a global unicast address; nothing suggested"
	}
	proto := ""
	if class == "syn" {
		proto = "TCP"
	}
	req := map[string]any{"kind": "ip", "value": a.String(), "direction": "ingress"}
	if proto != "" {
		req["protocol"] = proto
	}
	return &Suggestion{
		Kind: "ip", Value: a.String(), Direction: "ingress", Protocol: proto, PreviewRequest: req,
		Steps: []string{
			"Preview the blast radius: POST /api/v1/ebpf/deny/preview with previewRequest (review the lockout section).",
			"Only if the preview and lockout check are clean: POST /api/v1/ebpf/deny with the ip and direction ingress, then PUT /api/v1/ebpf/mode enforce with a short lease. Enforce is leased and fails open to observe.",
			"Source addresses of a flood are often spoofed: denying one may block an innocent address. Prefer a SYN-drop or rate limit at the upstream edge when the source set is large.",
		},
	}, ""
}
