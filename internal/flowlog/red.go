// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package flowlog

import (
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// REDRow is rate, errors, and duration for one workload over a window.
// Rate and errors come from flow deltas. Duration is average TCP SRTT.
// HTTP status is a separate cumulative field for cleartext HTTP/1 only.
type REDRow struct {
	Namespace    string   `json:"namespace,omitempty"`
	Pod          string   `json:"pod,omitempty"`
	WorkloadName string   `json:"workloadName,omitempty"`
	Node         string   `json:"node,omitempty"`
	Packets      uint64   `json:"packets"`
	Bytes        uint64   `json:"bytes"`
	RatePerSec   float64  `json:"ratePerSec"`
	Errors       uint64   `json:"errors"`
	ErrorRatio   float64  `json:"errorRatio,omitempty"`
	AvgSRTTUS    uint64   `json:"avgSrttUs,omitempty"`
	DNSFailures  uint64   `json:"dnsFailures,omitempty"`
	HTTPRequests uint64   `json:"httpRequests,omitempty"`
	HTTP5xx      uint64   `json:"http5xx,omitempty"`
	AppProtocols []string `json:"appProtocols,omitempty"`
}

// REDResult is GET /api/v1/insights/red.
type REDResult struct {
	Window      string   `json:"window"`
	Rows        []REDRow `json:"rows"`
	Count       int      `json:"count"`
	Limitations []string `json:"limitations"`
}

func redLimitations() []string {
	return []string{
		"Rate is flow-counter deltas over the window, not an HTTP request trace.",
		"Errors are blocked packets plus TCP retransmission and RTO deltas. Cleartext HTTP/1 5xx counts are a separate field, and only when the status line starts the packet.",
		"Duration is average TCP SRTT on flows that reported one, not a request latency histogram.",
		"DNS failures, HTTP request counts, and HTTP/1 5xx counts are the latest cumulative agent counters, not window deltas. HTTP/3 and split status lines are not decoded.",
		"When NETRA_L7_SAMPLE is on, sampled HTTP/1+HTTP/2+gRPC 5xx (scaled by Eligible/Emitted) are folded into the node-level RED row (key node/); they are estimates and not namespace/pod attributed.",
		"App protocol is a well-known-port hint.",
	}
}

// isHTTP5xxCode reports whether an L7 sample status code string is an HTTP/gRPC 5xx.
func isHTTP5xxCode(code string) bool {
	if len(code) == 0 {
		return false
	}
	// Numeric HTTP statuses: 500-599.
	if code[0] == '5' {
		for i := 1; i < len(code); i++ {
			if code[i] < '0' || code[i] > '9' {
				return false
			}
		}
		return len(code) == 3
	}
	return false
}

// RED aggregates flow records and the live agent snapshot.
func RED(recs []Record, agents []models.AgentStatus, window time.Duration) REDResult {
	if window <= 0 {
		window = 5 * time.Minute
	}
	type acc struct {
		row   REDRow
		srttN uint64
		srttW uint64
		apps  map[string]struct{}
	}
	by := map[string]*acc{}
	for _, rec := range recs {
		key := rec.Namespace + "/" + rec.Pod
		if rec.Pod == "" {
			key = rec.Node + "/"
		}
		a := by[key]
		if a == nil {
			a = &acc{apps: map[string]struct{}{}, row: REDRow{
				Namespace: rec.Namespace, Pod: rec.Pod, WorkloadName: rec.WorkloadName, Node: rec.Node,
			}}
			by[key] = a
		}
		a.row.Packets += rec.Packets
		a.row.Bytes += rec.Bytes
		a.row.Errors += rec.Blocked + rec.Retrans + rec.RTOs
		if rec.SRTTUS > 0 && rec.Packets > 0 {
			a.srttW += rec.SRTTUS * rec.Packets
			a.srttN += rec.Packets
		}
		if rec.AppProtocol != "" {
			a.apps[rec.AppProtocol] = struct{}{}
		}
	}
	dnsFail := map[string]uint64{}
	httpReq := map[string]uint64{}
	http5xx := map[string]uint64{}
	for _, ag := range agents {
		for _, d := range ag.DNSHealth {
			dnsFail[d.Namespace+"/"+d.Pod] += d.Failures
		}
		for _, h := range ag.HTTPMetadata {
			httpReq[h.Namespace+"/"+h.Pod] += h.Requests
		}
		for _, h := range ag.HTTPStatus {
			if h.Status >= 500 {
				http5xx[h.Namespace+"/"+h.Pod] += h.Count
			}
		}
		// Opt-in L7 sampling is node-scoped (no ns/pod). Fold estimated
		// HTTP/1+HTTP/2+gRPC 5xx into the node-level key so RED http5xx is
		// not empty when only the sampler saw the responses.
		if s := ag.L7Sample; s != nil && s.Attached {
			scale := s.ScaleFactor
			if scale < 1 {
				scale = 1
			}
			var n5xx uint64
			for _, p := range s.Protocols {
				switch p.Protocol {
				case "http1", "http2", "grpc":
				default:
					continue
				}
				for _, c := range p.Codes {
					if isHTTP5xxCode(c.Code) {
						n5xx += uint64(float64(c.Count) * scale)
					}
				}
			}
			if n5xx > 0 {
				http5xx[ag.Node+"/"] += n5xx
			}
		}
	}
	sec := window.Seconds()
	if sec <= 0 {
		sec = 1
	}
	rows := make([]REDRow, 0, len(by))
	for key, a := range by {
		if a.row.Packets > 0 {
			a.row.RatePerSec = float64(a.row.Packets) / sec
			a.row.ErrorRatio = float64(a.row.Errors) / float64(a.row.Packets)
		}
		if a.srttN > 0 {
			a.row.AvgSRTTUS = a.srttW / a.srttN
		}
		a.row.DNSFailures = dnsFail[key]
		a.row.HTTPRequests = httpReq[key]
		a.row.HTTP5xx = http5xx[key]
		for app := range a.apps {
			a.row.AppProtocols = append(a.row.AppProtocols, app)
		}
		sort.Strings(a.row.AppProtocols)
		rows = append(rows, a.row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Errors != rows[j].Errors {
			return rows[i].Errors > rows[j].Errors
		}
		return rows[i].Packets > rows[j].Packets
	})
	return REDResult{Window: window.String(), Rows: rows, Count: len(rows), Limitations: redLimitations()}
}
