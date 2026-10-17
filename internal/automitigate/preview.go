// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package automitigate

import (
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/scandetect"
)

// Candidate is one control auto-mitigate would apply under an active
// enforce lease. Preview never mutates store or datapath state.
type Candidate struct {
	Kind      string `json:"kind"` // conn_rate | syn_drop | blocked_ip | shield
	Target    string `json:"target"`
	FindingID string `json:"findingId,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Skipped   string `json:"skipped,omitempty"` // why it would not apply now
}

// PreviewResult is GET /api/v1/ebpf/auto-mitigate/preview.
type PreviewResult struct {
	Enabled           bool        `json:"enabled"`
	LeaseActive       bool        `json:"leaseActive"`
	Mode              string      `json:"mode,omitempty"`
	Candidates        []Candidate `json:"candidates"`
	WouldActCount     int         `json:"wouldActCount"`
	SkippedRecent     int         `json:"skippedRecent"`
	Note              string      `json:"note"`
	Caveat            string      `json:"caveat"`
}

const previewCaveat = "Shadow preview only — applies nothing. Candidates are derived from current scan findings and UDP destination packet deltas using the same rules as live auto-mitigate. Metric anomalies never feed this path. Actions still require mode=enforce with an active lease."

// Preview evaluates what tick would do without mutating config, seen, or
// lastPkts. UDP deltas use a read-only peek of the last observed counters.
func (e *Engine) Preview(agents []models.AgentStatus) PreviewResult {
	if e == nil {
		return PreviewResult{
			Note:   "disabled",
			Caveat: previewCaveat,
		}
	}
	cfg := e.store.Config()
	leaseActive := cfg.Mode == "enforce" && cfg.EnforceUntil != nil && time.Now().Before(*cfg.EnforceUntil)
	out := PreviewResult{
		Enabled:     e.cfg.Enabled,
		LeaseActive: leaseActive,
		Mode:        cfg.Mode,
		Candidates:  []Candidate{},
		Note:        "Review-only. Live auto-mitigate stays inert without an enforce lease.",
		Caveat:      previewCaveat,
	}
	if !e.cfg.Enabled {
		out.Note = "set NETRA_AUTOMITIGATE_ENABLED=true"
		return out
	}

	acted := 0
	if e.scan != nil {
		for _, f := range e.scan.Findings() {
			if acted >= e.cfg.MaxActionsPerTick {
				break
			}
			if f.Type != scandetect.FindingSYNFlood && f.Type != scandetect.FindingFanOut &&
				f.Type != scandetect.FindingLateral && f.Type != scandetect.FindingPortScan {
				continue
			}
			if e.already(f.ID) {
				out.SkippedRecent++
				out.Candidates = append(out.Candidates, Candidate{
					Kind: "conn_rate", Target: f.Namespace + "/" + f.Pod, FindingID: f.ID,
					Detail: string(f.Type) + " → conn-rate", Skipped: "acted within 10m cooldown",
				})
				continue
			}
			c := Candidate{
				Kind: "conn_rate", Target: f.Namespace + "/" + f.Pod, FindingID: f.ID,
				Detail: string(f.Type) + " → conn-rate lease control",
			}
			if !leaseActive {
				c.Skipped = "no active enforce lease"
			}
			out.Candidates = append(out.Candidates, c)
			if leaseActive {
				out.WouldActCount++
			}
			acted++
			if f.Type == scandetect.FindingSYNFlood && e.cfg.ShieldSynPPS > 0 {
				sc := Candidate{Kind: "shield", Target: "syn", FindingID: f.ID, Detail: "tighten XDP Shield SYN PPS"}
				if !leaseActive {
					sc.Skipped = "no active enforce lease"
				}
				out.Candidates = append(out.Candidates, sc)
				if leaseActive {
					out.WouldActCount++
				}
			}
		}
	}
	for _, a := range agents {
		if a.Stale || acted >= e.cfg.MaxActionsPerTick {
			continue
		}
		for _, st := range a.Stats {
			if acted >= e.cfg.MaxActionsPerTick {
				break
			}
			if !strings.EqualFold(st.Protocol, "UDP") {
				continue
			}
			key := a.Node + "|" + st.DestinationIP + "|udp"
			delta := e.peekDelta(key, st.Packets)
			if delta < e.cfg.UDPPacketDelta {
				continue
			}
			ukey := "udp|" + st.DestinationIP
			if e.already(ukey) {
				out.SkippedRecent++
				out.Candidates = append(out.Candidates, Candidate{
					Kind: "blocked_ip", Target: st.DestinationIP,
					Detail: "udp amplify packet delta", Skipped: "acted within 10m cooldown",
				})
				continue
			}
			c := Candidate{
				Kind: "blocked_ip", Target: st.DestinationIP,
				Detail: "udp amplify packet delta",
			}
			if !leaseActive {
				c.Skipped = "no active enforce lease"
			}
			out.Candidates = append(out.Candidates, c)
			if leaseActive {
				out.WouldActCount++
			}
			acted++
		}
	}
	return out
}

func (e *Engine) peekDelta(key string, now uint64) uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	prev := e.lastPkts[key]
	if now < prev {
		return now
	}
	return now - prev
}
