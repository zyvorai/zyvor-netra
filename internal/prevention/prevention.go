// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package prevention builds a threat-prevention-style effectiveness
// snapshot from intel hits, leased denials, and detector findings.
// Coverage counts — not IPS efficacy percentages.
package prevention

import (
	"time"

	"github.com/zyvorai/netra/internal/ainet"
	"github.com/zyvorai/netra/internal/encdns"
	"github.com/zyvorai/netra/internal/intel"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/watchlist"
)

// Input is gathered by the API layer from store + optional detectors.
type Input struct {
	GeneratedAt         time.Time
	Mode                string
	LeaseUntil          *time.Time
	Agents              []models.AgentStatus
	IntelFeed           []intel.Entry
	BlockedIPv4         int
	BlockedIPv6         int
	BlockedDNS          int
	BlockedSNI          int
	DNSFindings         int
	ScanFindings        int
	AIDestHits          int
	EncDNSDoT           int
	EncDNSDoH           int
	TLSFPUnique         int
	AutoMitigateActions int
}

// Snapshot is the JSON report.
type Snapshot struct {
	GeneratedAt          time.Time `json:"generatedAt"`
	Headline             string    `json:"headline"`
	Mode                 string    `json:"mode"`
	LeaseActive          bool      `json:"leaseActive"`
	LeaseExpiresAt       time.Time `json:"leaseExpiresAt,omitempty"`
	IntelFeedEntries     int       `json:"intelFeedEntries"`
	IntelLiveHits        int       `json:"intelLiveHits"`
	DenyExactIPs         int       `json:"denyExactIps"`
	DenyDNS              int       `json:"denyDns"`
	DenySNI              int       `json:"denySni"`
	DNSDetectorFindings  int       `json:"dnsDetectorFindings"`
	ScanDetectorFindings int       `json:"scanDetectorFindings"`
	AIDestinationHits    int       `json:"aiDestinationHits"`
	DoTSightings         int       `json:"dotSightings"`
	DoHSightings         int       `json:"dohSightings"`
	TLSFingerprints      int       `json:"tlsFingerprints"`
	AutoMitigateActions  int       `json:"autoMitigateActions"`
	CoverageScore        int       `json:"coverageScore"` // 0-100 heuristic completeness
	Coverage             []string  `json:"coverage"`
	Gaps                 []string  `json:"gaps"`
	Note                 string    `json:"note"`
}

// Build derives a Snapshot. When IntelFeed is non-empty, live hits are
// computed via watchlist.Match against Agents.
func Build(in Input) Snapshot {
	now := in.GeneratedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	leaseActive := in.Mode == "enforce" && in.LeaseUntil != nil && now.Before(*in.LeaseUntil)
	intelHits := 0
	if len(in.IntelFeed) > 0 {
		intelHits = watchlist.Match(in.Agents, in.IntelFeed, watchlist.MaxHits).Count
	}
	if in.AIDestHits == 0 {
		in.AIDestHits = ainet.Match(in.Agents, nil, ainet.MaxHits).Count
	}
	if in.EncDNSDoT == 0 && in.EncDNSDoH == 0 {
		ed := encdns.Match(in.Agents, encdns.MaxHits)
		in.EncDNSDoT, in.EncDNSDoH = ed.DoT, ed.DoH
	}

	s := Snapshot{
		GeneratedAt: now, Mode: in.Mode, LeaseActive: leaseActive,
		IntelFeedEntries: len(in.IntelFeed), IntelLiveHits: intelHits,
		DenyExactIPs: in.BlockedIPv4 + in.BlockedIPv6,
		DenyDNS:      in.BlockedDNS, DenySNI: in.BlockedSNI,
		DNSDetectorFindings: in.DNSFindings, ScanDetectorFindings: in.ScanFindings,
		AIDestinationHits: in.AIDestHits, DoTSightings: in.EncDNSDoT, DoHSightings: in.EncDNSDoH,
		TLSFingerprints: in.TLSFPUnique, AutoMitigateActions: in.AutoMitigateActions,
		Note: "Coverage of Netra observe/lease controls — not signature-IPS efficacy.",
	}
	if in.LeaseUntil != nil {
		s.LeaseExpiresAt = *in.LeaseUntil
	}
	var cov, gaps []string
	if s.IntelFeedEntries > 0 {
		cov = append(cov, "threat-intel feed loaded")
		if s.IntelLiveHits > 0 {
			cov = append(cov, "intel entries matching live traffic")
		}
	} else {
		gaps = append(gaps, "no active threat-intel feed (PUT /api/v1/intel/feed)")
	}
	if s.DenyExactIPs+s.DenyDNS+s.DenySNI > 0 {
		cov = append(cov, "deny primitives staged")
	} else {
		gaps = append(gaps, "no deny rules staged")
	}
	if leaseActive {
		cov = append(cov, "enforce lease active (denies effective)")
	} else {
		gaps = append(gaps, "observe mode or expired lease — denies not enforced")
	}
	if s.DNSDetectorFindings+s.ScanDetectorFindings > 0 {
		cov = append(cov, "behavioral detectors reporting findings")
	}
	if s.AIDestinationHits > 0 {
		cov = append(cov, "GenAI/MCP SaaS destinations observed")
	}
	if s.DoTSightings+s.DoHSightings > 0 {
		cov = append(cov, "encrypted DNS (DoT/DoH) observed")
	}
	if s.TLSFingerprints > 0 {
		cov = append(cov, "TLS JA3 fingerprints from datapath/capture ClientHello samples")
	} else {
		gaps = append(gaps, "no JA3 yet — wait for L7 ClientHello samples or start a capture")
	}
	s.Coverage, s.Gaps = cov, gaps
	s.CoverageScore = coverageScore(len(cov), len(gaps), leaseActive, s.IntelFeedEntries > 0)
	s.Headline = headline(s)
	return s
}

func coverageScore(covN, gapN int, lease, feed bool) int {
	s := covN * 12
	if feed {
		s += 15
	}
	if lease {
		s += 20
	}
	s -= gapN * 8
	if s < 0 {
		s = 0
	}
	if s > 100 {
		s = 100
	}
	return s
}

func headline(s Snapshot) string {
	switch {
	case s.LeaseActive && s.IntelLiveHits > 0:
		return "Lease active with live intel hits"
	case s.LeaseActive:
		return "Lease active — prevention window open"
	case s.IntelFeedEntries > 0:
		return "Intel feed loaded (observe); lease inactive"
	default:
		return "Observe posture — load intel / open lease for containment"
	}
}
