// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Package denycensus counts deny/allow list sizes without echoing the
// entries themselves.
package denycensus

import (
	"time"

	"github.com/zyvorai/netra/internal/models"
)

type Census struct {
	GeneratedAt      time.Time `json:"generatedAt"`
	Mode             string    `json:"mode"`
	BlockedIPv4      int       `json:"blockedIPv4"`
	BlockedIPv6      int       `json:"blockedIPv6"`
	BlockedCIDRs     int       `json:"blockedCidrs"`
	BlockedPorts     int       `json:"blockedPorts"`
	BlockedDNS       int       `json:"blockedDns"`
	BlockedUIDs      int       `json:"blockedUids"`
	BlockedIngressV4 int       `json:"blockedIngressIPv4"`
	BlockedIngressV6 int       `json:"blockedIngressIPv6"`
	AllowedIPv4      int       `json:"allowedIPv4"`
	AllowedIPv6      int       `json:"allowedIPv6"`
	AllowedCIDRs     int       `json:"allowedCidrs"`
	AllowedPorts     int       `json:"allowedPorts"`
	TotalDenied      int       `json:"totalDenied"`
	TotalAllowed     int       `json:"totalAllowed"`
}

func Build(cfg models.EBPFFastPathConfig, now time.Time) Census {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	c := Census{
		GeneratedAt: now.UTC(), Mode: cfg.Mode,
		BlockedIPv4: len(cfg.BlockedIPv4), BlockedIPv6: len(cfg.BlockedIPv6),
		BlockedCIDRs: len(cfg.BlockedCIDRs), BlockedPorts: len(cfg.BlockedPorts),
		BlockedDNS: len(cfg.BlockedDNS), BlockedUIDs: len(cfg.BlockedUIDs),
		BlockedIngressV4: len(cfg.BlockedIngressIPv4), BlockedIngressV6: len(cfg.BlockedIngressIPv6),
		AllowedIPv4: len(cfg.AllowedIPv4), AllowedIPv6: len(cfg.AllowedIPv6),
		AllowedCIDRs: len(cfg.AllowedCIDRs), AllowedPorts: len(cfg.AllowedPorts),
	}
	c.TotalDenied = c.BlockedIPv4 + c.BlockedIPv6 + c.BlockedCIDRs + c.BlockedPorts + c.BlockedDNS + c.BlockedUIDs + c.BlockedIngressV4 + c.BlockedIngressV6
	c.TotalAllowed = c.AllowedIPv4 + c.AllowedIPv6 + c.AllowedCIDRs + c.AllowedPorts
	return c
}
