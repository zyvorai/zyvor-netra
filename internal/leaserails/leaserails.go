// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package leaserails holds operator-configured limits checked when a deny
// lease is created. It is pure: no I/O, no store. Every rail is off unless the
// operator sets it, so a controller without configuration behaves as before.
package leaserails

import (
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Rail codes returned in errors, audit entries and metrics.
const (
	CodeMaxConcurrent = "lease_rail_max_concurrent"
	CodeMaxDuration   = "lease_rail_max_duration"
	CodeMaxBreadth    = "lease_rail_max_breadth"
	CodeCatchAll      = "lease_rail_catch_all"
	CodeProtected     = "lease_rail_protected"
	CodeActorRate     = "lease_rail_actor_rate"
	CodeBreakGlass    = "lease_rail_break_glass_invalid"
)

// Codes lists every code, for metrics.
var Codes = []string{CodeMaxConcurrent, CodeMaxDuration, CodeMaxBreadth, CodeCatchAll, CodeProtected, CodeActorRate, CodeBreakGlass}

// Config is the operator configuration. Zero values disable a rail.
type Config struct {
	MaxConcurrent int           `json:"maxConcurrent"`
	MaxDuration   time.Duration `json:"maxDuration"`
	MaxBreadthV4  uint64        `json:"maxBreadthV4"` // total IPv4 addresses across active CIDR leases
	MaxBreadthV6  uint64        `json:"maxBreadthV6"` // total /64 networks across active CIDR leases
	BreakGlass    bool          `json:"breakGlassRequired"`
	RateCount     int           `json:"rateCount"`
	RateWindow    time.Duration `json:"rateWindow"`
}

// Enabled reports whether any rail is on.
func (c Config) Enabled() bool {
	return c.MaxConcurrent > 0 || c.MaxDuration > 0 || c.MaxBreadthV4 > 0 || c.MaxBreadthV6 > 0 || c.BreakGlass || c.RateCount > 0
}

// ParseEnv reads NETRA_LEASE_MAX_CONCURRENT, NETRA_LEASE_MAX_DURATION,
// NETRA_LEASE_MAX_BREADTH_V4, NETRA_LEASE_MAX_BREADTH_V6,
// NETRA_LEASE_BREAK_GLASS_REQUIRED and NETRA_LEASE_ACTOR_RATE ("N/window").
// A malformed value is an error so a typo cannot silently disable a rail.
func ParseEnv(getenv func(string) string) (Config, error) {
	var c Config
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }
	if v := get("NETRA_LEASE_MAX_CONCURRENT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 100000 {
			return Config{}, fmt.Errorf("NETRA_LEASE_MAX_CONCURRENT must be an integer 0-100000")
		}
		c.MaxConcurrent = n
	}
	if v := get("NETRA_LEASE_MAX_DURATION"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			return Config{}, fmt.Errorf("NETRA_LEASE_MAX_DURATION must be a non-negative duration")
		}
		c.MaxDuration = d
	}
	for k, dst := range map[string]*uint64{"NETRA_LEASE_MAX_BREADTH_V4": &c.MaxBreadthV4, "NETRA_LEASE_MAX_BREADTH_V6": &c.MaxBreadthV6} {
		if v := get(k); v != "" {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return Config{}, fmt.Errorf("%s must be a non-negative integer", k)
			}
			*dst = n
		}
	}
	if v := get("NETRA_LEASE_BREAK_GLASS_REQUIRED"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("NETRA_LEASE_BREAK_GLASS_REQUIRED must be a boolean")
		}
		c.BreakGlass = b
	}
	if v := get("NETRA_LEASE_ACTOR_RATE"); v != "" {
		cnt, win, ok := strings.Cut(v, "/")
		n, err1 := strconv.Atoi(strings.TrimSpace(cnt))
		d, err2 := time.ParseDuration(strings.TrimSpace(win))
		if !ok || err1 != nil || err2 != nil || n < 1 || n > 100000 || d < time.Second || d > 24*time.Hour {
			return Config{}, fmt.Errorf("NETRA_LEASE_ACTOR_RATE must look like 10/1m (1-100000 per 1s-24h)")
		}
		c.RateCount, c.RateWindow = n, d
	}
	return c, nil
}

// Op is one lease creation or extension in a request.
type Op struct {
	Rule      string // display text
	Prefix    netip.Prefix
	Seconds   int64
	CatchAll  bool // rule denies everything (prefix /0)
	Protected bool // lockout check says the rule reaches a protected path
}

// Held is one lease that exists (or would exist after the request).
type Held struct {
	Prefix netip.Prefix // invalid for non-CIDR rules
}

// Request is evaluated by Evaluate.
type Request struct {
	Actor       string
	Ops         []Op
	Resulting   []Held // every lease that would exist after applying, all owners
	BreakGlass  string // operator-supplied justification, empty if none
	ActorRecent int    // lease creations/extensions by Actor inside the rate window, before this request
}

// Trip is one rail that fired.
type Trip struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Rule    string `json:"rule,omitempty"`
	// Waivable rails can be overridden with a break-glass confirm.
	Waivable bool `json:"waivable,omitempty"`
}

// Decision is the outcome.
type Decision struct {
	Trips           []Trip `json:"trips"`           // rails that block the request
	Waived          []Trip `json:"waived"`          // waivable rails overridden by a valid break-glass
	BreakGlass      bool   `json:"breakGlass"`      // a break-glass justification was used
	NeedsBreakGlass bool   `json:"needsBreakGlass"` // blocked only by waivable rails
}

// Allowed reports that the request may proceed.
func (d Decision) Allowed() bool { return len(d.Trips) == 0 }

// ValidBreakGlass checks a justification: 8-200 printable characters.
func ValidBreakGlass(reason string) error {
	r := strings.TrimSpace(reason)
	if len(r) < 8 || len(r) > 200 {
		return fmt.Errorf("break-glass justification must be 8-200 characters")
	}
	for _, c := range r {
		if unicode.IsControl(c) || c == unicode.ReplacementChar {
			return fmt.Errorf("break-glass justification contains control or invalid characters")
		}
	}
	return nil
}

// Breadth returns the saturating total of IPv4 addresses and IPv6 /64
// networks covered by prefixes.
func Breadth(prefixes []netip.Prefix) (v4, v6 uint64) {
	for _, p := range prefixes {
		if !p.IsValid() {
			continue
		}
		if p.Addr().Is4() {
			v4 = satAdd(v4, uint64(1)<<(32-uint(p.Bits())))
		} else {
			bits := p.Bits()
			if bits >= 64 {
				v6 = satAdd(v6, 1)
			} else if 64-bits >= 64 {
				v6 = math.MaxUint64
			} else {
				v6 = satAdd(v6, uint64(1)<<uint(64-bits))
			}
		}
	}
	return v4, v6
}

func satAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

// Evaluate checks req against cfg. With cfg disabled it always allows.
func Evaluate(cfg Config, req Request) Decision {
	var d Decision
	if !cfg.Enabled() {
		return d
	}
	var hard, soft []Trip
	if cfg.MaxConcurrent > 0 && len(req.Resulting) > cfg.MaxConcurrent {
		hard = append(hard, Trip{Code: CodeMaxConcurrent, Message: fmt.Sprintf("%d leases would be active; the limit is %d", len(req.Resulting), cfg.MaxConcurrent)})
	}
	if cfg.MaxBreadthV4 > 0 || cfg.MaxBreadthV6 > 0 {
		ps := make([]netip.Prefix, 0, len(req.Resulting))
		for _, h := range req.Resulting {
			ps = append(ps, h.Prefix)
		}
		v4, v6 := Breadth(ps)
		if cfg.MaxBreadthV4 > 0 && v4 > cfg.MaxBreadthV4 {
			hard = append(hard, Trip{Code: CodeMaxBreadth, Message: fmt.Sprintf("active IPv4 lease breadth would be %d addresses; the limit is %d", v4, cfg.MaxBreadthV4)})
		}
		if cfg.MaxBreadthV6 > 0 && v6 > cfg.MaxBreadthV6 {
			hard = append(hard, Trip{Code: CodeMaxBreadth, Message: fmt.Sprintf("active IPv6 lease breadth would be %d /64 networks; the limit is %d", v6, cfg.MaxBreadthV6)})
		}
	}
	if cfg.RateCount > 0 && len(req.Ops) > 0 && req.ActorRecent+len(req.Ops) > cfg.RateCount {
		hard = append(hard, Trip{Code: CodeActorRate, Message: fmt.Sprintf("actor %q would make %d lease changes in %s; the limit is %d", req.Actor, req.ActorRecent+len(req.Ops), cfg.RateWindow, cfg.RateCount)})
	}
	for _, op := range req.Ops {
		if cfg.MaxDuration > 0 && time.Duration(op.Seconds)*time.Second > cfg.MaxDuration {
			hard = append(hard, Trip{Code: CodeMaxDuration, Rule: op.Rule, Message: fmt.Sprintf("lease %s exceeds the maximum %s", time.Duration(op.Seconds)*time.Second, cfg.MaxDuration)})
		}
		if cfg.BreakGlass {
			if op.CatchAll {
				soft = append(soft, Trip{Code: CodeCatchAll, Rule: op.Rule, Waivable: true, Message: "catch-all deny needs a break-glass confirm"})
			} else if op.Protected {
				soft = append(soft, Trip{Code: CodeProtected, Rule: op.Rule, Waivable: true, Message: "deny reaches a protected destination and needs a break-glass confirm"})
			}
		}
	}
	d.Trips = hard
	if len(soft) > 0 {
		if strings.TrimSpace(req.BreakGlass) == "" {
			d.Trips = append(d.Trips, soft...)
			d.NeedsBreakGlass = len(hard) == 0
		} else if err := ValidBreakGlass(req.BreakGlass); err != nil {
			d.Trips = append(d.Trips, Trip{Code: CodeBreakGlass, Message: err.Error()})
			d.Trips = append(d.Trips, soft...)
		} else {
			d.Waived = soft
			d.BreakGlass = true
		}
	}
	return d
}
