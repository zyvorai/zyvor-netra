// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package oidcauth verifies OIDC/JWT bearer tokens for the Netra API and maps
// a token's claims to one of three roles. It is verification only: it never
// issues tokens and never talks to the IdP except to fetch signing keys.
package oidcauth

import (
	"fmt"
	"strings"
)

// Role is a coarse privilege level. Higher values include lower ones.
type Role uint8

const (
	// RoleNone means "authenticated, but no Netra role": always denied.
	RoleNone Role = iota
	// RoleViewer may read state and run read-only computations.
	RoleViewer
	// RoleOperator may also change enforcement rules and start captures.
	RoleOperator
	// RoleAdmin may also change posture, apply policy, and open consoles.
	RoleAdmin
)

func (r Role) String() string {
	switch r {
	case RoleViewer:
		return "viewer"
	case RoleOperator:
		return "operator"
	case RoleAdmin:
		return "admin"
	default:
		return "none"
	}
}

// AtLeast reports whether r grants everything need does.
func (r Role) AtLeast(need Role) bool { return r >= need }

// ParseRole reads a role name; "" and "none" both mean RoleNone.
func ParseRole(s string) (Role, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none":
		return RoleNone, nil
	case "viewer":
		return RoleViewer, nil
	case "operator":
		return RoleOperator, nil
	case "admin":
		return RoleAdmin, nil
	default:
		return RoleNone, fmt.Errorf("unknown role %q (want viewer, operator, admin)", s)
	}
}

// ParseRoleMap reads "claimValue=role,claimValue=role", e.g.
// "netra-admins=admin,sre=operator,everyone=viewer". Claim values are matched
// case-sensitively, as IdPs treat group names.
func ParseRoleMap(s string) (map[string]Role, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	out := map[string]Role{}
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, fmt.Errorf("role map entry %q must be claimValue=role", part)
		}
		r, err := ParseRole(v)
		if err != nil {
			return nil, err
		}
		if r == RoleNone {
			return nil, fmt.Errorf("role map entry %q maps to no role", part)
		}
		out[k] = r
	}
	return out, nil
}
