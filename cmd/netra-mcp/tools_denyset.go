// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/zyvorai/netra/internal/mcpserver"
)

// denysetReadTools are the always-available, read-only declarative-denyset
// tools. netra_denyset_plan opts out of the preflight receipt with a fixed
// header, so a read-only MCP session can never obtain a token that applies
// anything.
func denysetReadTools() []endpointTool {
	return []endpointTool{
		{
			name: "netra_denyset_plan", method: "POST", path: "/api/v1/ebpf/denysets/plan",
			description: "Read-only plan for a declarative leased-deny file (format netra-denyset/1). Validates it (line-numbered errors), diffs it against current leases (add/extend/remove/unchanged/skip), runs the deny-preview and self-lockout check per rule, dry-runs the lease safety rails and returns a stable planHash. Applies nothing and returns no apply receipt. Rules are always lease-bounded; removal only ever touches leases the same denyset created.",
			schema: objSchema(map[string]any{
				"file":       strProp("Full denyset file text, starting with the line netra-denyset/1."),
				"breakGlass": strProp("Optional break-glass justification (8-200 chars) to dry-run a catch-all or protected-destination rule."),
			}, "file"),
			bodyFields: true,
			headers:    map[string]string{"X-Netra-No-Receipt": "1"},
		},
		{
			name: "netra_deny_leases", method: "GET", path: "/api/v1/ebpf/deny-leases",
			description: "Active denyset leases with time remaining. Set expiring=true (and optionally within, default 15m) to list only leases about to lapse. Read-only.",
			schema: objSchema(map[string]any{
				"owner":    strProp("Only leases owned by this denyset name."),
				"within":   strProp("Expiring-soon window, e.g. 15m (1s-24h)."),
				"expiring": strProp("\"true\" to list only leases ending within the window."),
			}),
			queryParams: []string{"owner", "within", "expiring"},
		},
		{
			name: "netra_deny_lease_history", method: "GET", path: "/api/v1/ebpf/deny-leases/history",
			description: "Read-only timeline of lease create, extend, expire, revoke and rail rejections with the actor and the rail decisions (including audited break-glass). Newest first.",
			schema: objSchema(map[string]any{
				"owner": strProp("Only events for this denyset name."),
				"limit": intProp("Max events, 1-1000. Default 200."),
				"since": strProp("Duration (up to 720h) or RFC3339 start."),
			}),
			queryParams: []string{"owner", "limit", "since"},
		},
		{
			name: "netra_deny_lease_rails", method: "GET", path: "/api/v1/ebpf/deny-leases/rails",
			description: "Read-only lease safety rail configuration (max concurrent leases, max duration, prefix breadth, break-glass, per-actor rate) and current usage. Rails are off unless the operator configured them.",
			schema:      objSchema(map[string]any{}),
		},
	}
}

// denysetMutateTools need NETRA_MCP_ALLOW_MUTATIONS: the plan variant that
// returns a single-use receipt, and the apply.
func registerDenysetMutateTools(srv *mcpserver.Server, c *client) error {
	if err := registerEndpointTool(srv, c, endpointTool{
		name: "netra_denyset_plan_receipt", method: "POST", path: "/api/v1/ebpf/denysets/plan",
		description: "Same plan as netra_denyset_plan but also issues a single-use, 5-minute receipt.token bound to the plan hash. Pass it as plan_token to netra_denyset_apply together with the returned planHash. Plan risk is high (critical if the lockout check says likely); apply needs confirm_risk equal to it.",
		schema: objSchema(map[string]any{
			"file":       strProp("Full denyset file text."),
			"breakGlass": strProp("Optional break-glass justification (8-200 chars)."),
		}, "file"),
		bodyFields: true,
	}); err != nil {
		return err
	}
	return srv.Register(mcpserver.Tool{
		Name:        "netra_denyset_apply",
		Description: "Apply a declarative leased-deny file. Requires plan_hash and plan_token from netra_denyset_plan_receipt for the identical file, and confirm_risk equal to the plan risk. Applies only if the plan hash still matches the current leases and the lease safety rails allow it; every rule is lease-bounded, removals only touch leases this denyset created, and the mode is never changed. Catch-all or protected-destination rules additionally need break_glass when the operator enabled that rail; it is audited.",
		InputSchema: objSchema(map[string]any{
			"file":         strProp("Must be identical to the planned file."),
			"plan_hash":    strProp("planHash from the plan."),
			"plan_token":   strProp("receipt.token from netra_denyset_plan_receipt."),
			"confirm_risk": enumProp("Must equal the plan's risk.", "low", "medium", "high", "critical"),
			"break_glass":  strProp("Break-glass justification (8-200 chars), only when the plan says it is required."),
		}, "file", "plan_hash", "plan_token"),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			var a struct {
				File        string `json:"file"`
				PlanHash    string `json:"plan_hash"`
				PlanToken   string `json:"plan_token"`
				ConfirmRisk string `json:"confirm_risk"`
				BreakGlass  string `json:"break_glass"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return fmt.Sprintf("invalid arguments: %v", err), true, nil
			}
			body, _ := json.Marshal(map[string]string{"file": a.File, "planHash": a.PlanHash, "breakGlass": a.BreakGlass})
			extra := map[string]string{"X-Netra-Plan-Token": a.PlanToken}
			if a.ConfirmRisk != "" {
				extra["X-Netra-Confirm-Risk"] = a.ConfirmRisk
			}
			out, status, err := c.do(ctx, "POST", "/api/v1/ebpf/denysets/apply", body, extra)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}
