// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// statusCmd prints a Cilium-style human-readable cluster board, or JSON with --json.
func statusCmd(args []string, out io.Writer) error {
	if out == nil {
		out = os.Stdout
	}
	asJSON := false
	wait := false
	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
		case "--wait":
			wait = true
		case "-h", "--help":
			fmt.Fprintln(out, "netractl status [--json] [--wait]")
			return nil
		default:
			return fmt.Errorf("unknown status flag: %s", a)
		}
	}
	if !asJSON {
		maybeBanner()
	}

	var lastErr error
	deadline := time.Now().Add(2 * time.Minute)
	for {
		rep, err := collectStatusReport()
		if err != nil {
			lastErr = err
			if !wait || time.Now().After(deadline) {
				return err
			}
			fmt.Fprintf(os.Stderr, "waiting for controller: %v\n", err)
			time.Sleep(3 * time.Second)
			continue
		}
		if asJSON {
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(rep)
		}
		formatStatusReport(out, rep)
		if wait && !rep.Healthy {
			if time.Now().After(deadline) {
				return fmt.Errorf("cluster not healthy after --wait")
			}
			time.Sleep(3 * time.Second)
			continue
		}
		if !rep.Healthy && !rep.ControllerOnly {
			return fmt.Errorf("cluster unhealthy: %s", rep.Summary)
		}
		_ = lastErr
		return nil
	}
}

type statusReport struct {
	Version         string       `json:"version"`
	Datapath        string       `json:"datapath"`
	Mode            string       `json:"mode,omitempty"`
	Agents          int          `json:"agents"`
	StaleAgents     int          `json:"staleAgents"`
	CiliumEnabled   bool         `json:"ciliumEnabled"`
	HubbleOK        bool         `json:"hubbleOk"`
	HubbleError     string       `json:"hubbleError,omitempty"`
	LeaseActive     bool         `json:"leaseActive"`
	LeaseUntil      string       `json:"leaseUntil,omitempty"`
	FeaturesOn      int          `json:"featuresOn"`
	FeaturesOff     int          `json:"featuresOff"`
	FeaturesUnknown int          `json:"featuresUnknown"`
	Nodes           []statusNode `json:"nodes,omitempty"`
	Healthy         bool         `json:"healthy"`
	ControllerOnly  bool         `json:"controllerOnly"`
	Summary         string       `json:"summary"`
}

type statusNode struct {
	Node   string   `json:"node"`
	Stale  bool     `json:"stale"`
	Mode   string   `json:"mode,omitempty"`
	Hooks  []string `json:"hooks,omitempty"`
	AgeSec int64    `json:"ageSeconds,omitempty"`
}

func collectStatusReport() (*statusReport, error) {
	statusBody, _, err := doRequest("GET", "/api/v1/status", nil, nil)
	if err != nil {
		return nil, err
	}
	var status map[string]any
	if err := json.Unmarshal(statusBody, &status); err != nil {
		return nil, err
	}

	fleetBody, _, _ := doRequest("GET", "/api/v1/fleet", nil, nil)
	var fleet map[string]any
	_ = json.Unmarshal(fleetBody, &fleet)

	leaseBody, _, _ := doRequest("GET", "/api/v1/lease", nil, nil)
	var lease map[string]any
	_ = json.Unmarshal(leaseBody, &lease)

	featBody, _, _ := doRequest("GET", "/api/v1/features", nil, nil)
	var featWrap struct {
		Features []struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
			Source  string `json:"source"`
		} `json:"features"`
	}
	_ = json.Unmarshal(featBody, &featWrap)

	rep := &statusReport{
		Version:       strAny(status["version"]),
		Datapath:      strAny(status["datapath"]),
		CiliumEnabled: boolAny(status["ciliumEnabled"]),
		Agents:        intAny(status["agents"]),
		StaleAgents:   intAny(status["staleAgents"]),
	}
	if fp, ok := status["fastPath"].(map[string]any); ok {
		rep.Mode = strAny(fp["mode"])
		if eu := strAny(fp["enforceUntil"]); eu != "" {
			rep.LeaseActive = true
			rep.LeaseUntil = eu
		}
	}
	if he := strAny(status["hubbleError"]); he != "" {
		rep.HubbleError = he
	} else if status["hubble"] != nil {
		rep.HubbleOK = true
	}
	if lease != nil {
		if boolAny(lease["active"]) || strAny(lease["mode"]) == "enforce" {
			rep.LeaseActive = true
		}
		if u := strAny(lease["enforceUntil"]); u != "" {
			rep.LeaseUntil = u
		}
	}
	for _, f := range featWrap.Features {
		switch {
		case f.Source == "unknown":
			rep.FeaturesUnknown++
		case f.Enabled:
			rep.FeaturesOn++
		default:
			rep.FeaturesOff++
		}
	}

	// Prefer fleet inventory for per-node detail when present.
	if agents, ok := fleet["agents"].([]any); ok {
		for _, a := range agents {
			m, _ := a.(map[string]any)
			if m == nil {
				continue
			}
			n := statusNode{
				Node:   strAny(m["node"]),
				Stale:  boolAny(m["stale"]),
				Mode:   strAny(m["mode"]),
				AgeSec: int64(intAny(m["ageSeconds"])),
			}
			if hooks, ok := m["hooks"].([]any); ok {
				for _, h := range hooks {
					n.Hooks = append(n.Hooks, fmt.Sprint(h))
				}
			}
			rep.Nodes = append(rep.Nodes, n)
		}
	}
	if len(rep.Nodes) == 0 && rep.Agents == 0 {
		rep.ControllerOnly = true
		rep.Healthy = true
		rep.Summary = "controller reachable; no agents reporting (controller-only or agent not enabled)"
	} else if rep.Agents == 0 {
		rep.Healthy = false
		rep.Summary = "no agents reporting"
	} else if rep.StaleAgents == rep.Agents {
		rep.Healthy = false
		rep.Summary = "all agents stale"
	} else {
		rep.Healthy = true
		rep.Summary = fmt.Sprintf("%d agents (%d stale)", rep.Agents, rep.StaleAgents)
	}
	return rep, nil
}

func formatStatusReport(w io.Writer, r *statusReport) {
	fmt.Fprintf(w, "Netra status\n")
	fmt.Fprintf(w, "  Version:          %s\n", dash(r.Version))
	fmt.Fprintf(w, "  Datapath:         %s\n", dash(r.Datapath))
	fmt.Fprintf(w, "  Fast-path mode:   %s\n", dash(r.Mode))
	fmt.Fprintf(w, "  Cilium:           %s\n", onOff(r.CiliumEnabled))
	hubble := "ok"
	if r.HubbleError != "" {
		hubble = "error: " + r.HubbleError
	} else if !r.HubbleOK {
		hubble = "disabled / unavailable"
	}
	fmt.Fprintf(w, "  Hubble:           %s\n", hubble)
	lease := "observe (no active lease)"
	if r.LeaseActive {
		lease = "enforce"
		if r.LeaseUntil != "" {
			lease += " until " + r.LeaseUntil
		}
	}
	fmt.Fprintf(w, "  Lease:            %s\n", lease)
	fmt.Fprintf(w, "  Agents:           %d reporting (%d stale)\n", r.Agents, r.StaleAgents)
	fmt.Fprintf(w, "  Features:         %d on / %d off / %d unknown\n", r.FeaturesOn, r.FeaturesOff, r.FeaturesUnknown)
	fmt.Fprintf(w, "  Summary:          %s\n", r.Summary)
	if len(r.Nodes) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Nodes")
		for _, n := range r.Nodes {
			state := "ok"
			if n.Stale {
				state = "STALE"
			}
			hooks := strings.Join(n.Hooks, ",")
			if hooks == "" {
				hooks = "-"
			}
			fmt.Fprintf(w, "  %-24s  %-6s  mode=%-8s  hooks=%s\n", n.Node, state, dash(n.Mode), hooks)
		}
	}
	fmt.Fprintln(w)
}

func strAny(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func boolAny(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	default:
		return false
	}
}

func intAny(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case json.Number:
		i, _ := t.Int64()
		return int(i)
	default:
		return 0
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func onOff(v bool) string {
	if v {
		return "enabled"
	}
	return "disabled"
}
