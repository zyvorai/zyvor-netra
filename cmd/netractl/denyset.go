// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/zyvorai/netra/internal/denyset"
)

const denysetUsage = "denyset validate FILE | plan FILE [--break-glass WHY] [--json] | apply FILE --plan-hash H --confirm-risk RISK [--break-glass WHY] | leases [--expiring] [--within 15m] [--owner N] | history [--owner N] [--limit N] [--since 1h] | rails"

const maxDenysetFile = denyset.MaxFileBytes

func readDenysetFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, maxDenysetFile+1)
	n, err := f.Read(b)
	if err != nil && n == 0 {
		return nil, err
	}
	if n > maxDenysetFile {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxDenysetFile)
	}
	return b[:n], nil
}

// denysetFlags parses --flag value pairs after the positional args.
func denysetFlags(args []string, allowed map[string]bool) (map[string]string, error) {
	out := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			return nil, fmt.Errorf("unexpected argument %q", a)
		}
		name := strings.TrimPrefix(a, "--")
		kind, ok := map[bool]string{true: "bool", false: "value"}[name == "json" || name == "expiring"], allowed[name]
		if !ok {
			return nil, fmt.Errorf("unknown flag %s", a)
		}
		if kind == "bool" {
			out[name] = "true"
			continue
		}
		if i+1 >= len(args) {
			return nil, fmt.Errorf("%s needs a value", a)
		}
		i++
		out[name] = args[i]
	}
	return out, nil
}

func denysetCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", denysetUsage)
	}
	switch args[0] {
	case "validate":
		if len(args) != 2 {
			return fmt.Errorf("denyset validate FILE")
		}
		data, err := readDenysetFile(args[1])
		if err != nil {
			return err
		}
		f, errs := denyset.Parse(data)
		if len(errs) > 0 {
			for _, e := range errs {
				fmt.Fprintf(os.Stderr, "%s:%d: %s\n", args[1], e.Line, e.Message)
			}
			return fmt.Errorf("%d validation error(s)", len(errs))
		}
		fmt.Printf("%s: ok (%s, %d rules, every rule leased)\n", args[1], f.Name, len(f.Rules))
		return nil
	case "plan":
		if len(args) < 2 {
			return fmt.Errorf("denyset plan FILE [--break-glass WHY] [--json]")
		}
		fl, err := denysetFlags(args[2:], map[string]bool{"break-glass": true, "json": true})
		if err != nil {
			return err
		}
		body, err := denysetBody(args[1], "", fl["break-glass"])
		if err != nil {
			return err
		}
		out, status, err := doRequest("POST", "/api/v1/ebpf/denysets/plan", body, nil)
		if err != nil {
			return err
		}
		if status >= 300 {
			return denysetHTTPError(args[1], status, out)
		}
		if fl["json"] == "true" {
			fmt.Println(string(out))
			return nil
		}
		return printDenysetPlan(out)
	case "apply":
		if len(args) < 2 {
			return fmt.Errorf("denyset apply FILE --plan-hash H --confirm-risk RISK")
		}
		fl, err := denysetFlags(args[2:], map[string]bool{"plan-hash": true, "confirm-risk": true, "break-glass": true})
		if err != nil {
			return err
		}
		if fl["plan-hash"] == "" {
			return fmt.Errorf("--plan-hash is required: run denyset plan FILE and pass its planHash")
		}
		body, err := denysetBody(args[1], fl["plan-hash"], fl["break-glass"])
		if err != nil {
			return err
		}
		// Re-plan to obtain a receipt bound to the plan the server computes now,
		// and refuse unless it is the plan the operator reviewed.
		planBody, _ := denysetBody(args[1], "", fl["break-glass"])
		out, status, err := doRequest("POST", "/api/v1/ebpf/denysets/plan", planBody, nil)
		if err != nil {
			return err
		}
		if status >= 300 {
			return denysetHTTPError(args[1], status, out)
		}
		var planned struct {
			PlanHash string `json:"planHash"`
			Risk     string `json:"risk"`
			Receipt  *struct {
				Token string `json:"token"`
			} `json:"receipt"`
		}
		if err := json.Unmarshal(out, &planned); err != nil {
			return fmt.Errorf("decode plan: %w", err)
		}
		if planned.PlanHash != fl["plan-hash"] {
			return fmt.Errorf("plan hash changed (reviewed %s, now %s): file or leases differ; plan again and review", fl["plan-hash"], planned.PlanHash)
		}
		if planned.Receipt == nil || planned.Receipt.Token == "" {
			// Nothing to change, or a rail blocks the plan; apply reports which.
			planned.Receipt = &struct {
				Token string `json:"token"`
			}{}
		}
		headers := map[string]string{"X-Netra-Plan-Token": planned.Receipt.Token}
		risk := strings.ToLower(planned.Risk)
		if risk == "high" || risk == "critical" {
			if !strings.EqualFold(strings.TrimSpace(fl["confirm-risk"]), risk) {
				return fmt.Errorf("plan risk is %s; re-run with --confirm-risk %s", risk, risk)
			}
			headers["X-Netra-Confirm-Risk"] = risk
		}
		out, status, err = doRequest("POST", "/api/v1/ebpf/denysets/apply", body, headers)
		if err != nil {
			return err
		}
		if status >= 300 {
			return denysetHTTPError(args[1], status, out)
		}
		return prettyPrint(out)
	case "leases":
		fl, err := denysetFlags(args[1:], map[string]bool{"expiring": true, "within": true, "owner": true})
		if err != nil {
			return err
		}
		q := url.Values{}
		for _, k := range []string{"within", "owner"} {
			if fl[k] != "" {
				q.Set(k, fl[k])
			}
		}
		if fl["expiring"] == "true" {
			q.Set("expiring", "true")
		}
		return request("GET", "/api/v1/ebpf/deny-leases?"+q.Encode(), nil)
	case "history":
		fl, err := denysetFlags(args[1:], map[string]bool{"owner": true, "limit": true, "since": true})
		if err != nil {
			return err
		}
		q := url.Values{}
		for _, k := range []string{"owner", "limit", "since"} {
			if fl[k] != "" {
				q.Set(k, fl[k])
			}
		}
		return request("GET", "/api/v1/ebpf/deny-leases/history?"+q.Encode(), nil)
	case "rails":
		return request("GET", "/api/v1/ebpf/deny-leases/rails", nil)
	}
	return fmt.Errorf("%s", denysetUsage)
}

func denysetBody(path, planHash, breakGlass string) ([]byte, error) {
	data, err := readDenysetFile(path)
	if err != nil {
		return nil, err
	}
	m := map[string]string{"file": string(data)}
	if planHash != "" {
		m["planHash"] = planHash
	}
	if breakGlass != "" {
		m["breakGlass"] = breakGlass
	}
	return json.Marshal(m)
}

func prettyPrint(out []byte) error {
	var v any
	if json.Unmarshal(out, &v) == nil {
		x, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(x))
		return nil
	}
	fmt.Print(string(out))
	return nil
}

// denysetHTTPError prints line-numbered validation errors and rail codes.
func denysetHTTPError(path string, status int, out []byte) error {
	var e struct {
		Error  string `json:"error"`
		Code   string `json:"code"`
		Errors []struct {
			Line    int    `json:"line"`
			Message string `json:"message"`
		} `json:"errors"`
		Trips []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"trips"`
		BreakGlass bool `json:"breakGlassRequired"`
	}
	if json.Unmarshal(out, &e) != nil || e.Error == "" {
		return fmt.Errorf("HTTP %d: %s", status, string(out))
	}
	for _, x := range e.Errors {
		fmt.Fprintf(os.Stderr, "%s:%d: %s\n", path, x.Line, x.Message)
	}
	for _, t := range e.Trips {
		fmt.Fprintf(os.Stderr, "rail %s: %s\n", t.Code, t.Message)
	}
	msg := fmt.Sprintf("HTTP %d %s: %s", status, e.Code, e.Error)
	if e.BreakGlass {
		msg += " (re-run with --break-glass \"reason\")"
	}
	return fmt.Errorf("%s", msg)
}

func printDenysetPlan(out []byte) error {
	var p struct {
		Name     string         `json:"name"`
		PlanHash string         `json:"planHash"`
		Risk     string         `json:"risk"`
		Summary  map[string]int `json:"summary"`
		Items    []struct {
			Action  string `json:"action"`
			Summary string `json:"summary"`
			Lease   int64  `json:"leaseSeconds"`
			Note    string `json:"note"`
			Lockout *struct {
				Risk string `json:"risk"`
			} `json:"lockout"`
			Preview *struct {
				HitCount int `json:"hitCount"`
			} `json:"preview"`
		} `json:"items"`
		Rails struct {
			Trips []struct {
				Code, Message string
			} `json:"trips"`
		} `json:"rails"`
		Applicable bool   `json:"applicable"`
		BreakGlass bool   `json:"breakGlassRequired"`
		Caveat     string `json:"caveat"`
	}
	if err := json.Unmarshal(out, &p); err != nil {
		return prettyPrint(out)
	}
	fmt.Printf("denyset %s\nplan hash: %s\nrisk: %s\n", p.Name, p.PlanHash, p.Risk)
	fmt.Printf("add %d, extend %d, remove %d, unchanged %d, skipped %d\n\n", p.Summary["add"], p.Summary["extend"], p.Summary["remove"], p.Summary["unchanged"], p.Summary["skip"])
	for _, it := range p.Items {
		line := fmt.Sprintf("  %-9s %s", it.Action, it.Summary)
		if it.Lease > 0 {
			line += fmt.Sprintf("  lease %ds", it.Lease)
		}
		if it.Lockout != nil && it.Lockout.Risk != "none-detected" {
			line += "  lockout:" + it.Lockout.Risk
		}
		if it.Preview != nil {
			line += fmt.Sprintf("  observed-hits:%d", it.Preview.HitCount)
		}
		if it.Note != "" {
			line += "  (" + it.Note + ")"
		}
		fmt.Println(line)
	}
	for _, t := range p.Rails.Trips {
		fmt.Printf("\nrail would trip: %s: %s\n", t.Code, t.Message)
	}
	if p.BreakGlass {
		fmt.Println("break-glass required: pass --break-glass \"reason\" to plan and apply")
	}
	if p.Applicable {
		fmt.Printf("\napply: netractl denyset apply FILE --plan-hash %s --confirm-risk %s\n", p.PlanHash, p.Risk)
	}
	fmt.Println("\n" + p.Caveat)
	return nil
}
