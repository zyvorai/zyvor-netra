// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/zyvorai/netra/internal/features"
)

func featuresCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("features list|enable|disable")
	}
	switch args[0] {
	case "list":
		return featuresList(args[1:])
	case "enable":
		return featuresToggle(args[1:], true)
	case "disable":
		return featuresToggle(args[1:], false)
	case "-h", "--help":
		fmt.Println(`netractl features list
netractl features enable  NAME [--yes] [--set via helm]
netractl features disable NAME [--yes]`)
		return nil
	default:
		return fmt.Errorf("features list|enable|disable")
	}
}

func featuresList(args []string) error {
	asJSON := false
	for _, a := range args {
		if a == "--json" {
			asJSON = true
		}
	}
	maybeBanner()

	body, status, err := doRequest("GET", "/api/v1/features", nil, nil)
	if err != nil || status >= 300 {
		fmt.Fprintln(os.Stderr, "controller unreachable; showing catalog (state unknown)")
		if asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]any{"features": features.Catalog(), "note": "controller unreachable"})
		}
		fmt.Printf("%-18s  %-10s  %s\n", "ID", "SCOPE", "TITLE")
		for _, f := range features.Catalog() {
			fmt.Printf("%-18s  %-10s  %s\n", f.ID, f.Scope, f.Title)
		}
		return nil
	}
	if asJSON {
		fmt.Print(string(body))
		if len(body) == 0 || body[len(body)-1] != '\n' {
			fmt.Println()
		}
		return nil
	}
	var wrap struct {
		Features []features.Status `json:"features"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return err
	}
	fmt.Printf("%-18s  %-8s  %-10s  %s\n", "ID", "STATE", "SCOPE", "TITLE")
	for _, f := range wrap.Features {
		state := "off"
		if f.Source == "unknown" {
			state = "?"
		} else if f.Enabled {
			state = "on"
		}
		fmt.Printf("%-18s  %-8s  %-10s  %s\n", f.ID, state, f.Scope, f.Title)
		if f.Note != "" {
			fmt.Printf("  └ %s\n", f.Note)
		}
	}
	return nil
}

func featuresToggle(args []string, enabled bool) error {
	if len(args) < 1 {
		return fmt.Errorf("feature name required")
	}
	id := args[0]
	yes := false
	viaAPI := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--yes", "-y":
			yes = true
		case "--api":
			viaAPI = true
		default:
			return fmt.Errorf("unknown flag: %s", args[i])
		}
	}
	f := features.ByID(id)
	if f == nil {
		return fmt.Errorf("unknown feature: %s (try netractl features list)", id)
	}
	setPair, err := features.HelmSetPair(id, enabled)
	if err != nil {
		return err
	}
	action := "disable"
	if enabled {
		action = "enable"
	}
	maybeBanner()
	fmt.Printf("%s feature %s (%s)\n", action, f.ID, f.Title)
	fmt.Printf("  Helm: --set %s\n", setPair)
	fmt.Printf("  CLI:  %s\n", f.CLI)
	if !yes {
		return fmt.Errorf("refusing without --yes (preview above)")
	}

	if viaAPI {
		body, _ := json.Marshal(map[string]any{"enabled": enabled})
		out, status, err := doRequest("POST", "/api/v1/features/"+id, body, map[string]string{
			"X-Netra-Confirm-Risk": "high",
		})
		if err != nil {
			return err
		}
		if status >= 300 {
			return fmt.Errorf("%s: %s", httpStatusText(status), string(out))
		}
		fmt.Println(string(out))
		return nil
	}

	if _, err := exec.LookPath("helm"); err != nil {
		return fmt.Errorf("helm not on PATH; use --api to patch via controller, or install helm")
	}
	ns := env("NETRA_NAMESPACE", "netra-system")
	release := env("NETRA_RELEASE", "netra")
	chart := chartPath()
	helmArgs := []string{"upgrade", "--install", release, chart, "--namespace", ns, "--reuse-values", "--set", setPair}
	fmt.Printf("Running: helm %s\n", strings.Join(helmArgs, " "))
	cmd := exec.Command("helm", helmArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func httpStatusText(code int) string {
	if code == 0 {
		return "error"
	}
	return fmt.Sprintf("HTTP %d", code)
}
