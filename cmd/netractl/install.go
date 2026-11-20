// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func installCmd(args []string) error {
	return helmLifecycle("install", args)
}

func upgradeCmd(args []string) error {
	return helmLifecycle("upgrade", args)
}

func uninstallCmd(args []string) error {
	ns := env("NETRA_NAMESPACE", "netra-system")
	release := "netra"
	yes := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--namespace", "-n":
			if i+1 >= len(args) {
				return fmt.Errorf("--namespace requires a value")
			}
			ns = args[i+1]
			i++
		case "--release":
			if i+1 >= len(args) {
				return fmt.Errorf("--release requires a value")
			}
			release = args[i+1]
			i++
		case "--yes", "-y":
			yes = true
		case "-h", "--help":
			fmt.Println("netractl uninstall [--namespace NS] [--release NAME] --yes")
			return nil
		default:
			return fmt.Errorf("unknown uninstall flag: %s", args[i])
		}
	}
	if !yes {
		return fmt.Errorf("refusing to uninstall without --yes")
	}
	maybeBanner()
	fmt.Printf("Uninstalling Helm release %s in %s…\n", release, ns)
	cmd := exec.Command("helm", "uninstall", release, "--namespace", ns)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func helmLifecycle(verb string, args []string) error {
	ns := env("NETRA_NAMESPACE", "netra-system")
	release := "netra"
	chart := chartPath()
	nodePort := ""
	extraSet := []string{}
	apiKey := ""
	agentKey := ""
	reuse := verb == "upgrade"
	dryRun := false
	skipCLI := false
	cliPrefix := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--namespace", "-n":
			if i+1 >= len(args) {
				return fmt.Errorf("--namespace requires a value")
			}
			ns = args[i+1]
			i++
		case "--release":
			if i+1 >= len(args) {
				return fmt.Errorf("--release requires a value")
			}
			release = args[i+1]
			i++
		case "--chart":
			if i+1 >= len(args) {
				return fmt.Errorf("--chart requires a value")
			}
			chart = args[i+1]
			i++
		case "--node-port":
			if i+1 >= len(args) {
				return fmt.Errorf("--node-port requires a value")
			}
			nodePort = args[i+1]
			i++
		case "--set":
			if i+1 >= len(args) {
				return fmt.Errorf("--set requires a value")
			}
			extraSet = append(extraSet, args[i+1])
			i++
		case "--api-key":
			if i+1 >= len(args) {
				return fmt.Errorf("--api-key requires a value")
			}
			apiKey = args[i+1]
			i++
		case "--agent-key":
			if i+1 >= len(args) {
				return fmt.Errorf("--agent-key requires a value")
			}
			agentKey = args[i+1]
			i++
		case "--reuse-values":
			reuse = true
		case "--no-reuse-values":
			reuse = false
		case "--dry-run":
			dryRun = true
		case "--skip-cli":
			skipCLI = true
		case "--cli-prefix":
			if i+1 >= len(args) {
				return fmt.Errorf("--cli-prefix requires a value")
			}
			cliPrefix = args[i+1]
			i++
		case "-h", "--help":
			fmt.Printf("netractl %s [--namespace NS] [--release NAME] [--chart PATH] [--node-port N] [--api-key K] [--agent-key K] [--cli-prefix DIR] [--skip-cli] [--set k=v]...\n", verb)
			fmt.Println("  Also installs this netractl onto PATH (make install); use --skip-cli to opt out.")
			return nil
		default:
			return fmt.Errorf("unknown %s flag: %s", verb, args[i])
		}
	}

	if _, err := exec.LookPath("helm"); err != nil {
		return fmt.Errorf("helm not found on PATH")
	}
	if st, err := os.Stat(chart); err != nil || !st.IsDir() {
		return fmt.Errorf("chart not found at %s (set --chart or NETRA_CHART)", chart)
	}

	maybeBanner()

	helmArgs := []string{"upgrade", "--install", release, chart, "--namespace", ns, "--create-namespace"}
	if reuse && verb == "upgrade" {
		helmArgs = append(helmArgs, "--reuse-values")
	}
	if dryRun {
		helmArgs = append(helmArgs, "--dry-run")
	}

	// Defaults for fresh install (not reuse): agent + TLS on.
	if verb == "install" || !reuse {
		helmArgs = append(helmArgs,
			"--set", "agent.enabled=true",
			"--set", "tls.enabled=true",
		)
	}
	if nodePort != "" {
		helmArgs = append(helmArgs,
			"--set", "service.type=NodePort",
			"--set", "service.nodePort="+nodePort,
		)
	}

	if verb == "install" || !reuse {
		if apiKey == "" {
			apiKey = randHex(32)
		}
		if agentKey == "" {
			agentKey = randHex(32)
		}
		helmArgs = append(helmArgs,
			"--set", "auth.apiKey="+apiKey,
			"--set", "auth.agentKey="+agentKey,
		)
		fmt.Fprintf(os.Stderr, "Generated auth.apiKey / auth.agentKey (save them; shown once):\n")
		fmt.Fprintf(os.Stderr, "  export NETRA_API_KEY=%s\n", apiKey)
		fmt.Fprintf(os.Stderr, "  # agent-key is in the netra auth Secret\n")
	}

	for _, s := range extraSet {
		helmArgs = append(helmArgs, "--set", s)
	}

	fmt.Printf("Running: helm %s\n", strings.Join(redactHelmArgs(helmArgs), " "))
	cmd := exec.Command("helm", helmArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	if !dryRun {
		maybeInstallCLIAfterHelm(skipCLI, cliPrefix)
	}
	fmt.Println("Done. Next: netractl status  (export NETRA_URL / NETRA_API_KEY / NETRA_TLS_INSECURE as needed)")
	return nil
}

func chartPath() string {
	if p := os.Getenv("NETRA_CHART"); p != "" {
		return p
	}
	candidates := []string{"./helm/netra", "helm/netra"}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "helm", "netra"))
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return "./helm/netra"
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("netra-%d", os.Getpid())
	}
	return hex.EncodeToString(b)
}

func redactHelmArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i < len(out)-1; i++ {
		if out[i] != "--set" {
			continue
		}
		if strings.HasPrefix(out[i+1], "auth.apiKey=") || strings.HasPrefix(out[i+1], "auth.agentKey=") {
			kv := strings.SplitN(out[i+1], "=", 2)
			out[i+1] = kv[0] + "=***"
		}
	}
	return out
}
