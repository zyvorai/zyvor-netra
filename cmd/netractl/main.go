// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var base = strings.TrimRight(env("NETRA_URL", "https://127.0.0.1:30870"), "/")

var configOnce sync.Once

func ensureConfig() {
	configOnce.Do(loadNetraConfig)
}

// loadNetraConfig applies ~/.netra defaults for lab/self-signed installs:
// optional env file, api-key file, and loopback TLS skip-verify when unset.
//
// base is only updated when NETRA_URL is set (after dotenv). The package
// default already covers the unset case — always assigning here would
// clobber httptest URLs that unit tests set before the first doRequest.
func loadNetraConfig() {
	if os.Getenv("NETRA_SKIP_DOTENV") != "1" {
		home, err := os.UserHomeDir()
		if err == nil && home != "" {
			loadEnvFile(filepath.Join(home, ".netra", "env"))
			if os.Getenv("NETRA_API_KEY") == "" {
				if b, err := os.ReadFile(filepath.Join(home, ".netra", "api-key")); err == nil {
					if k := strings.TrimSpace(string(b)); k != "" {
						_ = os.Setenv("NETRA_API_KEY", k)
					}
				}
			}
		}
	}
	if v := strings.TrimSpace(os.Getenv("NETRA_URL")); v != "" {
		base = strings.TrimRight(v, "/")
	}
	if os.Getenv("NETRA_TLS_INSECURE") == "" && urlIsLoopback(base) {
		// Chart default is a self-signed in-pod cert; localhost NodePort
		// access cannot verify it without installing the CA.
		_ = os.Setenv("NETRA_TLS_INSECURE", "true")
	}
}

func loadEnvFile(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		if k == "" || os.Getenv(k) != "" {
			continue
		}
		_ = os.Setenv(k, v)
	}
}

func urlIsLoopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

func tlsInsecure() bool {
	v := strings.TrimSpace(os.Getenv("NETRA_TLS_INSECURE"))
	if strings.EqualFold(v, "false") || v == "0" {
		return false
	}
	if strings.EqualFold(v, "true") || v == "1" {
		return true
	}
	return urlIsLoopback(base)
}

func httpClient(timeout time.Duration) *http.Client {
	ensureConfig()
	c := &http.Client{Timeout: timeout}
	if tlsInsecure() {
		c.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}} // self-signed / local opt-in
	}
	return c
}

func annotateTLSErr(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "x509:") || strings.Contains(msg, "certificate") {
		return fmt.Errorf("%w\nHint: chart TLS is self-signed by default. For NodePort/localhost:\n  export NETRA_TLS_INSECURE=true\n  # or write ~/.netra/env (deploy-remote creates this)\n  export NETRA_URL=https://<node-ip>:30870\n  export NETRA_API_KEY=$(cat ~/.netra/api-key)", err)
	}
	return err
}

func main() {
	ensureConfig()
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// run executes netractl with args (without the binary name). Used by main and CI.
func run(args []string) error {
	if len(args) < 1 {
		usage()
		return nil
	}
	switch args[0] {
	case "-h", "--help", "help":
		if os.Getenv("NETRA_CLI_HELP") == "plain" {
			usagePlain(os.Stdout)
			return nil
		}
		usage()
		return nil
	}

	oldArgs := os.Args
	os.Args = append([]string{"netractl"}, args...)
	defer func() { os.Args = oldArgs }()

	switch args[0] {
	case "explain":
		return explainCmd(args[1:], os.Stdout)
	case "status":
		return statusCmd(args[1:], os.Stdout)
	case "install":
		return installCmd(args[1:])
	case "install-cli":
		return installCLICmd(args[1:])
	case "upgrade":
		return upgradeCmd(args[1:])
	case "uninstall":
		return uninstallCmd(args[1:])
	case "features":
		return featuresCmd(args[1:])
	case "audit":
		if len(args) >= 2 && args[1] == "summary" {
			return request("GET", "/api/v1/audit/summary", nil)
		}
		return request("GET", "/api/v1/audit?limit=100", nil)
	case "export":
		return exportCmd(args[1:])
	case "report":
		return reportCmd(args[1:])
	case "playbooks", "playbook":
		return playbooksCmd(args[1:])
	case "security":
		if len(args) != 2 || (args[1] != "optimizer" && args[1] != "incidents") {
			return fmt.Errorf("security optimizer|incidents")
		}
		return request("GET", "/api/v1/security/"+args[1], nil)
	case "intel":
		return intelCmd(args[1:])
	case "watchlist":
		return watchlistCmd(args[1:])
	case "fleet":
		return request("GET", "/api/v1/fleet", nil)
	case "fleet-clusters":
		return request("GET", "/api/v1/fleet/clusters", nil)
	case "fleet-tenants":
		return request("GET", "/api/v1/fleet/tenants", nil)
	case "compliance":
		return request("GET", "/api/v1/compliance", nil)
	case "node-resources":
		return request("GET", "/api/v1/node-resources", nil)
	case "netlink":
		return netlinkCmd(args[1:])
	case "metrics":
		return metricsCmd(args[1:], os.Stdout)
	case "handoff":
		return handoffCmd(args[1:])
	case "scorecard":
		return request("GET", "/api/v1/scorecard", nil)
	case "talkers":
		return request("GET", "/api/v1/talkers", nil)
	case "namespaces", "heat":
		return request("GET", "/api/v1/namespaces/heat", nil)
	case "protocols":
		return request("GET", "/api/v1/protocols", nil)
	case "baselines":
		return request("GET", "/api/v1/baselines", nil)
	case "ports":
		return request("GET", "/api/v1/ports", nil)
	case "dnsboard":
		return request("GET", "/api/v1/dns/board", nil)
	case "lease":
		return request("GET", "/api/v1/lease", nil)
	case "capture":
		return captureCmd(args[1:])
	case "policy":
		return policy()
	case "flows":
		return flows()
	case "drops":
		return request("GET", "/api/v1/drops/explain", nil)
	case "ebpf":
		return ebpf()
	case "insights":
		return insightCmd()
	case "incidents":
		return incidentsCmd()
	case "ai":
		return aiCmd()
	default:
		return fmt.Errorf("unknown command %q (try: netractl --help)", args[0])
	}
}

func aiCmd() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("ai status|brief|digest|suggestions|ask|agent|draft|explain")
	}
	switch os.Args[2] {
	case "status":
		return request("GET", "/api/v1/ai/status", nil)
	case "brief":
		return request("GET", "/api/v1/ai/brief", nil)
	case "digest":
		return request("GET", "/api/v1/ai/digest", nil)
	case "suggestions":
		return request("GET", "/api/v1/ai/suggestions", nil)
	case "ask", "draft", "agent":
		if len(os.Args) < 4 {
			return fmt.Errorf("ai %s QUESTION...", os.Args[2])
		}
		q := strings.Join(os.Args[3:], " ")
		b, err := json.Marshal(map[string]any{"question": q})
		if err != nil {
			return err
		}
		return request("POST", "/api/v1/ai/"+os.Args[2], b)
	case "explain":
		if len(os.Args) < 4 {
			return fmt.Errorf("ai explain KIND [MESSAGE...]")
		}
		body := map[string]any{"kind": os.Args[3]}
		if len(os.Args) > 4 {
			body["message"] = strings.Join(os.Args[4:], " ")
		}
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		return request("POST", "/api/v1/ai/explain", b)
	default:
		return fmt.Errorf("ai status|brief|digest|suggestions|ask|agent|draft|explain")
	}
}
func policy() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("policy subcommand required")
	}
	switch os.Args[2] {
	case "list":
		ns := "default"
		if len(os.Args) > 4 && os.Args[3] == "--namespace" {
			ns = os.Args[4]
		} else if len(os.Args) > 3 {
			ns = os.Args[3]
		}
		return request("GET", "/api/v1/policies?namespace="+url.QueryEscape(ns), nil)
	case "build":
		return buildPolicy(os.Args[3:])
	case "plan":
		file, err := policyFile(os.Args[3:])
		if err != nil {
			return err
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		return request("POST", "/api/v1/policies/plan", b)
	case "simulate":
		file, err := policyFile(os.Args[3:])
		if err != nil {
			return err
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		return request("POST", "/api/v1/policies/simulate", b)
	case "apply":
		file, err := policyFile(os.Args[3:])
		if err != nil {
			return err
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		if hasArg(os.Args[3:], "--dry-run") {
			return request("POST", "/api/v1/policies/apply?dryRun=true", b)
		}
		return planAndApply(b, flagValue(os.Args[3:], "--confirm-risk"))
	case "gitops":
		if len(os.Args) < 4 {
			return fmt.Errorf("use policy gitops status|resync <file> [--confirm-risk high|critical]")
		}
		switch os.Args[3] {
		case "status":
			return request("GET", "/api/v1/policies/gitops/status", nil)
		case "resync":
			file, err := policyFile(os.Args[4:])
			if err != nil {
				return err
			}
			b, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			headers := map[string]string{}
			if risk := flagValue(os.Args[4:], "--confirm-risk"); risk != "" {
				headers["X-Netra-Confirm-Risk"] = risk
			}
			return requestHeaders("POST", "/api/v1/policies/gitops/resync", b, headers)
		default:
			return fmt.Errorf("use policy gitops status|resync <file> [--confirm-risk high|critical]")
		}
	case "history":
		if len(os.Args) < 5 {
			return fmt.Errorf("namespace and name required")
		}
		q := url.Values{"namespace": {os.Args[3]}, "name": {os.Args[4]}, "limit": {"50"}}
		return request("GET", "/api/v1/policies/history?"+q.Encode(), nil)
	case "archive":
		if len(os.Args) < 5 {
			return fmt.Errorf("use policy archive export|import <file>")
		}
		switch os.Args[3] {
		case "export":
			out, status, err := doRequest("GET", "/api/v1/policies/history/export", nil, nil)
			if err != nil {
				return err
			}
			if status >= 300 {
				return fmt.Errorf("%s: %s", http.StatusText(status), string(out))
			}
			if err := os.WriteFile(os.Args[4], out, 0o600); err != nil {
				return err
			}
			fmt.Printf("wrote %s\n", os.Args[4])
			return nil
		case "import":
			b, err := os.ReadFile(os.Args[4])
			if err != nil {
				return err
			}
			mode := flagValue(os.Args[5:], "--mode")
			q := ""
			if mode != "" {
				q = "?mode=" + url.QueryEscape(mode)
			}
			headers := map[string]string{}
			if strings.EqualFold(mode, "replace") {
				headers["X-Netra-Confirm-History-Replace"] = "replace"
			}
			return requestHeaders("POST", "/api/v1/policies/history/import"+q, b, headers)
		default:
			return fmt.Errorf("use policy archive export|import <file>")
		}
	case "rollback":
		if len(os.Args) < 6 {
			return fmt.Errorf("namespace, name and revision required")
		}
		q := url.Values{}
		if hasArg(os.Args[6:], "--dry-run") {
			q.Set("dryRun", "true")
		}
		if v := flagValue(os.Args[6:], "--confirm-risk"); v != "" {
			q.Set("confirmRisk", v)
		}
		p := "/api/v1/policies/" + url.PathEscape(os.Args[3]) + "/" + url.PathEscape(os.Args[4]) + "/rollback/" + url.PathEscape(os.Args[5])
		if enc := q.Encode(); enc != "" {
			p += "?" + enc
		}
		return request("POST", p, nil)
	case "delete":
		if len(os.Args) < 5 {
			return fmt.Errorf("namespace and name required")
		}
		return request("DELETE", "/api/v1/policies/"+url.PathEscape(os.Args[3])+"/"+url.PathEscape(os.Args[4]), nil)
	}
	return fmt.Errorf("unknown policy subcommand")
}
func buildPolicy(args []string) error {
	req := map[string]any{"namespace": "default", "selector": map[string]string{}, "protocol": "TCP"}
	selector := req["selector"].(map[string]string)
	var to []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--include-dns":
			req["includeDns"] = true
		case "--name", "--namespace", "--selector", "--kind", "--to", "--port", "--protocol":
			if i+1 >= len(args) {
				return fmt.Errorf("%s requires a value", args[i])
			}
			key, value := args[i], args[i+1]
			i++
			switch key {
			case "--name":
				req["name"] = value
			case "--namespace":
				req["namespace"] = value
			case "--kind":
				req["kind"] = value
			case "--protocol":
				req["protocol"] = value
			case "--to":
				to = append(to, value)
			case "--selector":
				parts := strings.SplitN(value, "=", 2)
				if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
					return fmt.Errorf("selector must be key=value")
				}
				selector[parts[0]] = parts[1]
			case "--port":
				n, err := strconv.ParseUint(value, 10, 16)
				if err != nil || n == 0 {
					return fmt.Errorf("port must be 1-65535")
				}
				req["port"] = uint16(n)
			}
		default:
			return fmt.Errorf("unknown policy build flag %s", args[i])
		}
	}
	req["to"] = to
	b, _ := json.Marshal(req)
	return request("POST", "/api/v1/policies/build", b)
}
func policyFile(args []string) (string, error) {
	for i := 0; i < len(args); i++ {
		if args[i] == "--file" {
			if i+1 >= len(args) {
				return "", fmt.Errorf("--file requires a path")
			}
			return args[i+1], nil
		}
		if !strings.HasPrefix(args[i], "--") {
			return args[i], nil
		}
	}
	return "", fmt.Errorf("file required")
}
func hasArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}
func flagValue(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func planAndApply(body []byte, confirmedRisk string) error {
	out, status, err := doRequest("POST", "/api/v1/policies/plan", body, nil)
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("preflight %s: %s", http.StatusText(status), string(out))
	}
	var planned struct {
		Plan struct {
			Risk string `json:"risk"`
		} `json:"plan"`
		DryRun struct {
			Passed bool `json:"passed"`
		} `json:"dryRun"`
		Receipt *struct {
			Token string `json:"token"`
		} `json:"receipt"`
	}
	if err := json.Unmarshal(out, &planned); err != nil {
		return fmt.Errorf("decode preflight: %w", err)
	}
	if !planned.DryRun.Passed || planned.Receipt == nil || planned.Receipt.Token == "" {
		return fmt.Errorf("preflight did not produce an apply receipt: %s", string(out))
	}
	risk := strings.ToLower(strings.TrimSpace(planned.Plan.Risk))
	if risk == "high" || risk == "critical" {
		if !strings.EqualFold(strings.TrimSpace(confirmedRisk), risk) {
			return fmt.Errorf("preflight risk is %s; re-run with --confirm-risk %s", risk, risk)
		}
	}
	headers := map[string]string{"X-Netra-Plan-Token": planned.Receipt.Token}
	if risk == "high" || risk == "critical" {
		headers["X-Netra-Confirm-Risk"] = risk
	}
	return requestHeaders("POST", "/api/v1/policies/apply", body, headers)
}

// netpolQuarantine is a client-side convenience over three existing, already
// fully-safety-gated endpoints (netpol v2 enable, netpol rule add, and the
// mandatory plan→confirm-risk→apply default-deny flow) — it introduces no
// new server-side logic and preserves every existing check, in particular
// the "zero covering allow rules is a certain-outage config" refusal. It
// exists because a real incident calls for one command, not five.
func netpolQuarantine(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("netpol quarantine [--namespace NS] [--pod POD] [--kind KIND] [--workload NAME] [--label k=v] [--allow-peer IP[:PORT[/PROTO]]]... [--lease DURATION] [--confirm-risk RISK] [--allow-no-rules]")
	}
	selector, labels := map[string]any{}, map[string]string{}
	var allowPeers []string
	lease, confirmRisk := "5m", ""
	allowNoRules := false
	for i := 0; i < len(args); i++ {
		flag := args[i]
		if flag == "--allow-no-rules" {
			allowNoRules = true
			continue
		}
		if i+1 >= len(args) {
			return fmt.Errorf("%s requires a value", flag)
		}
		value := args[i+1]
		i++
		switch flag {
		case "--namespace":
			selector["namespace"] = value
		case "--pod":
			selector["pod"] = value
		case "--kind":
			selector["workloadKind"] = value
		case "--workload":
			selector["workloadName"] = value
		case "--label":
			parts := strings.SplitN(value, "=", 2)
			if len(parts) != 2 || parts[0] == "" {
				return fmt.Errorf("label must be key=value")
			}
			labels[parts[0]] = parts[1]
		case "--allow-peer":
			allowPeers = append(allowPeers, value)
		case "--lease":
			lease = value
		case "--confirm-risk":
			confirmRisk = value
		default:
			return fmt.Errorf("unknown netpol quarantine flag %s", flag)
		}
	}
	if len(labels) > 0 {
		selector["labels"] = labels
	}
	if len(selector) == 0 {
		return fmt.Errorf("quarantine requires at least one selector flag (--namespace/--pod/--kind/--workload/--label)")
	}

	if err := request("PUT", "/api/v1/ebpf/netpol/v2/config", mustJSON(map[string]bool{"enabled": true})); err != nil {
		return fmt.Errorf("enable netpol v2: %w", err)
	}
	for _, peer := range allowPeers {
		host, port, proto := peer, uint64(0), "ANY"
		if h, rest, ok := strings.Cut(peer, ":"); ok {
			host = h
			portStr, protoStr, hasProto := strings.Cut(rest, "/")
			p, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				return fmt.Errorf("--allow-peer %q: invalid port", peer)
			}
			port = p
			if hasProto {
				proto = protoStr
			}
		}
		body := map[string]any{"selector": selector, "peerIpv4": host, "action": "allow", "direction": "egress", "protocol": proto}
		if port != 0 {
			body["port"] = uint16(port)
		}
		if err := request("POST", "/api/v1/ebpf/netpol/rules", mustJSON(body)); err != nil {
			return fmt.Errorf("add allow rule for %s: %w", peer, err)
		}
	}

	planBody := mustJSON(map[string]any{"selector": selector, "enabled": true})
	planPath := "/api/v1/ebpf/netpol/default-deny/plan"
	if allowNoRules {
		planPath += "?allowNoRules=true"
	}
	out, status, err := doRequest("POST", planPath, planBody, nil)
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("quarantine preflight %s: %s", http.StatusText(status), string(out))
	}
	var planned struct {
		Risk    string `json:"risk"`
		Receipt struct {
			Token string `json:"token"`
		} `json:"receipt"`
	}
	if err := json.Unmarshal(out, &planned); err != nil {
		return fmt.Errorf("decode quarantine preflight: %w", err)
	}
	if planned.Receipt.Token == "" {
		return fmt.Errorf("preflight did not produce a receipt: %s", string(out))
	}
	risk := strings.ToLower(strings.TrimSpace(planned.Risk))
	if risk == "high" || risk == "critical" {
		if !strings.EqualFold(strings.TrimSpace(confirmRisk), risk) {
			return fmt.Errorf("quarantine preflight risk is %s; re-run with --confirm-risk %s (allow-list rules were still added above)", risk, risk)
		}
	}
	setBody := mustJSON(map[string]any{"selector": selector, "enabled": true, "lease": lease})
	headers := map[string]string{"X-Netra-Plan-Token": planned.Receipt.Token}
	if risk == "high" || risk == "critical" {
		headers["X-Netra-Confirm-Risk"] = risk
	}
	return requestHeaders("PUT", "/api/v1/ebpf/netpol/default-deny", setBody, headers)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// denyImport reads a plain-text deny list (one "TYPE VALUE [DIRECTION]" per
// line; blank lines and "#" comments ignored) and bulk-applies it via
// POST /api/v1/ebpf/deny/import — introduces no client-side validation of
// its own, the server dispatches every entry through the exact same
// per-type validators the single-rule endpoints already use.
func denyImport(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var entries []map[string]string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return fmt.Errorf("invalid line %q: expected TYPE VALUE [DIRECTION]", line)
		}
		e := map[string]string{"type": fields[0], "value": fields[1]}
		if len(fields) > 2 {
			e["direction"] = fields[2]
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("%s contains no entries", path)
	}
	return request("POST", "/api/v1/ebpf/deny/import", mustJSON(map[string]any{"entries": entries}))
}

func flows() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("use flows watch|summary|history")
	}
	if os.Args[2] == "history" {
		q := url.Values{}
		for i := 3; i+1 < len(os.Args); i += 2 {
			m := map[string]string{
				"--since": "since", "--namespace": "namespace", "--pod": "pod",
				"--peer": "peer", "--protocol": "protocol", "--app": "app",
				"--node": "node", "--limit": "limit",
			}
			k, ok := m[os.Args[i]]
			if !ok {
				return fmt.Errorf("unknown flag %s", os.Args[i])
			}
			q.Set(k, os.Args[i+1])
		}
		p := "/api/v1/flows/history"
		if enc := q.Encode(); enc != "" {
			p += "?" + enc
		}
		return request("GET", p, nil)
	}
	if os.Args[2] != "watch" && os.Args[2] != "summary" {
		return fmt.Errorf("use flows watch|summary|history")
	}
	q := url.Values{"number": {map[string]string{"watch": "100", "summary": "500"}[os.Args[2]]}}
	for i := 3; i+1 < len(os.Args); i += 2 {
		m := map[string]string{"--verdict": "verdict", "--direction": "direction", "--protocol": "protocol", "--namespace": "namespace", "--pod": "pod", "--to": "destination"}
		k, ok := m[os.Args[i]]
		if !ok {
			return fmt.Errorf("unknown flag %s", os.Args[i])
		}
		q.Set(k, os.Args[i+1])
	}
	if os.Args[2] == "summary" {
		return request("GET", "/api/v1/flows/summary?"+q.Encode(), nil)
	}
	return stream("/api/v1/flows/stream?" + q.Encode())
}
func ebpf() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("ebpf subcommand required")
	}
	switch os.Args[2] {
	case "stats":
		return request("GET", "/api/v1/agents", nil)
	case "summary":
		return request("GET", "/api/v1/ebpf/summary", nil)
	case "coverage":
		return request("GET", "/api/v1/ebpf/coverage", nil)
	case "reasons":
		return request("GET", "/api/v1/ebpf/reasons", nil)
	case "census":
		return request("GET", "/api/v1/ebpf/census", nil)
	case "health":
		return request("GET", "/api/v1/ebpf/health", nil)
	case "capdrift":
		return request("GET", "/api/v1/ebpf/capdrift", nil)
	case "nsdrift":
		return request("GET", "/api/v1/ebpf/nsdrift", nil)
	case "exehash":
		return request("GET", "/api/v1/ebpf/exehash", nil)
	case "path":
		return request("GET", "/api/v1/ebpf/path", nil)
	case "drops":
		return request("GET", "/api/v1/ebpf/drops", nil)
	case "kernel-network", "sysctl":
		path := "/api/v1/ebpf/kernel-network"
		if len(os.Args) >= 4 {
			if _, err := time.ParseDuration(os.Args[3]); err != nil {
				return fmt.Errorf("window must be a duration such as 5m or 1h: %w", err)
			}
			path += "?window=" + url.QueryEscape(os.Args[3])
		}
		return request("GET", path, nil)
	case "attachments":
		path := "/api/v1/ebpf/attachments"
		if len(os.Args) >= 5 && os.Args[3] == "--node" {
			path += "?node=" + url.QueryEscape(os.Args[4])
		} else if len(os.Args) > 3 {
			return fmt.Errorf("ebpf attachments [--node NODE]")
		}
		return request("GET", path, nil)
	case "sysctl-audit":
		return request("GET", "/api/v1/ebpf/sysctl-audit", nil)
	case "dns-findings":
		return request("GET", "/api/v1/ebpf/dns-findings", nil)
	case "scan-findings":
		return request("GET", "/api/v1/ebpf/scan-findings", nil)
	case "ai-destinations":
		return request("GET", "/api/v1/ebpf/ai-destinations", nil)
	case "app-categories":
		return request("GET", "/api/v1/ebpf/app-categories", nil)
	case "auto-mitigate":
		return request("GET", "/api/v1/ebpf/auto-mitigate", nil)
	case "tls-fingerprints":
		return request("GET", "/api/v1/ebpf/tls-fingerprints", nil)
	case "tls-fingerprint-risk":
		return request("GET", "/api/v1/ebpf/tls-fingerprints/risk", nil)
	case "encrypted-dns":
		return request("GET", "/api/v1/ebpf/encrypted-dns", nil)
	case "ipv6":
		return request("GET", "/api/v1/ebpf/ipv6", nil)
	case "shield":
		if len(os.Args) < 4 {
			return request("GET", "/api/v1/ebpf/shield", nil)
		}
		if os.Args[3] != "set" {
			return fmt.Errorf("shield [set --mode off|audit|enforce] [--protect-all] [--ip IPv4]... [--ip6 IPv6]... [--syn-pps N] [--udp-pps N] [--icmp-pps N] [--other-pps N] [--burst-seconds N]")
		}
		cfg := map[string]any{}
		var ips []string
		var ips6 []string
		for i := 4; i < len(os.Args); i++ {
			flag := os.Args[i]
			if flag == "--protect-all" {
				cfg["protectAll"] = true
				continue
			}
			if i+1 >= len(os.Args) {
				return fmt.Errorf("%s requires a value", flag)
			}
			value := os.Args[i+1]
			i++
			switch flag {
			case "--mode":
				cfg["mode"] = value
			case "--ip":
				ips = append(ips, value)
			case "--ip6":
				ips6 = append(ips6, value)
			case "--syn-pps":
				n, err := strconv.ParseUint(value, 10, 32)
				if err != nil {
					return fmt.Errorf("valid --syn-pps required")
				}
				cfg["synPps"] = uint32(n)
			case "--udp-pps":
				n, err := strconv.ParseUint(value, 10, 32)
				if err != nil {
					return fmt.Errorf("valid --udp-pps required")
				}
				cfg["udpPps"] = uint32(n)
			case "--icmp-pps":
				n, err := strconv.ParseUint(value, 10, 32)
				if err != nil {
					return fmt.Errorf("valid --icmp-pps required")
				}
				cfg["icmpPps"] = uint32(n)
			case "--other-pps":
				n, err := strconv.ParseUint(value, 10, 32)
				if err != nil {
					return fmt.Errorf("valid --other-pps required")
				}
				cfg["otherPps"] = uint32(n)
			case "--burst-seconds":
				n, err := strconv.ParseUint(value, 10, 32)
				if err != nil {
					return fmt.Errorf("valid --burst-seconds required")
				}
				cfg["burstSeconds"] = uint32(n)
			default:
				return fmt.Errorf("unknown shield flag %s", flag)
			}
		}
		if _, ok := cfg["mode"]; !ok {
			return fmt.Errorf("--mode off|audit|enforce is required")
		}
		if len(ips) > 0 {
			cfg["protectedIpv4"] = ips
		}
		if len(ips6) > 0 {
			cfg["protectedIpv6"] = ips6
		}
		b, _ := json.Marshal(cfg)
		return request("PUT", "/api/v1/ebpf/shield", b)
	case "netpol":
		if len(os.Args) < 4 {
			return fmt.Errorf("netpol enable|disable | netpol v2 enable|disable | netpol rule add|del | netpol default-deny plan|set | netpol quarantine")
		}
		switch os.Args[3] {
		case "enable":
			b, _ := json.Marshal(map[string]bool{"enabled": true})
			return request("PUT", "/api/v1/ebpf/netpol/config", b)
		case "disable":
			b, _ := json.Marshal(map[string]bool{"enabled": false})
			return request("PUT", "/api/v1/ebpf/netpol/config", b)
		case "v2":
			if len(os.Args) < 5 {
				return fmt.Errorf("netpol v2 enable|disable")
			}
			switch os.Args[4] {
			case "enable":
				b, _ := json.Marshal(map[string]bool{"enabled": true})
				return request("PUT", "/api/v1/ebpf/netpol/v2/config", b)
			case "disable":
				b, _ := json.Marshal(map[string]bool{"enabled": false})
				return request("PUT", "/api/v1/ebpf/netpol/v2/config", b)
			default:
				return fmt.Errorf("netpol v2 enable|disable")
			}
		case "rule":
			if len(os.Args) < 5 {
				return fmt.Errorf("netpol rule add (--peer IP | --port N) --action allow|deny [selector flags] [--port N] [--protocol P] [--direction D] | netpol rule del ID")
			}
			switch os.Args[4] {
			case "del":
				if len(os.Args) < 6 {
					return fmt.Errorf("netpol rule del ID")
				}
				return request("DELETE", "/api/v1/ebpf/netpol/rules/"+url.PathEscape(os.Args[5]), nil)
			case "add":
				selector, labels := map[string]any{}, map[string]string{}
				body := map[string]any{}
				for i := 5; i < len(os.Args); i++ {
					if i+1 >= len(os.Args) {
						return fmt.Errorf("%s requires a value", os.Args[i])
					}
					flag, value := os.Args[i], os.Args[i+1]
					i++
					switch flag {
					case "--namespace":
						selector["namespace"] = value
					case "--pod":
						selector["pod"] = value
					case "--kind":
						selector["workloadKind"] = value
					case "--workload":
						selector["workloadName"] = value
					case "--label":
						parts := strings.SplitN(value, "=", 2)
						if len(parts) != 2 || parts[0] == "" {
							return fmt.Errorf("label must be key=value")
						}
						labels[parts[0]] = parts[1]
					case "--peer":
						body["peerIpv4"] = value
					case "--port":
						port, err := strconv.ParseUint(value, 10, 16)
						if err != nil {
							return fmt.Errorf("valid port required")
						}
						body["port"] = uint16(port)
					case "--protocol":
						body["protocol"] = value
					case "--direction":
						body["direction"] = value
					case "--action":
						body["action"] = value
					default:
						return fmt.Errorf("unknown netpol rule flag %s", flag)
					}
				}
				if len(labels) > 0 {
					selector["labels"] = labels
				}
				body["selector"] = selector
				b, _ := json.Marshal(body)
				return request("POST", "/api/v1/ebpf/netpol/rules", b)
			default:
				return fmt.Errorf("netpol rule add|del")
			}
		case "default-deny":
			if len(os.Args) < 5 {
				return fmt.Errorf("netpol default-deny plan|set [--namespace NS] [--pod POD] [--kind KIND] [--workload NAME] [--label k=v] [--disable] [--lease DURATION] [--allow-no-rules] [--token TOKEN] [--confirm-risk RISK]")
			}
			selector, labels := map[string]any{}, map[string]string{}
			body := map[string]any{"enabled": true}
			token, confirmRisk, allowNoRules := "", "", false
			for i := 5; i < len(os.Args); i++ {
				flag := os.Args[i]
				if flag == "--disable" {
					body["enabled"] = false
					continue
				}
				if flag == "--allow-no-rules" {
					allowNoRules = true
					continue
				}
				if i+1 >= len(os.Args) {
					return fmt.Errorf("%s requires a value", flag)
				}
				value := os.Args[i+1]
				i++
				switch flag {
				case "--namespace":
					selector["namespace"] = value
				case "--pod":
					selector["pod"] = value
				case "--kind":
					selector["workloadKind"] = value
				case "--workload":
					selector["workloadName"] = value
				case "--label":
					parts := strings.SplitN(value, "=", 2)
					if len(parts) != 2 || parts[0] == "" {
						return fmt.Errorf("label must be key=value")
					}
					labels[parts[0]] = parts[1]
				case "--lease":
					body["lease"] = value
				case "--token":
					token = value
				case "--confirm-risk":
					confirmRisk = value
				default:
					return fmt.Errorf("unknown netpol default-deny flag %s", flag)
				}
			}
			if len(labels) > 0 {
				selector["labels"] = labels
			}
			body["selector"] = selector
			b, _ := json.Marshal(body)
			switch os.Args[4] {
			case "plan":
				p := "/api/v1/ebpf/netpol/default-deny/plan"
				if allowNoRules {
					p += "?allowNoRules=true"
				}
				return request("POST", p, b)
			case "set":
				if token == "" {
					return fmt.Errorf("--token TOKEN is required; run 'netpol default-deny plan' first")
				}
				return requestHeaders("PUT", "/api/v1/ebpf/netpol/default-deny", b, map[string]string{"X-Netra-Plan-Token": token, "X-Netra-Confirm-Risk": confirmRisk})
			default:
				return fmt.Errorf("netpol default-deny plan|set")
			}
		case "quarantine":
			return netpolQuarantine(os.Args[4:])
		default:
			return fmt.Errorf("netpol enable|disable | netpol v2 enable|disable | netpol rule add|del | netpol default-deny plan|set | netpol quarantine")
		}
	case "conn-rate-limit":
		if len(os.Args) < 4 {
			return fmt.Errorf("conn-rate-limit add --per-second N [selector flags] | conn-rate-limit del ID")
		}
		switch os.Args[3] {
		case "del":
			if len(os.Args) < 5 {
				return fmt.Errorf("conn-rate-limit del ID")
			}
			return request("DELETE", "/api/v1/ebpf/conn-rate-limit/"+url.PathEscape(os.Args[4]), nil)
		case "add":
			selector, labels := map[string]any{}, map[string]string{}
			body := map[string]any{}
			for i := 4; i < len(os.Args); i++ {
				if i+1 >= len(os.Args) {
					return fmt.Errorf("%s requires a value", os.Args[i])
				}
				flag, value := os.Args[i], os.Args[i+1]
				i++
				switch flag {
				case "--namespace":
					selector["namespace"] = value
				case "--pod":
					selector["pod"] = value
				case "--kind":
					selector["workloadKind"] = value
				case "--workload":
					selector["workloadName"] = value
				case "--label":
					parts := strings.SplitN(value, "=", 2)
					if len(parts) != 2 || parts[0] == "" {
						return fmt.Errorf("label must be key=value")
					}
					labels[parts[0]] = parts[1]
				case "--per-second":
					pps, err := strconv.ParseUint(value, 10, 32)
					if err != nil || pps == 0 {
						return fmt.Errorf("--per-second must be a positive integer")
					}
					body["perSecond"] = uint32(pps)
				default:
					return fmt.Errorf("unknown conn-rate-limit flag %s", flag)
				}
			}
			if len(labels) > 0 {
				selector["labels"] = labels
			}
			body["selector"] = selector
			b, _ := json.Marshal(body)
			return request("POST", "/api/v1/ebpf/conn-rate-limit", b)
		default:
			return fmt.Errorf("conn-rate-limit add|del")
		}
	case "interfaces":
		return request("GET", "/api/v1/ebpf/interfaces", nil)
	case "diagnose":
		return request("GET", "/api/v1/ebpf/diagnose", nil)
	case "l7":
		return request("GET", "/api/v1/ebpf/l7", nil)
	case "capabilities":
		return request("GET", "/api/v1/ebpf/capabilities", nil)
	case "maps":
		return ebpfMapsCmd(os.Args[3:])
	case "mode":
		if len(os.Args) < 4 {
			return fmt.Errorf("mode required")
		}
		p := "/api/v1/ebpf/mode"
		if os.Args[3] == "enforce" {
			lease := "15m"
			if len(os.Args) > 4 {
				lease = os.Args[4]
			}
			p += "?lease=" + url.QueryEscape(lease)
		}
		b, _ := json.Marshal(map[string]string{"mode": os.Args[3]})
		return request("PUT", p, b)
	case "deny-preview":
		if len(os.Args) < 5 {
			return fmt.Errorf("deny-preview KIND VALUE [direction] [--protocol P] [--port N] [--namespace NS] [--pod POD] [--kind K] [--workload NAME] [--limit N]")
		}
		body := map[string]any{"kind": os.Args[3], "value": os.Args[4]}
		i := 5
		if i < len(os.Args) && !strings.HasPrefix(os.Args[i], "--") {
			body["direction"] = os.Args[i]
			i++
		}
		for ; i < len(os.Args); i++ {
			flag := os.Args[i]
			if i+1 >= len(os.Args) {
				return fmt.Errorf("%s requires a value", flag)
			}
			value := os.Args[i+1]
			i++
			switch flag {
			case "--protocol":
				body["protocol"] = value
			case "--port":
				n, err := strconv.ParseUint(value, 10, 16)
				if err != nil {
					return fmt.Errorf("valid --port required")
				}
				body["port"] = uint16(n)
			case "--namespace":
				body["namespace"] = value
			case "--pod":
				body["pod"] = value
			case "--kind":
				body["workloadKind"] = value
			case "--workload":
				body["workloadName"] = value
			case "--limit":
				n, err := strconv.Atoi(value)
				if err != nil {
					return fmt.Errorf("valid --limit required")
				}
				body["limit"] = n
			default:
				return fmt.Errorf("unknown deny-preview flag %s", flag)
			}
		}
		b, _ := json.Marshal(body)
		return request("POST", "/api/v1/ebpf/deny/preview", b)
	case "deny":
		if len(os.Args) < 5 {
			return fmt.Errorf("deny add|del IP | deny import FILE")
		}
		if os.Args[3] == "add" {
			dir := "egress"
			if len(os.Args) > 5 {
				dir = os.Args[5]
			}
			b, _ := json.Marshal(map[string]string{"ip": os.Args[4], "direction": dir})
			return request("POST", "/api/v1/ebpf/deny", b)
		}
		if os.Args[3] == "del" {
			return request("DELETE", "/api/v1/ebpf/deny/"+url.PathEscape(os.Args[4]), nil)
		}
		if os.Args[3] == "import" {
			return denyImport(os.Args[4])
		}
	case "allow-cidr":
		if len(os.Args) < 5 {
			return fmt.Errorf("allow-cidr add|del CIDR [direction]")
		}
		dir := "egress"
		if len(os.Args) > 5 {
			dir = os.Args[5]
		}
		b, _ := json.Marshal(map[string]any{"cidr": os.Args[4], "direction": dir})
		if os.Args[3] == "add" {
			return request("POST", "/api/v1/ebpf/allow-cidr", b)
		}
		if os.Args[3] == "del" {
			return request("POST", "/api/v1/ebpf/allow-cidr/delete", b)
		}
	case "allow":
		if len(os.Args) < 5 {
			return fmt.Errorf("allow add|del IP")
		}
		if os.Args[3] == "add" {
			b, _ := json.Marshal(map[string]string{"ip": os.Args[4]})
			return request("POST", "/api/v1/ebpf/allow", b)
		}
		if os.Args[3] == "del" {
			return request("DELETE", "/api/v1/ebpf/allow/"+url.PathEscape(os.Args[4]), nil)
		}
	case "cidr":
		if len(os.Args) < 5 {
			return fmt.Errorf("cidr add|del CIDR [direction]")
		}
		dir := "egress"
		if len(os.Args) > 5 {
			dir = os.Args[5]
		}
		b, _ := json.Marshal(map[string]any{"cidr": os.Args[4], "direction": dir})
		if os.Args[3] == "add" {
			return request("POST", "/api/v1/ebpf/cidr", b)
		}
		if os.Args[3] == "del" {
			return request("POST", "/api/v1/ebpf/cidr/delete", b)
		}
	case "syn-drop":
		if len(os.Args) < 6 {
			return fmt.Errorf("syn-drop add|del IP egress|ingress")
		}
		b, _ := json.Marshal(map[string]any{"address": os.Args[4], "direction": os.Args[5]})
		if os.Args[3] == "add" {
			return request("POST", "/api/v1/ebpf/syn-drop", b)
		}
		if os.Args[3] == "del" {
			return request("POST", "/api/v1/ebpf/syn-drop/delete", b)
		}
	case "syn-drop-cidr":
		if len(os.Args) < 6 {
			return fmt.Errorf("syn-drop-cidr add|del CIDR egress|ingress")
		}
		b, _ := json.Marshal(map[string]any{"cidr": os.Args[4], "direction": os.Args[5]})
		if os.Args[3] == "add" {
			return request("POST", "/api/v1/ebpf/syn-drop-cidr", b)
		}
		if os.Args[3] == "del" {
			return request("POST", "/api/v1/ebpf/syn-drop-cidr/delete", b)
		}
	case "port":
		if len(os.Args) < 6 {
			return fmt.Errorf("port add|del TCP|UDP|ANY PORT [direction]")
		}
		port, err := strconv.ParseUint(os.Args[5], 10, 16)
		if err != nil || port == 0 {
			return fmt.Errorf("valid port required")
		}
		dir := "egress"
		if len(os.Args) > 6 {
			dir = os.Args[6]
		}
		b, _ := json.Marshal(map[string]any{"protocol": os.Args[4], "port": uint16(port), "direction": dir})
		if os.Args[3] == "add" {
			return request("POST", "/api/v1/ebpf/port", b)
		}
		if os.Args[3] == "del" {
			return request("POST", "/api/v1/ebpf/port/delete", b)
		}
	case "allow-port":
		if len(os.Args) < 6 {
			return fmt.Errorf("allow-port add|del TCP|UDP|ANY PORT [direction]")
		}
		port, err := strconv.ParseUint(os.Args[5], 10, 16)
		if err != nil || port == 0 {
			return fmt.Errorf("valid port required")
		}
		dir := "egress"
		if len(os.Args) > 6 {
			dir = os.Args[6]
		}
		b, _ := json.Marshal(map[string]any{"protocol": os.Args[4], "port": uint16(port), "direction": dir})
		if os.Args[3] == "add" {
			return request("POST", "/api/v1/ebpf/allow-port", b)
		}
		if os.Args[3] == "del" {
			return request("POST", "/api/v1/ebpf/allow-port/delete", b)
		}
	case "uid":
		if len(os.Args) < 5 {
			return fmt.Errorf("uid add|del UID")
		}
		uid, err := strconv.ParseUint(os.Args[4], 10, 32)
		if err != nil {
			return fmt.Errorf("valid UID required")
		}
		if os.Args[3] == "add" {
			b, _ := json.Marshal(map[string]any{"uid": uint32(uid)})
			return request("POST", "/api/v1/ebpf/uid", b)
		}
		if os.Args[3] == "del" {
			return request("DELETE", "/api/v1/ebpf/uid/"+strconv.FormatUint(uid, 10), nil)
		}
	case "allow-uid":
		if len(os.Args) < 5 {
			return fmt.Errorf("allow-uid add|del UID")
		}
		uid, err := strconv.ParseUint(os.Args[4], 10, 32)
		if err != nil {
			return fmt.Errorf("valid UID required")
		}
		if os.Args[3] == "add" {
			b, _ := json.Marshal(map[string]any{"uid": uint32(uid)})
			return request("POST", "/api/v1/ebpf/allow-uid", b)
		}
		if os.Args[3] == "del" {
			return request("DELETE", "/api/v1/ebpf/allow-uid/"+strconv.FormatUint(uid, 10), nil)
		}
	case "dns":
		if len(os.Args) < 5 {
			return fmt.Errorf("dns add|del NAME")
		}
		b, _ := json.Marshal(map[string]string{"name": os.Args[4]})
		if os.Args[3] == "add" {
			return request("POST", "/api/v1/ebpf/dns", b)
		}
		if os.Args[3] == "del" {
			return request("POST", "/api/v1/ebpf/dns/delete", b)
		}
	case "sni":
		if len(os.Args) < 5 {
			return fmt.Errorf("sni add|del NAME")
		}
		b, _ := json.Marshal(map[string]string{"name": os.Args[4]})
		if os.Args[3] == "add" {
			return request("POST", "/api/v1/ebpf/sni", b)
		}
		if os.Args[3] == "del" {
			return request("POST", "/api/v1/ebpf/sni/delete", b)
		}
	case "process":
		if len(os.Args) < 5 {
			return fmt.Errorf("process add|del COMM")
		}
		b, _ := json.Marshal(map[string]string{"name": os.Args[4]})
		if os.Args[3] == "add" {
			return request("POST", "/api/v1/ebpf/process", b)
		}
		if os.Args[3] == "del" {
			return request("POST", "/api/v1/ebpf/process/delete", b)
		}
	case "capability":
		if len(os.Args) < 5 {
			return fmt.Errorf("capability add|del CAP_NET_RAW|CAP_NET_ADMIN")
		}
		b, _ := json.Marshal(map[string]string{"name": os.Args[4]})
		if os.Args[3] == "add" {
			return request("POST", "/api/v1/ebpf/capability", b)
		}
		if os.Args[3] == "del" {
			return request("POST", "/api/v1/ebpf/capability/delete", b)
		}
	case "allow-process":
		if len(os.Args) < 5 {
			return fmt.Errorf("allow-process add|del COMM")
		}
		b, _ := json.Marshal(map[string]string{"name": os.Args[4]})
		if os.Args[3] == "add" {
			return request("POST", "/api/v1/ebpf/allow-process", b)
		}
		if os.Args[3] == "del" {
			return request("POST", "/api/v1/ebpf/allow-process/delete", b)
		}
	case "workloads":
		p := "/api/v1/ebpf/workloads"
		if len(os.Args) > 3 {
			p += "?node=" + url.QueryEscape(os.Args[3])
		}
		return request("GET", p, nil)
	case "scope":
		if len(os.Args) < 4 {
			return fmt.Errorf("scope show|all|selected|set")
		}
		switch os.Args[3] {
		case "show":
			return request("GET", "/api/v1/ebpf/config", nil)
		case "all":
			b, _ := json.Marshal(map[string]any{"mode": "all", "scopes": []any{}})
			return request("PUT", "/api/v1/ebpf/scope", b)
		case "set":
			if len(os.Args) < 5 {
				return fmt.Errorf("scope set FILE")
			}
			b, err := os.ReadFile(os.Args[4])
			if err != nil {
				return err
			}
			return request("PUT", "/api/v1/ebpf/scope", b)
		case "selected":
			scope := map[string]any{}
			labels := map[string]string{}
			for i := 4; i < len(os.Args); i++ {
				if i+1 >= len(os.Args) {
					return fmt.Errorf("%s requires a value", os.Args[i])
				}
				flag, value := os.Args[i], os.Args[i+1]
				i++
				switch flag {
				case "--namespace":
					scope["namespace"] = value
				case "--pod":
					scope["pod"] = value
				case "--kind":
					scope["workloadKind"] = value
				case "--workload":
					scope["workloadName"] = value
				case "--label":
					parts := strings.SplitN(value, "=", 2)
					if len(parts) != 2 || parts[0] == "" {
						return fmt.Errorf("label must be key=value")
					}
					labels[parts[0]] = parts[1]
				case "--cgroup":
					id, err := strconv.ParseUint(value, 10, 64)
					if err != nil || id == 0 {
						return fmt.Errorf("valid cgroup ID required")
					}
					scope["cgroupId"] = id
				default:
					return fmt.Errorf("unknown scope flag %s", flag)
				}
			}
			if len(labels) > 0 {
				scope["labels"] = labels
			}
			if len(scope) == 0 {
				return fmt.Errorf("selected scope requires at least one selector")
			}
			b, _ := json.Marshal(map[string]any{"mode": "selected", "scopes": []any{scope}})
			return request("PUT", "/api/v1/ebpf/scope", b)
		default:
			return fmt.Errorf("scope show|all|selected|set")
		}
	case "rate":
		if len(os.Args) < 5 {
			return fmt.Errorf("rate set IP PPS [BPS] | rate del IP")
		}
		if os.Args[3] == "del" {
			return request("DELETE", "/api/v1/ebpf/rate/"+url.PathEscape(os.Args[4]), nil)
		}
		if os.Args[3] == "set" {
			if len(os.Args) < 6 {
				return fmt.Errorf("rate set IP PPS [BPS]")
			}
			pps, err := strconv.ParseUint(os.Args[5], 10, 32)
			if err != nil {
				return fmt.Errorf("valid PPS required (0 if BPS is given)")
			}
			body := map[string]any{"destination": os.Args[4], "pps": uint32(pps)}
			if len(os.Args) > 6 {
				bps, err := strconv.ParseUint(os.Args[6], 10, 32)
				if err != nil || bps == 0 {
					return fmt.Errorf("valid BPS required")
				}
				body["bps"] = uint32(bps)
			} else if pps == 0 {
				return fmt.Errorf("valid PPS required, or supply BPS")
			}
			b, _ := json.Marshal(body)
			return request("PUT", "/api/v1/ebpf/rate", b)
		}
	case "rules":
		if len(os.Args) < 4 {
			return fmt.Errorf("rules list | get ID | patch ID JSON | delete ID | history ID | rollback ID REVISION")
		}
		switch os.Args[3] {
		case "list":
			return request("GET", "/api/v1/ebpf/rules", nil)
		case "get":
			if len(os.Args) < 5 {
				return fmt.Errorf("rules get ID")
			}
			return request("GET", "/api/v1/ebpf/rules/"+url.PathEscape(os.Args[4]), nil)
		case "patch":
			if len(os.Args) < 6 {
				return fmt.Errorf("rules patch ID JSON")
			}
			if !json.Valid([]byte(os.Args[5])) {
				return fmt.Errorf("JSON body is not valid")
			}
			return request("PATCH", "/api/v1/ebpf/rules/"+url.PathEscape(os.Args[4]), []byte(os.Args[5]))
		case "delete":
			if len(os.Args) < 5 {
				return fmt.Errorf("rules delete ID")
			}
			return request("DELETE", "/api/v1/ebpf/rules/"+url.PathEscape(os.Args[4]), nil)
		case "history":
			if len(os.Args) < 5 {
				return fmt.Errorf("rules history ID")
			}
			return request("GET", "/api/v1/ebpf/rules/"+url.PathEscape(os.Args[4])+"/history", nil)
		case "rollback":
			if len(os.Args) < 6 {
				return fmt.Errorf("rules rollback ID REVISION")
			}
			return request("POST", "/api/v1/ebpf/rules/"+url.PathEscape(os.Args[4])+"/rollback/"+url.PathEscape(os.Args[5]), nil)
		default:
			return fmt.Errorf("rules list | get ID | patch ID JSON | delete ID | history ID | rollback ID REVISION")
		}
	}
	return fmt.Errorf("unknown ebpf command")
}

func insightCmd() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("insights subcommand required")
	}
	switch os.Args[2] {
	case "summary":
		return request("GET", "/api/v1/insights/summary", nil)
	case "dependencies":
		p := "/api/v1/insights/dependencies"
		if len(os.Args) > 3 {
			if _, err := strconv.Atoi(os.Args[3]); err != nil {
				return fmt.Errorf("limit must be numeric")
			}
			p += "?limit=" + url.QueryEscape(os.Args[3])
		}
		return request("GET", p, nil)
	case "drift":
		return request("GET", "/api/v1/insights/drift", nil)
	case "rates":
		p := "/api/v1/insights/rates"
		if len(os.Args) > 3 {
			p += "?window=" + url.QueryEscape(os.Args[3])
		}
		return request("GET", p, nil)
	case "rate-drift":
		p := "/api/v1/insights/rate-drift"
		if len(os.Args) > 3 {
			p += "?window=" + url.QueryEscape(os.Args[3])
		}
		return request("GET", p, nil)
	case "exposure":
		p := "/api/v1/insights/exposure"
		if len(os.Args) > 3 {
			p += "?window=" + url.QueryEscape(os.Args[3])
		}
		return request("GET", p, nil)
	case "remediations":
		p := "/api/v1/insights/remediations"
		if len(os.Args) > 3 {
			p += "?window=" + url.QueryEscape(os.Args[3])
		}
		return request("GET", p, nil)
	case "protocol-downgrades":
		return request("GET", "/api/v1/insights/protocol-downgrades", nil)
	case "policy-review":
		if len(os.Args) < 4 {
			return fmt.Errorf("policy-review requires a recommendation ID (see insights recommendations for ids)")
		}
		q := url.Values{}
		q.Set("recommendationId", os.Args[3])
		return request("GET", "/api/v1/insights/policy-review?"+q.Encode(), nil)
	case "new-since-start":
		p := "/api/v1/insights/new-since-start"
		if len(os.Args) > 3 {
			if _, err := strconv.Atoi(os.Args[3]); err != nil {
				return fmt.Errorf("maxRestarts must be numeric")
			}
			p += "?maxRestarts=" + url.QueryEscape(os.Args[3])
		}
		return request("GET", p, nil)
	case "blast-radius":
		if len(os.Args) < 4 {
			return fmt.Errorf("blast-radius requires a root node ID (see insights dependencies for IDs)")
		}
		q := url.Values{}
		q.Set("root", os.Args[3])
		if len(os.Args) > 4 {
			if _, err := strconv.Atoi(os.Args[4]); err != nil {
				return fmt.Errorf("hops must be numeric")
			}
			q.Set("hops", os.Args[4])
		}
		return request("GET", "/api/v1/insights/blast-radius?"+q.Encode(), nil)
	case "health-trend":
		p := "/api/v1/insights/health-trend"
		if len(os.Args) > 3 {
			if _, err := strconv.Atoi(os.Args[3]); err != nil {
				return fmt.Errorf("threshold must be numeric")
			}
			p += "?threshold=" + url.QueryEscape(os.Args[3])
		}
		return request("GET", p, nil)
	case "rate-baseline":
		if len(os.Args) < 4 {
			return fmt.Errorf("rate-baseline show|capture [window]|clear")
		}
		switch os.Args[3] {
		case "show":
			return request("GET", "/api/v1/insights/rate-baseline", nil)
		case "capture":
			p := "/api/v1/insights/rate-baseline"
			if len(os.Args) > 4 {
				p += "?window=" + url.QueryEscape(os.Args[4])
			}
			return request("POST", p, nil)
		case "clear":
			return requestHeaders("DELETE", "/api/v1/insights/rate-baseline", nil, map[string]string{"X-Netra-Confirm-Rate-Baseline-Clear": "clear"})
		default:
			return fmt.Errorf("rate-baseline show|capture [window]|clear")
		}
	case "recommendations":
		q := url.Values{}
		if len(os.Args) > 3 {
			q.Set("namespace", os.Args[3])
		}
		if len(os.Args) > 4 {
			q.Set("workload", os.Args[4])
		}
		p := "/api/v1/insights/recommendations"
		if enc := q.Encode(); enc != "" {
			p += "?" + enc
		}
		return request("GET", p, nil)
	case "zero-trust":
		return request("GET", "/api/v1/insights/zero-trust", nil)
	case "microseg":
		return request("GET", "/api/v1/insights/microseg", nil)
	case "shadow-saas":
		return request("GET", "/api/v1/insights/shadow-saas", nil)
	case "experience":
		return request("GET", "/api/v1/insights/experience", nil)
	case "red":
		p := "/api/v1/insights/red"
		if len(os.Args) > 3 {
			p += "?window=" + url.QueryEscape(os.Args[3])
		}
		return request("GET", p, nil)
	case "traces":
		p := "/api/v1/insights/traces"
		if len(os.Args) > 3 {
			p += "?since=" + url.QueryEscape(os.Args[3])
		}
		return request("GET", p, nil)
	case "profiles":
		return request("GET", "/api/v1/insights/profiles", nil)
	case "workload-events":
		q := url.Values{}
		if len(os.Args) > 3 {
			q.Set("namespace", os.Args[3])
		}
		if len(os.Args) > 4 {
			q.Set("pod", os.Args[4])
		}
		p := "/api/v1/insights/workload-events"
		if enc := q.Encode(); enc != "" {
			p += "?" + enc
		}
		return request("GET", p, nil)
	case "kernel-notes":
		return request("GET", "/api/v1/insights/kernel-notes", nil)
	case "destination-risk":
		return request("GET", "/api/v1/insights/destination-risk", nil)
	case "policy-packs":
		return request("GET", "/api/v1/insights/policy-packs", nil)
	case "identity-drafts":
		return request("GET", "/api/v1/insights/identity-drafts", nil)
	case "ech-blind":
		return request("GET", "/api/v1/insights/ech-blind", nil)
	case "exfil":
		return request("GET", "/api/v1/insights/exfil", nil)
	case "lateral":
		return request("GET", "/api/v1/insights/lateral", nil)
	case "category-deny":
		return request("GET", "/api/v1/insights/category-deny", nil)
	case "baseline":
		if len(os.Args) < 4 {
			return fmt.Errorf("baseline show|capture|clear")
		}
		switch os.Args[3] {
		case "show":
			return request("GET", "/api/v1/insights/baseline", nil)
		case "capture":
			return request("POST", "/api/v1/insights/baseline", nil)
		case "clear":
			return requestHeaders("DELETE", "/api/v1/insights/baseline", nil, map[string]string{"X-Netra-Confirm-Baseline-Clear": "clear"})
		default:
			return fmt.Errorf("baseline show|capture|clear")
		}
	default:
		return fmt.Errorf("unknown insights command")
	}
}

func incidentsCmd() error {
	if len(os.Args) < 3 {
		return request("GET", "/api/v1/incidents", nil)
	}
	switch os.Args[2] {
	case "timeline":
		p := "/api/v1/incidents/timeline"
		if len(os.Args) > 3 {
			p += "?since=" + url.QueryEscape(os.Args[3])
		}
		return request("GET", p, nil)
	default:
		return fmt.Errorf("unknown incidents command")
	}
}

func request(method, p string, b []byte) error {
	return requestHeaders(method, p, b, nil)
}

func requestHeaders(method, p string, b []byte, extra map[string]string) error {
	out, status, err := doRequest(method, p, b, extra)
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("%s: %s", http.StatusText(status), string(out))
	}
	var v any
	if json.Unmarshal(out, &v) == nil {
		x, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(x))
	} else {
		fmt.Print(string(out))
	}
	return nil
}

func doRequest(method, p string, b []byte, extra map[string]string) ([]byte, int, error) {
	ensureConfig()
	req, err := http.NewRequest(method, base+p, bytes.NewReader(b))
	if err != nil {
		return nil, 0, err
	}
	auth(req)
	if len(b) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	r, err := httpClient(20 * time.Second).Do(req)
	if err != nil {
		return nil, 0, annotateTLSErr(err)
	}
	defer r.Body.Close()
	out, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		return nil, r.StatusCode, readErr
	}
	return out, r.StatusCode, nil
}
func stream(p string) error {
	ensureConfig()
	req, e := http.NewRequest("GET", base+p, nil)
	if e != nil {
		return e
	}
	auth(req)
	r, e := httpClient(0).Do(req)
	if e != nil {
		return annotateTLSErr(e)
	}
	defer r.Body.Close()
	if r.StatusCode >= 300 {
		x, _ := io.ReadAll(r.Body)
		return fmt.Errorf("%s: %s", r.Status, x)
	}
	s := bufio.NewScanner(r.Body)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "data: ") {
			fmt.Println(strings.TrimPrefix(line, "data: "))
		}
	}
	return s.Err()
}
func auth(r *http.Request) {
	ensureConfig()
	if k := os.Getenv("NETRA_API_KEY"); k != "" {
		r.Header.Set("Authorization", "Bearer "+k)
	}
	r.Header.Set("X-Netra-Actor", "netractl")
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
