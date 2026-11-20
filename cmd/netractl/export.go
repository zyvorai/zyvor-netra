// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

func exportCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("export audit|events|flows|blocks|status [--format json|jsonl|cef|syslog|otlp|otlp-trace] [--limit N] [--include LIST]")
	}
	kind := args[0]
	format := "json"
	limit := "100"
	include := ""
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--format":
			i++
			if i >= len(args) {
				return fmt.Errorf("--format needs a value")
			}
			format = args[i]
		case "--limit":
			i++
			if i >= len(args) {
				return fmt.Errorf("--limit needs a value")
			}
			limit = args[i]
		case "--include":
			i++
			if i >= len(args) {
				return fmt.Errorf("--include needs a value")
			}
			include = args[i]
		default:
			return fmt.Errorf("unknown flag %s", args[i])
		}
	}
	q := url.Values{}
	q.Set("format", format)
	q.Set("limit", limit)
	var path string
	switch kind {
	case "audit":
		path = "/api/v1/export/audit?" + q.Encode()
	case "events":
		if include != "" {
			q.Set("include", include)
		}
		path = "/api/v1/export/events?" + q.Encode()
	case "flows":
		path = "/api/v1/export/flows?" + q.Encode()
	case "blocks":
		path = "/api/v1/export/blocks?" + q.Encode()
	case "status":
		path = "/api/v1/export/status"
	default:
		return fmt.Errorf("export audit|events|flows|blocks|status")
	}
	return request("GET", path, nil)
}

func reportCmd(args []string) error {
	if len(args) > 0 && args[0] == "prevention" {
		return request("GET", "/api/v1/report/prevention", nil)
	}
	format := "markdown"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format":
			i++
			if i >= len(args) {
				return fmt.Errorf("--format needs a value")
			}
			format = args[i]
		default:
			return fmt.Errorf("unknown flag %s", args[i])
		}
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "md" {
		format = "markdown"
	}
	return request("GET", "/api/v1/report?format="+url.QueryEscape(format), nil)
}

func playbooksCmd(args []string) error {
	format := "markdown"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format":
			i++
			if i >= len(args) {
				return fmt.Errorf("--format needs a value")
			}
			format = args[i]
		default:
			return fmt.Errorf("unknown flag %s", args[i])
		}
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "md" {
		format = "markdown"
	}
	return request("GET", "/api/v1/playbooks?format="+url.QueryEscape(format), nil)
}

func intelCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("intel preview|feed|hits|dns-hits|history|rollback|apply|clear [FILE] [--matched-only]")
	}
	switch args[0] {
	case "preview":
		if len(args) < 2 {
			return fmt.Errorf("intel preview FILE")
		}
		body, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		return request("POST", "/api/v1/intel/preview", body)
	case "feed":
		if len(args) < 2 {
			return request("GET", "/api/v1/intel/feed", nil)
		}
		body, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		return request("PUT", "/api/v1/intel/feed", body)
	case "hits":
		return request("GET", "/api/v1/intel/hits", nil)
	case "history":
		return request("GET", "/api/v1/intel/history", nil)
	case "rollback":
		if len(args) != 2 {
			return fmt.Errorf("intel rollback REVISION")
		}
		rev, err := strconv.ParseUint(args[1], 10, 64)
		if err != nil || rev == 0 {
			return fmt.Errorf("revision must be a positive integer")
		}
		return request("POST", "/api/v1/intel/rollback/"+strconv.FormatUint(rev, 10), nil)
	case "dns-hits":
		return request("GET", "/api/v1/intel/dns-hits", nil)
	case "clear":
		return request("DELETE", "/api/v1/intel/feed", nil)
	case "apply":
		path := "/api/v1/intel/apply"
		for _, a := range args[1:] {
			if a == "--matched-only" {
				path += "?matchedOnly=true"
			}
		}
		return requestHeaders("POST", path, nil, map[string]string{"X-Netra-Confirm-Risk": "high"})
	default:
		return fmt.Errorf("intel preview|feed|hits|dns-hits|history|rollback|apply|clear [FILE] [--matched-only]")
	}
}

func watchlistCmd(args []string) error {
	if len(args) < 2 || args[0] != "match" {
		return fmt.Errorf("watchlist match FILE")
	}
	body, err := os.ReadFile(args[1])
	if err != nil {
		return err
	}
	return request("POST", "/api/v1/watchlist/match", body)
}

func handoffCmd(args []string) error {
	format := "markdown"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format":
			i++
			if i >= len(args) {
				return fmt.Errorf("--format needs a value")
			}
			format = args[i]
		default:
			return fmt.Errorf("unknown flag %s", args[i])
		}
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "md" {
		format = "markdown"
	}
	return request("GET", "/api/v1/handoff?format="+url.QueryEscape(format), nil)
}
