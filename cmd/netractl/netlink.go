// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"fmt"
	"net/url"
)

const netlinkUsage = "netlink state|events|findings [--node NODE] [--kind link|address|route|neighbor|overrun] [--since 30m] [--limit N] [--window 15m]"

// netlinkCmd reads the host network change recorder. It only ever issues a GET:
// there is nothing here that changes a link, address, route or neighbor.
func netlinkCmd(args []string) error {
	path, err := netlinkPath(args)
	if err != nil {
		return err
	}
	return request("GET", path, nil)
}

// netlinkPath turns `state|events|findings [flags]` into the API path. `state` is
// the per-node snapshot (routes, neighbors, links), `events` the change timeline
// and `findings` what is wrong now, derived from the changes.
func netlinkPath(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("%s", netlinkUsage)
	}
	q := url.Values{}
	switch args[0] {
	case "state":
		q.Set("view", "state")
	case "events":
		q.Set("view", "events")
	case "findings":
		// What is wrong now, derived from the changes: not a view of the recorder.
	default:
		return "", fmt.Errorf("%s", netlinkUsage)
	}
	flags := map[string]string{"--node": "node", "--kind": "kind", "--since": "since", "--limit": "limit", "--window": "window"}
	for i := 1; i < len(args); i += 2 {
		key, ok := flags[args[i]]
		if !ok {
			return "", fmt.Errorf("unknown netlink flag %s", args[i])
		}
		if i+1 >= len(args) {
			return "", fmt.Errorf("%s needs a value", args[i])
		}
		switch {
		case args[0] == "state" && (key == "kind" || key == "since" || key == "limit" || key == "window"):
			return "", fmt.Errorf("%s applies to `netlink events` or `netlink findings`, not `netlink state`", args[i])
		case args[0] == "events" && key == "window":
			return "", fmt.Errorf("--window applies to `netlink findings`; use --since for events")
		case args[0] == "findings" && (key == "kind" || key == "since" || key == "limit"):
			return "", fmt.Errorf("%s applies to `netlink events`, not `netlink findings`", args[i])
		}
		q.Set(key, args[i+1])
	}
	if args[0] == "findings" {
		return "/api/v1/netlink/findings?" + q.Encode(), nil
	}
	return "/api/v1/netlink?" + q.Encode(), nil
}
