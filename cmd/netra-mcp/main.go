// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Command netra-mcp is a Model Context Protocol (MCP) server exposing a
// running Netra controller's HTTP API as MCP tools over stdio, for
// consumption by an MCP client such as Hermes Agent or Claude Desktop.
// See docs/mcp-integration.md.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/zyvorai/netra/internal/mcpserver"
)

const version = "0.31.0"

func main() {
	c := newClient()
	allowMutations := strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_MCP_ALLOW_MUTATIONS")), "true")
	srv, err := buildServer(c, allowMutations)
	if err != nil {
		fmt.Fprintln(os.Stderr, "netra-mcp:", err)
		os.Exit(1)
	}

	// Stdout is the JSON-RPC channel; nothing but Server.Serve's own
	// responses may ever be written to it. Diagnostics go to stderr.
	if err := srv.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "netra-mcp:", err)
		os.Exit(1)
	}
}

// buildServer wires up all tools. Kept separate from main so tests can
// construct a server against a fake controller without a real process.
func buildServer(c *client, allowMutations bool) (*mcpserver.Server, error) {
	srv := mcpserver.New("netra-mcp", version)
	if err := registerReadTools(srv, c); err != nil {
		return nil, err
	}
	if err := registerPrompts(srv); err != nil {
		return nil, err
	}
	if err := registerResources(srv, c); err != nil {
		return nil, err
	}
	if allowMutations {
		if err := registerMutateTools(srv, c); err != nil {
			return nil, err
		}
	}
	return srv, nil
}
