// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/zyvorai/netra/internal/mcpserver"
)

// endpointTool describes one Netra controller HTTP endpoint as a
// table-driven MCP tool. It covers the overwhelming majority of
// endpoints (simple GETs, and mutating POST/PUT/DELETEs whose body is
// just the tool's arguments); the handful of endpoints with a genuinely
// different shape (the policy plan/apply token hand-off) get bespoke
// registration instead — see tools_mutate.go.
type endpointTool struct {
	name        string
	method      string
	path        string // may contain {param} placeholders
	description string
	schema      map[string]any

	pathParams  []string          // placeholder names appearing in path, consumed from arguments
	queryParams []string          // argument names to forward as query-string parameters
	bodyFields  bool              // if true, remaining arguments (after path/query extraction) are marshaled as the JSON request body
	headers     map[string]string // fixed headers always sent, e.g. a static risk/replace confirmation
}

func registerEndpointTool(srv *mcpserver.Server, c *client, t endpointTool) error {
	return srv.Register(mcpserver.Tool{
		Name:        t.name,
		Description: t.description,
		InputSchema: t.schema,
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			args := map[string]any{}
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &args); err != nil {
					return fmt.Sprintf("invalid arguments: %v", err), true, nil
				}
			}

			path := t.path
			for _, name := range t.pathParams {
				v, _ := args[name].(string)
				path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(v))
				delete(args, name)
			}

			q := url.Values{}
			for _, name := range t.queryParams {
				if v, ok := args[name]; ok {
					q.Set(name, fmt.Sprint(v))
					delete(args, name)
				}
			}
			if len(q) > 0 {
				path += "?" + q.Encode()
			}

			var body []byte
			if t.bodyFields && len(args) > 0 {
				b, err := json.Marshal(args)
				if err != nil {
					return fmt.Sprintf("invalid arguments: %v", err), true, nil
				}
				body = b
			}

			out, status, err := c.do(ctx, t.method, path, body, t.headers)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}

// Small schema-building helpers to keep the tool tables in
// tools_read.go/tools_mutate.go readable — every InputSchema is a
// hand-written JSON-Schema map literal, never derived via reflection.

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func intProp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func enumProp(desc string, values ...string) map[string]any {
	return map[string]any{"type": "string", "enum": values, "description": desc}
}

func objSchema(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func emptySchema() map[string]any { return objSchema(map[string]any{}) }

// httpResultToToolResult centralizes the status -> isError mapping
// shared by nearly every tool: any 2xx is success, anything else is an
// isError result carrying the status and whatever body the controller
// sent (typically {"error": "..."} per internal/api/server.go's
// errorJSON helper).
func httpResultToToolResult(body []byte, status int) (any, bool, error) {
	var v any
	if json.Unmarshal(body, &v) != nil {
		v = string(body)
	}
	if status < 200 || status >= 300 {
		return map[string]any{"status": status, "body": v}, true, nil
	}
	return v, false, nil
}
