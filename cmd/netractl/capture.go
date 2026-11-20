// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func captureCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("capture start|stop|status|history|summaries|context ID")
	}
	switch args[0] {
	case "status":
		return request("GET", "/api/v1/capture/status", nil)
	case "history":
		return request("GET", "/api/v1/capture/history", nil)
	case "summaries":
		return request("GET", "/api/v1/capture/summaries", nil)
	case "context":
		if len(args) < 2 {
			return fmt.Errorf("capture context ARTIFACT_ID")
		}
		return request("GET", "/api/v1/capture/artifacts/"+url.PathEscape(args[1])+"/context", nil)
	case "stop":
		if len(args) < 2 {
			return fmt.Errorf("capture stop NODE")
		}
		return request("DELETE", "/api/v1/vms/"+url.PathEscape(args[1])+"/capture", nil)
	case "start":
		return captureStartCmd(args[1:])
	default:
		return fmt.Errorf("capture start|stop|status|history|summaries|context ID")
	}
}

func captureStartCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("capture start NODE [--backend ebpf|afpacket] [--protocol tcp|udp|icmp|icmpv6] [--host IP] [--port N] [--snaplen N] [--max-pps N] [--duration 60s]")
	}
	node := args[0]
	body := struct {
		Backend         string `json:"backend,omitempty"`
		Protocol        string `json:"protocol,omitempty"`
		Host            string `json:"host,omitempty"`
		Port            uint16 `json:"port,omitempty"`
		SnapLen         uint16 `json:"snapLen,omitempty"`
		MaxPPS          uint32 `json:"maxPps,omitempty"`
		DurationSeconds int    `json:"durationSeconds,omitempty"`
	}{}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--backend":
			i++
			if i >= len(args) {
				return fmt.Errorf("--backend needs a value")
			}
			backend, err := models.NormalizeCaptureBackend(args[i])
			if err != nil {
				return err
			}
			body.Backend = backend
		case "--protocol":
			i++
			if i >= len(args) {
				return fmt.Errorf("--protocol needs a value")
			}
			body.Protocol = args[i]
		case "--host":
			i++
			if i >= len(args) {
				return fmt.Errorf("--host needs a value")
			}
			body.Host = args[i]
		case "--port":
			i++
			if i >= len(args) {
				return fmt.Errorf("--port needs a value")
			}
			n, err := strconv.ParseUint(args[i], 10, 16)
			if err != nil {
				return fmt.Errorf("--port: %w", err)
			}
			body.Port = uint16(n)
		case "--snaplen":
			i++
			if i >= len(args) {
				return fmt.Errorf("--snaplen needs a value")
			}
			n, err := strconv.ParseUint(args[i], 10, 16)
			if err != nil {
				return fmt.Errorf("--snaplen: %w", err)
			}
			body.SnapLen = uint16(n)
		case "--max-pps":
			i++
			if i >= len(args) {
				return fmt.Errorf("--max-pps needs a value")
			}
			n, err := strconv.ParseUint(args[i], 10, 32)
			if err != nil {
				return fmt.Errorf("--max-pps: %w", err)
			}
			body.MaxPPS = uint32(n)
		case "--duration":
			i++
			if i >= len(args) {
				return fmt.Errorf("--duration needs a value")
			}
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return fmt.Errorf("--duration: %w", err)
			}
			body.DurationSeconds = int(d.Seconds())
		default:
			return fmt.Errorf("unknown flag %s", args[i])
		}
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return request("PUT", "/api/v1/vms/"+url.PathEscape(node)+"/capture", b)
}
