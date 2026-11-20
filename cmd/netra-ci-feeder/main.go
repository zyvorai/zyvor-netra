// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

// Command netra-ci-feeder streams AF_PACKET frames from a named interface to
// Netra's agent capture WebSocket. Used by scripts/ci-auto-capture-veth.sh to
// prove auto-capture writes a real PCAP without running the full node agent.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"

	"github.com/zyvorai/netra/internal/afcapture"
	"github.com/zyvorai/netra/internal/capture"
)

func main() {
	var (
		controller = flag.String("controller", "http://127.0.0.1:30870", "netrad base URL (http or https)")
		agentKey   = flag.String("agent-key", "", "X-Netra-Agent-Key (or NETRA_AGENT_KEY)")
		node       = flag.String("node", "ci-veth", "node name matching the auto-capture session")
		iface      = flag.String("iface", "netra-ci0", "AF_PACKET interface")
		protocol   = flag.String("protocol", "tcp", "capture filter protocol")
		duration   = flag.Duration("duration", 20*time.Second, "how long to stream")
		maxPPS     = flag.Uint("max-pps", 2000, "userspace PPS cap")
		insecure   = flag.Bool("insecure", true, "skip TLS verify when controller is https")
	)
	flag.Parse()

	key := strings.TrimSpace(*agentKey)
	if key == "" {
		key = strings.TrimSpace(os.Getenv("NETRA_AGENT_KEY"))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cctx, cancel := context.WithTimeout(ctx, *duration)
	defer cancel()

	spec := capture.SpecValue{
		Enabled:  1,
		Protocol: protoNum(*protocol),
		MaxPPS:   uint32(*maxPPS),
		SnapLen:  256,
	}
	sess, err := afcapture.Open(cctx, []string{*iface}, spec)
	if err != nil {
		log.Fatalf("afcapture open: %v", err)
	}
	defer sess.Close()

	u, err := url.Parse(*controller)
	if err != nil {
		log.Fatal(err)
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	default:
		log.Fatalf("unsupported controller scheme %q", u.Scheme)
	}
	u.Path = "/api/v1/agents/capture/stream"
	q := u.Query()
	q.Set("node", *node)
	u.RawQuery = q.Encode()

	header := http.Header{}
	if key != "" {
		header.Set("X-Netra-Agent-Key", key)
	}
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	if *insecure {
		dialer.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} //nolint:gosec // CI feeder only
	}
	conn, _, err := dialer.DialContext(cctx, u.String(), header)
	if err != nil {
		log.Fatalf("ws dial: %v", err)
	}
	defer conn.Close()

	var n int
	for {
		select {
		case <-cctx.Done():
			log.Printf("feeder done: frames=%d", n)
			return
		case f, ok := <-sess.Frames():
			if !ok {
				log.Printf("feeder frames closed: frames=%d", n)
				return
			}
			if err := conn.WriteMessage(websocket.BinaryMessage, capture.EncodeFrame(f)); err != nil {
				log.Fatalf("ws write: %v", err)
			}
			n++
		}
	}
}

func protoNum(p string) uint8 {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "udp":
		return 17
	case "icmp":
		return 1
	default:
		return 6 // tcp
	}
}
