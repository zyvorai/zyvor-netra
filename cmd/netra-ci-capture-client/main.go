// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Command netra-ci-capture-client is the browser's side of a packet capture: it
// connects to the controller's capture WebSocket for one node, decodes the frames
// the agent streams, writes them as a classic .pcap file, and prints a JSON summary
// (frame count, direction and protocol mix, the packets' addresses and ports).
// scripts/ci-capture-live.sh uses it to check a real capture end to end.
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"

	"github.com/zyvorai/netra/internal/capture"
)

type summary struct {
	Frames     int            `json:"frames"`
	Bytes      int            `json:"bytes"`
	Directions map[string]int `json:"directions"`
	Protocols  map[string]int `json:"protocols"`
	Families   map[string]int `json:"families"`
	Tuples     map[string]int `json:"tuples"`    // "src:sport>dst:dport" -> frames
	DstPorts   map[string]int `json:"dstPorts"`  // TCP/UDP destination port -> frames
	SrcPorts   map[string]int `json:"srcPorts"`  // TCP/UDP source port -> frames
	Undecoded  int            `json:"undecoded"` // frames whose L3/L4 headers could not be parsed
	OrigLenMin uint32         `json:"origLenMin"`
	Elapsed    string         `json:"elapsed"`
}

func main() {
	var (
		controller = flag.String("controller", "http://127.0.0.1:30870", "netrad base URL")
		key        = flag.String("key", "", "API key (or NETRA_API_KEY)")
		node       = flag.String("node", "", "node whose capture to watch")
		out        = flag.String("out", "", "write a classic .pcap here")
		duration   = flag.Duration("duration", 15*time.Second, "how long to listen")
		insecure   = flag.Bool("insecure", false, "skip TLS verification (https controller)")
		ready      = flag.String("ready-file", "", "create this file once the WebSocket is connected")
	)
	flag.Parse()
	if *node == "" {
		fmt.Fprintln(os.Stderr, "netra-ci-capture-client: -node is required")
		os.Exit(2)
	}
	apiKey := strings.TrimSpace(*key)
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv("NETRA_API_KEY"))
	}
	u, err := url.Parse(strings.TrimRight(*controller, "/"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "netra-ci-capture-client:", err)
		os.Exit(2)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	default:
		u.Scheme = "ws"
	}
	u.Path = "/api/v1/vms/" + url.PathEscape(*node) + "/capture/ws"

	dialer := *websocket.DefaultDialer
	if *insecure {
		dialer.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} //nolint:gosec // CI helper, explicit flag
	}
	hdr := http.Header{}
	if apiKey != "" {
		hdr.Set("Authorization", "Bearer "+apiKey)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	conn, _, err := dialer.DialContext(ctx, u.String(), hdr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "netra-ci-capture-client: dial:", err)
		os.Exit(1)
	}
	defer conn.Close()
	if *ready != "" {
		_ = os.WriteFile(*ready, []byte("ready\n"), 0o600)
	}

	var pcap *os.File
	if *out != "" {
		if pcap, err = os.Create(*out); err != nil {
			fmt.Fprintln(os.Stderr, "netra-ci-capture-client:", err)
			os.Exit(1)
		}
		defer pcap.Close()
		if err := capture.WritePCAPHeader(pcap); err != nil {
			fmt.Fprintln(os.Stderr, "netra-ci-capture-client:", err)
			os.Exit(1)
		}
	}

	s := summary{Directions: map[string]int{}, Protocols: map[string]int{}, Families: map[string]int{}, Tuples: map[string]int{}, DstPorts: map[string]int{}, SrcPorts: map[string]int{}}
	start := time.Now()
	deadline := start.Add(*duration)
	go func() { <-ctx.Done(); _ = conn.Close() }()
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(deadline)
		typ, raw, err := conn.ReadMessage()
		if err != nil {
			break // deadline, cancellation, or the controller closed the stream
		}
		if typ != websocket.BinaryMessage {
			continue
		}
		f, err := capture.DecodeFrame(raw)
		if err != nil {
			s.Undecoded++
			continue
		}
		s.Frames++
		s.Bytes += len(f.Data)
		if s.OrigLenMin == 0 || f.OrigLen < s.OrigLenMin {
			s.OrigLenMin = f.OrigLen
		}
		s.Directions[dirName(f.Direction)]++
		s.Families[famName(f.Family)]++
		s.Protocols[protoName(f.Protocol)]++
		if src, sp, dst, dp, ok := parse(f); ok {
			s.Tuples[fmt.Sprintf("%s:%d>%s:%d", src, sp, dst, dp)]++
			s.DstPorts[fmt.Sprint(dp)]++
			s.SrcPorts[fmt.Sprint(sp)]++
		} else {
			s.Undecoded++
		}
		if pcap != nil {
			if err := capture.WritePCAPRecord(pcap, f); err != nil {
				fmt.Fprintln(os.Stderr, "netra-ci-capture-client: write pcap:", err)
				os.Exit(1)
			}
		}
	}
	s.Elapsed = time.Since(start).Round(time.Millisecond).String()
	_ = json.NewEncoder(os.Stdout).Encode(s)
}

func dirName(d uint8) string {
	switch d {
	case 1:
		return "ingress"
	case 2:
		return "egress"
	}
	return fmt.Sprintf("dir%d", d)
}

func famName(f uint8) string {
	switch f {
	case 4:
		return "ipv4"
	case 6:
		return "ipv6"
	}
	return fmt.Sprintf("family%d", f)
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	}
	return fmt.Sprintf("proto%d", p)
}

// parse reads the Ethernet, IP and TCP/UDP headers of a captured frame (it carries
// the whole frame starting at the Ethernet header) and returns its addresses and ports.
func parse(f capture.Frame) (src string, sp uint16, dst string, dp uint16, ok bool) {
	d := f.Data
	if len(d) < 14 {
		return
	}
	etype := binary.BigEndian.Uint16(d[12:14])
	d = d[14:]
	var proto byte
	switch etype {
	case 0x0800:
		if len(d) < 20 || d[0]>>4 != 4 {
			return
		}
		ihl := int(d[0]&0x0f) * 4
		if ihl < 20 || len(d) < ihl {
			return
		}
		proto = d[9]
		s, _ := netip.AddrFromSlice(d[12:16])
		t, _ := netip.AddrFromSlice(d[16:20])
		src, dst = s.String(), t.String()
		d = d[ihl:]
	case 0x86dd:
		if len(d) < 40 || d[0]>>4 != 6 {
			return
		}
		proto = d[6] // extension headers are not walked: the test traffic has none
		s, _ := netip.AddrFromSlice(d[8:24])
		t, _ := netip.AddrFromSlice(d[24:40])
		src, dst = s.String(), t.String()
		d = d[40:]
	default:
		return
	}
	if (proto != 6 && proto != 17) || len(d) < 4 {
		return
	}
	return src, binary.BigEndian.Uint16(d[0:2]), dst, binary.BigEndian.Uint16(d[2:4]), true
}
