// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package hubble

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

type Client struct {
	addr    string
	dial    []grpc.DialOption
	enabled bool
}

// Filter maps Netra's stable API query fields to native Hubble FlowFilter fields.
// Multiple fields in one Hubble FlowFilter are ANDed. Netra emits two whitelist
// filters when namespace/pod is set so either endpoint can match while all of the
// other constraints remain active.
type Filter struct {
	Verdict     string
	Namespace   string
	Pod         string
	Direction   string
	Protocol    string
	Destination string
}

func NewFromEnvironment() (*Client, error) {
	enabled := !strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_HUBBLE_ENABLED")), "false")
	if !enabled {
		return &Client{enabled: false}, nil
	}
	addr := os.Getenv("NETRA_HUBBLE_ADDR")
	if addr == "" {
		addr = "hubble-relay.kube-system.svc:80"
	}
	var creds credentials.TransportCredentials
	ca := os.Getenv("NETRA_HUBBLE_CA")
	cert := os.Getenv("NETRA_HUBBLE_CERT")
	key := os.Getenv("NETRA_HUBBLE_KEY")
	serverName := os.Getenv("NETRA_HUBBLE_SERVER_NAME")
	if ca != "" || cert != "" || key != "" {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
		if ca != "" {
			pem, err := os.ReadFile(ca)
			if err != nil {
				return nil, err
			}
			pool, _ := x509.SystemCertPool()
			if pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("no certificates in Hubble CA")
			}
			cfg.RootCAs = pool
		}
		if cert != "" || key != "" {
			pair, err := tls.LoadX509KeyPair(cert, key)
			if err != nil {
				return nil, err
			}
			cfg.Certificates = []tls.Certificate{pair}
		}
		creds = credentials.NewTLS(cfg)
	} else {
		creds = insecure.NewCredentials()
	}
	return &Client{addr: addr, dial: []grpc.DialOption{grpc.WithTransportCredentials(creds)}, enabled: true}, nil
}

func (c *Client) connect(ctx context.Context) (*grpc.ClientConn, observerpb.ObserverClient, error) {
	if !c.enabled {
		return nil, nil, fmt.Errorf("Hubble integration is disabled; Netra standalone eBPF remains available")
	}
	conn, err := grpc.NewClient(c.addr, c.dial...)
	if err != nil {
		return nil, nil, err
	}
	return conn, observerpb.NewObserverClient(conn), nil
}

func (c *Client) Status(ctx context.Context) (any, error) {
	if !c.enabled {
		return map[string]any{"enabled": false, "optional": true}, nil
	}
	conn, cli, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s, err := cli.ServerStatus(ctx, &observerpb.ServerStatusRequest{})
	if err != nil {
		return nil, err
	}
	b, err := protojson.MarshalOptions{UseProtoNames: false}.Marshal(s)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) Stream(ctx context.Context, number uint64, follow bool, filter Filter, accept func([]byte) error) error {
	conn, cli, err := c.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	req := &observerpb.GetFlowsRequest{Number: number, Follow: follow, Whitelist: buildFlowFilters(filter)}
	stream, err := cli.GetFlows(ctx, req)
	if err != nil {
		return err
	}
	marshaler := protojson.MarshalOptions{UseProtoNames: false, EmitUnpopulated: false}
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if resp.GetFlow() == nil {
			continue
		}
		b, err := marshaler.Marshal(resp.GetFlow())
		if err != nil {
			return err
		}
		if err := accept(b); err != nil {
			return err
		}
	}
}

func buildFlowFilters(filter Filter) []*flowpb.FlowFilter {
	common := func(f *flowpb.FlowFilter) {
		if v, ok := verdictValue(filter.Verdict); ok {
			f.Verdict = []flowpb.Verdict{v}
		}
		if d, ok := directionValue(filter.Direction); ok {
			f.TrafficDirection = []flowpb.TrafficDirection{d}
		}
		if p := strings.TrimSpace(filter.Protocol); p != "" {
			f.Protocol = []string{strings.ToLower(p)}
		}
		if dst := strings.TrimSpace(filter.Destination); dst != "" {
			f.DestinationIp = []string{dst}
		}
	}

	scope := podScope(filter.Namespace, filter.Pod)
	if scope == "" {
		f := &flowpb.FlowFilter{}
		common(f)
		if isEmptyFlowFilter(f) {
			return nil
		}
		return []*flowpb.FlowFilter{f}
	}

	src := &flowpb.FlowFilter{SourcePod: []string{scope}}
	dst := &flowpb.FlowFilter{DestinationPod: []string{scope}}
	common(src)
	common(dst)
	return []*flowpb.FlowFilter{src, dst}
}

func verdictValue(v string) (flowpb.Verdict, bool) {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "FORWARDED":
		return flowpb.Verdict_FORWARDED, true
	case "DROPPED":
		return flowpb.Verdict_DROPPED, true
	case "ERROR":
		return flowpb.Verdict_ERROR, true
	case "AUDIT":
		return flowpb.Verdict_AUDIT, true
	case "REDIRECTED":
		return flowpb.Verdict_REDIRECTED, true
	case "TRACED":
		return flowpb.Verdict_TRACED, true
	case "TRANSLATED":
		return flowpb.Verdict_TRANSLATED, true
	default:
		return 0, false
	}
}

func directionValue(v string) (flowpb.TrafficDirection, bool) {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "EGRESS":
		return flowpb.TrafficDirection_EGRESS, true
	case "INGRESS":
		return flowpb.TrafficDirection_INGRESS, true
	default:
		return 0, false
	}
}

func podScope(namespace, pod string) string {
	ns := strings.TrimSpace(namespace)
	p := strings.TrimSpace(pod)
	if ns == "" {
		return p
	}
	if p == "" {
		return ns + "/"
	}
	return ns + "/" + p
}

func isEmptyFlowFilter(f *flowpb.FlowFilter) bool {
	return len(f.Verdict) == 0 && len(f.TrafficDirection) == 0 && len(f.Protocol) == 0 && len(f.DestinationIp) == 0
}

func MatchFlowJSON(raw []byte, filter Filter) bool {
	if filter.Verdict == "" && filter.Namespace == "" && filter.Pod == "" && filter.Direction == "" {
		return true
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	if filter.Verdict != "" && !strings.EqualFold(fmt.Sprint(m["verdict"]), filter.Verdict) {
		return false
	}
	if filter.Direction != "" && !strings.EqualFold(fmt.Sprint(m["trafficDirection"]), filter.Direction) {
		return false
	}
	if filter.Namespace != "" && !endpointContains(m, "source", filter.Namespace, "") && !endpointContains(m, "destination", filter.Namespace, "") {
		return false
	}
	if filter.Pod != "" && !endpointContains(m, "source", "", filter.Pod) && !endpointContains(m, "destination", "", filter.Pod) {
		return false
	}
	return true
}

func Explain(raw []byte) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	out := map[string]any{"flow": m, "verdict": fmt.Sprint(m["verdict"])}
	if v, ok := m["dropReasonDesc"]; ok {
		out["dropReason"] = v
	}
	if v, ok := m["policyLog"]; ok {
		out["policyLog"] = v
	}
	return out
}

func endpointContains(m map[string]any, side, ns, pod string) bool {
	e, _ := m[side].(map[string]any)
	if e == nil {
		return false
	}
	if ns != "" && fmt.Sprint(e["namespace"]) != ns {
		return false
	}
	if pod != "" && !strings.HasPrefix(fmt.Sprint(e["podName"]), pod) {
		return false
	}
	return true
}

// Compile-time anchor: this package intentionally consumes Cilium's supported protobuf API.
var _ = flowpb.Verdict_DROPPED
