// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gorilla/websocket"
)

// StreamPodLogs opens a streaming GET to the pods/log subresource.
// The caller must Close the returned body.
func (c *Client) StreamPodLogs(ctx context.Context, ns, pod, container string, tailLines int, follow bool) (io.ReadCloser, error) {
	q := url.Values{}
	if container != "" {
		q.Set("container", container)
	}
	if tailLines > 0 {
		q.Set("tailLines", strconv.Itoa(tailLines))
	}
	if follow {
		q.Set("follow", "true")
	}
	path := "/api/v1/namespaces/" + esc(ns) + "/pods/" + esc(pod) + "/log?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.streamHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		return nil, fmt.Errorf("kubernetes API %s: %s", resp.Status, string(b))
	}
	return resp.Body, nil
}

// DialPodExec opens a WebSocket to the pods/exec subresource (v4 channel protocol).
func (c *Client) DialPodExec(ctx context.Context, ns, pod, container string, command []string, tty bool) (*websocket.Conn, error) {
	if len(command) == 0 {
		command = []string{"/bin/sh"}
	}
	u, err := url.Parse(c.base)
	if err != nil {
		return nil, err
	}
	u.Scheme = strings.Replace(u.Scheme, "http", "ws", 1)
	u.Path = "/api/v1/namespaces/" + esc(ns) + "/pods/" + esc(pod) + "/exec"
	q := url.Values{}
	for _, arg := range command {
		q.Add("command", arg)
	}
	q.Set("stdin", "true")
	q.Set("stdout", "true")
	q.Set("stderr", "true")
	if tty {
		q.Set("tty", "true")
	}
	if container != "" {
		q.Set("container", container)
	}
	u.RawQuery = q.Encode()

	header := http.Header{}
	if c.token != "" {
		header.Set("Authorization", "Bearer "+c.token)
	}
	dialer := websocket.Dialer{
		TLSClientConfig: c.tlsConfig,
		Subprotocols:    []string{"v4.channel.k8s.io", "v3.channel.k8s.io"},
	}
	conn, resp, err := dialer.DialContext(ctx, u.String(), header)
	if err != nil {
		if resp != nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			return nil, fmt.Errorf("pod exec dial: %w (%s)", err, string(b))
		}
		return nil, fmt.Errorf("pod exec dial: %w", err)
	}
	return conn, nil
}

// DialVMIVnc opens a WebSocket to the KubeVirt VMI VNC subresource.
func (c *Client) DialVMIVnc(ctx context.Context, ns, name string) (*websocket.Conn, error) {
	u, err := url.Parse(c.base)
	if err != nil {
		return nil, err
	}
	u.Scheme = strings.Replace(u.Scheme, "http", "ws", 1)
	u.Path = "/apis/subresources.kubevirt.io/v1/namespaces/" + esc(ns) + "/virtualmachineinstances/" + esc(name) + "/vnc"
	header := http.Header{}
	if c.token != "" {
		header.Set("Authorization", "Bearer "+c.token)
	}
	dialer := websocket.Dialer{TLSClientConfig: c.tlsConfig}
	conn, resp, err := dialer.DialContext(ctx, u.String(), header)
	if err != nil {
		if resp != nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			return nil, fmt.Errorf("vmi vnc dial: %w (%s)", err, string(b))
		}
		return nil, fmt.Errorf("vmi vnc dial: %w", err)
	}
	return conn, nil
}

// EncodeExecResize builds a Kubernetes channel-4 terminal resize frame.
func EncodeExecResize(cols, rows uint16) []byte {
	payload, _ := json.Marshal(map[string]uint16{"Width": cols, "Height": rows})
	return append([]byte{4}, payload...)
}
