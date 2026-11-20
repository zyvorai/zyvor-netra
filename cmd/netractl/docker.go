// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const dockerInspectLimit = 4 << 20

var dockerNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
var dockerIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type dockerContainer struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	State struct {
		Running   bool      `json:"Running"`
		PID       int       `json:"Pid"`
		StartedAt time.Time `json:"StartedAt"`
	} `json:"State"`
}

// Only selected identity fields are decoded. Never print the raw inspect response:
// Docker inspect may contain environment variables and registry credentials.
type dockerEvidence struct {
	Name      string    `json:"name"`
	ID        string    `json:"id"`
	PID       int       `json:"initPid"`
	CgroupID  string    `json:"cgroupId"` // JSON string preserves uint64 precision for JS consumers.
	StartedAt time.Time `json:"startedAt"`
	Node      string    `json:"node"`
}

func dockerClient(socket string) (*http.Client, error) {
	if !filepath.IsAbs(socket) || strings.ContainsRune(socket, 0) {
		return nil, fmt.Errorf("--docker-socket must be an absolute Unix socket path")
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
	}, DisableKeepAlives: true}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func inspectDocker(client *http.Client, name string) (dockerContainer, error) {
	var c dockerContainer
	if !dockerNamePattern.MatchString(name) {
		return c, fmt.Errorf("Docker selector must be an exact container name or full ID")
	}
	req, e := http.NewRequest(http.MethodGet, "http://docker/containers/"+url.PathEscape(name)+"/json", nil)
	if e != nil {
		return c, e
	}
	// Do not send the Netra bearer token to Docker.
	res, e := client.Do(req)
	if e != nil {
		return c, fmt.Errorf("Docker inspect: %w", e)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return c, fmt.Errorf("Docker inspect: HTTP %d %s", res.StatusCode, http.StatusText(res.StatusCode))
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, dockerInspectLimit+1))
	if e != nil {
		return c, e
	}
	if len(b) > dockerInspectLimit {
		return c, fmt.Errorf("Docker inspect response exceeds 4 MiB")
	}
	if json.Unmarshal(b, &c) != nil {
		return c, fmt.Errorf("invalid Docker inspect response")
	}
	if !dockerIDPattern.MatchString(c.ID) || !dockerNamePattern.MatchString(strings.TrimPrefix(c.Name, "/")) {
		return c, fmt.Errorf("Docker inspect returned an invalid container identity")
	}
	if strings.TrimPrefix(c.Name, "/") != name && c.ID != name {
		return c, fmt.Errorf("Docker selector must match the exact name or full ID; abbreviated IDs are not accepted")
	}
	if !c.State.Running || c.State.PID <= 0 || c.State.StartedAt.IsZero() {
		return c, fmt.Errorf("container is not running or has incomplete process identity")
	}
	return c, nil
}
func sameDockerIncarnation(a, b dockerContainer) bool {
	return a.ID == b.ID && a.State.PID == b.State.PID && a.State.StartedAt.Equal(b.State.StartedAt) && b.State.Running
}

// Inspect by the original full ID again after fetching Netra reports. This detects
// restarts and name reuse instead of silently diagnosing a replacement container.
func collectDocker(o explainOptions, client *http.Client, resolve func(dockerContainer) (uint64, error), fetch func() ([]explainAgent, error)) ([]explainAgent, explainOptions, error) {
	before, e := inspectDocker(client, o.Docker)
	if e != nil {
		return nil, o, e
	}
	cg, e := resolve(before)
	if e != nil {
		return nil, o, e
	}
	if cg == 0 {
		return nil, o, fmt.Errorf("resolved cgroup ID is zero")
	}
	agents, e := fetch()
	if e != nil {
		return nil, o, e
	}
	after, e := inspectDocker(client, before.ID)
	if e != nil {
		return nil, o, e
	}
	if !sameDockerIncarnation(before, after) {
		return nil, o, fmt.Errorf("container restarted during diagnosis; retry")
	}
	confirmed, e := resolve(after)
	if e != nil {
		return nil, o, e
	}
	if confirmed != cg {
		return nil, o, fmt.Errorf("container cgroup changed during diagnosis; retry")
	}
	o.cgroupID = cg
	o.dockerDetails = &dockerEvidence{Name: strings.TrimPrefix(before.Name, "/"), ID: before.ID, PID: before.State.PID, CgroupID: fmt.Sprint(cg), StartedAt: before.State.StartedAt, Node: o.Node}
	return agents, o, nil
}
