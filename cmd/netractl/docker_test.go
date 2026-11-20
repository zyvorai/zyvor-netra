// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func dockerFixture() dockerContainer {
	c := dockerContainer{ID: strings.Repeat("a", 64), Name: "/app"}
	c.State.Running = true
	c.State.PID = 42
	c.State.StartedAt = time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	return c
}
func dockerTestClient(t *testing.T, handler http.HandlerFunc) *http.Client {
	t.Helper()
	return &http.Client{Transport: explainRoundTrip(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Result(), nil
	}), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func TestDockerUnixTransport(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", socket)
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("sandbox forbids Unix sockets: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	c := dockerFixture()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(c) })}
	go func() { _ = server.Serve(l) }()
	t.Cleanup(func() { _ = server.Close() })
	client, err := dockerClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	got, err := inspectDocker(client, "app")
	if err != nil || got.ID != c.ID {
		t.Fatal(got, err)
	}
}
func TestDockerInspectAndIdentityRecheck(t *testing.T) {
	c := dockerFixture()
	calls := 0
	t.Setenv("DOCKER_HOST", "tcp://untrusted.invalid:2375")
	t.Setenv("NETRA_API_KEY", "secret-netra-key")
	client := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		expected := "/containers/app/json"
		if calls == 2 {
			expected = "/containers/" + c.ID + "/json"
		}
		if r.Method != "GET" || r.URL.Path != expected || r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(c)
	})
	o, err := parseExplain([]string{"--docker", "app", "--node", "n"})
	if err != nil {
		t.Fatal(err)
	}
	const cg uint64 = 18446744073709551600
	rows, got, err := collectDocker(o, client, func(dockerContainer) (uint64, error) { return cg, nil }, func() ([]explainAgent, error) { return []explainAgent{{Node: "n"}}, nil })
	if err != nil || calls != 2 || len(rows) != 1 || got.cgroupID != cg || got.dockerDetails.CgroupID != "18446744073709551600" {
		t.Fatal(got, err, calls)
	}
}
func TestDockerInspectRejectsUnsafeResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"server error", 500, "secret-body"}, {"redirect", 302, "secret-body"}, {"malformed", 200, "secret-body"},
		{"oversized", 200, strings.Repeat("x", dockerInspectLimit+1)},
		{"short ID", 200, `{"Id":"aaa","Name":"/app"}`},
		{"stopped", 200, fmt.Sprintf(`{"Id":%q,"Name":"/app","State":{"Running":false,"Pid":42}}`, strings.Repeat("a", 64))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "http://untrusted.invalid")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			_, err := inspectDocker(client, "app")
			if err == nil || strings.Contains(err.Error(), "secret-body") {
				t.Fatal(err)
			}
		})
	}
}
func TestDockerDetectsRestartAndCgroupMigration(t *testing.T) {
	for _, change := range []string{"pid", "start", "id", "cgroup"} {
		t.Run(change, func(t *testing.T) {
			c := dockerFixture()
			calls := 0
			client := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				after := c
				if calls == 2 {
					switch change {
					case "pid":
						after.State.PID++
					case "start":
						after.State.StartedAt = after.State.StartedAt.Add(time.Second)
					case "id":
						after.ID = strings.Repeat("b", 64)
					}
				}
				_ = json.NewEncoder(w).Encode(after)
			})
			resolves := 0
			_, _, err := collectDocker(explainOptions{Docker: "app", Node: "n"}, client, func(dockerContainer) (uint64, error) {
				resolves++
				if change == "cgroup" {
					return uint64(resolves), nil
				}
				return 99, nil
			}, func() ([]explainAgent, error) { return nil, nil })
			if err == nil {
				t.Fatal("accepted changing identity")
			}
		})
	}
}
func TestDockerSelectorsAndEvidenceIsolation(t *testing.T) {
	for _, args := range [][]string{{"--docker", "app"}, {"--docker", "../app", "--node", "n"}, {"--docker", "app", "--node", "n", "--pid", "42"}, {"--docker", "app", "--node", "n", "--all"}, {"--docker", "app", "--node", "n", "--input", "-"}, {"--docker-socket", "/tmp/d.sock", "--node", "n"}, {"--docker", "app", "--node", "n", "--docker-socket", "relative"}} {
		if _, err := parseExplain(args); err == nil {
			t.Fatal("accepted", args)
		}
	}
	c := dockerFixture()
	now := c.State.StartedAt.Add(time.Minute)
	o, err := parseExplain([]string{"--docker", "app", "--node", "n"})
	if err != nil {
		t.Fatal(err)
	}
	o.cgroupID = 99
	o.dockerDetails = &dockerEvidence{ID: c.ID, StartedAt: c.State.StartedAt}
	a := explainAgent{Node: "n", ObservedAt: now, Events: []explainEvent{
		{explainIdentity: explainIdentity{CgroupID: 99}, Action: "blocked"},
		{explainIdentity: explainIdentity{CgroupID: 98, PID: 42}, Action: "blocked"},
		{explainIdentity: explainIdentity{CgroupID: 99, ContainerID: strings.Repeat("b", 64)}, Action: "blocked"},
	}, DNS: []explainDNS{{CgroupID: 99, Name: "example.com", Queries: 1}, {CgroupID: 98, Name: "other.com", Queries: 1}}}
	if got := buildExplain([]explainAgent{a}, o, now); got.FindingsTotal != 2 {
		t.Fatal(got)
	}
	a.ObservedAt = c.State.StartedAt.Add(-time.Second)
	if got := buildExplain([]explainAgent{a}, o, now); got.FindingsTotal != 0 || got.AgentsExcluded != 1 {
		t.Fatal(got)
	}
}
