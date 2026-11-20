// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package chatops

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestClientPinsRequestsToControllerAPI(t *testing.T) {
	c := NewClient("https://127.0.0.1:30870", "k")
	tr := c.httpClient.Transport.(*http.Transport)
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLS certificate verification must stay enabled")
	}
	for _, path := range []string{
		"https://evil.example/api/v1/status",
		"//evil.example/api/v1/status",
		"/api/v1/vms/../../etc/passwd",
		"/api/v1/vms/node@evil/capture",
		"/other",
	} {
		if _, _, err := c.Do(context.Background(), http.MethodGet, path, nil, ""); err == nil {
			t.Fatalf("path %q was not refused", path)
		}
	}
	got, err := c.endpoint("/api/v1/vms/node-a.example/capture?x=1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "https://127.0.0.1:30870/api/v1/vms/node-a.example/capture") {
		t.Fatalf("endpoint = %s", got)
	}
	if strings.Contains(got, "@") {
		t.Fatalf("endpoint changed host: %s", got)
	}
}
