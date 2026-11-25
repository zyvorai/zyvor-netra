// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestRunHTTPReportsABusyPortAndACleanStop(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("NETRA_TLS_CERT", "")
	t.Setenv("NETRA_TLS_KEY", "")
	t.Setenv("NETRA_AGENT_MTLS", "")

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	t.Setenv("NETRA_LISTEN", l.Addr().String())
	done := make(chan error, 1)
	go func() { done <- runHTTP(context.Background(), log, http.NotFoundHandler(), false, false) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a listener that cannot bind must report an error")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("runHTTP did not return for a busy port")
	}

	t.Setenv("NETRA_LISTEN", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { done <- runHTTP(ctx, log, http.NotFoundHandler(), false, false) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a requested stop is not an error: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("runHTTP did not stop with its context")
	}
}
