// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package kube

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// A cluster whose full pod list is larger than the 8 MiB response cap must
// still list completely: pages are requested with limit/continue.
func TestListPodsPagesWithContinue(t *testing.T) {
	const total = 1234
	pad := strings.Repeat("x", 8<<10)
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit <= 0 || limit > listPageSize {
			t.Errorf("limit=%q", q.Get("limit"))
		}
		if q.Get("fieldSelector") != "spec.nodeName=node-a,"+activePodsSelector {
			t.Errorf("fieldSelector lost: %q", r.URL.RawQuery)
		}
		start, _ := strconv.Atoi(q.Get("continue"))
		end := min(start+limit, total)
		var b strings.Builder
		next := ""
		if end < total {
			next = strconv.Itoa(end)
		}
		fmt.Fprintf(&b, `{"metadata":{"continue":%q},"items":[`, next)
		for i := start; i < end; i++ {
			if i > start {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"metadata":{"uid":"u%d","name":"p%d","namespace":"ns","annotations":{"pad":%q}},"spec":{"nodeName":"node-a"}}`, i, i, pad)
		}
		b.WriteString("]}")
		if b.Len() >= 8<<20 {
			t.Errorf("page of %d bytes would be truncated", b.Len())
		}
		_, _ = w.Write([]byte(b.String()))
	}))
	defer srv.Close()
	c := &Client{base: srv.URL, http: srv.Client()}
	got, err := c.ListWorkloads(context.Background(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != total || got[total-1].Pod != fmt.Sprintf("p%d", total-1) {
		t.Fatalf("listed %d pods, want %d", len(got), total)
	}
	if want := (total + listPageSize - 1) / listPageSize; calls != want {
		t.Fatalf("calls=%d, want %d", calls, want)
	}
}

func TestListPodsSkipsTerminatedButListAllPodsDoesNot(t *testing.T) {
	var selectors []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		selectors = append(selectors, r.URL.Query().Get("fieldSelector"))
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()
	c := &Client{base: srv.URL, http: srv.Client()}
	if _, err := c.ListPods(context.Background(), "prod"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListAllPods(context.Background(), "prod"); err != nil {
		t.Fatal(err)
	}
	if len(selectors) != 2 || selectors[0] != activePodsSelector || selectors[1] != "" {
		t.Fatalf("selectors=%q", selectors)
	}
}
