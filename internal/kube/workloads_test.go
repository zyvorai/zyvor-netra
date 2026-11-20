// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package kube

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestListPodsParsesStartedAtAndRestartCount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{
			"metadata":{"name":"api-1","namespace":"prod"},
			"spec":{"nodeName":"node-a"},
			"status":{"phase":"Running","podIP":"10.0.0.5","containerStatuses":[
				{"name":"app","ready":true,"restartCount":2,"imageID":"docker-pullable://img@sha256:abc","state":{"running":{"startedAt":"2026-09-14T01:02:03Z"}}},
				{"name":"sidecar","ready":true,"restartCount":1,"state":{"running":{"startedAt":"2026-09-14T01:00:00Z"}}}
			]}
		}]}`))
	}))
	defer srv.Close()
	c := &Client{base: srv.URL, http: srv.Client()}
	items, err := c.ListPods(context.Background(), "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("items=%d", len(items))
	}
	p := items[0]
	if p.RestartCount != 3 {
		t.Fatalf("restartCount=%d, want 3 (summed across containers)", p.RestartCount)
	}
	if p.Started == nil || !p.Started.Equal(time.Date(2026, 9, 14, 1, 2, 3, 0, time.UTC)) {
		t.Fatalf("started=%v, want the more recent of the two containers' startedAt", p.Started)
	}
}

func TestListPodsStartedNilWhenNoContainerRunning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"pending-1","namespace":"prod"},"spec":{},"status":{"phase":"Pending","containerStatuses":[{"name":"app","ready":false,"restartCount":0,"state":{"waiting":{"reason":"ContainerCreating"}}}]}}]}`))
	}))
	defer srv.Close()
	c := &Client{base: srv.URL, http: srv.Client()}
	items, err := c.ListPods(context.Background(), "prod")
	if err != nil {
		t.Fatal(err)
	}
	if items[0].Started != nil {
		t.Fatalf("started=%v, want nil for a non-running container", items[0].Started)
	}
}

func TestGetPodParsesPerContainerFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"metadata":{"name":"api-1","namespace":"prod"},
			"spec":{"nodeName":"node-a","containers":[{"name":"app"}]},
			"status":{"phase":"Running","containerStatuses":[
				{"name":"app","ready":true,"restartCount":5,"imageID":"docker-pullable://img@sha256:def","state":{"running":{"startedAt":"2026-09-14T02:00:00Z"}}}
			]}
		}`))
	}))
	defer srv.Close()
	c := &Client{base: srv.URL, http: srv.Client()}
	p, err := c.GetPod(context.Background(), "prod", "api-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Containers) != 1 {
		t.Fatalf("containers=%d", len(p.Containers))
	}
	ci := p.Containers[0]
	if ci.RestartCount != 5 || ci.ImageID != "docker-pullable://img@sha256:def" {
		t.Fatalf("container=%#v", ci)
	}
	if ci.StartedAt == nil || !ci.StartedAt.Equal(time.Date(2026, 9, 14, 2, 0, 0, 0, time.UTC)) {
		t.Fatalf("startedAt=%v", ci.StartedAt)
	}
	if p.RestartCount != 5 {
		t.Fatalf("pod restartCount=%d, want 5", p.RestartCount)
	}
}
