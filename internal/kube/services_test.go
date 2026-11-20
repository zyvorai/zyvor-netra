package kube

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type serviceRoundTripper func(*http.Request) (*http.Response, error)

func (f serviceRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestListServices(t *testing.T) {
	c := &Client{base: "https://kube", http: &http.Client{Transport: serviceRoundTripper(func(r *http.Request) (*http.Response, error) {
		body := `{"items":[{"metadata":{"name":"redis","namespace":"prod"},"spec":{"clusterIP":"10.96.0.20","selector":{"app":"redis"},"ports":[{"name":"tcp","port":6379,"protocol":"TCP"}]}},{"metadata":{"name":"headless","namespace":"prod"},"spec":{"clusterIP":"None"}}]}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}}
	svcs, err := c.ListServices(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].Name != "redis" || svcs[0].Ports[0].Port != 6379 {
		t.Fatalf("svcs=%#v", svcs)
	}
}
