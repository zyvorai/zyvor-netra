package ha

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGateReadinessAndFollowerRejection(t *testing.T) {
	g := NewGate("pod-a", "0.8.0")
	for _, tc := range []struct {
		path string
		want int
	}{{"/livez", 200}, {"/healthz", 200}, {"/readyz", 503}, {"/api/v1/status", 503}} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s: got %d want %d", tc.path, w.Code, tc.want)
		}
	}
	g.Promote(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	for _, tc := range []struct {
		path string
		want int
	}{{"/readyz", 200}, {"/api/v1/status", http.StatusTeapot}} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("leader %s: got %d want %d", tc.path, w.Code, tc.want)
		}
	}
	g.Demote()
	w := httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected demoted gate to be unready, got %d", w.Code)
	}
}
