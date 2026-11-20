package kube

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeLeaseAPI struct {
	mu    sync.Mutex
	lease *leaseDocument
	rv    int
}

func (f *fakeLeaseAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if !strings.Contains(r.URL.Path, "/leases") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if f.lease == nil {
			http.Error(w, `{"reason":"NotFound"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(f.lease)
	case http.MethodPost:
		if f.lease != nil {
			http.Error(w, `{"reason":"Conflict"}`, http.StatusConflict)
			return
		}
		var x leaseDocument
		if err := json.NewDecoder(r.Body).Decode(&x); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		f.rv++
		x.Metadata.ResourceVersion = strconv.Itoa(f.rv)
		f.lease = &x
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(x)
	case http.MethodPut:
		if f.lease == nil {
			http.Error(w, `{"reason":"NotFound"}`, http.StatusNotFound)
			return
		}
		var x leaseDocument
		if err := json.NewDecoder(r.Body).Decode(&x); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if x.Metadata.ResourceVersion != f.lease.Metadata.ResourceVersion {
			http.Error(w, `{"reason":"Conflict"}`, http.StatusConflict)
			return
		}
		f.rv++
		x.Metadata.ResourceVersion = strconv.Itoa(f.rv)
		f.lease = &x
		_ = json.NewEncoder(w).Encode(x)
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

func TestLeaseAcquireRenewReleaseAndTakeover(t *testing.T) {
	api := &fakeLeaseAPI{}
	ts := httptest.NewServer(api)
	defer ts.Close()
	c := &Client{base: ts.URL, http: ts.Client()}
	ctx := context.Background()

	ok, err := c.TryAcquireOrRenewLease(ctx, "netra", "controller", "pod-a", 15*time.Second)
	if err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}
	ok, err = c.TryAcquireOrRenewLease(ctx, "netra", "controller", "pod-b", 15*time.Second)
	if err != nil || ok {
		t.Fatalf("second holder must not acquire live lease: ok=%v err=%v", ok, err)
	}
	ok, err = c.TryAcquireOrRenewLease(ctx, "netra", "controller", "pod-a", 15*time.Second)
	if err != nil || !ok {
		t.Fatalf("renew: ok=%v err=%v", ok, err)
	}
	if err := c.ReleaseLease(ctx, "netra", "controller", "pod-a"); err != nil {
		t.Fatal(err)
	}
	ok, err = c.TryAcquireOrRenewLease(ctx, "netra", "controller", "pod-b", 15*time.Second)
	if err != nil || !ok {
		t.Fatalf("takeover after release: ok=%v err=%v", ok, err)
	}
}

// microTimeRe matches exactly what a real Kubernetes API server accepts for
// a Lease's acquireTime/renewTime: metav1.MicroTime, whose wire format is
// always exactly six fractional-second digits. A real API server rejects
// anything else (8 or 9 digits included, which time.RFC3339Nano produces)
// with a 400 "cannot be handled as a Lease: parsing time ... as ...Z07:00" —
// the fake server in fakeLeaseAPI never validated this, so it couldn't have
// caught a regression back to the wrong layout; this one specifically does.
var microTimeRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$`)

type strictLeaseAPI struct {
	fakeLeaseAPI
}

func (f *strictLeaseAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		body, _ := io.ReadAll(r.Body)
		var x leaseDocument
		if err := json.Unmarshal(body, &x); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		for _, stamp := range []string{x.Spec.AcquireTime, x.Spec.RenewTime} {
			if stamp != "" && !microTimeRe.MatchString(stamp) {
				http.Error(w, fmt.Sprintf(`{"reason":"BadRequest","message":"cannot be handled as a Lease: parsing time %q"}`, stamp), http.StatusBadRequest)
				return
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	f.fakeLeaseAPI.ServeHTTP(w, r)
}

// TestLeaseTimestampsMatchKubernetesMicroTimeFormat is a regression test for
// a real bug caught during live-cluster HA verification: TryAcquireOrRenewLease
// formatted acquireTime/renewTime with time.RFC3339Nano, which emits a
// variable, often 9-digit fractional-second count. A real Kubernetes API
// server decodes those fields as metav1.MicroTime (fixed 6 digits) and
// rejects anything else — every lease acquire/renew/release against a real
// cluster failed outright, even though the fake-backend unit tests above
// passed throughout, since that fake never validated the wire format.
func TestLeaseTimestampsMatchKubernetesMicroTimeFormat(t *testing.T) {
	api := &strictLeaseAPI{}
	ts := httptest.NewServer(api)
	defer ts.Close()
	c := &Client{base: ts.URL, http: ts.Client()}
	ctx := context.Background()

	ok, err := c.TryAcquireOrRenewLease(ctx, "netra", "controller", "pod-a", 15*time.Second)
	if err != nil || !ok {
		t.Fatalf("acquire against a MicroTime-strict server: ok=%v err=%v", ok, err)
	}
	ok, err = c.TryAcquireOrRenewLease(ctx, "netra", "controller", "pod-a", 15*time.Second)
	if err != nil || !ok {
		t.Fatalf("renew against a MicroTime-strict server: ok=%v err=%v", ok, err)
	}
	if err := c.ReleaseLease(ctx, "netra", "controller", "pod-a"); err != nil {
		t.Fatalf("release against a MicroTime-strict server: %v", err)
	}
}

func TestLeaseExpiredHolderCanBeTakenOver(t *testing.T) {
	api := &fakeLeaseAPI{}
	ts := httptest.NewServer(api)
	defer ts.Close()
	c := &Client{base: ts.URL, http: ts.Client()}

	now := time.Now().UTC().Add(-time.Minute)
	var old leaseDocument
	old.APIVersion = "coordination.k8s.io/v1"
	old.Kind = "Lease"
	old.Metadata.Name = "controller"
	old.Metadata.Namespace = "netra"
	old.Metadata.ResourceVersion = "1"
	old.Spec.HolderIdentity = "dead-pod"
	old.Spec.LeaseDurationSeconds = 10
	old.Spec.AcquireTime = now.Format(time.RFC3339Nano)
	old.Spec.RenewTime = now.Format(time.RFC3339Nano)
	api.lease = &old
	api.rv = 1

	ok, err := c.TryAcquireOrRenewLease(context.Background(), "netra", "controller", "pod-b", 15*time.Second)
	if err != nil || !ok {
		t.Fatalf("expired takeover: ok=%v err=%v", ok, err)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if api.lease.Spec.HolderIdentity != "pod-b" || api.lease.Spec.LeaseTransitions != 1 {
		t.Fatalf("lease after takeover: %#v", api.lease.Spec)
	}
}
