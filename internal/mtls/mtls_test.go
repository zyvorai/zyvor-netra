package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/mtls/mtlstest"
)

// serve starts a real TLS listener configured exactly as netrad configures its
// own, and returns a handler-visible answer: "verified:<cn>" or "anonymous".
func serve(t *testing.T, mode Mode, serverCA *mtlstest.CA, clientCA *mtlstest.CA) *httptest.Server {
	t.Helper()
	cfg, err := ServerConfig(mode, clientCA.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	sp := serverCA.Server(t)
	cert, err := tls.LoadX509KeyPair(sp.CertFile, sp.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Certificates = []tls.Certificate{cert}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !Allows(mode, r) {
			http.Error(w, "no cert", http.StatusUnauthorized)
			return
		}
		if Verified(r) {
			_, _ = io.WriteString(w, "verified:"+r.TLS.PeerCertificates[0].Subject.CommonName)
			return
		}
		_, _ = io.WriteString(w, "anonymous")
	}))
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string, cfg *tls.Config) (int, string, error) {
	t.Helper()
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}
	resp, err := c.Get(url)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b)), nil
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": Off, "off": Off, " OFF ": Off, "optional": Optional, "Required": Required} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	// A typo must never silently turn a security setting off.
	for _, in := range []string{"on", "true", "requried", "1"} {
		if _, err := ParseMode(in); err == nil {
			t.Errorf("ParseMode(%q) accepted", in)
		}
	}
}

func TestServerConfigRefusesWhatCouldLeaveTheControllerUnchecked(t *testing.T) {
	if cfg, err := ServerConfig(Off, ""); cfg != nil || err != nil {
		t.Fatalf("off must be a no-op, got %v, %v", cfg, err)
	}
	if _, err := ServerConfig(Required, ""); err == nil {
		t.Error("required without a CA was accepted")
	}
	if _, err := ServerConfig(Required, "/nonexistent/ca.pem"); err == nil {
		t.Error("a missing CA file was accepted")
	}
	empty := t.TempDir() + "/empty.pem"
	if err := os.WriteFile(empty, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ServerConfig(Optional, empty); err == nil {
		t.Error("a CA file with no certificate was accepted: the controller would trust nothing, or be thought to check")
	}
}

func TestFromEnvRefusesMTLSWithoutHTTPS(t *testing.T) {
	ca := mtlstest.NewCA(t, "ca")
	t.Setenv("NETRA_AGENT_MTLS", "required")
	t.Setenv("NETRA_AGENT_CLIENT_CA", ca.CAFile)
	if _, _, err := FromEnv(false); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("required over plain HTTP must be refused, got %v", err)
	}
	if mode, cfg, err := FromEnv(true); err != nil || mode != Required || cfg == nil || cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("FromEnv(true) = %v, %v, %v", mode, cfg, err)
	}
	t.Setenv("NETRA_AGENT_MTLS", "")
	if mode, cfg, err := FromEnv(false); err != nil || mode != Off || cfg != nil {
		t.Fatalf("default must be off and change nothing: %v %v %v", mode, cfg, err)
	}
}

func TestHandshakes(t *testing.T) {
	agentCA := mtlstest.NewCA(t, "agent-ca")
	otherCA := mtlstest.NewCA(t, "other-ca")
	srv := serve(t, Required, agentCA, agentCA)

	good := agentCA.Client(t, "agent-1")
	tlsFor := func(p mtlstest.Pair) *tls.Config {
		cfg, err := ClientConfig(agentCA.CAFile, p.CertFile, p.KeyFile, false)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	t.Run("a certificate from the agent CA is verified", func(t *testing.T) {
		code, body, err := get(t, srv.URL, tlsFor(good))
		if err != nil || code != 200 || body != "verified:agent-1" {
			t.Fatalf("code=%d body=%q err=%v", code, body, err)
		}
	})
	t.Run("no certificate: the handshake succeeds and the route refuses (browsers keep working)", func(t *testing.T) {
		cfg, err := ClientConfig(agentCA.CAFile, "", "", false)
		if err != nil {
			t.Fatal(err)
		}
		code, _, err := get(t, srv.URL, cfg)
		if err != nil || code != http.StatusUnauthorized {
			t.Fatalf("code=%d err=%v; want a 401 from the route, not a failed handshake", code, err)
		}
	})
	t.Run("a certificate from another CA fails the handshake", func(t *testing.T) {
		rogue := otherCA.Client(t, "agent-1") // same name, wrong issuer
		if _, _, err := get(t, srv.URL, tlsFor(rogue)); err == nil {
			t.Fatal("a certificate signed by an untrusted CA was accepted")
		}
	})
	t.Run("a server-auth certificate cannot be used as a client certificate", func(t *testing.T) {
		wrong := agentCA.Issue(t, "not-a-client", x509.ExtKeyUsageServerAuth, time.Now().Add(time.Hour))
		if _, _, err := get(t, srv.URL, tlsFor(wrong)); err == nil {
			t.Fatal("a certificate without the client-auth usage was accepted")
		}
	})
	t.Run("an expired certificate fails the handshake", func(t *testing.T) {
		old := agentCA.Issue(t, "expired", x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute))
		if _, _, err := get(t, srv.URL, tlsFor(old)); err == nil {
			t.Fatal("an expired certificate was accepted")
		}
	})
}

func TestOptionalModeAcceptsBothButOnlyVerifiesRealOnes(t *testing.T) {
	ca := mtlstest.NewCA(t, "ca")
	srv := serve(t, Optional, ca, ca)
	p := ca.Client(t, "agent-2")
	withCert, _ := ClientConfig(ca.CAFile, p.CertFile, p.KeyFile, false)
	if _, body, err := get(t, srv.URL, withCert); err != nil || body != "verified:agent-2" {
		t.Fatalf("with cert: %q %v", body, err)
	}
	noCert, _ := ClientConfig(ca.CAFile, "", "", false)
	if code, body, err := get(t, srv.URL, noCert); err != nil || code != 200 || body != "anonymous" {
		t.Fatalf("rollout stage must still serve agents that have no certificate yet: %d %q %v", code, body, err)
	}
}

func TestInsecureServerVerificationStillPresentsTheClientCertificate(t *testing.T) {
	// The chart's default is NETRA_TLS_INSECURE=true (self-signed server cert). An
	// operator who adds a client certificate to that must get authenticated.
	ca := mtlstest.NewCA(t, "ca")
	srv := serve(t, Required, ca, ca)
	p := ca.Client(t, "agent-3")
	cfg, err := ClientConfig("", p.CertFile, p.KeyFile, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, body, err := get(t, srv.URL, cfg); err != nil || body != "verified:agent-3" {
		t.Fatalf("%q %v", body, err)
	}
}

func TestClientConfigFailsLoudly(t *testing.T) {
	ca := mtlstest.NewCA(t, "ca")
	p := ca.Client(t, "a")
	if _, err := ClientConfig("", p.CertFile, "", false); err == nil {
		t.Error("a certificate without a key was accepted")
	}
	if _, err := ClientConfig("", "", p.KeyFile, false); err == nil {
		t.Error("a key without a certificate was accepted")
	}
	if _, err := ClientConfig("", "/no/such.crt", "/no/such.key", false); err == nil {
		t.Error("missing certificate files were accepted at startup")
	}
	if _, err := ClientConfig("/no/such-ca.pem", "", "", false); err == nil {
		t.Error("a missing CA file was accepted")
	}
	cfg, err := ClientConfig("", "", "", false)
	if err != nil || cfg.GetClientCertificate != nil || cfg.InsecureSkipVerify || cfg.RootCAs != nil {
		t.Fatalf("with nothing configured the config must be the plain default: %+v %v", cfg, err)
	}
}

func TestRenewedCertificateIsPickedUpWithoutARestart(t *testing.T) {
	ca := mtlstest.NewCA(t, "ca")
	srv := serve(t, Required, ca, ca)
	first := ca.Client(t, "before-rotation")
	cfg, err := ClientConfig(ca.CAFile, first.CertFile, first.KeyFile, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, body, err := get(t, srv.URL, cfg); err != nil || body != "verified:before-rotation" {
		t.Fatalf("before: %q %v", body, err)
	}

	// cert-manager rewrites the files in place. Do the same: new pair, same paths.
	second := ca.Client(t, "after-rotation")
	copyOver(t, second.CertFile, first.CertFile)

	// Mid-rotation the certificate and key disagree (cert replaced, key not yet):
	// that must not break connections; the old pair keeps being used.
	time.Sleep(1100 * time.Millisecond) // past the reloader's stat interval
	if _, body, err := get(t, srv.URL, cfg); err != nil || body != "verified:before-rotation" {
		t.Fatalf("a half-rotated pair must fall back to the previous one: %q %v", body, err)
	}
	copyOver(t, second.KeyFile, first.KeyFile)
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(first.CertFile, future, future)
	_ = os.Chtimes(first.KeyFile, future, future)
	time.Sleep(1100 * time.Millisecond)
	if _, body, err := get(t, srv.URL, cfg); err != nil || body != "verified:after-rotation" {
		t.Fatalf("after rotation: %q %v", body, err)
	}
}

func copyOver(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
