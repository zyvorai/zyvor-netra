// Package mtls is mutual TLS between netra-agent and netrad.
//
// The controller's listener serves browsers and API clients as well as agents, so
// it cannot demand a client certificate from everyone. It asks for one and
// verifies it if it is offered (tls.VerifyClientCertIfGiven); a route that only
// agents call then decides whether a verified certificate is required
// (Mode Required). A certificate that is offered but not signed by the configured
// CA fails the handshake in every mode except Off.
//
// By default the certificate proves "a holder of the agent client key", exactly
// as the shared agent key does — a second factor and a channel a network
// attacker cannot join. With NETRA_AGENT_MTLS_BIND_NODE the controller also
// requires the reported node name to match the certificate identity (URI SAN
// spiffe://netra.local/node/<name>, else DNS SAN, else CN). Optional
// NETRA_AGENT_MTLS_DENY_SERIALS lists revoked serials (hex or decimal).
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Mode says how the controller treats agent client certificates.
type Mode string

const (
	// Off never asks for a client certificate.
	Off Mode = "off"
	// Optional verifies a certificate when one is offered and records that it was,
	// but does not require it. This is the rollout stage: agents can be moved over
	// one at a time and watched before Required is turned on.
	Optional Mode = "optional"
	// Required rejects agent-only requests that lack a verified certificate.
	Required Mode = "required"
)

// ParseMode reads NETRA_AGENT_MTLS. Empty means Off; an unknown value is an
// error, never a silent downgrade of a security setting.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(s))); m {
	case "", Off:
		return Off, nil
	case Optional, Required:
		return m, nil
	default:
		return Off, fmt.Errorf("NETRA_AGENT_MTLS=%q: want off, optional or required", s)
	}
}

// LoadPool reads a PEM bundle and refuses one with no usable certificate, so a
// typo'd or empty file cannot leave the controller trusting nothing (or, worse,
// silently not checking).
func LoadPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile) //nolint:gosec // operator-configured path
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s: no PEM certificate found", caFile)
	}
	return pool, nil
}

// ServerConfig returns the ClientAuth settings to merge into the listener's
// tls.Config for mode, or nil for Off. It is an error to ask for optional or
// required without a CA.
func ServerConfig(mode Mode, caFile string) (*tls.Config, error) {
	if mode == Off {
		return nil, nil
	}
	if strings.TrimSpace(caFile) == "" {
		return nil, errors.New("NETRA_AGENT_MTLS is " + string(mode) + " but NETRA_AGENT_CLIENT_CA is not set")
	}
	pool, err := LoadPool(caFile)
	if err != nil {
		return nil, fmt.Errorf("NETRA_AGENT_CLIENT_CA: %w", err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientCAs:  pool,
		ClientAuth: tls.VerifyClientCertIfGiven,
	}, nil
}

// Verified reports whether the request arrived on a connection whose client
// certificate chained to the configured CA (with the client-auth key usage,
// which crypto/tls checks when it verifies a client).
func Verified(r *http.Request) bool {
	return r.TLS != nil && len(r.TLS.VerifiedChains) > 0
}

// Allows reports whether a request may use an agent-only route under mode.
func Allows(mode Mode, r *http.Request) bool {
	return mode != Required || Verified(r)
}

// ClientConfig is the agent side: it trusts caFile (empty: the system roots),
// and presents certFile/keyFile when both are set. The pair is re-read when the
// files change, so a renewed certificate (cert-manager rotates them in place) is
// used by the next connection without restarting the agent.
//
// insecure keeps the chart's existing NETRA_TLS_INSECURE behaviour for the
// server certificate; the client certificate is still presented, so the
// controller can authenticate the agent even where the agent does not verify it.
func ClientConfig(caFile, certFile, keyFile string, insecure bool) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure} //nolint:gosec // explicit operator opt-in, as before
	if caFile != "" {
		pool, err := LoadPool(caFile)
		if err != nil {
			return nil, fmt.Errorf("NETRA_CA_FILE: %w", err)
		}
		cfg.RootCAs = pool
	}
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("NETRA_CLIENT_CERT and NETRA_CLIENT_KEY must be set together")
	}
	if certFile != "" {
		r := &reloader{certFile: certFile, keyFile: keyFile}
		if _, err := r.get(); err != nil { // fail at startup, not on the first report
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return r.get() }
	}
	return cfg, nil
}

// reloader caches a key pair and re-reads it when either file's modification
// time changes. Checks are rate limited so a busy agent does not stat per dial.
type reloader struct {
	certFile, keyFile string

	mu       sync.Mutex
	cert     *tls.Certificate
	certMod  time.Time
	keyMod   time.Time
	lastStat time.Time
}

func (r *reloader) get() (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cert != nil && time.Since(r.lastStat) < time.Second {
		return r.cert, nil
	}
	r.lastStat = time.Now()
	cs, err := os.Stat(r.certFile)
	if err != nil {
		return r.keepOrFail(err)
	}
	ks, err := os.Stat(r.keyFile)
	if err != nil {
		return r.keepOrFail(err)
	}
	if r.cert != nil && cs.ModTime().Equal(r.certMod) && ks.ModTime().Equal(r.keyMod) {
		return r.cert, nil
	}
	c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		// Mid-rotation the two files can briefly disagree; keep serving the old
		// pair rather than dropping every connection.
		return r.keepOrFail(err)
	}
	r.cert, r.certMod, r.keyMod = &c, cs.ModTime(), ks.ModTime()
	return r.cert, nil
}

func (r *reloader) keepOrFail(err error) (*tls.Certificate, error) {
	if r.cert != nil {
		return r.cert, nil
	}
	return nil, err
}

// FromEnv resolves the controller's policy from NETRA_AGENT_MTLS and
// NETRA_AGENT_CLIENT_CA. tlsOn says whether the listener serves TLS at all: a
// client certificate cannot be asked for over plain HTTP, and pretending
// otherwise would leave an operator believing agents are authenticated.
func FromEnv(tlsOn bool) (Mode, *tls.Config, error) {
	mode, err := ParseMode(os.Getenv("NETRA_AGENT_MTLS"))
	if err != nil {
		return Off, nil, err
	}
	if mode != Off && !tlsOn {
		return Off, nil, errors.New("NETRA_AGENT_MTLS=" + string(mode) + " needs HTTPS: set NETRA_TLS_CERT and NETRA_TLS_KEY (helm tls.enabled)")
	}
	cfg, err := ServerConfig(mode, os.Getenv("NETRA_AGENT_CLIENT_CA"))
	return mode, cfg, err
}
