// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package mtls

import (
	"crypto/x509"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// SPIFFEPrefix is the URI SAN prefix for per-node agent certificates.
const SPIFFEPrefix = "spiffe://netra.local/node/"

// BindNodeFromEnv reads NETRA_AGENT_MTLS_BIND_NODE.
func BindNodeFromEnv() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("NETRA_AGENT_MTLS_BIND_NODE")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

// NodeIdentity returns the node name bound to the verified client certificate.
// Preference order: URI SAN spiffe://netra.local/node/<name>, then DNS SAN,
// then Subject CN. Empty / false when no verified client cert is present.
func NodeIdentity(r *http.Request) (string, bool) {
	cert := leaf(r)
	if cert == nil {
		return "", false
	}
	return IdentityFromCert(cert)
}

// IdentityFromCert extracts a node name from a client certificate.
func IdentityFromCert(cert *x509.Certificate) (string, bool) {
	if cert == nil {
		return "", false
	}
	for _, u := range cert.URIs {
		if u == nil {
			continue
		}
		s := u.String()
		if strings.HasPrefix(s, SPIFFEPrefix) {
			name := strings.TrimPrefix(s, SPIFFEPrefix)
			name = strings.Trim(name, "/")
			if name != "" {
				return name, true
			}
		}
	}
	for _, d := range cert.DNSNames {
		d = strings.TrimSpace(d)
		if d != "" && d != "localhost" {
			return d, true
		}
	}
	if cn := strings.TrimSpace(cert.Subject.CommonName); cn != "" {
		return cn, true
	}
	return "", false
}

// MatchNode reports whether claimed equals the certificate identity.
func MatchNode(r *http.Request, claimed string) bool {
	id, ok := NodeIdentity(r)
	if !ok {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(claimed), id)
}

func leaf(r *http.Request) *x509.Certificate {
	if r == nil || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil
	}
	return r.TLS.VerifiedChains[0][0]
}

// URIForNode builds the SPIFFE URI SAN for a node name.
func URIForNode(node string) *url.URL {
	node = strings.TrimSpace(node)
	u, err := url.Parse(SPIFFEPrefix + node)
	if err != nil {
		return nil
	}
	return u
}
