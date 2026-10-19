// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package mtls_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"

	"github.com/zyvorai/netra/internal/mtls"
)

func TestIdentityFromCertSPIFFE(t *testing.T) {
	u, err := url.Parse(mtls.SPIFFEPrefix + "worker-1")
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(9),
		Subject:      pkix.Name{CommonName: "other"},
		URIs:         []*url.URL{u},
		DNSNames:     []string{"dns-name"},
	}
	id, ok := mtls.IdentityFromCert(cert)
	if !ok || id != "worker-1" {
		t.Fatalf("got %q %v", id, ok)
	}
}

func TestIdentityFromCertDNSFallback(t *testing.T) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cn-only"},
		DNSNames:     []string{"node-a"},
	}
	id, ok := mtls.IdentityFromCert(cert)
	if !ok || id != "node-a" {
		t.Fatalf("got %q %v", id, ok)
	}
}
