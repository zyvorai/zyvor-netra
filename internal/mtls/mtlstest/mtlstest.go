// Package mtlstest builds a throwaway PKI for tests: a CA, a server certificate
// for 127.0.0.1, and client certificates, written as PEM files in a temp dir.
package mtlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// CA signs certificates. Its certificate is in CAFile.
type CA struct {
	CAFile string
	dir    string
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	serial int64
}

// Pair is a certificate and key on disk.
type Pair struct{ CertFile, KeyFile string }

// NewCA makes a CA named cn.
func NewCA(t testing.TB, cn string) *CA {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(t, err)
	cert, err := x509.ParseCertificate(der)
	must(t, err)
	ca := &CA{dir: dir, cert: cert, key: key, serial: 1, CAFile: filepath.Join(dir, cn+"-ca.pem")}
	must(t, os.WriteFile(ca.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return ca
}

// Issue writes a certificate for cn signed by the CA. usage is the extended key
// usage (client or server auth); notAfter lets a test mint an expired one.
func (c *CA) Issue(t testing.TB, cn string, usage x509.ExtKeyUsage, notAfter time.Time) Pair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	c.serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(c.serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	must(t, err)
	kder, err := x509.MarshalECPrivateKey(key)
	must(t, err)
	p := Pair{CertFile: filepath.Join(c.dir, cn+".crt"), KeyFile: filepath.Join(c.dir, cn+".key")}
	must(t, os.WriteFile(p.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	must(t, os.WriteFile(p.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600))
	return p
}

// Client is a valid client certificate.
func (c *CA) Client(t testing.TB, cn string) Pair {
	return c.Issue(t, cn, x509.ExtKeyUsageClientAuth, time.Now().Add(time.Hour))
}

// ClientNode issues a client certificate with URI SAN spiffe://netra.local/node/<node>.
func (c *CA) ClientNode(t testing.TB, node string) Pair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	c.serial++
	uri, err := url.Parse("spiffe://netra.local/node/" + node)
	must(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(c.serial), Subject: pkix.Name{CommonName: node},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	must(t, err)
	kder, err := x509.MarshalECPrivateKey(key)
	must(t, err)
	p := Pair{CertFile: filepath.Join(c.dir, node+"-node.crt"), KeyFile: filepath.Join(c.dir, node+"-node.key")}
	must(t, os.WriteFile(p.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	must(t, os.WriteFile(p.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600))
	return p
}

// LastSerial returns the hex serial of the most recently issued certificate.
func (c *CA) LastSerial() string {
	return strings.ToLower(big.NewInt(c.serial).Text(16))
}

// Server is a valid server certificate for 127.0.0.1 and localhost.
func (c *CA) Server(t testing.TB) Pair {
	return c.Issue(t, "netra-server", x509.ExtKeyUsageServerAuth, time.Now().Add(time.Hour))
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
