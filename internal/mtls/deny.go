// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package mtls

import (
	"bufio"
	"crypto/x509"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// DenyList is a hot-reloaded set of revoked certificate serial numbers
// (hex or decimal, one per line; # comments allowed). Empty path disables.
type DenyList struct {
	path string

	mu       sync.Mutex
	serials  map[string]struct{}
	modTime  time.Time
	lastStat time.Time
}

// NewDenyList watches path (NETRA_AGENT_MTLS_DENY_SERIALS). Missing file is OK.
func NewDenyList(path string) *DenyList {
	path = strings.TrimSpace(path)
	if path == "" {
		return &DenyList{}
	}
	d := &DenyList{path: path}
	_ = d.reload()
	return d
}

// DenyListFromEnv builds from NETRA_AGENT_MTLS_DENY_SERIALS.
func DenyListFromEnv() *DenyList {
	return NewDenyList(os.Getenv("NETRA_AGENT_MTLS_DENY_SERIALS"))
}

// Denied reports whether the verified client certificate's serial is listed.
func (d *DenyList) Denied(r *http.Request) bool {
	if d == nil || d.path == "" {
		return false
	}
	cert := leaf(r)
	if cert == nil || cert.SerialNumber == nil {
		return false
	}
	d.refresh()
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.serials[serialKey(cert.SerialNumber)]
	return ok
}

func (d *DenyList) refresh() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if time.Since(d.lastStat) < time.Second {
		return
	}
	d.lastStat = time.Now()
	st, err := os.Stat(d.path)
	if err != nil {
		return
	}
	if !d.modTime.IsZero() && st.ModTime().Equal(d.modTime) {
		return
	}
	_ = d.reloadLocked()
}

func (d *DenyList) reload() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reloadLocked()
}

func (d *DenyList) reloadLocked() error {
	f, err := os.Open(d.path)
	if err != nil {
		if os.IsNotExist(err) {
			d.serials = map[string]struct{}{}
			d.modTime = time.Time{}
			return nil
		}
		return err
	}
	defer f.Close()
	st, _ := f.Stat()
	out := map[string]struct{}{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		line = strings.TrimPrefix(strings.ToLower(line), "0x")
		n := new(big.Int)
		if _, ok := n.SetString(line, 16); ok && n.Sign() > 0 {
			out[serialKey(n)] = struct{}{}
			continue
		}
		if _, ok := n.SetString(line, 10); ok && n.Sign() > 0 {
			out[serialKey(n)] = struct{}{}
		}
	}
	d.serials = out
	if st != nil {
		d.modTime = st.ModTime()
	}
	return sc.Err()
}

func serialKey(n *big.Int) string {
	if n == nil {
		return ""
	}
	return strings.ToLower(n.Text(16))
}

// SerialHex is the lowercase hex form of a certificate serial (for deny files).
func SerialHex(cert *x509.Certificate) string {
	if cert == nil || cert.SerialNumber == nil {
		return ""
	}
	return serialKey(cert.SerialNumber)
}
