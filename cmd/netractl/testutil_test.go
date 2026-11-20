// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"os"
	"strings"
	"sync"
	"testing"
)

// useTestServer points netractl HTTP helpers at an httptest URL without
// letting ~/.netra/env or a prior configOnce load clobber it.
func useTestServer(t *testing.T, url string) {
	t.Helper()
	t.Setenv("NETRA_SKIP_DOTENV", "1")
	t.Setenv("NETRA_URL", url)
	t.Setenv("NETRA_API_KEY", "")
	t.Setenv("NETRA_TLS_INSECURE", "true")
	t.Setenv("NETRA_CLI_NO_BANNER", "1")
	t.Setenv("NO_COLOR", "1")

	configOnce = sync.Once{}
	ensureConfig()

	oldBase := base
	base = strings.TrimRight(url, "/")
	t.Cleanup(func() {
		base = oldBase
		configOnce = sync.Once{}
	})
}

// withArgs sets os.Args for handlers that still read the process argv.
func withArgs(t *testing.T, args ...string) {
	t.Helper()
	old := os.Args
	os.Args = append([]string{"netractl"}, args...)
	t.Cleanup(func() { os.Args = old })
}
