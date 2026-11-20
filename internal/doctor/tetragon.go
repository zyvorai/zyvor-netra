// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package doctor

import (
	"os"
	"path/filepath"
	"strings"
)

// checkTetragon looks for evidence that Cilium Tetragon is present on the
// host. Netra does not fight Tetragon for exclusive attachment; this check
// is informational so operators know coexistence is expected. Netra still
// refuses to grow a TracingPolicy / LSM enforcement product of its own.
func checkTetragon(root string) Check {
	var signals []string
	for _, p := range []string{
		"/sys/fs/bpf/tetragon",
		"/var/run/cilium/tetragon",
		"/run/cilium/tetragon",
	} {
		if st, err := os.Stat(filepath.Join(root, strings.TrimPrefix(p, "/"))); err == nil {
			kind := "path"
			if st.IsDir() {
				kind = "dir"
			}
			signals = append(signals, kind+" "+p)
		}
	}
	// Optional: pinned maps under a tetragon bpffs subtree discovered via mountinfo is overkill;
	// also peek for a well-known unit/binary name in /proc/*/comm on live hosts only.
	if root == "/" {
		if entries, err := os.ReadDir("/proc"); err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
				if err != nil {
					continue
				}
				comm := strings.TrimSpace(string(b))
				if comm == "tetragon" || strings.HasPrefix(comm, "tetragon-") {
					signals = append(signals, "process "+comm)
					break
				}
			}
		}
	}
	if len(signals) == 0 {
		return Check{
			ID:     "tetragon",
			Title:  "Tetragon coexistence",
			Status: StatusInfo,
			Detail: "no Tetragon bpffs/runtime paths detected; Netra cgroup hooks remain independent",
		}
	}
	return Check{
		ID:          "tetragon",
		Title:       "Tetragon coexistence",
		Status:      StatusInfo,
		Detail:      "Tetragon signals: " + strings.Join(signals, ", "),
		Remediation: "side-by-side is supported for Netra cgroup/sockops observe+lease; do not enable conflicting LSM/raw_tp attaches on the same hooks; Netra will not load a TracingPolicy engine",
	}
}
