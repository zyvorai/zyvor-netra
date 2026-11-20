// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package doctor performs read-only host readiness checks for Netra's
// standalone eBPF agent. It deliberately does not mount filesystems, change
// sysctls, load BPF programs, or mutate network state.
package doctor

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Status string

const (
	StatusPass Status = "pass"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
	StatusInfo Status = "info"
)

type Check struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Status      Status `json:"status"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

type Summary struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
	Info int `json:"info"`
}

type Report struct {
	GeneratedAt   time.Time `json:"generatedAt"`
	Hostname      string    `json:"hostname,omitempty"`
	OS            string    `json:"os"`
	Architecture  string    `json:"architecture"`
	KernelRelease string    `json:"kernelRelease,omitempty"`
	Checks        []Check   `json:"checks"`
	Summary       Summary   `json:"summary"`
}

type Options struct {
	// Root prefixes filesystem reads. "/" inspects the live host. A temporary
	// root makes the checker deterministic in tests and useful for support
	// bundles mounted elsewhere.
	Root string

	RequireTCX         bool
	RequireDropReasons bool
	Now                func() time.Time
}

func Run(opts Options) Report {
	root := opts.Root
	if root == "" {
		root = "/"
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	r := Report{
		GeneratedAt:  now().UTC(),
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
	}
	if h, err := os.Hostname(); err == nil {
		r.Hostname = h
	}
	if b, err := readTrim(root, "/proc/sys/kernel/osrelease"); err == nil {
		r.KernelRelease = b
	}
	// Support-bundle / fixture roots are always Linux trees even when the
	// inspecting binary is built on darwin/windows for CI and developer laptops.
	if root != "/" {
		r.OS = "linux"
	}

	r.Checks = append(r.Checks,
		checkOS(root),
		checkArch(),
		checkKernel(r.KernelRelease),
		checkTCX(r.KernelRelease, opts.RequireTCX),
		checkCgroupV2(root),
		checkCgroupMembership(root),
		checkBPFFS(root),
		checkNetraPins(root),
		checkBTF(root),
		checkTraceFS(root),
		checkDropReasons(root, opts.RequireDropReasons),
		checkCapabilities(root),
		checkUnprivilegedBPF(root),
		checkLockdown(root),
		checkTetragon(root),
	)

	if root == "/" {
		r.Checks = append(r.Checks, checkMemlock(), checkInterfaces())
	} else {
		r.Checks = append(r.Checks,
			Check{ID: "memlock", Title: "memlock resource limit", Status: StatusInfo, Detail: "skipped for non-live --root"},
			Check{ID: "interfaces", Title: "network interfaces", Status: StatusInfo, Detail: "skipped for non-live --root"},
		)
	}

	for _, c := range r.Checks {
		switch c.Status {
		case StatusPass:
			r.Summary.Pass++
		case StatusWarn:
			r.Summary.Warn++
		case StatusFail:
			r.Summary.Fail++
		default:
			r.Summary.Info++
		}
	}
	return r
}

func checkOS(root string) Check {
	if root != "/" {
		if _, err := os.Stat(rooted(root, "/proc/sys/kernel/osrelease")); err == nil {
			return Check{ID: "os", Title: "Linux host", Status: StatusPass, Detail: "linux (offline --root)"}
		}
		return Check{ID: "os", Title: "Linux host", Status: StatusFail, Detail: "offline root missing /proc/sys/kernel/osrelease", Remediation: "point --root at a Linux support bundle or live host"}
	}
	if runtime.GOOS == "linux" {
		return Check{ID: "os", Title: "Linux host", Status: StatusPass, Detail: "linux"}
	}
	return Check{ID: "os", Title: "Linux host", Status: StatusFail, Detail: runtime.GOOS, Remediation: "run netra-agent on Linux"}
}

func checkArch() Check {
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return Check{ID: "arch", Title: "supported architecture", Status: StatusPass, Detail: runtime.GOARCH}
	default:
		return Check{ID: "arch", Title: "supported architecture", Status: StatusWarn, Detail: runtime.GOARCH, Remediation: "validate the BPF object and agent on amd64 or arm64 before production use"}
	}
}

func checkKernel(release string) Check {
	maj, min, ok := kernelMajorMinor(release)
	if !ok {
		return Check{ID: "kernel", Title: "kernel baseline", Status: StatusWarn, Detail: fmt.Sprintf("unable to parse kernel release %q", release)}
	}
	if versionLess(maj, min, 5, 8) {
		return Check{ID: "kernel", Title: "kernel baseline", Status: StatusFail, Detail: release, Remediation: "upgrade to Linux 5.8+; a modern LTS kernel is recommended"}
	}
	return Check{ID: "kernel", Title: "kernel baseline", Status: StatusPass, Detail: fmt.Sprintf("%s (Netra core baseline: 5.8+)", release)}
}

func checkTCX(release string, required bool) Check {
	maj, min, ok := kernelMajorMinor(release)
	if ok && !versionLess(maj, min, 6, 6) {
		return Check{ID: "tcx", Title: "TCX kernel baseline", Status: StatusPass, Detail: fmt.Sprintf("%s supports Netra's practical TCX baseline", release)}
	}
	status := StatusWarn
	if required {
		status = StatusFail
	}
	return Check{ID: "tcx", Title: "TCX kernel baseline", Status: status, Detail: fmt.Sprintf("%s; TCX is optional and Netra cgroup hooks still work", emptyAs(release, "unknown kernel")), Remediation: "use Linux 6.6+ when enabling optional TCX hooks"}
}

func checkCgroupV2(root string) Check {
	p := rooted(root, "/sys/fs/cgroup/cgroup.controllers")
	b, err := os.ReadFile(p)
	if err != nil {
		return Check{ID: "cgroup-v2", Title: "cgroup v2", Status: StatusFail, Detail: "cgroup.controllers not found", Remediation: "boot with unified cgroup v2 and mount it at /sys/fs/cgroup"}
	}
	controllers := strings.Fields(string(b))
	return Check{ID: "cgroup-v2", Title: "cgroup v2", Status: StatusPass, Detail: fmt.Sprintf("%d controllers visible", len(controllers))}
}

func checkCgroupMembership(root string) Check {
	b, err := os.ReadFile(rooted(root, "/proc/self/cgroup"))
	if err != nil {
		return Check{ID: "cgroup-membership", Title: "unified cgroup membership", Status: StatusWarn, Detail: err.Error()}
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "0::") {
			path := strings.TrimPrefix(line, "0::")
			if path == "" {
				path = "/"
			}
			return Check{ID: "cgroup-membership", Title: "unified cgroup membership", Status: StatusPass, Detail: path}
		}
	}
	return Check{ID: "cgroup-membership", Title: "unified cgroup membership", Status: StatusWarn, Detail: "no 0:: unified hierarchy entry found", Remediation: "verify the host is using cgroup v2"}
}

func checkBPFFS(root string) Check {
	mounts, err := mountInfo(root)
	if err != nil {
		return Check{ID: "bpffs", Title: "bpffs mount", Status: StatusFail, Detail: err.Error(), Remediation: "mount bpffs at /sys/fs/bpf"}
	}
	for _, m := range mounts {
		if m.fsType == "bpf" && m.mountPoint == "/sys/fs/bpf" {
			return Check{ID: "bpffs", Title: "bpffs mount", Status: StatusPass, Detail: "/sys/fs/bpf"}
		}
	}
	return Check{ID: "bpffs", Title: "bpffs mount", Status: StatusFail, Detail: "no bpf filesystem mounted at /sys/fs/bpf", Remediation: "mount -t bpf bpf /sys/fs/bpf"}
}

func checkNetraPins(root string) Check {
	dir := rooted(root, "/sys/fs/bpf/netra")
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return Check{ID: "netra-pins", Title: "Netra pinned maps", Status: StatusInfo, Detail: "/sys/fs/bpf/netra not present (agent has not pinned maps on this host)", Remediation: "start netra-agent once, then rebuild the BPF object if allow/rate/icmp maps are missing"}
	}
	need := []string{"allowed_v4", "allowed_ports", "allowed_uids", "allowed_comms", "rate_v6", "icmp_type_stats", "blocked_ingress_v4"}
	var missing []string
	for _, n := range need {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			missing = append(missing, n)
		}
	}
	if len(missing) == 0 {
		return Check{ID: "netra-pins", Title: "Netra pinned maps", Status: StatusPass, Detail: dir}
	}
	return Check{ID: "netra-pins", Title: "Netra pinned maps", Status: StatusWarn, Detail: "missing " + strings.Join(missing, ", "), Remediation: "rebuild bpf/netra_tc.o, roll the agent, and let it re-pin maps under /sys/fs/bpf/netra"}
}

func checkBTF(root string) Check {
	p := rooted(root, "/sys/kernel/btf/vmlinux")
	st, err := os.Stat(p)
	if err == nil && st.Size() > 0 {
		return Check{ID: "btf", Title: "kernel BTF", Status: StatusPass, Detail: fmt.Sprintf("%s (%d bytes)", displayPath(root, p), st.Size())}
	}
	return Check{ID: "btf", Title: "kernel BTF", Status: StatusWarn, Detail: "/sys/kernel/btf/vmlinux unavailable", Remediation: "use a kernel package that exposes BTF for reliable CO-RE/debugging workflows"}
}

func checkTraceFS(root string) Check {
	mounts, err := mountInfo(root)
	if err == nil {
		for _, m := range mounts {
			if m.fsType == "tracefs" && (m.mountPoint == "/sys/kernel/tracing" || m.mountPoint == "/sys/kernel/debug/tracing") {
				return Check{ID: "tracefs", Title: "tracefs", Status: StatusPass, Detail: m.mountPoint}
			}
		}
	}
	for _, p := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		if st, statErr := os.Stat(rooted(root, p)); statErr == nil && st.IsDir() {
			return Check{ID: "tracefs", Title: "tracefs", Status: StatusWarn, Detail: p + " exists but mount type was not confirmed", Remediation: "mount tracefs for optional kernel drop diagnostics"}
		}
	}
	return Check{ID: "tracefs", Title: "tracefs", Status: StatusWarn, Detail: "tracefs not found", Remediation: "mount tracefs to enable optional kfree_skb drop-reason diagnostics"}
}

func checkDropReasons(root string, required bool) Check {
	paths := []string{
		"/sys/kernel/tracing/events/skb/kfree_skb/format",
		"/sys/kernel/debug/tracing/events/skb/kfree_skb/format",
	}
	for _, p := range paths {
		b, err := os.ReadFile(rooted(root, p))
		if err != nil {
			continue
		}
		if hasTracepointField(string(b), "reason") {
			return Check{ID: "drop-reasons", Title: "kfree_skb drop reason", Status: StatusPass, Detail: p + " exposes reason"}
		}
		status := StatusWarn
		if required {
			status = StatusFail
		}
		return Check{ID: "drop-reasons", Title: "kfree_skb drop reason", Status: status, Detail: p + " exists but has no reason field", Remediation: "use a kernel exposing the kfree_skb reason field or leave Netra kernel-drop tracing disabled"}
	}
	status := StatusWarn
	if required {
		status = StatusFail
	}
	return Check{ID: "drop-reasons", Title: "kfree_skb drop reason", Status: status, Detail: "tracepoint format unavailable", Remediation: "leave optional kernel-drop tracing disabled or use a kernel with skb:kfree_skb reason support"}
}

func checkCapabilities(root string) Check {
	b, err := os.ReadFile(rooted(root, "/proc/self/status"))
	if err != nil {
		return Check{ID: "capabilities", Title: "effective capabilities", Status: StatusWarn, Detail: err.Error()}
	}
	var raw string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			raw = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			break
		}
	}
	if raw == "" {
		return Check{ID: "capabilities", Title: "effective capabilities", Status: StatusWarn, Detail: "CapEff not present"}
	}
	mask, ok := parseCapabilityMask(raw)
	if !ok {
		return Check{ID: "capabilities", Title: "effective capabilities", Status: StatusWarn, Detail: "unable to parse CapEff"}
	}

	// CAP_NET_ADMIN=12, CAP_SYS_ADMIN=21, CAP_SYS_RESOURCE=24,
	// CAP_PERFMON=38, CAP_BPF=39.
	var have []string
	for _, cap := range []struct {
		bit  uint
		name string
	}{{12, "NET_ADMIN"}, {21, "SYS_ADMIN"}, {24, "SYS_RESOURCE"}, {38, "PERFMON"}, {39, "BPF"}} {
		if capSet(mask, cap.bit) {
			have = append(have, cap.name)
		}
	}
	if capSet(mask, 12) && (capSet(mask, 39) || capSet(mask, 21)) {
		return Check{ID: "capabilities", Title: "effective capabilities", Status: StatusPass, Detail: "present: " + strings.Join(have, ", ")}
	}
	return Check{ID: "capabilities", Title: "effective capabilities", Status: StatusWarn, Detail: "present: " + emptyAs(strings.Join(have, ", "), "none of Netra's relevant capabilities"), Remediation: "run the node agent with the privileges documented by Netra; Kubernetes deployment currently uses a privileged DaemonSet"}
}

func checkUnprivilegedBPF(root string) Check {
	v, err := readTrim(root, "/proc/sys/kernel/unprivileged_bpf_disabled")
	if err != nil {
		return Check{ID: "unprivileged-bpf", Title: "unprivileged BPF policy", Status: StatusInfo, Detail: "sysctl not available"}
	}
	switch v {
	case "1", "2":
		return Check{ID: "unprivileged-bpf", Title: "unprivileged BPF policy", Status: StatusPass, Detail: "kernel.unprivileged_bpf_disabled=" + v + " (privileged Netra is unaffected)"}
	case "0":
		return Check{ID: "unprivileged-bpf", Title: "unprivileged BPF policy", Status: StatusWarn, Detail: "kernel.unprivileged_bpf_disabled=0", Remediation: "consider disabling unprivileged BPF according to your host-hardening policy"}
	default:
		return Check{ID: "unprivileged-bpf", Title: "unprivileged BPF policy", Status: StatusInfo, Detail: "kernel.unprivileged_bpf_disabled=" + v}
	}
}

func checkLockdown(root string) Check {
	v, err := readTrim(root, "/sys/kernel/security/lockdown")
	if err != nil {
		return Check{ID: "lockdown", Title: "kernel lockdown", Status: StatusInfo, Detail: "lockdown state not exposed"}
	}
	if strings.Contains(v, "[confidentiality]") {
		return Check{ID: "lockdown", Title: "kernel lockdown", Status: StatusWarn, Detail: v, Remediation: "validate BPF loading on this host; confidentiality lockdown can restrict kernel observability depending on distribution policy"}
	}
	return Check{ID: "lockdown", Title: "kernel lockdown", Status: StatusPass, Detail: v}
}

func checkMemlock() Check {
	var lim syscall.Rlimit
	const rlimitMemlock = 8 // Linux RLIMIT_MEMLOCK ABI value.
	if err := syscall.Getrlimit(rlimitMemlock, &lim); err != nil {
		return Check{ID: "memlock", Title: "memlock resource limit", Status: StatusWarn, Detail: err.Error()}
	}
	const recommended = uint64(64 << 20)
	if lim.Cur == math.MaxUint64 || lim.Cur >= recommended {
		return Check{ID: "memlock", Title: "memlock resource limit", Status: StatusPass, Detail: formatLimit(lim.Cur)}
	}
	return Check{ID: "memlock", Title: "memlock resource limit", Status: StatusWarn, Detail: formatLimit(lim.Cur), Remediation: "raise RLIMIT_MEMLOCK for the agent when the kernel/runtime does not account BPF memory through memcg"}
}

func checkInterfaces() Check {
	ifaces, err := net.Interfaces()
	if err != nil {
		return Check{ID: "interfaces", Title: "network interfaces", Status: StatusWarn, Detail: err.Error()}
	}
	var candidates []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		candidates = append(candidates, iface.Name)
	}
	sort.Strings(candidates)
	if len(candidates) == 0 {
		return Check{ID: "interfaces", Title: "network interfaces", Status: StatusWarn, Detail: "no UP non-loopback interface found", Remediation: "TCX/XDP are optional; configure an interface only when those hooks are needed"}
	}
	return Check{ID: "interfaces", Title: "network interfaces", Status: StatusPass, Detail: strings.Join(candidates, ", ")}
}

func kernelMajorMinor(release string) (int, int, bool) {
	release = strings.TrimSpace(release)
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	maj, err1 := strconv.Atoi(leadingDigits(parts[0]))
	min, err2 := strconv.Atoi(leadingDigits(parts[1]))
	return maj, min, err1 == nil && err2 == nil
}

func leadingDigits(s string) string {
	for i, r := range s {
		if r < '0' || r > '9' {
			return s[:i]
		}
	}
	return s
}

func versionLess(maj, min, wantMaj, wantMin int) bool {
	return maj < wantMaj || (maj == wantMaj && min < wantMin)
}

type mount struct {
	mountPoint string
	fsType     string
}

func mountInfo(root string) ([]mount, error) {
	f, err := os.Open(rooted(root, "/proc/self/mountinfo"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []mount
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		sep := strings.Index(line, " - ")
		if sep < 0 {
			continue
		}
		left := strings.Fields(line[:sep])
		right := strings.Fields(line[sep+3:])
		if len(left) < 5 || len(right) < 1 {
			continue
		}
		out = append(out, mount{mountPoint: unescapeMount(left[4]), fsType: right[0]})
	}
	return out, s.Err()
}

func unescapeMount(s string) string {
	r := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return r.Replace(s)
}

func hasTracepointField(format, field string) bool {
	needle := "field:"
	for _, line := range strings.Split(format, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, needle) {
			continue
		}
		decl := strings.TrimSpace(strings.TrimPrefix(line, needle))
		decl = strings.SplitN(decl, ";", 2)[0]
		parts := strings.Fields(decl)
		if len(parts) == 0 {
			continue
		}
		name := strings.TrimLeft(parts[len(parts)-1], "*")
		if name == field {
			return true
		}
	}
	return false
}

func parseCapabilityMask(s string) ([]byte, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	if len(s)%2 == 1 {
		s = "0" + s
	}
	b, err := hex.DecodeString(s)
	return b, err == nil
}

func capSet(bigEndian []byte, bit uint) bool {
	byteFromRight := int(bit / 8)
	if byteFromRight >= len(bigEndian) {
		return false
	}
	idx := len(bigEndian) - 1 - byteFromRight
	mask := byte(1 << (bit % 8))
	return bigEndian[idx]&mask != 0
}

func readTrim(root, path string) (string, error) {
	b, err := os.ReadFile(rooted(root, path))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func rooted(root, path string) string {
	if root == "" || root == "/" {
		return path
	}
	return filepath.Join(root, strings.TrimPrefix(path, "/"))
}

func displayPath(root, path string) string {
	if root == "/" {
		return path
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return "/" + rel
}

func emptyAs(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func formatLimit(v uint64) string {
	if v == math.MaxUint64 {
		return "unlimited"
	}
	if v >= 1<<30 {
		return fmt.Sprintf("%.1f GiB", float64(v)/float64(1<<30))
	}
	if v >= 1<<20 {
		return fmt.Sprintf("%.1f MiB", float64(v)/float64(1<<20))
	}
	if v >= 1<<10 {
		return fmt.Sprintf("%.1f KiB", float64(v)/float64(1<<10))
	}
	return fmt.Sprintf("%d bytes", v)
}
