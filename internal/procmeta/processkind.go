//go:build linux

package procmeta

import (
	"path/filepath"
	"strings"
)

// ProcessKind is a coarse classification of what a process is, used to
// decide how to display it. It is heuristic. The authoritative answer
// always requires joining against Kubernetes state; this exists so a
// dashboard can render a sensible default before that join completes.
type ProcessKind int

const (
	// KindUnknown means not enough information to classify.
	KindUnknown ProcessKind = iota
	// KindHost is a process outside any container cgroup.
	KindHost
	// KindContainer is a process in a container cgroup, but not a VM.
	KindContainer
	// KindVMLauncher is the KubeVirt virt-launcher process, which
	// supervises the QEMU process for one VM. It is a container process
	// that happens to be the launcher for a VM.
	KindVMLauncher
	// KindVM is the actual virtual machine process, typically
	// qemu-system-<arch> or firecracker. It runs inside the virt-launcher
	// pod.
	KindVM
)

// String returns the stable lowercase name used in JSON and in the UI.
func (k ProcessKind) String() string {
	switch k {
	case KindHost:
		return "host"
	case KindContainer:
		return "container"
	case KindVMLauncher:
		return "vm-launcher"
	case KindVM:
		return "vm"
	default:
		return "unknown"
	}
}

// vmExecutables are basenames of well-known VM monitor processes.
var vmExecutables = map[string]struct{}{
	"firecracker":      {},
	"cloud-hypervisor": {},
	"stratovirt":       {},
}

// vmExecutablePrefixes matches the qemu-system-* family and the common
// distro aliases.
var vmExecutablePrefixes = []string{
	"qemu-system-",
	"qemu-kvm",
	"qemu-x86_64",
	"qemu-aarch64",
	"qemu-ppc64",
	"qemu-s390x",
	"qemu-riscv64",
}

// vmLauncherComms are comm values observed for KubeVirt virt-launcher. comm
// is limited to 15 visible bytes.
var vmLauncherComms = map[string]struct{}{
	"virt-launcher": {},
}

// classify returns the best-guess kind for a process. It uses only fields
// already collected on Meta; it does not read /proc again.
func classify(m *Meta) ProcessKind {
	if m == nil {
		return KindUnknown
	}
	// Kernel threads are neither host userspace nor container.
	if m.KernelThread {
		return KindUnknown
	}

	inContainer := m.Cgroup != nil && m.Cgroup.ContainerID != ""

	base := ""
	if m.Exe != "" {
		base = filepath.Base(m.Exe)
	}

	// virt-launcher has comm == "virt-launcher" and a long exe path under
	// /usr/bin. It is a container process, but we surface it separately
	// because a VM operator cares about it.
	if _, ok := vmLauncherComms[m.Comm]; ok {
		return KindVMLauncher
	}
	if base != "" && strings.HasPrefix(base, "virt-launcher") {
		return KindVMLauncher
	}

	// QEMU and other VMMs. The match is on exe basename only; comm is
	// truncated to 15 bytes and would collide with non-VM uses of the same
	// name.
	if base != "" {
		if _, ok := vmExecutables[base]; ok {
			return KindVM
		}
		for _, p := range vmExecutablePrefixes {
			if strings.HasPrefix(base, p) {
				return KindVM
			}
		}
	}

	if inContainer {
		return KindContainer
	}
	return KindHost
}
