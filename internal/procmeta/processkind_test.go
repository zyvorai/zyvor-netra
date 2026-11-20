//go:build linux

package procmeta

import "testing"

func TestClassifyVM(t *testing.T) {
	cases := []struct {
		name string
		exe  string
		comm string
		want ProcessKind
	}{
		{"kubevirt qemu x86", "/usr/libexec/qemu-kvm", "qemu-kvm", KindVM},
		{"qemu system x86", "/usr/bin/qemu-system-x86_64", "qemu-system-x86", KindVM},
		{"qemu system aarch", "/usr/bin/qemu-system-aarch64", "qemu-system-aar", KindVM},
		{"firecracker", "/usr/bin/firecracker", "firecracker", KindVM},
		{"cloud-hypervisor", "/usr/bin/cloud-hypervisor", "cloud-hyp", KindVM},
	}
	for _, c := range cases {
		m := &Meta{
			Exe:  c.exe,
			Comm: c.comm,
			Cgroup: &CgroupInfo{
				PodUID:      "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
				ContainerID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
		}
		if got := classify(m); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestClassifyVMLauncherByExe(t *testing.T) {
	m := &Meta{
		Exe:  "/usr/bin/virt-launcher",
		Comm: "virt-launcher",
		Cgroup: &CgroupInfo{
			PodUID:      "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			ContainerID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}
	if got := classify(m); got != KindVMLauncher {
		t.Errorf("got %v, want %v", got, KindVMLauncher)
	}
}

func TestClassifyVMLauncherByCommOnly(t *testing.T) {
	// exe may be unreadable for a process running as another user.
	m := &Meta{
		Comm: "virt-launcher",
		Cgroup: &CgroupInfo{
			ContainerID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}
	if got := classify(m); got != KindVMLauncher {
		t.Errorf("got %v, want %v", got, KindVMLauncher)
	}
}

func TestClassifyContainer(t *testing.T) {
	m := &Meta{
		Exe:  "/usr/bin/curl",
		Comm: "curl",
		Cgroup: &CgroupInfo{
			PodUID:      "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			ContainerID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}
	if got := classify(m); got != KindContainer {
		t.Errorf("got %v, want %v", got, KindContainer)
	}
}

func TestClassifyHost(t *testing.T) {
	m := &Meta{
		Exe:    "/usr/sbin/sshd",
		Comm:   "sshd",
		Cgroup: &CgroupInfo{Raw: "/system.slice/ssh.service"},
	}
	if got := classify(m); got != KindHost {
		t.Errorf("got %v, want %v", got, KindHost)
	}
}

func TestClassifyKernelThread(t *testing.T) {
	m := &Meta{KernelThread: true}
	if got := classify(m); got != KindUnknown {
		t.Errorf("got %v, want %v", got, KindUnknown)
	}
}

func TestClassifyNil(t *testing.T) {
	if got := classify(nil); got != KindUnknown {
		t.Errorf("got %v, want %v", got, KindUnknown)
	}
}

func TestClassifyDoesNotGuessVMFromCommAlone(t *testing.T) {
	// A userspace process that happens to be named qemu-system-x86_64 but
	// has a different exe should not be classified as a VM. comm is
	// truncated and not trustworthy for this decision.
	m := &Meta{
		Exe:  "/usr/local/bin/myapp",
		Comm: "qemu-system-x86",
		Cgroup: &CgroupInfo{
			ContainerID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}
	if got := classify(m); got != KindContainer {
		t.Errorf("got %v, want %v", got, KindContainer)
	}
}

func TestClassifyVMWithoutContainer(t *testing.T) {
	// A bare-metal host running qemu directly is still KindVM.
	m := &Meta{
		Exe:    "/usr/bin/qemu-system-x86_64",
		Comm:   "qemu-system-x86",
		Cgroup: &CgroupInfo{Raw: "/system.slice/libvirtd.service"},
	}
	if got := classify(m); got != KindVM {
		t.Errorf("got %v, want %v", got, KindVM)
	}
}

func TestProcessKindString(t *testing.T) {
	cases := map[ProcessKind]string{
		KindUnknown:    "unknown",
		KindHost:       "host",
		KindContainer:  "container",
		KindVMLauncher: "vm-launcher",
		KindVM:         "vm",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("%d: got %q, want %q", k, got, want)
		}
	}
}

func TestProcessKindOutOfRange(t *testing.T) {
	if got := ProcessKind(99).String(); got != "unknown" {
		t.Errorf("out-of-range kind = %q, want unknown", got)
	}
}
