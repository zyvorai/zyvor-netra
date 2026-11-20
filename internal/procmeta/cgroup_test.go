//go:build linux

package procmeta

import (
	"errors"
	"os"
	"testing"
)

func TestParseCgroupContainerd(t *testing.T) {
	in := []byte("0::/kubepods.slice/kubepods-burstable.slice/" +
		"kubepods-burstable-pod12345678_1234_1234_1234_123456789abc.slice/" +
		"cri-containerd-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n")

	got, err := parseCgroup(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.QoSClass != "burstable" {
		t.Errorf("QoSClass = %q", got.QoSClass)
	}
	if got.PodUID != "12345678-1234-1234-1234-123456789abc" {
		t.Errorf("PodUID = %q", got.PodUID)
	}
	const cid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if got.ContainerID != cid {
		t.Errorf("ContainerID = %q, want %q", got.ContainerID, cid)
	}
}

func TestParseCgroupCRIO(t *testing.T) {
	in := []byte("0::/kubepods.slice/kubepods-besteffort.slice/" +
		"kubepods-besteffort-podabcdef12_3456_7890_abcd_ef1234567890.slice/" +
		"crio-fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210.scope\n")

	got, err := parseCgroup(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.QoSClass != "besteffort" {
		t.Errorf("QoSClass = %q", got.QoSClass)
	}
	if got.PodUID != "abcdef12-3456-7890-abcd-ef1234567890" {
		t.Errorf("PodUID = %q", got.PodUID)
	}
}

func TestParseCgroupLegacyDocker(t *testing.T) {
	in := []byte("0::/kubepods/burstable/pod12345678-1234-1234-1234-123456789abc/" +
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n")

	got, err := parseCgroup(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.PodUID != "12345678-1234-1234-1234-123456789abc" {
		t.Errorf("PodUID = %q", got.PodUID)
	}
	if len(got.ContainerID) != 64 {
		t.Errorf("ContainerID = %q", got.ContainerID)
	}
}

func TestParseCgroupGuaranteedNoRuntimePrefix(t *testing.T) {
	in := []byte("0::/kubepods.slice/kubepods-guaranteed.slice/" +
		"kubepods-guaranteed-pod12345678_1234_1234_1234_123456789abc.slice/" +
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n")

	got, err := parseCgroup(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.QoSClass != "guaranteed" {
		t.Errorf("QoSClass = %q", got.QoSClass)
	}
	if len(got.ContainerID) != 64 {
		t.Errorf("ContainerID = %q", got.ContainerID)
	}
}

func TestParseCgroupNonKubepods(t *testing.T) {
	in := []byte("0::/user.slice/user-1000.slice/session-2.scope\n")

	got, err := parseCgroup(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.PodUID != "" || got.ContainerID != "" || got.QoSClass != "" {
		t.Errorf("expected empty identifiers, got %+v", got)
	}
	if got.Raw == "" {
		t.Error("Raw should be populated even for non-kubepods paths")
	}
	if got.IsKubernetes() {
		t.Error("non-kubepods path should not report IsKubernetes")
	}
}

func TestParseCgroupV1Only(t *testing.T) {
	// Only v1 hierarchy lines; no "0::" entry.
	in := []byte("12:pids:/kubepods/burstable/pod12345678-1234-1234-1234-123456789abc\n" +
		"11:memory:/kubepods/burstable/pod12345678-1234-1234-1234-123456789abc\n")

	_, err := parseCgroup(in)
	if !errors.Is(err, ErrNoCgroup) {
		t.Fatalf("want ErrNoCgroup, got %v", err)
	}
}

func TestParseCgroupEmptyInput(t *testing.T) {
	_, err := parseCgroup(nil)
	if !errors.Is(err, ErrNoCgroup) {
		t.Fatalf("want ErrNoCgroup, got %v", err)
	}
}

func TestParseCgroupFirstV2Wins(t *testing.T) {
	// Multiple v2 lines should not occur, but if they do, take the first
	// one deterministically.
	in := []byte("0::/kubepods.slice/kubepods-guaranteed.slice/" +
		"kubepods-guaranteed-pod12345678_1234_1234_1234_123456789abc.slice/" +
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n" +
		"0::/different/path\n")

	got, err := parseCgroup(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.QoSClass != "guaranteed" {
		t.Errorf("QoSClass = %q; first v2 line should win", got.QoSClass)
	}
}

func TestReadCgroupSelf(t *testing.T) {
	cg, err := ReadCgroup(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if cg.Raw == "" {
		t.Error("Raw should be populated")
	}
	if cg.IsKubernetes() && len(cg.ContainerID) != 64 {
		t.Errorf("kubepods path without container ID: %+v", cg)
	}
}

func TestReadCgroupNoProcess(t *testing.T) {
	_, err := ReadCgroup(1<<31 - 1)
	if !errors.Is(err, ErrNoProcess) {
		t.Fatalf("want ErrNoProcess, got %v", err)
	}
}

func TestCgroupIsKubernetes(t *testing.T) {
	if (*CgroupInfo)(nil).IsKubernetes() {
		t.Error("nil CgroupInfo should not report IsKubernetes")
	}
	if (&CgroupInfo{}).IsKubernetes() {
		t.Error("empty CgroupInfo should not report IsKubernetes")
	}
	if !(&CgroupInfo{PodUID: "x"}).IsKubernetes() {
		t.Error("Populated PodUID should report IsKubernetes")
	}
}
