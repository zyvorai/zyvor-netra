package cgroupmeta

import "testing"

func TestPodUIDSystemd(t *testing.T) {
	got := podUID("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod12345678_1234_5678_9abc_123456789abc.slice/cri-containerd-abcdef0123456789.scope")
	want := "12345678-1234-5678-9abc-123456789abc"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestContainerID(t *testing.T) {
	got := containerID("kubepods/pod12345678-1234-5678-9abc-123456789abc/cri-containerd-abcdef0123456789.scope")
	if got != "abcdef0123456789" {
		t.Fatalf("got %q", got)
	}
}
