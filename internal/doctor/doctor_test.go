// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunHealthyFixture(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/proc/sys/kernel/osrelease", "6.8.12-lts\n")
	write(t, root, "/sys/fs/cgroup/cgroup.controllers", "cpuset cpu io memory pids\n")
	write(t, root, "/proc/self/cgroup", "0::/kubepods.slice/pod123\n")
	write(t, root, "/proc/self/mountinfo", "36 25 0:32 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime - bpf bpf rw\n37 25 0:33 / /sys/kernel/tracing rw,nosuid,nodev,noexec,relatime - tracefs tracefs rw\n")
	write(t, root, "/sys/kernel/btf/vmlinux", "fake-btf")
	write(t, root, "/sys/kernel/tracing/events/skb/kfree_skb/format", "name: kfree_skb\nformat:\n\tfield:unsigned short common_type; offset:0; size:2; signed:0;\n\tfield:enum skb_drop_reason reason; offset:32; size:4; signed:0;\n")
	write(t, root, "/proc/self/status", "Name:\ttest\nCapEff:\t000000c001201000\n")
	write(t, root, "/proc/sys/kernel/unprivileged_bpf_disabled", "2\n")
	write(t, root, "/sys/kernel/security/lockdown", "[none] integrity confidentiality\n")

	r := Run(Options{Root: root, RequireTCX: true, RequireDropReasons: true, Now: func() time.Time {
		return time.Unix(1_700_000_000, 0)
	}})

	if r.Summary.Fail != 0 {
		t.Fatalf("unexpected failures: %#v", r.Checks)
	}
	assertStatus(t, r, "kernel", StatusPass)
	assertStatus(t, r, "tcx", StatusPass)
	assertStatus(t, r, "cgroup-v2", StatusPass)
	assertStatus(t, r, "bpffs", StatusPass)
	assertStatus(t, r, "drop-reasons", StatusPass)
	assertStatus(t, r, "capabilities", StatusPass)
	assertStatus(t, r, "tetragon", StatusInfo)
	if !r.GeneratedAt.Equal(time.Unix(1_700_000_000, 0).UTC()) {
		t.Fatalf("generatedAt=%v", r.GeneratedAt)
	}
}

func TestTetragonDetected(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/proc/sys/kernel/osrelease", "6.8.12\n")
	write(t, root, "/sys/fs/cgroup/cgroup.controllers", "cpu memory\n")
	write(t, root, "/proc/self/cgroup", "0::/\n")
	write(t, root, "/proc/self/mountinfo", "36 25 0:32 / /sys/fs/bpf rw - bpf bpf rw\n")
	write(t, root, "/proc/self/status", "CapEff:\t000000c001201000\n")
	if err := os.MkdirAll(filepath.Join(root, "sys/fs/bpf/tetragon"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := Run(Options{Root: root})
	assertStatus(t, r, "tetragon", StatusInfo)
	for _, c := range r.Checks {
		if c.ID == "tetragon" && !strings.Contains(c.Detail, "tetragon") {
			t.Fatalf("detail=%q", c.Detail)
		}
	}
}

func TestCheckNetraPins(t *testing.T) {
	root := t.TempDir()
	if got := checkNetraPins(root); got.Status != StatusInfo {
		t.Fatalf("no pin dir: status=%s want=info", got.Status)
	}

	need := []string{"allowed_v4", "allowed_ports", "allowed_uids", "allowed_comms", "rate_v6", "icmp_type_stats", "blocked_ingress_v4"}
	for _, n := range need[:len(need)-1] {
		write(t, root, "/sys/fs/bpf/netra/"+n, "")
	}
	if got := checkNetraPins(root); got.Status != StatusWarn || !strings.Contains(got.Detail, "blocked_ingress_v4") {
		t.Fatalf("partial pins: %#v", got)
	}

	for _, n := range need {
		write(t, root, "/sys/fs/bpf/netra/"+n, "")
	}
	if got := checkNetraPins(root); got.Status != StatusPass {
		t.Fatalf("all pins present: %#v", got)
	}
}

func TestRunMissingRequiredOptionalFeatures(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/proc/sys/kernel/osrelease", "5.15.0\n")
	write(t, root, "/sys/fs/cgroup/cgroup.controllers", "cpu memory\n")
	write(t, root, "/proc/self/cgroup", "0::/\n")
	write(t, root, "/proc/self/mountinfo", "36 25 0:32 / /sys/fs/bpf rw - bpf bpf rw\n")
	write(t, root, "/proc/self/status", "CapEff:\t0000000000000000\n")

	r := Run(Options{Root: root, RequireTCX: true, RequireDropReasons: true})
	assertStatus(t, r, "kernel", StatusPass)
	assertStatus(t, r, "tcx", StatusFail)
	assertStatus(t, r, "drop-reasons", StatusFail)
	assertStatus(t, r, "btf", StatusWarn)
	assertStatus(t, r, "capabilities", StatusWarn)
	if r.Summary.Fail != 2 {
		t.Fatalf("fail=%d want=2 checks=%#v", r.Summary.Fail, r.Checks)
	}
}

func TestKernelMajorMinor(t *testing.T) {
	for _, tc := range []struct {
		in       string
		maj, min int
		ok       bool
	}{
		{"6.6.51-1-lts", 6, 6, true},
		{"5.15.0-1092-azure", 5, 15, true},
		{"6.12-rc4", 6, 12, true},
		{"garbage", 0, 0, false},
	} {
		maj, min, ok := kernelMajorMinor(tc.in)
		if maj != tc.maj || min != tc.min || ok != tc.ok {
			t.Fatalf("kernelMajorMinor(%q)=(%d,%d,%v), want (%d,%d,%v)", tc.in, maj, min, ok, tc.maj, tc.min, tc.ok)
		}
	}
}

func TestTracepointReasonParser(t *testing.T) {
	withReason := "field:enum skb_drop_reason reason; offset:32; size:4; signed:0;"
	withoutReason := "field:void * skbaddr; offset:16; size:8; signed:0;"
	if !hasTracepointField(withReason, "reason") {
		t.Fatal("reason field not found")
	}
	if hasTracepointField(withoutReason, "reason") {
		t.Fatal("false reason field match")
	}
}

func TestCapabilityMask(t *testing.T) {
	// Bits 12 (NET_ADMIN) and 39 (BPF).
	mask, ok := parseCapabilityMask("0000008000001000")
	if !ok {
		t.Fatal("parse failed")
	}
	if !capSet(mask, 12) || !capSet(mask, 39) {
		t.Fatalf("expected NET_ADMIN and BPF bits in %x", mask)
	}
	if capSet(mask, 21) {
		t.Fatal("unexpected SYS_ADMIN bit")
	}
}

func assertStatus(t *testing.T, r Report, id string, want Status) {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			if c.Status != want {
				t.Fatalf("%s status=%s want=%s detail=%q", id, c.Status, want, c.Detail)
			}
			return
		}
	}
	t.Fatalf("check %q not found", id)
}

func write(t *testing.T, root, path, content string) {
	t.Helper()
	p := filepath.Join(root, path[1:])
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
