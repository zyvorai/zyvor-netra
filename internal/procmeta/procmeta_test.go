//go:build linux

package procmeta

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseStat(t *testing.T) {
	// comm contains a space and a nested paren, both of which the parser
	// must survive. After the closing paren there are exactly 20 fields;
	// index 19 is starttime.
	line := "12345 (weird name (with parens)) S 1 12345 12345 0 -1 4194304 " +
		"0 0 0 0 0 0 0 0 20 0 1 0 987654321"

	ppid, st, comm, err := parseStat(12345, []byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if ppid != 1 {
		t.Errorf("ppid = %d, want 1", ppid)
	}
	if st != 987654321 {
		t.Errorf("starttime = %d, want 987654321", st)
	}
	if comm != "weird name (with parens)" {
		t.Errorf("comm = %q", comm)
	}
}

func TestParseStatRejectsShort(t *testing.T) {
	if _, _, _, err := parseStat(1, []byte("1 (x) S 1 2")); err == nil {
		t.Fatal("want error for short stat")
	}
}

func TestParseStatRejectsNoParens(t *testing.T) {
	if _, _, _, err := parseStat(1, []byte("no parens here")); err == nil {
		t.Fatal("want error for stat with no parens")
	}
}

func TestParseStatus(t *testing.T) {
	body := "Name:\tcurl\n" +
		"Uid:\t1000\t1000\t1000\t1000\n" +
		"Gid:\t1000\t1000\t1000\t1000\n" +
		"NSpid:\t48213\t7\n" +
		"CapInh:\t0000000000000000\n" +
		"CapPrm:\t0000000000000400\n" +
		"CapEff:\t0000000000000400\n" +
		"CapBnd:\t000001ffffffffff\n" +
		"CapAmb:\t0000000000000000\n" +
		"NoNewPrivs:\t1\n" +
		"Seccomp:\t2\n"
	var m Meta
	parseStatus([]byte(body), &m)

	if m.Cred.EffUID != 1000 {
		t.Errorf("EffUID = %d, want 1000", m.Cred.EffUID)
	}
	if m.Cred.FSUID != 1000 {
		t.Errorf("FSUID = %d, want 1000", m.Cred.FSUID)
	}
	if len(m.NSpid) != 2 || m.NSpid[0] != 48213 || m.NSpid[1] != 7 {
		t.Errorf("NSpid = %v", m.NSpid)
	}
	if m.Caps.Eff != 0x400 {
		t.Errorf("CapEff = %#x, want 0x400", m.Caps.Eff)
	}
	if m.Caps.Bnd != 0x1ffffffffff {
		t.Errorf("CapBnd = %#x", m.Caps.Bnd)
	}
	if !m.NoNewPrivs {
		t.Error("NoNewPrivs should be true")
	}
	if m.Seccomp != SeccompFilter {
		t.Errorf("Seccomp = %d, want %d", m.Seccomp, SeccompFilter)
	}
}

func TestParseStatusToleratesUnknownKeys(t *testing.T) {
	var m Meta
	parseStatus([]byte("Future:\tnonsense\nUid:\t7\t7\t7\t7\n"), &m)
	if m.Cred.EffUID != 7 {
		t.Errorf("EffUID = %d", m.Cred.EffUID)
	}
}

func TestIdentitySame(t *testing.T) {
	a := Identity{PID: 100, StartTime: 1000}
	b := Identity{PID: 100, StartTime: 1000}
	c := Identity{PID: 100, StartTime: 2000} // PID reused
	d := Identity{PID: 200, StartTime: 1000}

	if !a.Same(b) {
		t.Error("identical identities should match")
	}
	if a.Same(c) {
		t.Error("PID reuse must not match")
	}
	if a.Same(d) {
		t.Error("different PIDs must not match")
	}
}

func TestIdentityWallClock(t *testing.T) {
	boot := time.Unix(1_700_000_000, 0)
	id := Identity{PID: 1, StartTime: 300} // 3s at 100 Hz
	got := id.WallClock(boot, 100)
	want := boot.Add(3 * time.Second)
	if !got.Equal(want) {
		t.Errorf("WallClock = %v, want %v", got, want)
	}
}

func TestIdentityWallClockDefaultsTicks(t *testing.T) {
	boot := time.Unix(0, 0)
	id := Identity{PID: 1, StartTime: 100}
	got := id.WallClock(boot, 0)
	if !got.Equal(boot.Add(time.Second)) {
		t.Errorf("WallClock with zero clkTck = %v", got)
	}
}

func TestReadSelf(t *testing.T) {
	pid := os.Getpid()
	m, err := Read(pid)
	if err != nil {
		t.Fatal(err)
	}
	if m.Identity.PID != pid {
		t.Errorf("PID = %d, want %d", m.Identity.PID, pid)
	}
	if m.Identity.StartTime == 0 {
		t.Error("StartTime should be nonzero")
	}
	if m.Cred.EffUID != uint32(os.Geteuid()) {
		t.Errorf("EffUID = %d, want %d", m.Cred.EffUID, os.Geteuid())
	}
	if len(m.NSpid) == 0 {
		t.Error("NSpid should have at least one entry")
	}
	if m.KernelThread {
		t.Error("test process should not look like a kernel thread")
	}
	if m.Comm == "" {
		t.Error("comm should not be empty")
	}
	if m.Kind == KindUnknown {
		t.Error("a userspace test process should be classifiable")
	}
}

func TestReadNoProcess(t *testing.T) {
	// 2^31-1 is above pid_max on every Linux build.
	_, err := Read(1<<31 - 1)
	if !errors.Is(err, ErrNoProcess) {
		t.Fatalf("want ErrNoProcess, got %v", err)
	}
}

func TestReadIsStable(t *testing.T) {
	// Two reads of the same process must produce the same Identity.
	a, err := Read(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Read(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if !a.Identity.Same(b.Identity) {
		t.Errorf("identity changed between reads: %+v vs %+v", a.Identity, b.Identity)
	}
}

func TestContainerPIDHostProcess(t *testing.T) {
	// The test binary is in the host PID namespace on CI, so NSpid has
	// exactly one entry and ContainerPID returns zero.
	m := &Meta{NSpid: []int{12345}}
	if got := m.ContainerPID(); got != 0 {
		t.Errorf("ContainerPID = %d, want 0", got)
	}
}

func TestContainerPIDNested(t *testing.T) {
	m := &Meta{NSpid: []int{48213, 7}}
	if got := m.ContainerPID(); got != 7 {
		t.Errorf("ContainerPID = %d, want 7", got)
	}
}

func TestReadSelfSaneSummary(t *testing.T) {
	m, err := Read(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range m.Caps.NetworkRelevant() {
		if !strings.HasPrefix(c, "CAP_") {
			t.Errorf("unexpected capability name %q", c)
		}
	}
	if m.Seccomp < SeccompDisabled || m.Seccomp > SeccompFilter {
		t.Errorf("Seccomp = %d out of range", m.Seccomp)
	}
}

func TestReadSelfHasNetNS(t *testing.T) {
	m, err := Read(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if m.NetNS == 0 {
		t.Fatal("expected a non-zero network namespace inode for the running test process")
	}
}

func TestHashExeMatchesSHA256(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/fake-exe"
	content := []byte("not a real binary, just deterministic test content")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])
	if got := hashExe(path); got != want {
		t.Fatalf("hashExe = %q, want %q", got, want)
	}
}

func TestHashExeMissingFile(t *testing.T) {
	if got := hashExe("/nonexistent/path/for/test"); got != "" {
		t.Fatalf("expected empty hash for missing file, got %q", got)
	}
}

func TestHashExeOverSizeCapIsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/big"
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxExeHashBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if got := hashExe(path); got != "" {
		t.Fatalf("expected empty hash for oversized file, got %q", got)
	}
}

func TestReadSelfHasExeHash(t *testing.T) {
	m, err := Read(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if m.ExeHash == "" {
		t.Fatal("expected a non-empty exe hash for the running test binary")
	}
	if len(m.ExeHash) != 64 {
		t.Fatalf("expected a 64-char hex SHA-256, got %d chars: %q", len(m.ExeHash), m.ExeHash)
	}
}

func TestParseNSInode(t *testing.T) {
	for _, tc := range []struct {
		target string
		want   uint64
	}{
		{"net:[4026531840]", 4026531840},
		{"mnt:[4026531841]", 4026531841},
		{"", 0},
		{"net:[]", 0},
		{"net:[notanumber]", 0},
		{"garbage", 0},
	} {
		if got := parseNSInode(tc.target); got != tc.want {
			t.Errorf("parseNSInode(%q) = %d, want %d", tc.target, got, tc.want)
		}
	}
}
