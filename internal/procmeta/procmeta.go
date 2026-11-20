//go:build linux

package procmeta

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// maxExeHashBytes caps how much of an executable Read will hash. A
// process being observed here already has a live TCP socket (the
// caller-provided PID set is scoped that way), so this is a bounded,
// small set of processes per cycle — the cap exists only to bound a
// single pathological case (an unusually large binary), not to sample
// hash content, so drift on the untouched remainder of a huge binary
// would go undetected. No known Netra-adjacent binary approaches this
// size.
const maxExeHashBytes = 64 << 20 // 64MiB

// ErrNoProcess is returned when /proc/PID does not exist. This covers both
// a PID that was never valid and a process that has exited since the
// caller last saw it.
var ErrNoProcess = errors.New("procmeta: process not found")

// DefaultClockTicks is the value of USER_HZ on essentially every Linux
// build (getconf CLK_TCK). It is used only to convert Identity.StartTime
// from jiffies to wall-clock. Identity comparison does not depend on it.
const DefaultClockTicks = 100

// Identity is the stable identity of one process incarnation.
//
// StartTime is /proc/PID/stat field 22: clock ticks since boot. It is
// unique among live and dead processes for the lifetime of the boot. Two
// Meta values with the same Identity refer to the same process
// incarnation; two with the same PID but different StartTime refer to a
// PID that was reused.
type Identity struct {
	PID       int    `json:"pid"`
	StartTime uint64 `json:"startTimeJiffies"`
}

// Same reports whether a and b refer to the same process incarnation. This
// is the PID-reuse-safe comparison. Use it instead of comparing PIDs.
func (a Identity) Same(b Identity) bool {
	return a.PID == b.PID && a.StartTime == b.StartTime
}

// WallClock converts the process start time to a wall-clock time. boot is
// the host boot time (see BootTime); clkTck is USER_HZ. A non-positive
// clkTck is treated as DefaultClockTicks.
func (id Identity) WallClock(boot time.Time, clkTck int64) time.Time {
	if clkTck <= 0 {
		clkTck = DefaultClockTicks
	}
	ticks := time.Duration(id.StartTime) * time.Second / time.Duration(clkTck)
	return boot.Add(ticks)
}

// Cred is the process credential set, as reported by /proc/PID/status.
type Cred struct {
	RealUID  uint32 `json:"realUid"`
	EffUID   uint32 `json:"effectiveUid"`
	SavedUID uint32 `json:"savedUid"`
	FSUID    uint32 `json:"fsUid"`
	RealGID  uint32 `json:"realGid"`
	EffGID   uint32 `json:"effectiveGid"`
}

// Seccomp modes, from <linux/seccomp.h>.
const (
	SeccompDisabled = 0
	SeccompStrict   = 1
	SeccompFilter   = 2
)

// Meta is everything this package can observe about a process at one
// instant. It deliberately does not include argv/cmdline content — see the
// package doc comment.
type Meta struct {
	Identity Identity `json:"identity"`
	Comm     string   `json:"comm"`
	PPID     int      `json:"ppid"`

	// NSpid is the PID as seen in each PID namespace, outermost first. A
	// process in the host PID namespace has a single entry equal to its
	// global PID. A process in one container has two entries; the last is
	// the container-local PID.
	NSpid []int `json:"nspid,omitempty"`

	Cred       Cred   `json:"cred"`
	Caps       Caps   `json:"caps"`
	NoNewPrivs bool   `json:"noNewPrivs"`
	Seccomp    int    `json:"seccomp"`
	LSMLabel   string `json:"lsmLabel,omitempty"`

	// Exe is the target of /proc/PID/exe. Empty for kernel threads or when
	// permission is denied.
	Exe string `json:"exe,omitempty"`

	// ExeHash is the SHA-256 of Exe's target file contents (hex-encoded),
	// read at the same instant as everything else in Meta. Empty when
	// unreadable (permission, kernel thread with no Exe, deleted
	// executable — a common and benign case after a package upgrade
	// replaces a running binary on disk, "(deleted)" appended to the
	// Exe target) or larger than maxExeHashBytes. Comparing this across
	// syncs for the same process identity detects the on-disk binary
	// backing a *running* process changing underneath it — a stronger
	// tamper signal than the target path alone, which a symlink swap
	// could spoof without this.
	ExeHash string `json:"exeHash,omitempty"`

	// NetNS is the inode number of /proc/PID/ns/net — the kernel's own
	// stable identifier for a network namespace, parsed from the symlink
	// target "net:[INODE]". Zero when unreadable (permission, or the
	// process exited mid-read). Comparing this across syncs for the same
	// process identity (pid+startTime) detects a live process moving
	// network namespaces after start — e.g. setns(2) from a container
	// escape or debugging tool — something CapEff alone would not catch.
	NetNS uint64 `json:"netNs,omitempty"`

	// Cgroup identifies the cgroup v2 workload. Nil if /proc/PID/cgroup
	// could not be read or had no v2 entry. PodUID and ContainerID are
	// populated only for kubepods paths.
	Cgroup *CgroupInfo `json:"cgroup,omitempty"`

	// Kind is a heuristic classification derived from Exe, Comm, and
	// Cgroup. See ProcessKind.
	Kind ProcessKind `json:"kind"`

	// KernelThread is set when the process has neither an exe symlink nor
	// argv. Kernel threads share this property with a userspace process
	// that has overwritten its own argv and deleted its executable, which
	// is rare but not impossible.
	KernelThread bool `json:"kernelThread"`

	ReadAt time.Time `json:"readAt"`
}

// ContainerPID returns the innermost namespace PID, or zero if the process
// is not in a nested PID namespace.
func (m *Meta) ContainerPID() int {
	if len(m.NSpid) < 2 {
		return 0
	}
	return m.NSpid[len(m.NSpid)-1]
}

// IsPrivileged reports whether the process holds any capability commonly
// used to bypass, alter, or observe network policy.
func (m *Meta) IsPrivileged() bool {
	return m.Caps.HasAny(
		"CAP_NET_ADMIN",
		"CAP_NET_RAW",
		"CAP_SYS_ADMIN",
		"CAP_BPF",
		"CAP_SYS_MODULE",
		"CAP_SYS_PTRACE",
	)
}

// Read loads metadata for pid. Returns ErrNoProcess if the process is gone.
// Other errors indicate a malformed or unreadable /proc entry.
//
// A single process may exit between reads of different /proc files. In
// that case Read returns whatever it managed to collect before the exit;
// callers that need strict consistency should re-read and check
// Identity.Same.
func Read(pid int) (*Meta, error) {
	statB, err := os.ReadFile(statPath(pid))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoProcess
		}
		return nil, fmt.Errorf("procmeta: read stat for pid %d: %w", pid, err)
	}
	return readFromStat(pid, statB)
}

func statPath(pid int) string {
	return "/proc/" + strconv.Itoa(pid) + "/stat"
}

// ListPIDs returns every PID currently present under /proc, by reading the
// directory listing and keeping only numeric entries. A PID that exits
// between this call and a subsequent Read/Cache.Get is not an error there
// (ErrNoProcess), so callers don't need to pre-filter this list.
func ListPIDs() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("procmeta: list /proc: %w", err)
	}
	out := make([]int, 0, len(entries))
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		out = append(out, pid)
	}
	return out, nil
}

// readFromStat finishes reading a Meta given the already-loaded contents of
// /proc/PID/stat. This exists so Cache.Get does not read stat twice on a
// miss.
func readFromStat(pid int, statB []byte) (*Meta, error) {
	ppid, startJiffies, comm, err := parseStat(pid, statB)
	if err != nil {
		return nil, err
	}

	m := &Meta{
		Identity: Identity{PID: pid, StartTime: startJiffies},
		Comm:     comm,
		PPID:     ppid,
		ReadAt:   time.Now(),
	}

	root := "/proc/" + strconv.Itoa(pid)

	// /proc/PID/status holds most of the interesting fields. A read
	// failure is tolerated: the process may have raced to exit, and the
	// identity we already have is still useful.
	if b, err := os.ReadFile(root + "/status"); err == nil {
		parseStatus(b, m)
	}

	// LSM label. Absent when no LSM is active.
	if b, err := os.ReadFile(root + "/attr/current"); err == nil {
		m.LSMLabel = strings.TrimSpace(string(b))
	}

	// exe and cmdline. Both fail (or read empty) for kernel threads.
	// cmdline content itself is never retained — see the package doc
	// comment — it is read only to help classify kernel threads.
	exePath, exeErr := os.Readlink(root + "/exe")
	if exeErr == nil {
		m.Exe = exePath
		// Open the magic symlink itself, not exePath's string target: the
		// kernel resolves /proc/PID/exe to the live backing inode even
		// after the on-disk file was unlinked (readlink then appends
		// " (deleted)" to the target string, which is not a real path).
		m.ExeHash = hashExe(root + "/exe")
	}

	if ns, err := os.Readlink(root + "/ns/net"); err == nil {
		m.NetNS = parseNSInode(ns)
	}

	cmdlineB, cmdlineErr := os.ReadFile(root + "/cmdline")
	haveCmdline := cmdlineErr == nil && len(bytes.Trim(cmdlineB, "\x00")) > 0

	// A process with no exe symlink and no argv is a kernel thread with
	// very high probability. There is no exact kernel-provided signal
	// available from userspace without reading task_struct.
	if exeErr != nil && !haveCmdline {
		m.KernelThread = true
	}

	// cgroup v2 identifiers. A read failure is tolerated; the rest of Meta
	// is still useful.
	if cg, err := ReadCgroup(pid); err == nil {
		m.Cgroup = cg
	}

	m.Kind = classify(m)

	return m, nil
}

// parseStat extracts PPID, comm, and StartTime from /proc/PID/stat.
//
// The comm field is between the first '(' and the last ')', because it may
// itself contain spaces and parentheses. After the closing paren, fields
// are space-separated and start at index 0 = state (field 3 in the
// proc(5) numbering). StartTime is field 22, i.e. index 19 after the
// closing paren.
func parseStat(pid int, b []byte) (ppid int, startJiffies uint64, comm string, err error) {
	s := string(b)
	open := strings.IndexByte(s, '(')
	closeIdx := strings.LastIndexByte(s, ')')
	if open < 0 || closeIdx < 0 || closeIdx < open {
		return 0, 0, "", fmt.Errorf("procmeta: malformed stat for pid %d", pid)
	}
	comm = s[open+1 : closeIdx]

	rest := strings.Fields(s[closeIdx+1:])
	// Need at least 20 fields after ')' to reach starttime at index 19.
	if len(rest) < 20 {
		return 0, 0, "", fmt.Errorf("procmeta: short stat for pid %d", pid)
	}

	ppid, err = strconv.Atoi(rest[1])
	if err != nil {
		return 0, 0, "", fmt.Errorf("procmeta: ppid for pid %d: %w", pid, err)
	}
	startJiffies, err = strconv.ParseUint(rest[19], 10, 64)
	if err != nil {
		return 0, 0, "", fmt.Errorf("procmeta: starttime for pid %d: %w", pid, err)
	}
	return ppid, startJiffies, comm, nil
}

// parseStatus fills m from the contents of /proc/PID/status.
//
// Unknown keys are ignored, so new kernel fields do not break parsing.
func parseStatus(b []byte, m *Meta) {
	for _, line := range strings.Split(string(b), "\n") {
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := line[:colon]
		val := strings.TrimSpace(line[colon+1:])
		switch key {
		case "Uid":
			if f := strings.Fields(val); len(f) >= 4 {
				m.Cred.RealUID = parseUint32(f[0])
				m.Cred.EffUID = parseUint32(f[1])
				m.Cred.SavedUID = parseUint32(f[2])
				m.Cred.FSUID = parseUint32(f[3])
			}
		case "Gid":
			if f := strings.Fields(val); len(f) >= 2 {
				m.Cred.RealGID = parseUint32(f[0])
				m.Cred.EffGID = parseUint32(f[1])
			}
		case "NSpid":
			for _, f := range strings.Fields(val) {
				if n, err := strconv.Atoi(f); err == nil {
					m.NSpid = append(m.NSpid, n)
				}
			}
		case "CapInh":
			m.Caps.Inh = parseUint64Hex(val)
		case "CapPrm":
			m.Caps.Prm = parseUint64Hex(val)
		case "CapEff":
			m.Caps.Eff = parseUint64Hex(val)
		case "CapBnd":
			m.Caps.Bnd = parseUint64Hex(val)
		case "CapAmb":
			m.Caps.Amb = parseUint64Hex(val)
		case "NoNewPrivs":
			m.NoNewPrivs = val == "1"
		case "Seccomp":
			if n, err := strconv.Atoi(val); err == nil {
				m.Seccomp = n
			}
		}
	}
}

func parseUint32(s string) uint32 {
	n, _ := strconv.ParseUint(s, 10, 32)
	return uint32(n)
}

// parseUint64Hex parses the hex masks printed in /proc/PID/status. The
// kernel prints them without an 0x prefix, but tolerate one.
// hashExe returns the hex SHA-256 of exePath's contents, or "" on any
// read error (permission, race with process exit, over maxExeHashBytes).
// A read error here is exactly as tolerable as every other best-effort
// field in Meta — the rest of the struct is still useful without it.
func hashExe(exePath string) string {
	f, err := os.Open(exePath)
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.Size() > maxExeHashBytes {
		return ""
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// parseNSInode extracts the inode number from a /proc/PID/ns/* symlink
// target of the form "net:[4026531840]". Returns 0 for any other shape
// rather than erroring — a namespace inode of 0 is not a valid kernel
// value, so callers can treat it as "unknown" the same as a read failure.
func parseNSInode(target string) uint64 {
	open := strings.IndexByte(target, '[')
	closeIdx := strings.LastIndexByte(target, ']')
	if open < 0 || closeIdx < 0 || closeIdx <= open+1 {
		return 0
	}
	n, err := strconv.ParseUint(target[open+1:closeIdx], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func parseUint64Hex(s string) uint64 {
	s = strings.TrimPrefix(s, "0x")
	n, _ := strconv.ParseUint(s, 16, 64)
	return n
}
