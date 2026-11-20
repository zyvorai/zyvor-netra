//go:build linux

package procmeta

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// QoS classes, matching the Kubernetes naming used in cgroup paths.
const (
	QoSGuaranteed = "guaranteed"
	QoSBurstable  = "burstable"
	QoSBestEffort = "besteffort"
)

// CgroupInfo is the subset of /proc/PID/cgroup that identifies the
// workload a process belongs to. Namespace, owner, and labels are not
// here: resolving those requires a Kubernetes API call and belongs in the
// caller, not in a /proc reader (see internal/cgroupmeta, internal/workload
// for how this codebase already does that join for eBPF-observed cgroup
// IDs).
type CgroupInfo struct {
	// Raw is the full cgroup v2 path, e.g.
	// "/kubepods.slice/kubepods-burstable.slice/...". Always populated
	// when the process is in a cgroup.
	Raw string `json:"raw"`

	// PodUID is the Kubernetes pod UID, or empty if the path is not a
	// kubepods path. The value uses hyphens, not the underscores systemd
	// uses in path escaping.
	PodUID string `json:"podUid,omitempty"`

	// ContainerID is the 64-hex container ID, or empty if the path has no
	// recognizable container scope.
	ContainerID string `json:"containerId,omitempty"`

	// QoSClass is "guaranteed", "burstable", "besteffort", or empty.
	QoSClass string `json:"qosClass,omitempty"`
}

// regexes for /proc/PID/cgroup v2 kubepods paths.
//
// Observed shapes:
//
//	systemd + containerd:
//	  0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<UID>.slice/cri-containerd-<CID>.scope
//	systemd + cri-o:
//	  0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod<UID>.slice/crio-<CID>.scope
//	legacy docker:
//	  0::/kubepods/burstable/pod<UID>/<CID>
//	best-effort without runtime prefix:
//	  0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod<UID>.slice/<CID>
//
// The UID in a systemd path has dashes escaped to underscores. The UID in
// a non-systemd path keeps the dashes.
var (
	rePodUIDSystemd = regexp.MustCompile(
		`kubepods-(guaranteed|burstable|besteffort)-pod([0-9a-f]{8}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{12})`,
	)
	rePodUIDPlain = regexp.MustCompile(
		`(?:^|/)kubepods/(guaranteed|burstable|besteffort)/pod([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`,
	)
	reContainerID = regexp.MustCompile(
		`(?:cri-containerd|crio|docker|cri-dockerd)-([0-9a-f]{64})\.scope$|/([0-9a-f]{64})$`,
	)
)

// ErrNoCgroup is returned when /proc/PID/cgroup cannot be read or contains
// no v2 line.
var ErrNoCgroup = errors.New("procmeta: no cgroup v2 entry")

// ReadCgroup reads and parses /proc/PID/cgroup. Only the cgroup v2 unified
// hierarchy ("0::") is considered. On a v1-only host this returns
// ErrNoCgroup; callers should treat that as "unknown", not as a failure.
func ReadCgroup(pid int) (*CgroupInfo, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoProcess
		}
		return nil, err
	}
	return parseCgroup(b)
}

// parseCgroup parses the contents of /proc/PID/cgroup.
func parseCgroup(b []byte) (*CgroupInfo, error) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	// /proc/PID/cgroup lines are short, but the path can be long on a
	// deeply nested systemd host. 64 KiB is generous.
	sc.Buffer(make([]byte, 0, 4096), 64*1024)

	for sc.Scan() {
		line := sc.Text()
		// v2 unified hierarchy line is exactly "0::<path>".
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		path := strings.TrimPrefix(line, "0::")
		return parseCgroupPath(path), nil
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, ErrNoCgroup
}

// parseCgroupPath extracts identifiers from a v2 cgroup path. It never
// fails: an unrecognized path yields a CgroupInfo with only Raw set.
func parseCgroupPath(path string) *CgroupInfo {
	info := &CgroupInfo{Raw: path}

	if m := rePodUIDSystemd.FindStringSubmatch(path); m != nil {
		info.QoSClass = m[1]
		info.PodUID = strings.ReplaceAll(m[2], "_", "-")
	} else if m := rePodUIDPlain.FindStringSubmatch(path); m != nil {
		info.QoSClass = m[1]
		info.PodUID = m[2]
	} else {
		return info
	}

	if m := reContainerID.FindStringSubmatch(path); m != nil {
		if m[1] != "" {
			info.ContainerID = m[1]
		} else {
			info.ContainerID = m[2]
		}
	}
	return info
}

// IsKubernetes reports whether the process is inside a kubepods cgroup. A
// nil receiver returns false.
func (c *CgroupInfo) IsKubernetes() bool {
	return c != nil && c.PodUID != ""
}
