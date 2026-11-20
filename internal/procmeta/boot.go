//go:build linux

package procmeta

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

// BootTime returns the host boot time, read once from /proc/stat. Cache
// the result; it does not change while the host is up. Used with
// Identity.WallClock to convert a process start jiffies value to an
// absolute wall-clock time.
func BootTime() (time.Time, error) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "btime ") {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(line[len("btime "):]), 10, 64)
		if err != nil {
			return time.Time{}, err
		}
		return time.Unix(n, 0), nil
	}
	return time.Time{}, errors.New("procmeta: btime not found in /proc/stat")
}
