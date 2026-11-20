// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package sslprobe

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Lib is one distinct libssl file mapped by some process.
type Lib struct {
	// Key identifies the file (device and inode), so the same library seen through
	// many processes and container mount namespaces is attached once: a uprobe is
	// registered on the inode and applies to every process that maps it.
	Key string
	// Path is a host-visible path to the file, through the first process seen
	// mapping it (/proc/<pid>/root/<path>), so a library inside a container image
	// can be opened from the host.
	Path string
	// MapsPath is the path as that process sees it.
	MapsPath string
	PID      int
}

// Discover scans procRoot (normally /proc) for processes that map libssl and
// returns each distinct file once. It needs the host's /proc: inside a container
// that is the host PID namespace (Kubernetes hostPID).
func Discover(procRoot string) []Lib {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	seen := map[string]Lib{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		f, err := os.Open(filepath.Join(procRoot, e.Name(), "maps"))
		if err != nil {
			continue // the process exited, or is not readable
		}
		for _, l := range parseMaps(f, procRoot, pid) {
			if _, dup := seen[l.Key]; !dup {
				seen[l.Key] = l
			}
		}
		f.Close()
	}
	out := make([]Lib, 0, len(seen))
	for _, l := range seen {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// parseMaps reads /proc/<pid>/maps lines ("addr perms offset dev inode path") and
// returns the libssl files in them.
func parseMaps(f *os.File, procRoot string, pid int) []Lib {
	var out []Lib
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		// The path is everything after the inode: it may contain spaces, and a file
		// replaced on disk carries a trailing " (deleted)" that is a separate field.
		path := strings.Join(fields[5:], " ")
		if strings.HasSuffix(path, " (deleted)") || fields[4] == "0" || !isLibSSL(path) {
			continue
		}
		key := fields[3] + ":" + fields[4]
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Lib{
			Key: key, MapsPath: path, PID: pid,
			Path: filepath.Join(procRoot, strconv.Itoa(pid), "root", path),
		})
	}
	return out
}

// isLibSSL matches libssl.so, libssl.so.3, libssl.so.1.1, and versioned variants
// but not lookalikes such as libsslcrypto or libssl_foo.
func isLibSSL(path string) bool {
	base := filepath.Base(path)
	return base == "libssl.so" || strings.HasPrefix(base, "libssl.so.")
}
