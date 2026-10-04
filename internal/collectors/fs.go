// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package collectors

import (
	"errors"
	"path/filepath"
	"strings"
	"time"
)

// fsUsage is the result of statfs on one mount.
type fsUsage struct {
	BlockSize           uint64
	Blocks, Free, Avail uint64
	Inodes, InodesFree  uint64
}

// statfs is replaced in tests.
var statfs = platformStatfs

var realFS = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true,
	"vfat": true, "exfat": true, "f2fs": true, "jfs": true, "reiserfs": true, "ntfs": true,
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "ceph": true, "fuse.glusterfs": true,
}

// Filesystems reports space and inode usage from mountinfo plus statfs.
type Filesystems struct {
	fs   fsys
	root string
}

func (*Filesystems) Info() Info {
	return Info{Name: "diskspace", Family: "disk", Every: 10 * time.Second}
}

type mount struct {
	point, fstype, device string
}

func parseMountinfo(lines []string) []mount {
	var out []mount
	seen := map[string]bool{}
	for _, l := range lines {
		pre, post, ok := strings.Cut(l, " - ")
		if !ok {
			continue
		}
		a := strings.Fields(pre)
		b := strings.Fields(post)
		if len(a) < 5 || len(b) < 2 {
			continue
		}
		point := unescapeMount(a[4])
		if seen[point] {
			continue
		}
		seen[point] = true
		out = append(out, mount{point: point, fstype: b[0], device: b[1]})
	}
	return out
}

func unescapeMount(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}

func (f *Filesystems) Collect(_ time.Time, e *Emitter) error {
	lines, err := readLines(f.fs.procPath("1", "mountinfo"))
	if err != nil {
		lines, err = readLines(f.fs.procPath("self", "mountinfo"))
		if err != nil {
			return err
		}
	}
	var errs []error
	for _, m := range parseMountinfo(lines) {
		if !realFS[m.fstype] || strings.HasPrefix(m.point, "/var/lib/kubelet/pods/") || strings.Contains(m.point, "/containers/storage/overlay") {
			continue
		}
		u, err := statfs(filepath.Join(f.root, m.point))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if u.Blocks == 0 {
			continue
		}
		bs := float64(u.BlockSize)
		const gib = 1 << 30
		lbl := map[string]string{"mount_point": m.point, "filesystem": m.fstype, "device": m.device}
		sp := Chart{Context: "disk.space", ID: "disk_space_" + m.point, Family: "disk", Units: "GiB", Title: "Disk space usage", Type: "stacked", Labels: lbl}
		e.Gauge(sp, "avail", float64(u.Avail)*bs/gib)
		e.Gauge(sp, "used", float64(u.Blocks-u.Free)*bs/gib)
		e.Gauge(sp, "reserved_for_root", float64(u.Free-u.Avail)*bs/gib)
		usable := float64(u.Blocks - u.Free + u.Avail)
		if usable > 0 {
			e.Gauge(Chart{Context: "disk.space_utilization", ID: "disk_space_utilization_" + m.point, Family: "disk", Units: "%", Title: "Disk space utilization", Labels: lbl}, "used", float64(u.Blocks-u.Free)/usable*100)
		}
		if u.Inodes > 0 {
			in := Chart{Context: "disk.inodes", ID: "disk_inodes_" + m.point, Family: "disk", Units: "inodes", Title: "Disk inode usage", Type: "stacked", Labels: lbl}
			e.Gauge(in, "avail", float64(u.InodesFree))
			e.Gauge(in, "used", float64(u.Inodes-u.InodesFree))
			e.Gauge(Chart{Context: "disk.inodes_utilization", ID: "disk_inodes_utilization_" + m.point, Family: "disk", Units: "%", Title: "Disk inode utilization", Labels: lbl}, "used", float64(u.Inodes-u.InodesFree)/float64(u.Inodes)*100)
		}
	}
	if len(e.Samples()) == 0 && len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
