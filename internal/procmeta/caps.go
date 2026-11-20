//go:build linux

package procmeta

// capNames lists Linux capabilities in bit order, starting at bit 0. See
// <linux/capability.h>. Bits above 40 are reserved.
var capNames = []string{
	"CAP_CHOWN",              // 0
	"CAP_DAC_OVERRIDE",       // 1
	"CAP_DAC_READ_SEARCH",    // 2
	"CAP_FOWNER",             // 3
	"CAP_FSETID",             // 4
	"CAP_KILL",               // 5
	"CAP_SETGID",             // 6
	"CAP_SETUID",             // 7
	"CAP_SETPCAP",            // 8
	"CAP_LINUX_IMMUTABLE",    // 9
	"CAP_NET_BIND_SERVICE",   // 10
	"CAP_NET_BROADCAST",      // 11
	"CAP_NET_ADMIN",          // 12
	"CAP_NET_RAW",            // 13
	"CAP_IPC_LOCK",           // 14
	"CAP_IPC_OWNER",          // 15
	"CAP_SYS_MODULE",         // 16
	"CAP_SYS_RAWIO",          // 17
	"CAP_SYS_CHROOT",         // 18
	"CAP_SYS_PTRACE",         // 19
	"CAP_SYS_PACCT",          // 20
	"CAP_SYS_ADMIN",          // 21
	"CAP_SYS_BOOT",           // 22
	"CAP_SYS_NICE",           // 23
	"CAP_SYS_RESOURCE",       // 24
	"CAP_SYS_TIME",           // 25
	"CAP_SYS_TTY_CONFIG",     // 26
	"CAP_MKNOD",              // 27
	"CAP_LEASE",              // 28
	"CAP_AUDIT_WRITE",        // 29
	"CAP_AUDIT_CONTROL",      // 30
	"CAP_SETFCAP",            // 31
	"CAP_MAC_OVERRIDE",       // 32
	"CAP_MAC_ADMIN",          // 33
	"CAP_SYSLOG",             // 34
	"CAP_WAKE_ALARM",         // 35
	"CAP_BLOCK_SUSPEND",      // 36
	"CAP_AUDIT_READ",         // 37
	"CAP_PERFMON",            // 38
	"CAP_BPF",                // 39
	"CAP_CHECKPOINT_RESTORE", // 40
}

// Caps is the capability set. Only Eff is populated from /proc today; the
// other fields are parsed so a future consumer does not have to reopen the
// same file.
type Caps struct {
	Inh uint64 `json:"inh"`
	Prm uint64 `json:"prm"`
	Eff uint64 `json:"eff"`
	Bnd uint64 `json:"bnd"`
	Amb uint64 `json:"amb"`
}

// Has reports whether cap is present in the effective set. Names are
// matched exactly; an unknown name returns false.
func (c Caps) Has(cap string) bool {
	for i, name := range capNames {
		if name == cap {
			return c.Eff&(uint64(1)<<uint(i)) != 0
		}
	}
	return false
}

// HasAny reports whether any of the named capabilities is effective.
func (c Caps) HasAny(caps ...string) bool {
	for _, cap := range caps {
		if c.Has(cap) {
			return true
		}
	}
	return false
}

// Names returns the effective capabilities in bit order.
func (c Caps) Names() []string {
	var out []string
	for i, name := range capNames {
		if c.Eff&(uint64(1)<<uint(i)) != 0 {
			out = append(out, name)
		}
	}
	return out
}

// NetworkRelevant returns the subset of effective capabilities that most
// directly affect network behavior, in a stable order. This is the set
// worth surfacing on a network-observability dashboard.
func (c Caps) NetworkRelevant() []string {
	wanted := []string{
		"CAP_NET_ADMIN",
		"CAP_NET_RAW",
		"CAP_NET_BIND_SERVICE",
		"CAP_NET_BROADCAST",
		"CAP_BPF",
		"CAP_SYS_ADMIN",
		"CAP_SYS_MODULE",
		"CAP_SYS_PTRACE",
	}
	var out []string
	for _, name := range wanted {
		if c.Has(name) {
			out = append(out, name)
		}
	}
	return out
}
