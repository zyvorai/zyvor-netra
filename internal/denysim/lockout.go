// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package denysim

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Severities of a LockoutWarning.
const (
	LockoutCritical = "critical" // the proposal reaches a path the operator needs to undo it
	LockoutCaution  = "warning"  // reaches a protected path only for a scoped workload, or only possibly
)

// Risk summarises the lockout check on a Result.
const (
	RiskNoneDetected = "none-detected"
	RiskPossible     = "possible"
	RiskLikely       = "likely"
)

// LockoutCaveat is fixed on every lockout section. A clean check is absence of
// evidence: the protected list is what this controller can see, not a map of
// every dependency the cluster has.
const LockoutCaveat = "Lockout check compares the proposal with the controller's own view of its control paths (kube-apiserver, DNS resolvers, the controller listen port, and NETRA_PROTECTED_DESTINATIONS). It cannot see node-local resolvers, cloud metadata or paths the controller does not know about, so risk 'none-detected' is not a guarantee. Enforce stays leased and fails open to observe when the lease expires."

// Protected is one destination (or process, or DNS name) whose loss would cut
// the operator off from the cluster or from Netra itself.
type Protected struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`  // ip, cidr, port, dns, process
	Value    string `json:"value"` // address, prefix, port number, name or comm
	Port     uint16 `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"` // TCP, UDP or empty for any
}

// LockoutWarning is one way the proposal reaches a protected path.
type LockoutWarning struct {
	Protected string `json:"protected"`
	Severity  string `json:"severity"`
	Reason    string `json:"reason"`
}

// Lockout is the self-lockout section of a deny preview.
type Lockout struct {
	Risk     string           `json:"risk"`
	Warnings []LockoutWarning `json:"warnings"`
	Checked  []string         `json:"checked"`
	Caveat   string           `json:"caveat"`
}

// ParseProtected reads operator entries from NETRA_PROTECTED_DESTINATIONS: a
// comma- or space-separated list of IP, CIDR, IP:port, [v6]:port, :port, name
// (DNS) or process:comm. Invalid entries are returned as errors so a typo is
// not silently ignored.
func ParseProtected(raw string) ([]Protected, error) {
	var out []Protected
	for _, tok := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		p, err := parseProtectedToken(tok)
		if err != nil {
			return nil, fmt.Errorf("protected destination %q: %w", tok, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func parseProtectedToken(tok string) (Protected, error) {
	if len(tok) > 255 {
		return Protected{}, fmt.Errorf("too long")
	}
	if rest, ok := strings.CutPrefix(tok, "process:"); ok {
		if rest == "" {
			return Protected{}, fmt.Errorf("process name is empty")
		}
		return Protected{Name: tok, Kind: KindProcess, Value: strings.ToLower(rest)}, nil
	}
	if strings.HasPrefix(tok, ":") {
		n, err := strconv.ParseUint(tok[1:], 10, 16)
		if err != nil || n == 0 {
			return Protected{}, fmt.Errorf("port must be 1-65535")
		}
		return Protected{Name: tok, Kind: KindPort, Value: tok[1:], Port: uint16(n)}, nil
	}
	if pfx, err := netip.ParsePrefix(tok); err == nil {
		return Protected{Name: tok, Kind: KindCIDR, Value: pfx.Masked().String()}, nil
	}
	if a, err := netip.ParseAddr(tok); err == nil {
		return Protected{Name: tok, Kind: KindIP, Value: a.String()}, nil
	}
	if ap, err := netip.ParseAddrPort(tok); err == nil {
		return Protected{Name: tok, Kind: KindIP, Value: ap.Addr().String(), Port: ap.Port()}, nil
	}
	if !validName(tok) {
		return Protected{}, fmt.Errorf("not an IP, CIDR, IP:port, :port, process:comm or DNS name")
	}
	return Protected{Name: tok, Kind: KindDNS, Value: strings.ToLower(strings.TrimSuffix(tok, "."))}, nil
}

func validName(s string) bool {
	if s == "" || strings.ContainsAny(s, " /\\:@") {
		return false
	}
	for _, r := range s {
		if !(r == '.' || r == '-' || r == '_' || r == '*' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}

// BuiltinProtected derives the controller's own control paths. getenv and
// resolvConf are injected so the function is pure: resolvConf is the text of
// /etc/resolv.conf (may be empty), listen is NETRA_LISTEN (":30870").
func BuiltinProtected(getenv func(string) string, resolvConf, listen string) []Protected {
	out := []Protected{{Name: "dns (any resolver)", Kind: KindPort, Value: "53", Port: 53}}
	if host := strings.TrimSpace(getenv("KUBERNETES_SERVICE_HOST")); host != "" {
		port := uint16(443)
		if n, err := strconv.ParseUint(strings.TrimSpace(getenv("KUBERNETES_SERVICE_PORT")), 10, 16); err == nil && n > 0 {
			port = uint16(n)
		}
		if a, err := netip.ParseAddr(host); err == nil {
			out = append(out, Protected{Name: "kube-apiserver", Kind: KindIP, Value: a.String(), Port: port, Protocol: "TCP"})
		}
	}
	sc := bufio.NewScanner(strings.NewReader(resolvConf))
	seen := 0
	for sc.Scan() && seen < 8 {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(f[1]); err == nil {
				out = append(out, Protected{Name: "dns resolver " + a.String(), Kind: KindIP, Value: a.String(), Port: 53})
				seen++
			}
		}
	}
	if _, p, err := net.SplitHostPort(strings.TrimSpace(listen)); err == nil {
		if n, err := strconv.ParseUint(p, 10, 16); err == nil && n > 0 {
			out = append(out, Protected{Name: "netra controller listen port", Kind: KindPort, Value: p, Port: uint16(n), Protocol: "TCP"})
		}
	}
	return out
}

// CheckLockout compares a proposal with a protected list. The proposal is
// validated the same way Preview does, so hostile input returns an error.
func CheckLockout(p Proposal, protected []Protected) (Lockout, error) {
	p, err := p.normalize()
	if err != nil {
		return Lockout{}, err
	}
	lo := Lockout{Risk: RiskNoneDetected, Warnings: []LockoutWarning{}, Checked: make([]string, 0, len(protected)), Caveat: LockoutCaveat}
	scoped := p.Namespace != "" || p.Pod != "" || p.WorkloadName != ""
	add := func(name, reason string, critical bool) {
		sev := LockoutCritical
		if !critical || scoped {
			sev = LockoutCaution
			if scoped && critical {
				reason += " (scoped to one workload, so only that workload loses it)"
			}
		}
		lo.Warnings = append(lo.Warnings, LockoutWarning{Protected: name, Severity: sev, Reason: reason})
	}

	// A catch-all prefix reaches everything, protected list or not.
	if p.Kind == KindCIDR {
		if pfx, err := netip.ParsePrefix(p.Value); err == nil && pfx.Bits() == 0 {
			add("all destinations", "the proposal covers every address, including the kube-apiserver, DNS and the controller", true)
		}
	}
	for _, pr := range protected {
		lo.Checked = append(lo.Checked, pr.Name)
		if reason, hit := proposalReaches(p, pr); hit {
			add(pr.Name, reason, true)
		}
	}
	for _, w := range lo.Warnings {
		if w.Severity == LockoutCritical {
			lo.Risk = RiskLikely
			break
		}
		lo.Risk = RiskPossible
	}
	return lo, nil
}

func protoOK(a, b string) bool {
	return a == "" || b == "" || strings.EqualFold(a, "ANY") || strings.EqualFold(b, "ANY") || strings.EqualFold(a, b)
}

func proposalReaches(p Proposal, pr Protected) (string, bool) {
	switch p.Kind {
	case KindIP, KindCIDR:
		if pr.Kind != KindIP && pr.Kind != KindCIDR {
			return "", false
		}
		if !addrsOverlap(p.Value, pr.Value) {
			return "", false
		}
		// A port-qualified proposal only reaches a port-qualified target on that port.
		if p.Port != 0 && pr.Port != 0 && p.Port != pr.Port {
			return "", false
		}
		if !protoOK(p.Protocol, pr.Protocol) {
			return "", false
		}
		return fmt.Sprintf("%s %s overlaps %s", p.Kind, p.Value, pr.Name), true
	case KindPort:
		if pr.Port == 0 || pr.Port != p.Port || !protoOK(p.Protocol, pr.Protocol) {
			return "", false
		}
		return fmt.Sprintf("port %d is used by %s", p.Port, pr.Name), true
	case KindDNS, KindSNI:
		if pr.Kind != KindDNS {
			return "", false
		}
		if nameMatch(p.Value, pr.Value) {
			return fmt.Sprintf("%s name %s matches %s", p.Kind, p.Value, pr.Name), true
		}
	case KindProcess:
		if pr.Kind == KindProcess && p.Value == pr.Value {
			return fmt.Sprintf("process %s is protected (%s)", p.Value, pr.Name), true
		}
	}
	return "", false
}

func nameMatch(a, b string) bool {
	a, b = strings.TrimSuffix(strings.ToLower(a), "."), strings.TrimSuffix(strings.ToLower(b), ".")
	if a == b {
		return true
	}
	if rest, ok := strings.CutPrefix(a, "*."); ok {
		return strings.HasSuffix(b, "."+rest)
	}
	if rest, ok := strings.CutPrefix(b, "*."); ok {
		return strings.HasSuffix(a, "."+rest)
	}
	return false
}

func toPrefix(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func addrsOverlap(a, b string) bool {
	pa, ok1 := toPrefix(a)
	pb, ok2 := toPrefix(b)
	if !ok1 || !ok2 {
		return false
	}
	return pa.Overlaps(pb)
}
