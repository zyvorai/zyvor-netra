// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const explainMaxBytes = 32 << 20

type explainOptions struct {
	Docker            string `json:"docker,omitempty"`
	dockerSocket      string
	cgroupID          uint64
	dockerDetails     *dockerEvidence
	Node              string        `json:"node,omitempty"`
	Namespace         string        `json:"namespace,omitempty"`
	Pod               string        `json:"pod,omitempty"`
	PID               uint          `json:"pid,omitempty"`
	Container         string        `json:"container,omitempty"`
	Destination       string        `json:"destination,omitempty"`
	DNS               string        `json:"dns,omitempty"`
	All               bool          `json:"all,omitempty"`
	Limit             int           `json:"limit"`
	MaxAge            time.Duration `json:"maxAgeNs"`
	input, format, ip string
	port              uint16
}

type explainIdentity struct {
	CgroupID    uint64 `json:"cgroupId"`
	Namespace   string `json:"namespace"`
	Pod         string `json:"pod"`
	PID         uint   `json:"pid"`
	ContainerID string `json:"containerId"`
}
type explainEvent struct {
	Type       string `json:"type"`
	Direction  string `json:"direction"`
	Protocol   string `json:"protocol"`
	SourceIP   string `json:"sourceIp"`
	SourcePort uint16 `json:"sourcePort"`
	DNSRcode   uint8  `json:"dnsRcode"`
	LatencyUS  uint32 `json:"latencyUs"`
	explainIdentity
	ObservedAt      time.Time `json:"observedAt"`
	DestinationIP   string    `json:"destinationIp"`
	DestinationPort uint16    `json:"destinationPort"`
	Action          string    `json:"action"`
	Reason          string    `json:"reason"`
	Hook            string    `json:"hook"`
	DNSQuery        string    `json:"dnsQuery"`
	Comm            string    `json:"comm"`
}
type explainTCP struct {
	explainIdentity
	RemoteIP           string `json:"remoteIp"`
	RemotePort         uint16 `json:"remotePort"`
	ActiveEstablished  uint64 `json:"activeEstablished"`
	PassiveEstablished uint64 `json:"passiveEstablished"`
	Retransmissions    uint64 `json:"retransmissions"`
	RTOs               uint64 `json:"rtos"`
	OwnershipStale     bool   `json:"ownershipStale"`
}
type explainDNS struct {
	CgroupID  uint64 `json:"cgroupId"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Name      string `json:"name"`
	Queries   uint64 `json:"queries"`
	Responses uint64 `json:"responses"`
	Failures  uint64 `json:"failures"`
}
type explainAgent struct {
	ICMP        []explainICMP       `json:"icmpErrors"`
	MissingMaps []string            `json:"missingMaps"`
	RateDrops   []explainNamedCount `json:"rateDrops"`
	Node        string              `json:"node"`
	Stale       bool                `json:"stale"`
	ObservedAt  time.Time           `json:"observedAt"`
	Events      []explainEvent      `json:"events"`
	TCP         []explainTCP        `json:"tcpHealth"`
	DNS         []explainDNS        `json:"dnsHealth"`
}
type explainFinding struct {
	Kind      string `json:"kind"`
	Node      string `json:"node"`
	Namespace string `json:"namespace,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Evidence  string `json:"evidence"`
	NextCheck string `json:"nextCheck"`
}
type explainReport struct {
	Docker           *dockerEvidence  `json:"docker,omitempty"`
	SchemaVersion    int              `json:"schemaVersion"`
	GeneratedAt      time.Time        `json:"generatedAt"`
	Scope            explainOptions   `json:"scope"`
	Status           string           `json:"status"`
	AgentsConsidered int              `json:"agentsConsidered"`
	AgentsExcluded   int              `json:"agentsExcluded"`
	Findings         []explainFinding `json:"findings"`
	FindingsTotal    int              `json:"findingsTotal"`
	Truncated        bool             `json:"truncated"`
	Limitations      []string         `json:"limitations"`
}

func parseExplain(args []string) (explainOptions, error) {
	o := explainOptions{}
	f := flag.NewFlagSet("explain", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&o.Docker, "docker", "", "exact local Docker container name or full ID; requires --node")
	f.StringVar(&o.dockerSocket, "docker-socket", "/var/run/docker.sock", "local Docker Unix socket")
	f.StringVar(&o.Node, "node", "", "exact node name")
	f.StringVar(&o.Namespace, "namespace", "", "exact namespace")
	f.StringVar(&o.Pod, "pod", "", "namespace/pod or pod with --namespace")
	f.UintVar(&o.PID, "pid", 0, "PID; requires --node")
	f.StringVar(&o.Container, "container", "", "exact reported container ID, not Docker name")
	f.StringVar(&o.Destination, "destination", "", "IP or IP:port; bracket IPv6 with a port")
	f.StringVar(&o.DNS, "dns", "", "exact observed DNS query name")
	f.BoolVar(&o.All, "all", false, "explicitly examine every reporting node")
	f.StringVar(&o.input, "input", "", "saved /api/v1/agents JSON; - for stdin")
	f.StringVar(&o.format, "format", "text", "text or json")
	f.IntVar(&o.Limit, "limit", 50, "maximum findings (1-1000)")
	f.DurationVar(&o.MaxAge, "max-age", 2*time.Minute, "maximum agent report age")
	if err := f.Parse(args); err != nil {
		return o, err
	}
	if f.NArg() != 0 {
		return o, fmt.Errorf("unexpected positional arguments")
	}
	if o.format != "text" && o.format != "json" {
		return o, fmt.Errorf("--format must be text or json")
	}
	if o.Limit < 1 || o.Limit > 1000 {
		return o, fmt.Errorf("--limit must be 1-1000")
	}
	if o.MaxAge <= 0 || o.MaxAge > 24*time.Hour {
		return o, fmt.Errorf("--max-age must be greater than zero and at most 24h")
	}
	for _, v := range []string{o.Docker, o.dockerSocket, o.Node, o.Namespace, o.Pod, o.Container, o.Destination, o.DNS} {
		if strings.TrimSpace(v) != v || strings.ContainsAny(v, "\r\n\t\x00") {
			return o, fmt.Errorf("selectors must not contain surrounding whitespace or control characters")
		}
	}
	if strings.Contains(o.Pod, "/") {
		p := strings.Split(o.Pod, "/")
		if len(p) != 2 || p[0] == "" || p[1] == "" {
			return o, fmt.Errorf("--pod must be namespace/name")
		}
		if o.Namespace != "" && o.Namespace != p[0] {
			return o, fmt.Errorf("--namespace conflicts with --pod")
		}
		o.Namespace, o.Pod = p[0], p[1]
	}
	if o.Pod != "" && o.Namespace == "" {
		return o, fmt.Errorf("--pod requires namespace/name or --namespace")
	}
	if o.PID > 0 && (o.Node == "" || uint64(o.PID) > 4294967295) {
		return o, fmt.Errorf("--pid requires --node and a 32-bit PID")
	}
	pidSet := false
	f.Visit(func(fl *flag.Flag) {
		if fl.Name == "pid" {
			pidSet = true
		}
	})
	if pidSet && o.PID == 0 {
		return o, fmt.Errorf("--pid must be greater than zero")
	}
	if o.Docker != "" {
		if !dockerNamePattern.MatchString(o.Docker) {
			return o, fmt.Errorf("--docker requires an exact container name or full ID")
		}
		if o.Node == "" {
			return o, fmt.Errorf("--docker requires --node matching the Netra agent on this Docker host")
		}
		if o.PID != 0 || o.Container != "" || o.Pod != "" || o.Namespace != "" || o.All || o.input != "" {
			return o, fmt.Errorf("--docker cannot be combined with PID, container, Kubernetes, all, or offline input selectors")
		}
		if _, err := dockerClient(o.dockerSocket); err != nil {
			return o, err
		}
	} else {
		socketSet := false
		f.Visit(func(fl *flag.Flag) {
			if fl.Name == "docker-socket" {
				socketSet = true
			}
		})
		if socketSet {
			return o, fmt.Errorf("--docker-socket requires --docker")
		}
	}
	if o.Destination != "" {
		host := o.Destination
		if a, e := netip.ParseAddr(host); e == nil {
			o.ip = a.Unmap().String()
		} else {
			h, p, e := net.SplitHostPort(host)
			if e != nil {
				return o, fmt.Errorf("--destination requires an IP or IP:port; use --dns for observed names")
			}
			a, e := netip.ParseAddr(h)
			if e != nil {
				return o, fmt.Errorf("destination host must be a literal IP; no DNS lookup is performed")
			}
			n, e := strconv.ParseUint(p, 10, 16)
			if e != nil || n == 0 {
				return o, fmt.Errorf("destination port must be 1-65535")
			}
			o.ip, o.port = a.Unmap().String(), uint16(n)
		}
	}
	if o.DNS != "" {
		o.DNS = strings.TrimSuffix(strings.ToLower(o.DNS), ".")
		if o.DNS == "" {
			return o, fmt.Errorf("DNS name must not be empty")
		}
		if o.Destination != "" || o.PID != 0 || o.Container != "" {
			return o, fmt.Errorf("--dns supports node/namespace/pod scope only; DNS counters cannot prove PID, container or destination-IP attribution")
		}
	}
	if !o.All && o.Node == "" && o.Namespace == "" && o.Pod == "" && o.PID == 0 && o.Container == "" && o.Destination == "" && o.DNS == "" {
		return o, fmt.Errorf("provide a selector or explicitly use --all")
	}
	return o, nil
}

func readExplain(r io.Reader) ([]explainAgent, error) {
	b, e := io.ReadAll(io.LimitReader(r, explainMaxBytes+1))
	if e != nil {
		return nil, e
	}
	if len(b) > explainMaxBytes {
		return nil, fmt.Errorf("agent report exceeds 32 MiB")
	}
	var envelope struct {
		Items *[]explainAgent `json:"items"`
	}
	if e = json.Unmarshal(b, &envelope); e != nil {
		return nil, fmt.Errorf("decode agent report: %w", e)
	}
	if envelope.Items == nil {
		return nil, fmt.Errorf("expected an object containing an items array from /api/v1/agents")
	}
	return *envelope.Items, nil
}

func fetchExplain(client *http.Client, endpoint string) ([]explainAgent, error) {
	req, e := http.NewRequest(http.MethodGet, endpoint+"/api/v1/agents", nil)
	if e != nil {
		return nil, e
	}
	auth(req)
	res, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent reports: HTTP %d %s", res.StatusCode, http.StatusText(res.StatusCode))
	}
	return readExplain(res.Body)
}

func (o explainOptions) identity(i explainIdentity) bool {
	return (o.cgroupID == 0 || o.cgroupID == i.CgroupID) && (o.dockerDetails == nil || i.ContainerID == "" || i.ContainerID == o.dockerDetails.ID) && (o.Namespace == "" || o.Namespace == i.Namespace) && (o.Pod == "" || o.Pod == i.Pod) && (o.PID == 0 || o.PID == i.PID) && (o.Container == "" || o.Container == i.ContainerID)
}
func (o explainOptions) destination(ip string, port uint16) bool {
	if o.ip == "" {
		return true
	}
	a, e := netip.ParseAddr(ip)
	return e == nil && a.Unmap().String() == o.ip && (o.port == 0 || o.port == port)
}
func buildExplain(agents []explainAgent, o explainOptions, now time.Time) explainReport {
	r := explainReport{SchemaVersion: 1, Docker: o.dockerDetails, GeneratedAt: now.UTC(), Scope: o, Status: "no-matching-evidence", Findings: []explainFinding{}, Limitations: []string{
		"Evidence is sampled or aggregated from agent reports; missing evidence does not prove no traffic or a healthy connection.",
		"TCP/DNS counters are cumulative snapshots, not measurements for a selected time window. Event timestamps are agent observation times.",
		"A passed/observed event does not prove end-to-end delivery. Events lack a stable historical winning rule ID and policy generation.",
		"ICMP errors are cumulative TC observations by node/interface/direction; one packet may be seen at multiple interfaces. No workload or quoted-flow attribution is inferred. Missing ICMP data can mean an older agent, unattached TC hooks, or no observed errors. Fragmented ICMP errors are excluded.",
		"DNS response findings use reported matched UDP/53 events and the four-bit base-header RCODE only. EDNS extended errors, answer records, TCP DNS, DoH, and DoT are not inferred. Event latency is the reported query-response interval, not resolver execution time.",
		"bpf-maps-missing reports an agent's BPF object load state, not a specific dropped connection; it appears only at node-wide or --all scope.",
		"Rate-drop findings are cumulative PPS-ceiling drop counters by destination IP since the map was created; they do not identify which flows or ports were affected.",
		"No active probes, DNS resolution, policy changes, or packet payload collection are performed.",
	}}
	if o.dockerDetails != nil {
		r.Limitations = append(r.Limitations, "Docker scope matches the inspected init process cgroup on the explicitly selected node. Nested child cgroups are not included. Node-to-host mapping is operator supplied.", "Inspection and cgroup identity are rechecked after fetching reports. Cached counters and buffered events cannot prove container-incarnation identity; current connectivity is not inferred.")
	}
	if o.PID != 0 {
		r.Limitations = append(r.Limitations, "PID events may describe an earlier process incarnation; DNS counters lack PID attribution and are excluded.")
	}
	if o.Container != "" {
		r.Limitations = append(r.Limitations, "Container selection uses exact reported IDs; Docker names are not resolved. DNS counters lack container identity and are excluded.")
	}
	if o.Destination != "" {
		r.Limitations = append(r.Limitations, "Destination matches packet destination for events and remote peer for TCP health. DNS counters are excluded because they do not identify the destination IP.")
	}
	if o.DNS != "" {
		r.Limitations = append(r.Limitations, "DNS evidence covers reported cleartext DNS only; no hostname-to-IP or DNS-to-TCP correlation is inferred.")
	}
	add := func(kind, node string, i explainIdentity, evidence, next string) {
		r.FindingsTotal++
		if len(r.Findings) < o.Limit {
			r.Findings = append(r.Findings, explainFinding{kind, node, i.Namespace, i.Pod, evidence, next})
		}
	}
	// Sort a copy so output ordering never depends on map iteration at the controller.
	agents = append([]explainAgent(nil), agents...)
	sort.SliceStable(agents, func(i, j int) bool { return agents[i].Node < agents[j].Node })
	for _, a := range agents {
		if o.Node != "" && a.Node != o.Node {
			continue
		}
		r.AgentsConsidered++
		if (o.dockerDetails != nil && a.ObservedAt.Before(o.dockerDetails.StartedAt)) || a.Node == "" || a.Stale || a.ObservedAt.IsZero() || now.Sub(a.ObservedAt) > o.MaxAge || a.ObservedAt.After(now.Add(time.Minute)) {
			r.AgentsExcluded++
			continue
		}
		if o.includesNodeICMP() {
			for _, e := range a.ICMP {
				kind, evidence, next := icmpFinding(e)
				if kind != "" {
					add(kind, a.Node, explainIdentity{}, evidence, next)
				}
			}
			if kind, evidence, next := bpfMapsMissingFinding(a.MissingMaps); kind != "" {
				add(kind, a.Node, explainIdentity{}, evidence, next)
			}
		}
		if o.includesRateDrops() {
			for _, d := range a.RateDrops {
				if !o.destination(d.Name, 0) {
					continue
				}
				if kind, evidence, next := rateDropFinding(d); kind != "" {
					add(kind, a.Node, explainIdentity{}, evidence, next)
				}
			}
		}
		for _, e := range a.Events {
			if !o.identity(e.explainIdentity) || !o.destination(e.DestinationIP, e.DestinationPort) {
				continue
			}
			if o.DNS != "" && strings.TrimSuffix(strings.ToLower(e.DNSQuery), ".") != o.DNS {
				continue
			}
			if kind, evidence, next := dnsResponseFinding(e); kind != "" {
				add(kind, a.Node, e.explainIdentity, evidence, next)
				continue
			}
			kind, next := "network-event", "Inspect peer availability and application logs; this event alone cannot establish delivery."
			if e.Action == "blocked" {
				kind, next = "observed-block", "Review Netra policy and its revision history; the reason does not identify a historical rule ID."
			}
			add(kind, a.Node, e.explainIdentity, fmt.Sprintf("action=%q reason=%q hook=%q destination=%q port=%d process=%q pid=%d observedAt=%q", e.Action, e.Reason, e.Hook, e.DestinationIP, e.DestinationPort, e.Comm, e.PID, e.ObservedAt.Format(time.RFC3339Nano)), next)
		}
		if o.DNS == "" {
			for _, t := range a.TCP {
				if !o.identity(t.explainIdentity) || !o.destination(t.RemoteIP, t.RemotePort) || (o.PID != 0 && t.OwnershipStale) {
					continue
				}
				if t.ActiveEstablished > 0 || t.PassiveEstablished > 0 {
					add("tcp-established", a.Node, t.explainIdentity, fmt.Sprintf("remote=%q port=%d active-established=%d passive-established=%d", t.RemoteIP, t.RemotePort, t.ActiveEstablished, t.PassiveEstablished), "TCP established at least once in these counters; check current application health separately.")
				}
				if t.Retransmissions > 0 || t.RTOs > 0 {
					add("tcp-loss-signal", a.Node, t.explainIdentity, fmt.Sprintf("remote=%q port=%d retransmissions=%d retransmission-timeouts=%d", t.RemoteIP, t.RemotePort, t.Retransmissions, t.RTOs), "Check path loss, congestion and peer response; these counters do not prove a firewall caused a timeout.")
				}
			}
		}
		if o.PID == 0 && o.Container == "" && o.Destination == "" {
			for _, d := range a.DNS {
				id := explainIdentity{Namespace: d.Namespace, Pod: d.Pod, CgroupID: d.CgroupID}
				if !o.identity(id) {
					continue
				}
				if o.DNS != "" && strings.TrimSuffix(strings.ToLower(d.Name), ".") != o.DNS {
					continue
				}
				if d.Queries == 0 && d.Responses == 0 && d.Failures == 0 {
					continue
				}
				next := "Inspect resolver reachability and application DNS behavior. Unmatched queries do not establish timeouts."
				if d.Failures > 0 {
					next = "Inspect DNS response codes and resolver logs; reported failures are not proof of packet loss."
				}
				add("dns-counters", a.Node, id, fmt.Sprintf("name=%q queries=%d matched-responses=%d failures=%d", d.Name, d.Queries, d.Responses, d.Failures), next)
			}
		}
	}
	if r.FindingsTotal > 0 {
		r.Status = "evidence-found"
	}
	r.Truncated = r.FindingsTotal > len(r.Findings)
	if r.AgentsExcluded > 0 {
		r.Limitations = append(r.Limitations, fmt.Sprintf("Excluded %d reports marked stale, too old, missing node/time, predating Docker start, or more than one minute in the future.", r.AgentsExcluded))
	}
	return r
}

func writeExplain(w io.Writer, r explainReport, format string) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	if _, e := fmt.Fprintf(w, "Netra connection explanation: %s\nAgents considered: %d; excluded: %d\nFindings: %d (showing %d)\n", r.Status, r.AgentsConsidered, r.AgentsExcluded, r.FindingsTotal, len(r.Findings)); e != nil {
		return e
	}
	if r.Docker != nil {
		if _, e := fmt.Fprintf(w, "Docker container: %q id=%q init-pid=%d cgroup=%s node=%q\n", r.Docker.Name, r.Docker.ID, r.Docker.PID, r.Docker.CgroupID, r.Docker.Node); e != nil {
			return e
		}
	}
	for _, f := range r.Findings {
		if _, e := fmt.Fprintf(w, "\n[%s] node=%q workload=%q\n  %s\n  Next: %s\n", f.Kind, f.Node, f.Namespace+"/"+f.Pod, f.Evidence, f.NextCheck); e != nil {
			return e
		}
	}
	if r.FindingsTotal == 0 {
		if _, e := fmt.Fprintln(w, "\nNo matching evidence. Check selectors, agent freshness, hook coverage, and whether the application attempted a connection."); e != nil {
			return e
		}
	}
	if r.Truncated {
		if _, e := fmt.Fprintln(w, "\nOutput truncated; narrow the scope or increase --limit."); e != nil {
			return e
		}
	}
	for _, s := range r.Limitations {
		if _, e := fmt.Fprintln(w, "Note:", s); e != nil {
			return e
		}
	}
	return nil
}
func explainCmd(args []string, w io.Writer) error {
	o, e := parseExplain(args)
	if e == flag.ErrHelp {
		_, e = fmt.Fprintln(w, "netractl explain --docker NAME --node NODE [--docker-socket PATH] | --pod NS/NAME | --node NODE --pid PID | --container EXACT_ID | --destination IP[:PORT] | --dns NAME | --all [--input FILE|-] [--format text|json] [--max-age 2m] [--limit 50]")
		return e
	}
	if e != nil {
		return e
	}
	var agents []explainAgent
	if o.Docker != "" {
		client, err := dockerClient(o.dockerSocket)
		if err != nil {
			return err
		}
		defer client.CloseIdleConnections()
		agents, o, e = collectDocker(o, client, localDockerCgroup, func() ([]explainAgent, error) {
			apiClient := httpClient(20 * time.Second)
			apiClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			return fetchExplain(apiClient, base)
		})
	} else if o.input != "" {
		if o.input == "-" {
			agents, e = readExplain(os.Stdin)
		} else {
			var f *os.File
			f, e = os.Open(o.input)
			if e == nil {
				defer f.Close()
				agents, e = readExplain(f)
			}
		}
	} else {
		client := httpClient(20 * time.Second)
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		agents, e = fetchExplain(client, base)
	}
	if e != nil {
		return e
	}
	return writeExplain(w, buildExplain(agents, o, time.Now()), o.format)
}
