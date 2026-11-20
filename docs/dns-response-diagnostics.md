# DNS response diagnostics

Netra now explains the response codes already captured by its native eBPF DNS
query/response tracking. Open **Health → DNS response diagnostics**, use the
browser's **Explain** page, or run:

```bash
netractl explain --pod production/api --dns api.example.com
netractl explain --node worker-1 --docker api --dns api.example.com
netractl explain --node worker-1 --format json
```

| Base response code | Finding | Next investigation |
| --- | --- | --- |
| 0 NOERROR | `dns-response` | Check answer records and application connectivity separately |
| 1 FORMERR | `dns-response-error` | Client request encoding and resolver compatibility |
| 2 SERVFAIL | `dns-response-error` | Resolver/upstream logs, DNSSEC validation, authoritative reachability |
| 3 NXDOMAIN | `dns-response-error` | Spelling, search domains, Kubernetes namespace qualification, records |
| 4 NOTIMP | `dns-response-error` | Whether the resolver supports the requested DNS operation |
| 5 REFUSED | `dns-response-error` | Resolver access controls and recursion policy |
| 6–15 | `dns-response-error` | Numeric code and resolver logs; no specific cause inferred |

Findings include the reported query, resolver source IP, base response code,
query-response latency in microseconds, and event observation timestamp. They
replace the generic network-event finding for the same response, so the response
is not counted twice in Explain. Existing DNS aggregate counters are still shown
separately and are not a count of these sampled event findings.

Only `dns-response` events marked observed, UDP, cgroup ingress, and source port
53 qualify. Query events, blocked packets, TCP DNS, and unrelated named events
are not classified as response errors. Explain retains its existing AND selectors,
agent freshness rules, and Docker cgroup identity checks. Destination selection
continues to match the packet destination: on a DNS response that is the client,
not the resolver. Use `--dns` to select the queried name.

The Health panel shows at most the 50 latest error responses with both report and
event observation timestamps inside the two-minute freshness window (and the
existing one-minute clock-skew allowance). It discloses truncation and does not
turn sampled or missing events into a failure rate or confirmed timeout.

This uses the existing event ABI and API. No new eBPF map, parser, probe, policy
mutation, or collection privilege is introduced. Only the four-bit base-header
RCODE is available. EDNS extended errors, answers, DNSSEC results, TCP DNS, DoH,
and DoT are not inferred. NOERROR does not prove an answer record exists. Reported
latency is the matched query-response interval, not resolver execution time;
observation timestamps are the agent's event-read timestamps. Buffered events may
represent earlier traffic. Missing evidence never establishes healthy DNS.

ICMP findings also now show the interface name when the agent's current host
lookup succeeds. The original index is always retained; a current name does not
prove the same interface held the index when an older observation was recorded.
