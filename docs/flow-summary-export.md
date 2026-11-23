# Flow summary export (`internal/flowexport`)

Retained flow history as summary records named after IANA IPFIX information elements, as JSON, JSON lines or CSV. A file and HTTP export for analytics tools that expect IPFIX-shaped fields. It is **not** an IPFIX or NetFlow v9 wire exporter: there are no template sets and nothing is sent over UDP.

```bash
netractl export flow-summary --format csv --since 1h --limit 1000 [--namespace shop]
```

`GET /api/v1/export/flow-summary?since=1h&format=json|jsonl|csv&limit=1000&namespace=&node=&protocol=`. MCP: `netra_export_flow_summary`. It reads the flow history of [`flow-log.md`](flow-log.md) (7 days by default); `since` is a duration within retention or an RFC3339 time. `limit` is the number of summary records, largest by bytes first (default 1000, at most 10000). Headers `X-Netra-Export-Count` and `X-Netra-Export-Truncated` report what was returned.

The destination-flow counters export at `/api/v1/export/flows` ([`siem-export.md`](siem-export.md)) is unchanged: that is a snapshot of current counters in SIEM formats; this is history aggregated over a window.

## Fields

IANA IPFIX names (element ids in parentheses, checked against the IANA registry): `flowStartMilliseconds` (152), `flowEndMilliseconds` (153), `flowDirection` (61; 0 ingress, 1 egress), `sourceIPv4Address` (8), `destinationIPv4Address` (12), `sourceIPv6Address` (27), `destinationIPv6Address` (28), `destinationTransportPort` (11), `protocolIdentifier` (4), `octetDeltaCount` (1), `packetDeltaCount` (2).

Netra extensions: `netraNode`, `netraNamespace`, `netraWorkload`, `netraAppProtocol`, `netraPeer` (only when the peer is not an IP address), `netraBlockedPacketCount`, `netraRetransmissions`, `netraObservations` (how many deltas were summed).

Records are summed per node, workload, peer, port, protocol, application protocol and direction. The peer is the remote address: `sourceIPv4/6Address` for ingress records and `destinationIPv4/6Address` for egress.

## Limits

- Built from retained flow deltas, not from packets. The first sample after a controller restart is only a baseline.
- The local address is not recorded, so only the peer is exported. `destinationTransportPort` is the port Netra recorded for the flow.
- `flowStartMilliseconds` and `flowEndMilliseconds` are the first and last time a delta was observed in the window, not connection start and end.
- Bounded: at most 200,000 distinct summary records are aggregated; the response flags truncation.
- CSV cells that begin with `=`, `+`, `-`, `@`, tab or carriage return are prefixed with a single quote so workload and namespace names cannot inject spreadsheet formulas.
- A scoped principal (namespace, cluster or tenant) is held to its scope exactly as for `GET /api/v1/flows/history`.
- No payloads, command lines or Secret contents are in the records.
