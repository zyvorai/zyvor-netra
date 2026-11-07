// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

/// Fixtures are shaped exactly like the Go structs' json tags (omitempty fields ABSENT, nil slices as null,
/// time.Time with nanoseconds). Each cites the Go type it mirrors.
final class CoreWireShapeTests: XCTestCase {
    private func data(_ s: String) -> Data { Data(s.utf8) }
    private func j(_ s: String) -> JSONValue { try! JSONDecoder().decode(JSONValue.self, from: data(s)) }
    private func dec<T: Decodable>(_ t: T.Type, _ s: String) throws -> T { try JSONDecoder().decode(T.self, from: data(s)) }

    // MARK: whoami (internal/api/rbac.go: map with kind, role always; the rest only when set)

    func testWhoAmIMinimalAnonymous() throws {
        let w = try dec(WhoAmI.self, #"{"authRequired":false,"oidcEnabled":false,"kind":"anonymous","role":"admin","scoped":false}"#)
        XCTAssertTrue(w.isAdmin); XCTAssertTrue(w.canMutate); XCTAssertNil(w.identity); XCTAssertTrue(w.namespaces.isEmpty)
    }
    func testWhoAmIScopedViewerAndMissingFields() throws {
        let w = try dec(WhoAmI.self, #"{"authRequired":true,"oidcEnabled":true,"kind":"oidc","role":"viewer","identity":"a@b.c","namespaces":["prod"],"scoped":true}"#)
        XCTAssertFalse(w.canMutate); XCTAssertEqual(w.identity, "a@b.c"); XCTAssertEqual(w.namespaces, ["prod"]); XCTAssertTrue(w.scoped)
        // Even `{}` or odd types decode instead of failing the connect.
        let e = try dec(WhoAmI.self, #"{"role":5,"authRequired":"true"}"#)
        XCTAssertEqual(e.parsedRole, .none); XCTAssertTrue(e.authRequired)
        _ = try dec(WhoAmI.self, "{}")
    }

    // MARK: lease (internal/leaseclock.Status)

    func testLeaseNoLeaseOmitsOptionalFields() throws {
        let l = try JSONDecoder.netra.decode(LeaseStatus.self, from: data(
            #"{"generatedAt":"2026-01-01T00:00:00.123456789Z","mode":"observe","remainingSeconds":0,"active":false,"expired":false,"note":"no enforce lease"}"#))
        XCTAssertEqual(l.mode, "observe"); XCTAssertNil(l.leaseExpiresAt); XCTAssertNil(l.leaseSeconds); XCTAssertFalse(l.active)
    }
    func testLeaseActiveWithNanosecondExpiry() throws {
        let l = try JSONDecoder.netra.decode(LeaseStatus.self, from: data(
            #"{"generatedAt":"2026-01-01T00:00:00Z","mode":"enforce","scopeMode":"all","leaseExpiresAt":"2026-01-01T00:15:00.987654321Z","leaseSeconds":900,"remainingSeconds":812,"active":true,"expired":false,"note":""}"#))
        XCTAssertNotNil(l.leaseExpiresAt); XCTAssertEqual(l.remainingSeconds, 812); XCTAssertEqual(l.leaseSeconds, 900)
        // A malformed date must not fail the 5s poll.
        let bad = try JSONDecoder.netra.decode(LeaseStatus.self, from: data(#"{"mode":"enforce","leaseExpiresAt":"garbage","remainingSeconds":3,"active":true,"expired":false}"#))
        XCTAssertNil(bad.leaseExpiresAt); XCTAssertEqual(bad.remainingSeconds, 3)
    }
    func testNanosecondDateParsing() {
        XCTAssertNotNil(NetraDate.parse("2026-03-04T05:06:07.123456789Z"))
        XCTAssertNotNil(NetraDate.parse("2026-03-04T05:06:07.1Z"))
        XCTAssertNotNil(NetraDate.parse("2026-03-04T05:06:07+02:00"))
        XCTAssertNil(NetraDate.parse(""))
    }

    // MARK: flows

    /// protojson of flow.Flow (UseProtoNames false): `IP`, `l4.TCP`, uint32 ports as numbers.
    func testHubbleFlowEvent() {
        let flow = #"{"time":"2026-01-01T00:00:00.123456789Z","verdict":"DROPPED","IP":{"source":"10.0.0.1","destination":"10.0.0.2","ipVersion":"IPv4"},"l4":{"TCP":{"sourcePort":43210,"destinationPort":443}},"source":{"ID":12,"identity":3,"namespace":"prod","labels":["k8s:app=web"],"podName":"web-1"},"destination":{"identity":2},"Type":"L3_L4","trafficDirection":"EGRESS","dropReasonDesc":"POLICY_DENIED"}"#
        let r = decodeFlowEvent(SSEEvent(event: "flow", data: flow, id: nil))
        XCTAssertEqual(r?.verdict, "DROPPED"); XCTAssertEqual(r?.direction, "EGRESS")
        XCTAssertEqual(r?.sourceEndpoint, "10.0.0.1:43210"); XCTAssertEqual(r?.destinationEndpoint, "10.0.0.2:443")
        XCTAssertEqual(r?.proto, "TCP"); XCTAssertEqual(r?.source, "prod/web-1"); XCTAssertEqual(r?.destination, "2")
        XCTAssertEqual(r?.dropReason, "POLICY_DENIED"); XCTAssertNotNil(r?.timestamp)
        // The server's own `ready` event is not a flow.
        XCTAssertNil(decodeFlowEvent(SSEEvent(event: "ready", data: #"{"source":"hubble-relay"}"#, id: nil)))
    }
    func testSSEReadyThenFlowStream() {
        var p = SSEParser()
        let evs = p.feed("event: ready\ndata: {\"source\":\"hubble-relay\"}\n\nevent: flow\ndata: {\"verdict\":\"FORWARDED\"}\n\n")
        XCTAssertEqual(evs.map(\.event), ["ready", "flow"])
        XCTAssertEqual(decodeFlowEvent(evs[1])?.verdict, "FORWARDED")
    }
    /// flowlog.Result with omitempty fields absent and a nil Records slice.
    func testFlowHistoryOmitempty() throws {
        let h = try dec(FlowHistory.self, #"{"records":[{"observedAt":"2026-01-01T00:00:00Z","peer":"1.2.3.4","port":443}],"matched":1,"limitations":["x"]}"#)
        XCTAssertEqual(h.records.count, 1); XCTAssertEqual(h.records[0].peer, "1.2.3.4"); XCTAssertEqual(h.records[0].packets, 0)
        XCTAssertFalse(h.truncated)
        let n = try dec(FlowHistory.self, #"{"records":null,"matched":0,"limitations":null}"#)
        XCTAssertTrue(n.records.isEmpty)
        let full = try dec(FlowHistory.self, #"{"records":[{"observedAt":"2026-01-01T00:00:00Z","node":"n1","namespace":"p","pod":"a","workloadKind":"Deployment","workloadName":"web","peer":"9.9.9.9","port":53,"protocol":"UDP","direction":"egress","appProtocol":"dns","packets":18446744073709551615,"bytes":10,"blocked":1,"retransmissions":2,"rtos":3,"srttUs":4,"pid":5,"comm":"curl","dnsName":"x.io","tlsSni":"x.io"}],"matched":1,"truncated":true,"limitations":[]}"#)
        XCTAssertEqual(full.records[0].workload, "Deployment/web"); XCTAssertEqual(full.records[0].tlsSni, "x.io"); XCTAssertTrue(full.truncated)
    }
    /// models.FlowSummary: topWorkloads/topBlockedWorkloads omitempty, maps may be null.
    func testFlowsSummaryOmitempty() throws {
        let s = try dec(FlowsSummary.self, #"{"total":7,"verdicts":{"FORWARDED":5,"DROPPED":2},"protocols":null,"dropReasons":[{"name":"POLICY_DENIED","count":2}],"topDestinations":null}"#)
        XCTAssertEqual(s.total, 7); XCTAssertEqual(s.verdicts["DROPPED"], 2); XCTAssertTrue(s.protocols.isEmpty)
        XCTAssertEqual(s.dropReasons.first?.count, 2); XCTAssertTrue(s.topWorkloads.isEmpty)
    }

    // MARK: topology (GET /ebpf/topology -> {"items":[models.NetworkEdge]})

    func testTopologyEdgeRowsOmitempty() throws {
        let g = try TopologyGraph.decodeEdgeRows(data(#"{"items":[{"node":"n1","namespace":"prod","pod":"web-1","workloadKind":"Deployment","workloadName":"web","destination":"10.1.2.3:443","protocol":"tcp","packets":10,"bytes":1000,"blocked":0},{"node":"n1","destination":"8.8.8.8:53","protocol":"udp","packets":1,"bytes":50,"blocked":1}]}"#))
        XCTAssertEqual(g.nodes.count, 4); XCTAssertEqual(g.edges.count, 2)
        XCTAssertTrue(g.nodes.contains { $0.id == "prod/deployment/web" })
        XCTAssertTrue(g.nodes.contains { $0.id == "node/n1" })
        XCTAssertEqual(try TopologyGraph.decodeEdgeRows(data(#"{"items":null}"#)).nodes.count, 0)
    }
    /// models.DependencyGraph (insights/dependencies): port/external omitempty.
    func testDependencyGraph() throws {
        let g = try dec(TopologyGraph.self, #"{"generatedAt":"2026-01-01T00:00:00Z","nodes":[{"id":"a","kind":"workload","name":"web"},{"id":"b","kind":"external","name":"x","ip":"1.1.1.1"}],"edges":[{"source":"a","target":"b","protocol":"tcp","packets":1,"bytes":2,"blocked":0}]}"#)
        XCTAssertEqual(g.nodes.count, 2); XCTAssertEqual(g.edges[0].port, 0); XCTAssertFalse(g.edges[0].external)
        let b = try dec(BlastRadius.self, #"{"generatedAt":"2026-01-01T00:00:00Z","root":"a","maxHops":3,"nodes":[{"id":"a","hops":0},{"id":"b","hops":1}],"edges":null,"truncated":false,"caveat":"c"}"#)
        XCTAssertEqual(b.hops["b"], 1)
    }

    // MARK: metrics

    func testMetricsSummaryAndFleet() throws {
        let s = try dec(MetricsSummary.self, #"{"available":true,"nodes":2,"staleNodes":0,"series":1500,"anomalyRate":1.25,"alertsCritical":0,"alertsWarning":1,"topAlerts":[{"rule":"r","status":"WARNING","node":"n1","chart":"c"}],"topAnomalous":[]}"#)
        XCTAssertEqual(s.series, 1500); XCTAssertEqual(s.topAlerts.first?.node, "n1")
        let off = try dec(MetricsSummary.self, #"{"available":false,"nodes":0,"staleNodes":0,"series":0,"anomalyRate":0,"alertsCritical":0,"alertsWarning":0,"topAlerts":[],"topAnomalous":[]}"#)
        XCTAssertFalse(off.available)
        let f = try dec(MetricsFleet.self, #"{"generatedAt":"2026-01-01T00:00:00Z","clusters":[{"name":"local","local":true,"ok":true,"fetchedAt":"2026-01-01T00:00:00Z","summary":{"available":true,"nodes":1,"staleNodes":0,"series":3,"anomalyRate":0,"alertsCritical":0,"alertsWarning":0,"topAlerts":[],"topAnomalous":[]}},{"name":"peer","url":"https://p","ok":false,"error":"timeout","fetchedAt":"2026-01-01T00:00:00Z"}],"totals":{"clusters":2,"okClusters":1,"nodes":1,"series":3,"anomalyRate":0,"alertsCritical":0,"alertsWarning":0},"note":"n"}"#)
        XCTAssertEqual(f.clusters.count, 2); XCTAssertNil(f.clusters[1].summary); XCTAssertEqual(f.totals?.okClusters, 1)
    }
    func testMetricNodesContextsAndData() throws {
        let nodes = try dec(MetricNodesResponse.self, #"{"nodes":[{"node":"n1","lastIngest":"2026-01-01T00:00:00.5Z","stats":{"series":10,"memoryBytes":1,"diskBytes":2,"oldestT":3,"newestT":4}}]}"#)
        XCTAssertEqual(nodes.nodes[0].stats?.series, 10)
        let ctx = try dec(MetricContextsResponse.self, #"{"contexts":[{"context":"net.bytes","family":"net","units":"B/s","charts":[{"node":"n1","chart":"eth0","dimensions":["rx","tx"]}],"firstT":1,"lastT":2}],"count":1}"#)
        XCTAssertEqual(ctx.contexts[0].charts[0].dimensions.count, 2); XCTAssertNil(ctx.contexts[0].title)
        let r = try dec(MetricResult.self, #"{"context":"net.bytes","units":"B/s","tier":0,"interval":1,"after":100,"before":103,"timestamps":[100,101,102],"dimensions":[{"name":"rx","values":[1,null,3.5],"anomalyRate":[0,null,0],"series":1}],"matched":1}"#)
        XCTAssertEqual(r.dimensions[0].values, [1, nil, 3.5]); XCTAssertNil(r.title)
        let empty = try dec(MetricResult.self, #"{"context":"c","tier":0,"interval":1,"after":1,"before":2,"timestamps":null,"dimensions":null,"matched":0}"#)
        XCTAssertTrue(empty.timestamps.isEmpty)
    }
    func testMetricAlertsSnapshotOmitempty() throws {
        let a = try dec(MetricAlertSnapshot.self, #"""
        {"active":[{"id":"ab12","rule":"r","node":"n1","context":"c","chart":"ch","status":"CRITICAL","value":null,"since":"2026-01-01T00:00:00.1Z","lastEval":"2026-01-01T00:00:01Z"}],
         "history":[{"time":"2026-01-01T00:00:00Z","id":"ab12","rule":"r","node":"n1","chart":"ch","from":"CLEAR","to":"CRITICAL","value":9.5}],
         "rules":[{"name":"r","context":"c","lookup":"average","source":"builtin"}],
         "silences":[{"id":"s1","until":"2026-01-02T00:00:00Z","created":"2026-01-01T00:00:00Z"}],
         "stats":{"rules":1,"instances":1,"warning":0,"critical":1,"evaluations":5,"droppedInstances":0}}
        """#)
        XCTAssertEqual(a.active[0].status, "CRITICAL"); XCTAssertNil(a.active[0].value); XCTAssertNil(a.active[0].acked)
        XCTAssertEqual(a.history[0].value, 9.5); XCTAssertEqual(a.silences[0].id, "s1"); XCTAssertNil(a.silences[0].rule)
        XCTAssertEqual(a.stats?.critical, 1)
        let nils = try dec(MetricAlertSnapshot.self, #"{"active":null,"history":null,"rules":null,"silences":null,"stats":{"rules":0,"instances":0,"warning":0,"critical":0,"evaluations":0,"droppedInstances":0}}"#)
        XCTAssertTrue(nils.active.isEmpty)
        let sil = try dec(MetricSilence.self, #"{"id":"s1","rule":"r*","until":"2026-01-02T00:00:00Z","comment":"c","createdBy":"admin","created":"2026-01-01T00:00:00Z"}"#)
        XCTAssertEqual(sil.rule, "r*"); XCTAssertNil(sil.node)
    }
    func testAnomaliesAndEvidenceOmitempty() throws {
        let an = try dec(AnomalySummary.self, #"{"after":1,"before":2,"nodes":[{"node":"n1","anomalyRate":2.5,"dimensions":10,"anomalousDimensions":1}],"ranked":[{"node":"n1","context":"c","chart":"ch","dimension":"d","anomalyRate":60,"score":3.2}]}"#)
        XCTAssertEqual(an.ranked[0].severity, .high); XCTAssertTrue(an.correlated.isEmpty)
        let ev = try dec(MetricEvidence.self, #"{"context":"c","after":1,"before":2,"kinds":["flows"],"links":[{"kind":"page","title":"t","href":"/x","why":"w"}],"flowRecords":3,"topPeers":[{"peer":"1.1.1.1","port":443,"packets":5,"bytes":6}],"limitations":["l"]}"#)
        XCTAssertEqual(ev.topPeers[0].peer, "1.1.1.1"); XCTAssertNil(ev.topPeers[0].blocked); XCTAssertTrue(ev.kernelDrops.isEmpty); XCTAssertNil(ev.node)
        let nul = try dec(MetricEvidence.self, #"{"context":"c","kinds":null,"links":null,"flowRecords":0,"topPeers":null,"limitations":null}"#)
        XCTAssertTrue(nul.links.isEmpty)
    }
    /// {"t":<unix>,"results":{id: tsdb.Result}}
    func testLiveFrame() throws {
        let f = MetricsLive.parseFrame(data(#"{"t":1700000000,"results":{"net|*|*":{"context":"net","tier":0,"interval":1,"after":1,"before":2,"timestamps":[1],"dimensions":[{"name":"rx","values":[null],"anomalyRate":[null],"series":1}],"matched":1}}}"#))
        XCTAssertEqual(f?.t, 1700000000); XCTAssertEqual(f?.results["net|*|*"]?.dimensions.count, 1)
        XCTAssertEqual(MetricsLive.parseFrame(data(#"{"t":5,"results":{}}"#))?.results.count, 0)
    }
    /// Subscription keys must be streamQuery's json tags.
    func testSubscribeKeys() throws {
        let msg = MetricsLive.subscribeMessage([.init(id: "i", context: "c", charts: ["x"], nodes: ["n"], labels: ["a": "b"], window: 300, points: 100, groupBy: "node")])
        let o = try XCTUnwrap(try JSONSerialization.jsonObject(with: data(msg)) as? [String: Any])
        let q = try XCTUnwrap((o["subscribe"] as? [[String: Any]])?.first)
        XCTAssertTrue(Set(q.keys).isSubset(of: ["id", "context", "charts", "nodes", "labels", "window", "points", "groupBy", "group", "aggregate"]))
    }

    // MARK: control rows (FirewallRule, PolicyRevision, features, capture)

    func testFirewallRuleRows() {
        let rows = controlRows(j(#"{"items":[{"id":"r1","type":"cidr","summary":"deny 10.0.0.0/8","cidr":"10.0.0.0/8","direction":"egress","createdAt":"2026-01-01T00:00:00Z","updatedAt":"0001-01-01T00:00:00Z"}]}"#), listKey: "items")
        XCTAssertEqual(rows[0].text("type"), "cidr"); XCTAssertEqual(rows[0].text("createdBy"), "")
        XCTAssertEqual(rows[0].text("updatedAt"), "", "Go's zero time.Time must render blank")
        XCTAssertEqual(controlRows(j(#"{"items":null}"#), listKey: "items").count, 0)
    }
    func testPolicyRevisionRows() {
        let rows = controlRows(j(#"{"items":[{"id":3,"at":"2026-01-01T00:00:00Z","actor":"admin","namespace":"p","name":"n","action":"apply","manifest":{}}]}"#), listKey: "items")
        XCTAssertEqual(rows[0].text("id"), "3"); XCTAssertEqual(rows[0].text("action"), "apply")
    }
    func testFeaturesAndCaptureRows() {
        let f = controlRows(j(#"{"features":[{"id":"dnsdetect","title":"DNS detect","description":"d","scope":"controller","helmSet":"x","cli":"c","enabled":true,"source":"env"}],"summary":{"on":1,"off":0,"unknown":0},"note":"n"}"#), listKey: "features")
        XCTAssertEqual(f[0].text("enabled"), "true"); XCTAssertEqual(f[0].text("title"), "DNS detect")
        let a = controlRows(j(#"{"active":[{"node":"n1","backend":"ebpf","protocol":"tcp","port":443,"startedAt":"2026-01-01T00:00:00Z","expiresAt":"2026-01-01T00:01:00Z"}]}"#), listKey: "active", idKeys: ["node"])
        XCTAssertEqual(a[0].text("port"), "443")
        let h = controlRows(j(#"{"entries":[{"node":"n1","startedAt":"2026-01-01T00:00:00Z","endedAt":"2026-01-01T00:01:00Z","reason":"manual","artifactFrames":12}]}"#), listKey: "entries", idKeys: ["node", "startedAt"])
        XCTAssertEqual(h[0].text("artifactFrames"), "12")
        XCTAssertEqual(controlRows(j(#"{"active":null}"#), listKey: "active").count, 0)
    }
    func testControlIntNeverTraps() {
        XCTAssertEqual(j("18446744073709551615").controlInt, Int.max)
        XCTAssertEqual(j("12").controlInt, 12)
    }
    /// leaseclock/ebpf mode body and capture body keys (captureRequestBody json tags; DisallowUnknownFields).
    func testMutationBodyKeys() throws {
        let c = NetraClient(profile: .init(baseURL: URL(string: "http://stub.invalid")!, token: "t"))
        var p = ControlMutations.CaptureParams(); p.node = "n1"; p.proto = "TCP"; p.host = "1.2.3.4"; p.port = 443; p.snapLen = 128; p.maxPPS = 1000
        let o = try XCTUnwrap(try JSONSerialization.jsonObject(with: XCTUnwrap(p.body)) as? [String: Any])
        XCTAssertEqual(Set(o.keys), ["backend", "protocol", "host", "port", "snapLen", "maxPps", "durationSeconds"])
        XCTAssertEqual(o["protocol"] as? String, "tcp")
        let lock = try XCTUnwrap(ControlMutations.lockdownBuildBody(namespace: "p", name: "n", kind: "pod", selector: ["a": "b"]))
        XCTAssertEqual(Set((try JSONSerialization.jsonObject(with: lock) as! [String: Any]).keys), ["namespace", "name", "kind", "selector"])
        let dp = c.denyPreviewRequest(ip: "1.2.3.4", direction: .both)
        XCTAssertEqual(Set((try JSONSerialization.jsonObject(with: XCTUnwrap(dp.httpBody)) as! [String: Any]).keys), ["kind", "value", "direction"])
        let d = c.denyRequest(ip: "1.2.3.4", direction: .egress, confirmRisk: true)
        XCTAssertEqual(Set((try JSONSerialization.jsonObject(with: XCTUnwrap(d.httpBody)) as! [String: Any]).keys), ["ip", "direction"])
        XCTAssertEqual(d.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "high")
    }

    // MARK: palette object sources

    /// talkers.Board is {"generatedAt","rows":[{"destination",...}],"count"}; FirewallRule has summary.
    func testPaletteTalkersAndRules() {
        let ips = PaletteObjects.ips([j(#"{"generatedAt":"2026-01-01T00:00:00Z","rows":[{"destination":"8.8.8.8","packets":1,"bytes":2,"blocked":0,"nodes":1}],"count":1}"#)])
        XCTAssertEqual(ips.map(\.title), ["8.8.8.8"])
        let rules = PaletteObjects.rules(j(#"{"items":[{"id":"abc123","type":"cidr","summary":"deny 10.0.0.0/8","direction":"egress"}]}"#))
        XCTAssertEqual(rules[0].title, "deny 10.0.0.0/8"); XCTAssertEqual(rules[0].query["q"], "abc123"); XCTAssertEqual(rules[0].subtitle, "cidr · egress")
        // models.WorkloadIdentity rows (ebpf/workloads) carry workloadKind/workloadName.
        let w = PaletteObjects.workloads(j(#"{"items":[{"uid":"u","namespace":"prod","pod":"web-1","workloadKind":"Deployment","workloadName":"web"}]}"#))
        XCTAssertEqual(w[0].title, "web"); XCTAssertEqual(w[0].subtitle, "Deployment · prod")
    }
}
