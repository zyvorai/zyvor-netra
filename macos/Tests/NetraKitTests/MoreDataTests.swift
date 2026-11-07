// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class MoreDataTests: XCTestCase {
    private func json(_ s: String) -> JSONValue { try! JSONDecoder().decode(JSONValue.self, from: Data(s.utf8)) }

    func testFriendlyErrors() {
        XCTAssertTrue(MoreData.friendlyError(status: 409, message: "off", feature: "TCP events").contains("not enabled"))
        XCTAssertTrue(MoreData.friendlyError(status: 404, message: "", feature: "X").contains("not enabled"))
        XCTAssertEqual(MoreData.friendlyError(status: 500, message: "boom", feature: "X"), "HTTP 500: boom")
    }

    func testAgentEventsFlattenNewestFirst() {
        let v = json(#"{"items":[{"node":"a","stale":false,"events":[{"observedAt":"2026-11-07T10:00:00Z","sourceIp":"10.0.0.1","sourcePort":1234,"destinationIp":"::1","destinationPort":443,"namespace":"web","pod":"p","action":"blocked"}]},{"node":"b","stale":true,"events":[{"observedAt":"2026-11-07T11:00:00Z","destinationIp":"1.1.1.1","action":"passed"}]},{"node":"c"}]}"#)
        let rows = MoreData.agentEvents(v)
        XCTAssertEqual(rows.map { $0.value["node"]?.string }, ["b", "a"])
        XCTAssertEqual(rows[1].value["src"]?.string, "10.0.0.1:1234")
        XCTAssertEqual(rows[1].value["dst"]?.string, "[::1]:443")
        XCTAssertEqual(rows[1].value["workload"]?.string, "web/p")
        XCTAssertEqual(rows[0].value["dst"]?.string, "1.1.1.1")
        XCTAssertEqual(rows[0].value["stale"], .bool(true))
        let s = MoreData.eventStats(rows)
        XCTAssertEqual(s, .init(total: 2, blocked: 1, workloads: 1, nodes: 2))
        XCTAssertEqual(MoreData.agentEvents(v, limit: 1).count, 1)
        XCTAssertTrue(MoreData.agentEvents(json("{}")).isEmpty)
    }

    func testTCPEventsWarningsAndSilentNodes() {
        let v = json(#"{"nodes":[{"node":"a","reporting":true,"sensors":["retransmit"]},{"node":"b","reporting":false,"sensors":[]}],"totals":{"retransmits":5,"readErrors":3,"mapFull":1}}"#)
        XCTAssertEqual(MoreData.tcpUndercountWarning(v), "The sensor reported 3 read errors, 1 map-full drops. Counts below are an undercount.")
        XCTAssertNil(MoreData.tcpUndercountWarning(json(#"{"totals":{"retransmits":1}}"#)))
        XCTAssertEqual(MoreData.tcpSilentNodes(v), ["b"])
    }

    func testJoinedArraysAndMaps() {
        let rows = MoreData.joined(json(#"{"nodes":[{"node":"a","sensors":["x","y"],"skipped":{"z":"no tp"}}]}"#).rows(at: "nodes", idKeys: ["node"]), key: "sensors")
        XCTAssertEqual(rows[0].value["sensorsText"]?.string, "x, y")
        let m = MoreData.joined(rows, key: "skipped")
        XCTAssertEqual(m[0].value["skippedText"]?.string, "z: no tp")
    }

    func testPathRows() {
        let v = json(#"{"pressure":[{"remoteIp":"10.1.1.1","remotePort":80,"namespace":"web","pod":"p","sendCwnd":10,"packetsOut":9},{"remoteIp":"2.2.2.2","remotePort":0,"cgroupId":7,"sendCwnd":0}],"connect":[{"remoteIp":"1.1.1.1","remotePort":53,"established":4,"totalLatencyUs":8000,"maxLatencyUs":5000}]}"#)
        let p = MoreData.pathRows(v, at: "pressure")
        XCTAssertEqual(p[0].value["cwndRatio"]?.asDouble ?? 0, 0.9, accuracy: 0.001)
        XCTAssertEqual(p[0].value["workload"]?.string, "web/p")
        XCTAssertEqual(p[1].value["workload"]?.string, "cgroup 7")
        XCTAssertNil(p[1].value["cwndRatio"])
        XCTAssertEqual(p[1].value["remote"]?.string, "2.2.2.2")
        XCTAssertEqual(MoreData.pathRows(v, at: "connect")[0].value["avgConnectUs"]?.asDouble, 2000)
        XCTAssertEqual(MoreData.micros(2000), "2.0 ms"); XCTAssertEqual(MoreData.micros(340), "340 us")
    }

    func testNestedInterfacesAndHottest() {
        let v = json(#"{"nodes":[{"node":"n1","interfaces":[{"interface":"eth0","packets":5},{"interface":"lo","packets":1}]},{"node":"n2"}]}"#)
        let r = MoreData.nested(v, child: "interfaces")
        XCTAssertEqual(r.count, 2); XCTAssertEqual(r[0].value["node"]?.string, "n1")
        let heat = json(#"{"rows":[{"namespace":"a","packets":900,"blocked":0},{"namespace":"b","packets":10,"blocked":4}]}"#)
        XCTAssertEqual(MoreData.hottestNamespace(heat), "b")
        XCTAssertNil(MoreData.hottestNamespace(json("{}")))
    }

    func testInvestigateQueryValidation() {
        XCTAssertNotNil(MoreData.investigateQuery(namespace: "", pod: "", peer: "", port: "", node: "", window: "").error)
        XCTAssertNotNil(MoreData.investigateQuery(namespace: "a", pod: "", peer: "", port: "70000", node: "", window: "").error)
        XCTAssertNotNil(MoreData.investigateQuery(namespace: "a", pod: "", peer: "", port: "", node: "", window: "soon").error)
        let q = MoreData.investigateQuery(namespace: " web ", pod: "", peer: "10.0.0.9", port: "443", node: "", window: "1h30m")
        XCTAssertNil(q.error)
        XCTAssertEqual(q.items.map { "\($0.name)=\($0.value ?? "")" }, ["namespace=web", "peer=10.0.0.9", "port=443", "window=1h30m"])
        XCTAssertTrue(MoreData.isGoDuration("90s")); XCTAssertFalse(MoreData.isGoDuration("5"))
    }

    func testExplainQueryClampsLimit() {
        XCTAssertEqual(MoreData.explainQuery(namespace: "", pod: "", limit: 500).map { "\($0.name)=\($0.value ?? "")" }, ["limit=100"])
        XCTAssertEqual(MoreData.explainQuery(namespace: "a", pod: "b", limit: 0).count, 3)
    }

    func testTimelineOrderAndStrings() {
        let v = json(#"{"events":[{"ts":"2026-11-07T10:05:00Z","stage":"late"},{"ts":"2026-11-07T10:00:00Z","stage":"early"}],"limitations":["a",""]}"#)
        XCTAssertEqual(MoreData.timeline(v).map { $0.value["stage"]?.string }, ["early", "late"])
        XCTAssertEqual(MoreData.strings(v, at: "limitations"), ["a"])
    }

    func testClientQueryAgainstStub() async throws {
        StubURLProtocol.handler = { _ in (200, #"{"events":[]}"#) }
        let cfg = URLSessionConfiguration.ephemeral; cfg.protocolClasses = [StubURLProtocol.self]
        StubURLProtocol.seen = []
        let c = NetraClient(profile: .init(baseURL: URL(string: "http://stub.invalid")!, token: "t"), session: URLSession(configuration: cfg))
        let q = MoreData.investigateQuery(namespace: "web", pod: "", peer: "", port: "443", node: "", window: "5m")
        _ = try await c.send(c.request("GET", "api/v1/investigate/connection", query: q.items))
        let url = StubURLProtocol.seen.last!.url!
        XCTAssertEqual(url.path, "/api/v1/investigate/connection")
        XCTAssertEqual(StubURLProtocol.seen.last!.httpMethod, "GET")
        XCTAssertTrue(url.query!.contains("port=443"))
    }

    func testDefaultingFalseFillsOmittedBooleans() {
        // models.AgentReport.MTLS is `json:"mtls,omitempty"`: false never appears on the wire.
        let rows = json(#"{"items":[{"node":"a"},{"node":"b","mtls":true}]}"#).rows(at: "items", idKeys: ["node"])
        let out = MoreData.defaultingFalse(rows, keys: ["mtls"])
        XCTAssertEqual(out.map { CellFormat.text($0.value["mtls"], .bool) }, ["no", "yes"])
    }

    /// Shapes copied from the json tags of tcpEventsView / coverage.Matrix / nsheat.Board / PathDiagnosticsResponse.
    func testGoTaggedFixturesProduceValues() {
        let tcp = json(#"{"nodes":[{"node":"n1","sensors":["retransmit"],"skipped":{"rst":"no tp"},"reporting":true}],"nodesReporting":1,"nodesNotReporting":0,"totals":{"retransmits":5,"rstSent":1,"rstReceived":2,"stateTransitions":9},"transitions":[{"from":"ESTABLISHED","to":"CLOSE","count":4}],"flows":[{"node":"n1","family":"ipv4","src":"10.0.0.1","dst":"10.0.0.2","srcPort":1,"dstPort":443,"retransmits":3,"lastSeenNs":9}]}"#)
        XCTAssertEqual(tcp.rows(at: "flows")[0].value["dstPort"]?.asDouble, 443)
        XCTAssertEqual(tcp.at("totals.rstReceived")?.asDouble, 2)
        XCTAssertEqual(tcp.rows(at: "transitions")[0].value["count"]?.asDouble, 4)
        let heat = json(#"{"generatedAt":"2026-11-07T10:00:00Z","rows":[{"namespace":"web","packets":10,"bytes":1000,"blocked":2,"destinations":3}],"count":1}"#)
        XCTAssertEqual(MoreData.hottestNamespace(heat), "web")
        let path = json(#"{"summary":{"connectionsMeasured":2,"averageConnectUs":1500,"maxConnectUs":3000,"congestedFlows":1,"retransOut":1,"lostOut":0,"packetsOut":4,"anomalies":[{"severity":"warning","kind":"cwnd","subject":"web/p","message":"m"}]},"pressure":[{"remoteIp":"1.1.1.1","remotePort":443,"namespace":"web","pod":"p","sendCwnd":10,"packetsOut":5,"mss":1460}],"connect":[{"remoteIp":"1.1.1.1","remotePort":443,"established":2,"totalLatencyUs":3000,"maxLatencyUs":2000}],"edgeIntel":{"counts":{"syn":3,"rst":1}}}"#)
        let p = MoreData.pathRows(path, at: "pressure")[0].value
        XCTAssertEqual(p["workload"]?.string, "web/p"); XCTAssertEqual(p["remote"]?.string, "1.1.1.1:443"); XCTAssertEqual(p["cwndRatio"]?.asDouble, 0.5)
        XCTAssertEqual(MoreData.pathRows(path, at: "connect")[0].value["avgConnectUs"]?.asDouble, 1500)
        XCTAssertEqual(path.mapRows(at: "edgeIntel.counts").map { CellFormat.text($0.value["value"], .int) }, ["1", "3"])
        let cov = json(#"{"nodes":[{"node":"n1","stale":false,"mode":"observe","ageSeconds":4,"programs":[{"name":"p","type":"cgroup_skb","attached":true,"runCount":7}],"attached":1,"detached":["x"],"missingMaps":["m"],"hookCount":2,"programCount":1}],"agentCount":1}"#)
        XCTAssertEqual(MoreData.nested(cov, child: "programs")[0].value["runCount"]?.asDouble, 7)
        XCTAssertEqual(MoreData.joined(cov.rows(at: "nodes", idKeys: ["node"]), key: "detached")[0].value["detachedText"]?.string, "x")
        let inv = json(#"{"request":{"since":"2026-11-07T09:00:00Z"},"events":[{"ts":"2026-11-07T10:00:00Z","source":"flow","stage":"flow","summary":"s","confidence":"high"}],"confidence":{"overall":"high","notes":["n"]},"limitations":["l"]}"#)
        XCTAssertEqual(MoreData.timeline(inv)[0].value["summary"]?.string, "s")
        XCTAssertEqual(MoreData.strings(inv, at: "confidence.notes"), ["n"])
    }
}
