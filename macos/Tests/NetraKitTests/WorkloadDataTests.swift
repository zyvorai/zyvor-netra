// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import XCTest
@testable import NetraKit

final class WorkloadDataTests: XCTestCase {
    private func json(_ s: String) -> JSONValue { try! JSONDecoder().decode(JSONValue.self, from: Data(s.utf8)) }
    private typealias W = WorkloadData

    private let pods = """
    {"items":[
     {"name":"web-1","namespace":"shop","phase":"Running","node":"n1","podIP":"10.0.0.5","ready":true,"labels":{"app":"web","tier":"fe"},
      "ownerKind":"ReplicaSet","ownerName":"web-abc","containers":[{"name":"app","ready":true,"restartCount":0},{"name":"side","ready":false,"restartCount":7}],
      "restartCount":7,"lockedDown":true},
     {"name":"job-1","namespace":"batch","phase":"Failed","ready":false},
     {"name":"pend","namespace":"batch","phase":"Pending","ready":false}]}
    """

    func testLabelsTextSorted() {
        XCTAssertEqual(W.labelsText(json(#"{"b":"2","a":"1"}"#)), "a=1, b=2")
        XCTAssertEqual(W.labelsText(nil), "")
    }

    func testPodRowsDerivedColumns() {
        let rows = W.podRows(json(pods))
        XCTAssertEqual(rows.count, 3)
        let web = rows[0].value
        XCTAssertEqual(web.at("containersText")?.string, "1/2")
        XCTAssertEqual(web.at("owner")?.string, "ReplicaSet/web-abc")
        XCTAssertEqual(web.at("health")?.string, "Warning")      // 7 restarts
        XCTAssertEqual(web.at("lockedDownText")?.string, "locked down")
        XCTAssertEqual(rows[1].value.at("health")?.string, "Critical")
        XCTAssertEqual(rows[2].value.at("health")?.string, "Warning")
    }

    func testPodSummary() {
        let s = W.podSummary(W.podRows(json(pods)))
        XCTAssertEqual(s.total, 3); XCTAssertEqual(s.running, 1); XCTAssertEqual(s.failed, 1)
        XCTAssertEqual(s.pending, 1); XCTAssertEqual(s.restarts, 7); XCTAssertEqual(s.lockedDown, 1)
        XCTAssertEqual(s.namespaces, 2); XCTAssertEqual(s.nodes, 1)
    }

    func testPodHealth() {
        XCTAssertEqual(W.podHealth(phase: "Running", ready: true, restarts: 0), .ok)
        XCTAssertEqual(W.podHealth(phase: "Running", ready: false, restarts: 0), .warn)
        XCTAssertEqual(W.podHealth(phase: "Unknown", ready: true, restarts: 0), .critical)
        XCTAssertEqual(W.podHealth(phase: "Succeeded", ready: false, restarts: 0), .ok)
    }

    func testWorkloadRowsJoinLockdown() {
        let wl = json(#"{"items":[{"uid":"u1","namespace":"shop","pod":"web-1","node":"n1","workloadKind":"Deployment","workloadName":"web","labels":{"app":"web"},"cgroupId":42},{"uid":"u2","namespace":"x","pod":"p"}]}"#)
        let rows = W.workloadRows(workloads: wl, pods: json(pods))
        XCTAssertEqual(rows[0].value.at("owner")?.string, "Deployment/web")
        XCTAssertEqual(rows[0].value.at("lockedDown"), .bool(true))
        XCTAssertEqual(rows[0].value.at("phase")?.string, "Running")
        XCTAssertEqual(rows[1].value.at("lockedDown"), .bool(false))
        let s = W.workloadSummary(rows)
        XCTAssertEqual(s.pods, 2); XCTAssertEqual(s.owners, 1); XCTAssertEqual(s.unowned, 1); XCTAssertEqual(s.lockedDown, 1)
    }

    func testWorkloadRowsWithoutPodsAndEmpty() {
        XCTAssertTrue(W.workloadRows(workloads: nil, pods: nil).isEmpty)
        let rows = W.workloadRows(workloads: json(#"{"items":[{"namespace":"a","pod":"b"}]}"#), pods: nil)
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows[0].value.at("lockedDown"), .bool(false))
    }

    func testPathsEncode() {
        XCTAssertEqual(W.detailPath(kind: "Pod", namespace: "a b", name: "x/y"), "api/v1/workloads/pod/a%20b/x%2Fy")
        XCTAssertEqual(W.logsPath(namespace: "ns", name: "p"), "api/v1/pods/ns/p/logs")
    }

    func testParseLogStream() {
        let sse = "event: ready\ndata: {\"ok\":true}\n\nevent: log\ndata: \"hello \\\"w\\\"\"\n\nevent: log\ndata: \"line2\"\n\nevent: error\ndata: \"boom\"\n\nevent: done\ndata: {}\n\n"
        let r = W.parseLogStream(Data(sse.utf8))
        XCTAssertEqual(r.lines, ["hello \"w\"", "line2"])
        XCTAssertEqual(r.error, "boom")
    }

    func testL7StatusClasses() {
        let rows = W.items(json(#"{"s":[{"status":200,"count":90},{"status":404,"count":6},{"status":503,"count":3},{"status":500,"count":1}]}"#), "s")
        let c = W.httpStatusClasses(rows)
        XCTAssertEqual(c.map(\.name), ["2xx", "4xx", "5xx"])
        XCTAssertEqual(c.last?.count, 4)
        XCTAssertEqual(W.errorRatio(rows), 0.04, accuracy: 1e-9)
        XCTAssertEqual(W.errorRatio([]), 0)
    }

    func testL7RowsWorkloadAndBlocked() {
        let rows = W.l7Rows(W.items(json(#"{"tls":[{"sni":"a.com","handshakes":10,"blocked":5,"namespace":"shop","workloadKind":"Deployment","workloadName":"web"},{"sni":"b.com","handshakes":0}]}"#), "tls"), totalKey: "handshakes")
        XCTAssertEqual(rows[0].value.at("workload")?.string, "shop/Deployment/web")
        XCTAssertEqual(rows[0].value.at("blockedRatio")?.asDouble, 0.5)
        XCTAssertNil(rows[1].value.at("blockedRatio"))
        XCTAssertEqual(rows[1].value.at("workload")?.string, "")
    }

    func testSampledProtocols() {
        let v = json(#"{"protocols":[{"protocol":"redis","role":"served","requests":10,"responses":8,"errors":2,"ops":[{"op":"GET","count":6,"estimated":60},{"op":"SET","count":4,"estimated":40}]},{"protocol":"sql","role":"issued","responses":0,"ops":[{"op":"SELECT","count":1,"estimated":200}]}]}"#)
        let rows = W.sampledProtocolRows(v)
        XCTAssertEqual(rows[0].value.at("errorRatio")?.asDouble, 0.25)
        XCTAssertEqual(rows[1].value.at("errorRatio")?.asDouble, 0)
        XCTAssertEqual(rows[0].value.at("name")?.string, "redis (served)")
        XCTAssertEqual(W.sampledTopOps(v, top: 2).map(\.label), ["sql SELECT", "redis GET"])
    }

    func testTLSVersionAndRows() {
        XCTAssertEqual(W.tlsVersion(0x0303), "TLS 1.2"); XCTAssertEqual(W.tlsVersion(0x0304), "TLS 1.3")
        XCTAssertEqual(W.tlsVersion(0), ""); XCTAssertEqual(W.tlsVersion(0x1234), "0x1234")
        let fps = json(#"{"fingerprints":[{"ja3":"aaaaaaaaaaaaaaaaaaaa","sni":"x.com","version":771,"count":1,"ech":true},{"ja3":"bbbb","sni":"","version":772,"count":50,"quic":true}],"stats":{"enabled":true,"uniqueJa3":2}}"#)
        let risk = json(#"{"items":[{"ja3":"aaaaaaaaaaaaaaaaaaaa","severity":"high","reasons":["rare-fingerprint","ech-extension"]}],"echSightings":1,"rare":1}"#)
        let rows = W.tlsRows(fingerprints: fps, risk: risk)
        XCTAssertEqual(rows[0].value.at("riskLevel")?.string, "Critical")
        XCTAssertEqual(rows[0].value.at("reasons")?.string, "rare-fingerprint, ech-extension")
        XCTAssertEqual(rows[0].value.at("ja3Short")?.string, "aaaaaaaaaaaa")
        XCTAssertEqual(rows[0].value.at("versionText")?.string, "TLS 1.2")
        XCTAssertEqual(rows[1].value.at("riskLevel")?.string, "OK")
        XCTAssertEqual(rows[1].value.at("transport")?.string, "QUIC")
        let s = W.tlsSummary(fingerprints: fps, risk: risk)
        XCTAssertEqual(s.unique, 2); XCTAssertEqual(s.ech, 1); XCTAssertEqual(s.rare, 1); XCTAssertEqual(s.quic, 1)
        XCTAssertEqual(s.missingSNI, 1); XCTAssertEqual(s.observations, 51)
    }

    func testTLSDisabledShape() {
        let off = json(#"{"fingerprints":[],"stats":{"enabled":false,"uniqueJa3":0},"note":"n"}"#)
        XCTAssertFalse(W.tlsSummary(fingerprints: off, risk: nil).enabled)
        XCTAssertTrue(W.tlsRows(fingerprints: off, risk: nil).isEmpty)
    }

    func testLevels() {
        XCTAssertEqual(W.level(severity: "High"), .critical); XCTAssertEqual(W.level(severity: "warning"), .warn)
        XCTAssertEqual(W.level(severity: "low"), .info); XCTAssertEqual(W.level(severity: nil), .ok)
        XCTAssertTrue(W.Level.ok < .critical)
    }

    func testDetectiveRows() {
        let v = json(#"{"summary":{"policyDropPackets":5},"findings":[{"confidence":"exact","code":"port-deny","protocol":6,"direction":1,"src":"1.1.1.1:5","dst":"10.0.0.2:80","packets":5,"namespace":"shop","pod":"web-1"},{"confidence":"probable","code":"reason-99","protocol":17}]}"#)
        let rows = W.detectiveRows(v)
        XCTAssertEqual(rows[0].value.at("protocolName")?.string, "tcp")
        XCTAssertEqual(rows[0].value.at("directionName")?.string, "ingress")
        XCTAssertEqual(rows[0].value.at("workload")?.string, "shop/web-1")
        XCTAssertEqual(rows[1].value.at("directionName")?.string, "egress")
        XCTAssertEqual(rows[1].value.at("protocolName")?.string, "udp")
    }

    func testPathRows() {
        let v = json(#"{"pressure":[{"remoteIp":"10.0.0.9","remotePort":443,"sendCwnd":10,"packetsOut":9},{"remoteIp":"fd00::1","remotePort":80,"sendCwnd":0}],"connect":[{"remoteIp":"1.2.3.4","remotePort":53,"established":4,"totalLatencyUs":8000,"maxLatencyUs":5000},{"remoteIp":"x","established":0}]}"#)
        let p = W.pressureRows(v)
        XCTAssertEqual(p[0].value.at("cwndUse")?.asDouble, 0.9)
        XCTAssertEqual(p[0].value.at("remote")?.string, "10.0.0.9:443")
        XCTAssertEqual(p[1].value.at("remote")?.string, "[fd00::1]:80")
        XCTAssertEqual(p[1].value.at("cwndUse")?.asDouble, 0)
        let c = W.connectRows(v)
        XCTAssertEqual(c[0].value.at("avgMs")?.asDouble, 2)
        XCTAssertEqual(c[0].value.at("maxMs")?.asDouble, 5)
        XCTAssertEqual(c[1].value.at("avgMs")?.asDouble, 0)
    }

    func testIPv6AndKernelAndAnomalies() {
        let v6 = json(#"{"nodes":[{"node":"n1","extHeaders":[{"hook":"tc","direction":"ingress","packets":200,"fragmented":50}]},{"node":"n2"}]}"#)
        let r = W.ipv6Rows(v6)
        XCTAssertEqual(r.count, 1); XCTAssertEqual(r[0].value.at("node")?.string, "n1"); XCTAssertEqual(r[0].value.at("fragmentRatio")?.asDouble, 0.25)
        let k = json(#"{"nodes":[{"node":"n1","findings":[{"severity":"warning","signal":"a","evidence":["x","y"]},{"severity":"critical","signal":"b"}]}]}"#)
        let kr = W.kernelFindingRows(k)
        XCTAssertEqual(kr.map { $0.value.at("signal")?.string }, ["b", "a"])      // most severe first
        XCTAssertEqual(kr[1].value.at("evidenceText")?.string, "x\ny")
        XCTAssertEqual(W.worstLevel(kr), .critical)
        let an = W.anomalyRows(json(#"{"summary":{"anomalies":[{"severity":"info","message":"m"},{"severity":"high","message":"h"}]}}"#))
        XCTAssertEqual(an.first?.value.at("message")?.string, "h")
        XCTAssertEqual(W.worstLevel([]), .ok)
    }

    func testCountBy() {
        let rows = W.podRows(json(pods))
        let c = W.countBy(rows, path: "namespace")
        XCTAssertEqual(c.first?.name, "batch"); XCTAssertEqual(c.first?.count, 2)
        XCTAssertEqual(W.countBy(rows, path: "node").first?.name, "(none)")
    }

    func testGarbageInputsDoNotCrash() {
        for v in [JSONValue.null, .string("x"), .array([.null, .number(1)]), .object([:])] {
            _ = W.podRows(v); _ = W.workloadRows(workloads: v, pods: v); _ = W.tlsRows(fingerprints: v, risk: v)
            _ = W.detectiveRows(v); _ = W.pressureRows(v); _ = W.connectRows(v); _ = W.ipv6Rows(v)
            _ = W.kernelFindingRows(v); _ = W.anomalyRows(v); _ = W.sampledProtocolRows(v); _ = W.tlsSummary(fingerprints: v, risk: v)
        }
    }

    // Fixtures below copy the Go json tags: tlsfp.Observation (embedded Fingerprint flattens), RiskItem, DropDetectiveFinding.
    func testGoShapedTLSObservation() {
        let fps = json(#"{"fingerprints":[{"ja3":"e7d705a3286e19ea42f587b344ee6865","ja3Raw":"771,4865","ja4":"t13d1516h2_8daaf6152771_b0da82dd1658","version":771,"sni":"api.example.com","alpn":"h2","ciphers":[4865],"exts":[0],"curves":[29],"sigAlgs":[1027],"node":"n1","firstSeen":"2026-01-01T00:00:00Z","lastSeen":"2026-01-02T00:00:00Z","count":12}],"stats":{"enabled":true,"uniqueJa3":1,"cap":2048},"note":"n"}"#)
        let rows = W.tlsRows(fingerprints: fps, risk: json(#"{"items":[],"count":0,"uniqueJa3":1,"echSightings":0,"rare":0,"note":""}"#))
        let v = rows[0].value
        for k in ["ja4", "sni", "alpn", "node", "ja3Short", "versionText", "riskLevel", "transport"] {
            XCTAssertFalse(CellFormat.text(v.at(k), .text).isEmpty, k)
        }
        XCTAssertEqual(CellFormat.text(v.at("count"), .int), "12")
        XCTAssertFalse(CellFormat.text(v.at("lastSeen"), .time).isEmpty)
        XCTAssertEqual(W.tlsSummary(fingerprints: fps, risk: nil).observations, 12)
    }

    func testGoShapedDetectiveRankSortable() {
        let v = json(#"{"summary":{"text":"t","policyDropPackets":5,"policyDropFlows":1,"conntrackEntries":0,"exactFindings":1,"probableFindings":1},"findings":[{"node":"n1","confidence":"probable","code":"c","stage":"s","reason":2,"packets":3,"explanation":"e"},{"confidence":"exact","code":"d","stage":"s","reason":1,"protocol":6,"direction":1,"packets":9,"bytes":100,"explanation":"e","pid":4,"comm":"curl","namespace":"a","pod":"p","attributionState":"ok"}]}"#)
        let rows = W.detectiveRows(v)
        XCTAssertEqual(rows[0].value.at("levelRank")?.asDouble, 1)   // probable = info
        XCTAssertEqual(rows[1].value.at("levelRank")?.asDouble, 2)
        XCTAssertEqual(CellFormat.text(rows[1].value.at("bytes"), .bytes), "100 B")
        XCTAssertEqual(rows[1].value.at("workload")?.string, "a/p")
    }
}
