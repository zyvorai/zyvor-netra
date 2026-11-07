// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
import Foundation
@testable import NetraKit

final class CoverageDataTests: XCTestCase {
    private func json(_ s: String) -> JSONValue { try! JSONDecoder().decode(JSONValue.self, from: Data(s.utf8)) }

    func testFeatureOffStatuses() {
        XCTAssertTrue(CoverageData.isFeatureOff(status: 409))
        XCTAssertTrue(CoverageData.isFeatureOff(status: 503))
        XCTAssertFalse(CoverageData.isFeatureOff(status: 400))
        XCTAssertTrue(CoverageData.friendlyError(status: 503, message: "metrics are disabled", feature: "Metric exporters").contains("not enabled"))
        XCTAssertTrue(CoverageData.friendlyError(status: 502, message: "kube", feature: "Policy review").contains("cannot reach"))
    }

    func testCapabilityNamesAndGainedLost() {
        XCTAssertEqual(CoverageData.capabilities((1 << 12) | (1 << 13)), ["CAP_NET_ADMIN", "CAP_NET_RAW"])
        let v = json(#"{"events":[{"pid":7,"comm":"nc","namespace":"web","pod":"p1","previousCapEff":8192,"currentCapEff":12288}]}"#)
        let r = CoverageData.capEventRows(v)
        XCTAssertEqual(r.count, 1)
        XCTAssertEqual(r[0].value["gained"]?.string, "CAP_NET_ADMIN")
        XCTAssertEqual(r[0].value["lost"]?.string, "")
        XCTAssertEqual(r[0].value["currentHex"]?.string, "0x3000")
        XCTAssertEqual(r[0].value["workload"]?.string, "web/p1")
    }

    func testExeAndNamespaceRows() {
        let e = CoverageData.exeEventRows(json(#"{"events":[{"pid":1,"workloadKind":"Deployment","workloadName":"api","previousExeHash":"abcdef0123456789ffff","currentExeHash":"00"}]}"#))
        XCTAssertEqual(e[0].value["previousShort"]?.string, "abcdef012345")
        XCTAssertEqual(e[0].value["workload"]?.string, "Deployment/api")
        XCTAssertEqual(CoverageData.nsEventRows(json(#"{"events":[]}"#)).count, 0)
    }

    func testBaselineInfoCapturedAndNot() {
        XCTAssertFalse(CoverageData.baselineInfo(json(#"{"captured":false,"baseline":null}"#)).captured)
        let b = CoverageData.baselineInfo(json(#"{"captured":true,"baseline":{"schemaVersion":1,"capturedAt":"2026-01-01T00:00:00Z","windowSeconds":300,"entries":[{"source":"a"},{"source":"b"}]}}"#))
        XCTAssertTrue(b.captured); XCTAssertEqual(b.entries, 2); XCTAssertEqual(b.windowSeconds, 300)
    }

    func testTraceStatsAndRecommendations() {
        let t = CoverageData.traceStats(json(#"{"spans":[{"traceId":"a","inferred":true},{"traceId":"a","inferred":false},{"traceId":"b","inferred":true}]}"#))
        XCTAssertEqual(t.traces, 2); XCTAssertEqual(t.spans, 3); XCTAssertEqual(t.inferred, 2)
        let r = CoverageData.recommendations(json(#"{"items":[{"id":"x1","namespace":"web","workloadName":"api"},{"namespace":"n"}]}"#))
        XCTAssertEqual(r, [.init(id: "x1", label: "web/api")])
    }

    func testPlanItemsOmitManifest() {
        let v = json(#"{"plan":{"namespace":"web","name":"p","exists":true,"risk":"high","currentEgressRules":2,"proposedEgressRules":5,"selectorChanged":false,"specChanged":true},"recommendation":{"manifest":{"secret":"x"}}}"#)
        let items = CoverageData.planItems(v)
        XCTAssertEqual(items.first { $0.label == "Risk" }?.value, "high")
        XCTAssertEqual(items.first { $0.label == "Policy" }?.value, "web/p")
        XCTAssertFalse(items.contains { $0.value.contains("secret") })
    }

    func testScanAndPreview() {
        let v = json(#"{"findings":[],"snapshot":{"findingsTotal":{"syn_flood":2,"port_scan":1}}}"#)
        XCTAssertEqual(CoverageData.findingTotals(v).map(\.type), ["port_scan", "syn_flood"])
        let p = json(#"{"candidates":[{"kind":"conn_rate"},{"kind":"shield","skipped":"no active enforce lease"}]}"#)
        let s = CoverageData.candidateSplit(p)
        XCTAssertEqual(s.wouldAct, 1); XCTAssertEqual(s.skipped, 1)
    }

    func testCensusGroupsAndBuckets() {
        let g = CoverageData.censusGroups(json(#"{"blockedIPv4":3,"totalDenied":9,"allowedPorts":2}"#))
        XCTAssertEqual(g[0].items.first { $0.label == "IPv4" }?.value, "3")
        XCTAssertEqual(g[0].items.last?.value, "9")
        XCTAssertEqual(g[1].items.first { $0.label == "Ports" }?.value, "2")
        XCTAssertEqual(CoverageData.depthBuckets(json(#"{"listenDepthBuckets":[{"label":"0","count":4},{"label":"1-8","count":1}]}"#)).map(\.count), [4, 1])
    }

    func testSparklineSortedAndSkipsBadWindows() {
        let v = json(#"{"windows":[{"endAt":"2026-01-01T00:02:00Z","rxDroppedPerSecond":2},{"endAt":"2026-01-01T00:01:00Z","rxDroppedPerSecond":1},{"rxDroppedPerSecond":9}]}"#)
        XCTAssertEqual(CoverageData.sparkline(v, field: "rxDroppedPerSecond").map(\.value), [1, 2])
        XCTAssertEqual(CoverageData.nodeNames(json(#"{"items":[{"node":"b"},{"node":"a"},{"node":"a"}]}"#)), ["a", "b"])
    }

    func testErrorRatioAndTotals() {
        XCTAssertEqual(CoverageData.errorRatio(json(#"{"responses":10,"errors":2}"#)) ?? -1, 0.2, accuracy: 1e-9)
        XCTAssertNil(CoverageData.errorRatio(json(#"{"responses":0,"errors":2}"#)))
        XCTAssertEqual(CoverageData.clusterHealth(json(#"{"clusters":[{"ok":true},{"ok":false}]}"#)).failed, 1)
        let t = CoverageData.exporterTotals(json(#"{"exporters":[{"pointsSent":5,"failures":1},{"pointsSent":7,"failures":0}]}"#))
        XCTAssertEqual(t.sent, 12); XCTAssertEqual(t.failures, 1)
    }

    func testFlowQueryClampsAndDropsBlanks() {
        let q = CoverageData.flowQuery(since: "1h", limit: 99999, namespace: " web ", pod: "", peer: " ")
        XCTAssertEqual(q.map(\.name), ["since", "limit", "namespace"])
        XCTAssertEqual(q[1].value, "2000"); XCTAssertEqual(q[2].value, "web")
    }

    func testNotesCollectsStringsAndArrays() {
        let n = CoverageData.notes(json(#"{"limitations":["a","b"],"note":"c","caveat":""}"#))
        XCTAssertEqual(n, ["a", "b", "c"])
    }
}
