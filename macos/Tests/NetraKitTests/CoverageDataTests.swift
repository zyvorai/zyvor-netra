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


// Fixtures copy the Go tags (internal/models CapChangeEvent/ExeHashChangeEvent/NamespaceChangeEvent, scandetect, automitigate,
// fleet.FlowRollup, flowlog.Record, metricexport.Status, denycensus, ebpf stack-histograms, l7SampleView).
extension CoverageDataTests {
    func testGoShapedProcessDriftScanAndPreview() {
        let ns = CoverageData.nsEventRows(json(#"{"anomalies":[],"events":[{"pid":1,"comm":"c","exe":"/x","previousNetNs":4026531840,"currentNetNs":4026532000,"namespace":"d","pod":"p"}]}"#))
        XCTAssertEqual(ns[0].value.at("previousNetNs")?.asDouble, 4026531840); XCTAssertEqual(CellFormat.text(ns[0].value.at("currentNetNs"), .int), "4026532000")
        let exe = CoverageData.exeEventRows(json(#"{"anomalies":[],"events":[{"pid":2,"exe":"/bin/sh","previousExeHash":"aaaaaaaaaaaaaaaabbbb","currentExeHash":"cccccccccccccccc","workloadKind":"Deployment","workloadName":"w"}]}"#))
        XCTAssertEqual(exe[0].value["previousShort"]?.string, "aaaaaaaaaaaa"); XCTAssertEqual(exe[0].value["workload"]?.string, "Deployment/w")
        let scan = json(#"{"findings":[{"id":"f1","type":"port-scan","severity":"high","score":7.5,"signals":["s"],"namespace":"d","pod":"p","uniqueDstIps":3,"uniqueDstPorts":40,"attempts":100,"synOnly":90,"resets":2,"firstSeen":"2026-11-07T09:00:00Z","lastSeen":"2026-11-07T10:00:00.1234Z"}],"snapshot":{"attemptsSeen":100,"workloadsTracked":2,"activeFindings":1,"findingsTotal":{"port-scan":3}}}"#)
        let f = scan.rows(at: "findings", idKeys: ["id"])[0].value
        XCTAssertEqual(CellFormat.text(f.at("uniqueDstIps"), .int), "3"); XCTAssertEqual(CellFormat.text(f.at("score"), .number(1)), "7.5")
        XCTAssertFalse(CellFormat.text(f.at("lastSeen"), .time).isEmpty)
        XCTAssertEqual(CoverageData.int(scan.at("snapshot.activeFindings")), 1); XCTAssertEqual(CoverageData.findingTotals(scan).first?.count, 3)
        let pv = json(#"{"enabled":true,"leaseActive":false,"mode":"shadow","candidates":[{"kind":"syn_drop","target":"1.2.3.4","findingId":"f1","detail":"d"},{"kind":"conn_rate","target":"w","skipped":"cooldown"}],"wouldActCount":1,"skippedRecent":1,"note":"n","caveat":"c"}"#)
        XCTAssertEqual(CoverageData.candidateSplit(pv).wouldAct, 1); XCTAssertEqual(CoverageData.candidateSplit(pv).skipped, 1)
        XCTAssertEqual(CoverageData.notes(pv), ["n", "c"])
    }

    func testGoShapedFleetExportersCensusStacks() {
        let fl = json(#"{"generatedAt":"2026-11-07T10:00:00Z","records":[{"observedAt":"2026-11-07T09:59:00.999999999Z","node":"n1","namespace":"d","pod":"p","workloadName":"w","peer":"8.8.8.8","port":443,"protocol":"tcp","direction":"egress","appProtocol":"tls","packets":10,"bytes":2048,"blocked":1,"retransmissions":2,"comm":"curl"}],"matched":1,"clusters":[{"name":"a","local":true,"ok":true,"matched":1},{"name":"b","ok":false,"error":"timeout"}],"limitations":["l"]}"#)
        let rec = fl.rows(at: "records", idKeys: ["peer"])[0].value
        XCTAssertEqual(CellFormat.text(rec.at("bytes"), .bytes), "2.0 KB"); XCTAssertEqual(CellFormat.text(rec.at("retransmissions"), .int), "2")
        XCTAssertFalse(CellFormat.text(rec.at("observedAt"), .time).isEmpty)
        XCTAssertEqual(CoverageData.clusterHealth(fl).ok, 1); XCTAssertEqual(CoverageData.clusterHealth(fl).failed, 1)
        let ex = json(#"{"exporters":[{"sink":"prom-rw","pointsSent":120,"batches":4,"failures":1,"lastError":"e","lastSend":"2026-11-07T10:00:00Z","resolution":"1s"}]}"#)
        XCTAssertEqual(CoverageData.exporterTotals(ex).sent, 120); XCTAssertEqual(CoverageData.exporterTotals(ex).failures, 1)
        XCTAssertEqual(CellFormat.text(ex.rows(at: "exporters")[0].value.at("batches"), .int), "4")
        let cen = CoverageData.censusGroups(json(#"{"generatedAt":"2026-11-07T10:00:00Z","mode":"shadow","blockedIPv4":3,"blockedIPv6":0,"blockedCidrs":1,"blockedPorts":2,"blockedDns":0,"blockedUids":0,"blockedIngressIPv4":4,"blockedIngressIPv6":0,"allowedIPv4":5,"allowedIPv6":0,"allowedCidrs":0,"allowedPorts":0,"totalDenied":10,"totalAllowed":5}"#))
        XCTAssertEqual(cen[0].items.first { $0.label == "IPv4" }?.value, "3"); XCTAssertEqual(cen[0].items.first { $0.label == "Ingress IPv4" }?.value, "4")
        XCTAssertEqual(cen[0].items.last?.value, "10"); XCTAssertEqual(cen[1].items.last?.value, "5")
        let st = json(#"{"nodes":[{"node":"n1","softirqNetRx":5,"listenDepthBuckets":[{"label":"0","count":3},{"label":"1-8","count":1}],"topListeners":[{"family":"ipv4","addr":"0.0.0.0","port":80,"queue":1,"max":128,"peak":2,"peakPct":1}]}]}"#)
        XCTAssertEqual(CoverageData.depthBuckets(st.rows(at: "nodes")[0].value).map(\.count), [3, 1])
        let sp = CoverageData.sparkline(json(#"{"node":"n1","windows":[{"node":"n1","startAt":"2026-11-07T09:59:50Z","endAt":"2026-11-07T10:00:00Z","seconds":10,"warming":false,"softnetDroppedPerSecond":1.5}]}"#), field: "softnetDroppedPerSecond")
        XCTAssertEqual(sp.count, 1); XCTAssertEqual(sp[0].value, 1.5)
        XCTAssertEqual(CoverageData.errorRatio(json(#"{"protocol":"http","role":"served","requests":5,"responses":10,"errors":2,"estimatedRequests":50}"#)), 0.2)
    }
}
