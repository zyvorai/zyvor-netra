// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class TrafficDataTests: XCTestCase {
    private func json(_ s: String) -> JSONValue { try! JSONDecoder().decode(JSONValue.self, from: Data(s.utf8)) }

    // Shapes from internal/talkers, portheat, protomix, dnsboard.
    private let talkers = #"{"generatedAt":"2026-11-07T10:00:00Z","count":3,"rows":[{"destination":"10.0.0.5","packets":100,"bytes":9000,"blocked":10,"nodes":2},{"destination":"1.1.1.1","packets":500,"bytes":1,"blocked":0,"nodes":1},{"packets":9}]}"#

    func testTalkerBarsRankedAndSkipUnlabelled() {
        let bars = TrafficData.talkerBars(json(talkers))
        XCTAssertEqual(bars.map(\.label), ["1.1.1.1", "10.0.0.5"])
        XCTAssertEqual(bars[1].blocked, 10)
        XCTAssertEqual(bars[1].allowed, 90)
    }

    func testSumAndTop() {
        let v = json(talkers)
        XCTAssertEqual(TrafficData.sum(v, key: "packets"), 609)
        XCTAssertEqual(TrafficData.talkerBars(v, top: 1).count, 1)
        XCTAssertEqual(TrafficData.sum(json("{}"), key: "packets"), 0)
    }

    func testPortBarsLabelAndFallbackKey() {
        let v = json(#"{"rows":[{"port":443,"protocol":"tcp","key":"tcp/443","packets":50,"blocked":5,"flows":3},{"key":"udp/53","packets":70}]}"#)
        XCTAssertEqual(TrafficData.portBars(v).map(\.label), ["udp/53", "tcp/443"])
    }

    func testDNSBarsPreferFailures() {
        let v = json(#"{"queries":10,"failures":3,"rows":[{"name":"a.io","queries":9,"failures":0,"failRate":0},{"name":"b.io","queries":1,"failures":3,"failRate":1}]}"#)
        XCTAssertEqual(TrafficData.dnsBars(v).first?.label, "b.io")
        let q = json(#"{"rows":[{"name":"a.io","queries":9,"failures":0},{"name":"c.io","queries":20,"failures":0}]}"#)
        XCTAssertEqual(TrafficData.dnsBars(q).first?.label, "c.io")
    }

    func testKernelReasonsAggregateAcrossNodes() {
        let v = json(#"{"summary":{},"nodes":[{"node":"a","kernelDrops":[{"reason":2,"reasonName":"NO_SOCKET","count":5},{"reason":9,"count":1}]},{"node":"b","kernelDrops":[{"reason":2,"reasonName":"NO_SOCKET","count":7}]},{"node":"c"}]}"#)
        let bars = TrafficData.kernelReasonBars(v)
        XCTAssertEqual(bars.map(\.label), ["NO_SOCKET", "reason #9"])
        XCTAssertEqual(bars[0].value, 12)
    }

    func testSeverityAndFormatting() {
        XCTAssertGreaterThan(TrafficData.severityRank("critical"), TrafficData.severityRank("warning"))
        XCTAssertEqual(TrafficData.severityRank("exact"), 3)
        XCTAssertEqual(TrafficData.severityRank(nil), 0)
        XCTAssertEqual(TrafficData.dnsHealth(failRate: 0.5), "high")
        XCTAssertEqual(TrafficData.dnsHealth(failRate: 0.1), "elevated")
        XCTAssertEqual(TrafficData.dnsHealth(failRate: 0), "ok")
        XCTAssertEqual(TrafficData.compact(999), "999")
        XCTAssertEqual(TrafficData.compact(1500), "1.5K")
        XCTAssertEqual(TrafficData.compact(2_500_000), "2.5M")
        XCTAssertEqual(TrafficData.percent(1, of: 4), "25.0%")
        XCTAssertEqual(TrafficData.percent(1, of: 0), "–")
    }
}
