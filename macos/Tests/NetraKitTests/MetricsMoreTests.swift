// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class MetricsMoreTests: XCTestCase {
    func testLabelsParam() {
        XCTAssertNil(MetricsMore.labelsParam([:]))
        XCTAssertEqual(MetricsMore.labelsParam(["pod": "web-1", "namespace": "prod"]), "namespace:prod,pod:web-1")
        XCTAssertEqual(MetricsMore.labelsParam(["bad,key": "x", "ok": "1"]), "ok:1")
    }

    func testFleetDecodes() throws {
        let j = #"{"generatedAt":"2026-01-01T00:00:00Z","clusters":[{"name":"a","local":true,"ok":true,"summary":{"available":true,"nodes":3,"series":10,"anomalyRate":1.5,"alertsCritical":1,"alertsWarning":0,"topAlerts":null,"topAnomalous":null}},{"name":"b","url":"https://b","ok":false,"error":"timeout"}],"totals":{"clusters":2,"okClusters":1,"nodes":3,"series":10,"anomalyRate":1.5,"alertsCritical":1,"alertsWarning":0},"note":"n"}"#
        let f = try JSONDecoder().decode(MetricsFleet.self, from: Data(j.utf8))
        XCTAssertEqual(f.clusters.count, 2)
        XCTAssertEqual(f.clusters[0].summary?.nodes, 3)
        XCTAssertEqual(f.clusters[1].error, "timeout")
        XCTAssertEqual(f.totals?.okClusters, 1)
    }

    func testGroupByFamilyPutsOtherLast() throws {
        func ctx(_ n: String, _ f: String?) throws -> MetricContext {
            try JSONDecoder().decode(MetricContext.self, from: Data(#"{"context":"\#(n)"\#(f.map { ",\"family\":\"\($0)\"" } ?? "")}"#.utf8))
        }
        let g = MetricsMore.groupByFamily([try ctx("z", nil), try ctx("b.x", "net"), try ctx("a.y", "cpu"), try ctx("a.x", "net")])
        XCTAssertEqual(g.map(\.family), ["cpu", "net", "other"])
        XCTAssertEqual(g[1].contexts.map(\.context), ["a.x", "b.x"])
    }

    func testStale() throws {
        let n = try JSONDecoder().decode(MetricNodeInfo.self, from: Data(#"{"node":"n","lastIngest":"2026-01-01T00:00:00Z"}"#.utf8))
        let t = MetricsFormat.parseTime("2026-01-01T00:00:00Z")!
        XCTAssertFalse(MetricsMore.isStale(n, now: t.addingTimeInterval(60)))
        XCTAssertTrue(MetricsMore.isStale(n, now: t.addingTimeInterval(300)))
    }
}
