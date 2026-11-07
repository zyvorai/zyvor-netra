// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import XCTest
@testable import NetraKit

final class MetricsTests: XCTestCase {
    func dec<T: Decodable>(_ s: String) throws -> T { try JSONDecoder().decode(T.self, from: Data(s.utf8)) }

    func testResultWithNullValues() throws {
        let r: MetricResult = try dec(#"{"context":"net.bytes","units":"B/s","tier":0,"interval":1,"after":1,"before":4,"timestamps":[1,2,3],"dimensions":[{"name":"rx","values":[1.5,null,3],"anomalyRate":[0,0,null],"series":2}],"matched":2}"#)
        XCTAssertEqual(r.dimensions[0].values, [1.5, nil, 3])
        XCTAssertEqual(MetricsFormat.nearestIndex(r.timestamps, to: 2.6), 2)
        XCTAssertNil(MetricsFormat.nearestIndex([], to: 1))
    }

    func testContextsAndNullSlices() throws {
        let c: MetricContextsResponse = try dec(#"{"contexts":[{"context":"a.b","title":"AB","charts":null,"firstT":1,"lastT":2},{"context":"c","charts":[{"node":"n1","chart":"x","dimensions":["d"]}]}],"count":2}"#)
        XCTAssertEqual(c.contexts[0].charts, [])
        XCTAssertEqual(c.contexts[1].charts[0].dimensions, ["d"])
    }

    func testAnomaliesSeverity() throws {
        let s: AnomalySummary = try dec(#"{"after":1,"before":2,"nodes":[{"node":"n","anomalyRate":4.2,"dimensions":10,"anomalousDimensions":1}],"ranked":[{"node":"n","context":"c","chart":"ch","dimension":"d","anomalyRate":60,"score":60},{"node":"n","context":"c","chart":"ch","dimension":"e","anomalyRate":12,"score":12},{"node":"n","context":"c","chart":"ch","dimension":"f","anomalyRate":1,"score":1}]}"#)
        XCTAssertEqual(s.ranked.map(\.severity), [.high, .elevated, .low])
        XCTAssertEqual(s.correlated, [])
    }

    func testAlertSnapshot() throws {
        let s: MetricAlertSnapshot = try dec(#"{"active":[{"id":"ab12","rule":"r","node":"n","chart":"c","status":"critical","value":9.5,"since":"2026-01-02T03:04:05.123456789Z","acked":true,"ackedBy":"bob"}],"history":null,"rules":[{"name":"r","context":"x"}],"silences":[{"id":"s1","rule":"r*","until":"2026-01-02T05:00:00Z","createdBy":"op","created":"2026-01-02T03:00:00Z"}],"stats":{"rules":1,"instances":1,"warning":0,"critical":1}}"#)
        XCTAssertEqual(s.active[0].ackedBy, "bob"); XCTAssertEqual(s.history, [])
        XCTAssertEqual(s.silences[0].id, "s1")
        XCTAssertNotNil(MetricsFormat.parseTime(s.active[0].since))
    }

    func testEvidenceAndSummary() throws {
        let e: MetricEvidence = try dec(#"{"context":"c","kinds":["drops"],"links":[{"kind":"drops","title":"T","href":"/x","why":"w"}],"flowRecords":3,"topPeers":[{"peer":"1.2.3.4","port":80,"protocol":"tcp","packets":1,"bytes":2}],"limitations":["l"]}"#)
        XCTAssertEqual(e.topPeers[0].protocolName, "tcp"); XCTAssertEqual(e.kernelDrops, [])
        let m: MetricsSummary = try dec(#"{"available":true,"nodes":2,"series":9,"anomalyRate":1.5,"topAlerts":null,"topAnomalous":[]}"#)
        XCTAssertEqual(m.nodes, 2); XCTAssertEqual(m.topAlerts, [])
    }

    func testRequestsAreLocalAndShaped() {
        let c = NetraClient(profile: .init(baseURL: URL(string: "http://127.0.0.1:8080")!, token: nil))
        let r = c.request("POST", "api/v1/metrics/alerts/ab12/ack")
        XCTAssertEqual(r.url?.absoluteString, "http://127.0.0.1:8080/api/v1/metrics/alerts/ab12/ack")
        XCTAssertEqual(MetricsFormat.value(1500, units: "B/s"), "1.50k B/s")
        XCTAssertEqual(MetricRange.h1.seconds, 3600)
    }
}
