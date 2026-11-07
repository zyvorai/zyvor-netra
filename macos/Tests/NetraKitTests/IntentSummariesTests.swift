// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class IntentSummariesTests: XCTestCase {
    private func lease(_ json: String) throws -> LeaseStatus {
        try JSONDecoder.netra.decode(LeaseStatus.self, from: Data(json.utf8))
    }
    private func alerts(_ json: String) throws -> MetricAlertSnapshot {
        try JSONDecoder().decode(MetricAlertSnapshot.self, from: Data(json.utf8))
    }
    private let snap = #"{"active":[{"id":"a1","rule":"r","node":"n","chart":"c","status":"critical"},{"id":"a2","rule":"r","node":"n","chart":"c","status":"warning"},{"id":"a3","rule":"r","node":"n","chart":"c","status":"critical","silenced":true},{"id":"a4","rule":"r","node":"n","chart":"c","status":"clear"}],"history":[],"rules":[],"silences":[]}"#

    func testObserveNoLease() throws {
        let l = try lease(#"{"mode":"observe","remainingSeconds":0,"active":false,"expired":false}"#)
        XCTAssertEqual(IntentSummaries.modeAndLease(l), "Netra is in observe mode (no active lease).")
    }
    func testEnforceLease() throws {
        let l = try lease(#"{"mode":"enforce","leaseSeconds":600,"remainingSeconds":245,"active":true,"expired":false}"#)
        XCTAssertEqual(IntentSummaries.modeAndLease(l), "Netra is in enforce mode, lease 4m 5s left.")
    }
    func testExpiredLease() throws {
        let l = try lease(#"{"mode":"enforce","remainingSeconds":0,"active":false,"expired":true}"#)
        XCTAssertTrue(IntentSummaries.modeAndLease(l).contains("fails open to observe"))
    }
    func testDurationFormats() {
        XCTAssertEqual(IntentSummaries.duration(45), "45s")
        XCTAssertEqual(IntentSummaries.duration(3700), "1h 1m")
        XCTAssertEqual(IntentSummaries.duration(-5), "0s")
    }
    func testAlertCountIgnoresSilencedAndClear() throws {
        XCTAssertEqual(IntentSummaries.activeAlertCount(try alerts(snap)), 2)
    }
    func testAlertSummaryText() throws {
        XCTAssertEqual(IntentSummaries.alertSummary(try alerts(snap)), "2 active metric alerts: 1 critical, 1 warning.")
        XCTAssertEqual(IntentSummaries.alertSummary(try alerts(#"{"active":[]}"#)), "No active metric alerts.")
    }
    func testTopTalkersFromGoShape() throws {
        let v = try JSONDecoder().decode(JSONValue.self, from: Data(#"{"count":3,"rows":[{"destination":"10.0.0.5","packets":100,"bytes":9000,"blocked":10,"nodes":2},{"destination":"1.1.1.1","packets":500,"blocked":0},{"packets":9}]}"#.utf8))
        let text = IntentSummaries.topTalkers(TrafficData.talkerBars(v))
        XCTAssertEqual(text, "Top talkers:\n1. 1.1.1.1 (500 packets)\n2. 10.0.0.5 (100 packets, 10 blocked)")
    }
    func testTopTalkersLimitAndEmpty() {
        XCTAssertEqual(IntentSummaries.topTalkers([]), "No talkers reported.")
        let bars = (1...9).map { RankedBar(label: "h\($0)", value: Double($0)) }
        XCTAssertEqual(IntentSummaries.topTalkers(bars, limit: 2).split(separator: "\n").count, 3)
    }
}
