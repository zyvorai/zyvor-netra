// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class AlertWatcherTests: XCTestCase {
    private func alert(_ id: String, status: String = "critical", acked: Bool? = nil, silenced: Bool? = nil) throws -> MetricAlert {
        let json = """
        {"id":"\(id)","rule":"r-\(id)","node":"n1","chart":"c","status":"\(status)"\(acked == true ? ",\"acked\":true" : "")\(silenced == true ? ",\"silenced\":true" : "")}
        """
        return try JSONDecoder().decode(MetricAlert.self, from: Data(json.utf8))
    }

    func testFirstPollPrimesThenOnlyNewAlertsFire() throws {
        var w = AlertWatcher()
        XCTAssertTrue(w.ingest(alerts: [try alert("a1")]).isEmpty)
        XCTAssertTrue(w.ingest(alerts: [try alert("a1")]).isEmpty)
        let ev = w.ingest(alerts: [try alert("a1"), try alert("a2", status: "warning")])
        XCTAssertEqual(ev.count, 1)
        XCTAssertEqual(ev[0].alertID, "a2")
        XCTAssertEqual(ev[0].category, .alerts)
        XCTAssertFalse(ev[0].body.contains("c"), "body is node only")
    }

    func testAckedSilencedAndClearIgnoredAndReraiseFires() throws {
        var w = AlertWatcher()
        _ = w.ingest(alerts: [])
        let ev = w.ingest(alerts: [try alert("a1", acked: true), try alert("a2", silenced: true), try alert("a3", status: "clear")])
        XCTAssertTrue(ev.isEmpty)
        XCTAssertEqual(w.ingest(alerts: [try alert("a4")]).count, 1)
        _ = w.ingest(alerts: [])                       // resolved
        XCTAssertEqual(w.ingest(alerts: [try alert("a4")]).count, 1)  // raised again
    }

    func testEscalationNotifiesAndCapSummarises() throws {
        var w = AlertWatcher(maxPerTick: 3)
        _ = w.ingest(alerts: [try alert("a1", status: "warning")])
        XCTAssertEqual(w.ingest(alerts: [try alert("a1", status: "critical")]).count, 1)
        let many = try (10..<20).map { try alert("x\($0)") }
        let ev = w.ingest(alerts: many)
        XCTAssertEqual(ev.count, 3)
        XCTAssertNil(ev.last?.alertID)
        XCTAssertTrue(ev.last?.title.contains("more") ?? false)
    }

    func testUnsafeAlertIDIsDropped() throws {
        var w = AlertWatcher()
        _ = w.ingest(alerts: [])
        XCTAssertTrue(w.ingest(alerts: [try alert("../x")]).isEmpty)
    }

    func testIncidentsAndIntelDedupe() {
        var w = AlertWatcher()
        func inc(_ k: String, _ sev: String) -> DetectData.Incident { .init(sourceKey: k, subject: "ns/pod", severity: sev, findings: []) }
        func hit(_ v: String) -> DetectData.IntelHit {
            .init(id: 0, type: "ip", value: v, kind: "", node: "n1", namespace: "", pod: "", subject: "", packets: 1, blocked: 0)
        }
        XCTAssertTrue(w.ingest(incidents: [inc("a", "high")]).isEmpty)
        XCTAssertEqual(w.ingest(incidents: [inc("a", "high"), inc("b", "critical")]).map(\.severity), ["critical"])
        XCTAssertEqual(w.ingest(incidents: [inc("a", "critical"), inc("b", "critical")]).count, 1)  // escalation
        func intel(_ h: [DetectData.IntelHit]) -> DetectData.IntelHits { .init(hits: h, checked: 0, capped: false, note: "") }
        XCTAssertTrue(w.ingest(intel: intel([hit("1.1.1.1")])).isEmpty)
        let ev = w.ingest(intel: intel([hit("1.1.1.1"), hit("2.2.2.2")]))
        XCTAssertEqual(ev.count, 1)
        XCTAssertFalse(ev[0].body.contains("2.2.2.2"))
    }

    func testLeaseSoonThenExpiredOnce() {
        var w = AlertWatcher(leaseWarnSeconds: 120)
        let now = Date(timeIntervalSince1970: 1_000_000)
        let exp = now.addingTimeInterval(300)
        func lease(active: Bool, expired: Bool = false, mode: String = "enforce") -> LeaseStatus {
            .init(mode: mode, scopeMode: nil, leaseExpiresAt: exp, leaseSeconds: nil, remainingSeconds: 0, active: active, expired: expired, note: nil)
        }
        XCTAssertTrue(w.ingest(lease: lease(active: true), now: now).isEmpty)
        let soon = w.ingest(lease: lease(active: true), now: now.addingTimeInterval(200))
        XCTAssertEqual(soon.count, 1)
        XCTAssertTrue(w.ingest(lease: lease(active: true), now: now.addingTimeInterval(210)).isEmpty)
        let gone = w.ingest(lease: lease(active: false, expired: true, mode: "observe"), now: now.addingTimeInterval(400))
        XCTAssertEqual(gone.count, 1)
        XCTAssertEqual(gone[0].title, "Enforce lease expired")
        XCTAssertTrue(w.ingest(lease: lease(active: false, expired: true, mode: "observe"), now: now.addingTimeInterval(410)).isEmpty)
    }
}
