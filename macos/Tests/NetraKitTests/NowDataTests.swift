// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import XCTest
@testable import NetraKit

final class NowDataTests: XCTestCase {
    private func j(_ s: String) -> JSONValue { try! JSONDecoder().decode(JSONValue.self, from: Data(s.utf8)) }

    func testSeverityMapping() {
        XCTAssertEqual(NowSeverity("pass"), .ok)
        XCTAssertEqual(NowSeverity("page"), .high)
        XCTAssertEqual(NowSeverity("ticket"), .warning)
        XCTAssertEqual(NowSeverity("FAIL"), .critical)
        XCTAssertEqual(NowSeverity("weird"), .unknown)
        XCTAssertEqual(NowSeverity(nil), .unknown)
        XCTAssertTrue(NowSeverity.critical > .warning)
    }

    func testHealthAggregation() {
        let h = j(#"""
        {"summary":{"healthScore":72,"anomalies":[{"severity":"warning","kind":"a"},{"severity":"critical","kind":"b"},{"severity":"warning","kind":"c"}],
        "topTcpProblems":[{"remoteIp":"10.0.0.8","remotePort":443,"retransmissions":5,"comm":"curl"},{"remoteIp":"10.0.0.9","remotePort":80,"retransmissions":0},{"remoteIp":"1.1.1.1","remotePort":53,"retransmissions":9}],
        "topDnsProblems":[{"name":"db.internal","failures":3},{"name":"ok","failures":0}]}}
        """#)
        let c = NowData.anomalyCounts(h)
        XCTAssertEqual(c.first?.0, .critical)
        XCTAssertEqual(c.last?.1, 2)
        XCTAssertEqual(NowData.worstAnomaly(h), .critical)
        let t = NowData.topRetransmitters(h)
        XCTAssertEqual(t.map(\.name), ["1.1.1.1:53", "10.0.0.8:443 (curl)"])
        XCTAssertEqual(NowData.topDNSFailures(h).map(\.name), ["db.internal"])
        XCTAssertEqual(NowData.scoreSeverity(72), .warning)
        XCTAssertEqual(NowData.worstAnomaly(j("{}")), .ok)
    }

    func testSLOItems() {
        let v = j(#"""
        {"enabled":true,"items":[{"name":"api-avail","sli":"availability","namespace":"pay","workload":"api","targetPct":99.9,"window":"30d",
        "severity":"page","hasData":true,"total":1000,"errors":5,"compliancePct":99.5,"budgetRemaining":0.2,
        "windows":[{"kind":"fast","long":"1h","short":"5m","longBurn":15.2,"shortBurn":16,"threshold":14.4,"firing":true}]},
        {"name":"empty","sli":"latency","targetPct":99,"window":"7d","severity":"none","hasData":false,"total":0,"errors":0,"compliancePct":100,"budgetRemaining":1}]}
        """#)
        let items = NowData.sloItems(v)
        XCTAssertEqual(items.count, 2)
        XCTAssertEqual(items[0].scope, "pay/api")
        XCTAssertEqual(items[0].severity, .high)
        XCTAssertTrue(items[0].firing)
        XCTAssertEqual(items[0].windows[0].threshold, 14.4)
        XCTAssertEqual(items[1].severity, .ok)
        XCTAssertFalse(items[1].hasData)
        XCTAssertTrue(NowData.sloItems(j(#"{"enabled":false,"items":[]}"#)).isEmpty)
    }

    func testComplianceFlatten() {
        let v = j(#"""
        {"packs":[{"id":"cis","title":"CIS","description":"d","passed":1,"failed":1,"warned":0,
        "controls":[{"id":"1.1","title":"Disable x","cisRef":"3.1","status":"pass"},{"id":"1.2","title":"Enable y","status":"fail","severity":"high","evidence":"e","remediation":"r","nodes":2}]}],
        "sysctlSummary":{"nodes":3}}
        """#)
        let p = NowData.packSummaries(v)
        XCTAssertEqual(p[0].total, 2); XCTAssertEqual(p[0].failed, 1)
        let c = NowData.controls(v)
        XCTAssertEqual(c.count, 2)
        XCTAssertEqual(c[1].status, .critical)
        XCTAssertEqual(c[1].pack, "CIS")
        XCTAssertEqual(c[1].nodes, 2)
        XCTAssertEqual(Set(c.map(\.id)).count, 2)
    }

    func testAuditSummary() {
        let s = j(#"""
        {"total":3,"byActor":[{"key":"alice","count":1},{"key":"bob","count":2}],"byAction":[{"key":"mode","count":3}],
        "byHour":[{"hour":"2026-11-07T11:00:00Z","count":2},{"hour":"2026-11-07T10:00:00Z","count":1},{"hour":"bad","count":9}]}
        """#)
        XCTAssertEqual(NowData.auditTop(s, key: "byActor").map(\.name), ["bob", "alice"])
        let h = NowData.auditHours(s)
        XCTAssertEqual(h.map(\.1), [1, 2])
        let ev = j(#"{"details":{"b":2,"a":"x","nested":{"z":1}}}"#)
        XCTAssertEqual(NowData.auditDetails(ev), "a=x b=2")
    }

    func testRealDateIgnoresZeroTime() {
        XCTAssertNil(NowData.realDate(.string("0001-01-01T00:00:00Z")))
        XCTAssertNotNil(NowData.realDate(.string("2026-11-07T10:00:00Z")))
        XCTAssertNil(NowData.realDate(nil))
    }

    func testScorecardCountersTolerateMissing() {
        let c = NowData.scorecardCounters(j(#"{"healthScore":88,"staleAgents":1}"#))
        XCTAssertEqual(c.count, 5)
        XCTAssertEqual(c[0].value, 88)
        XCTAssertEqual(c[3].value, 0)
    }
}
