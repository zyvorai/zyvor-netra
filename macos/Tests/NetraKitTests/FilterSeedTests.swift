// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class FilterSeedTests: XCTestCase {
    func testEmpty() {
        let p = FilterSeed.plan([:])
        XCTAssertTrue(p.isEmpty); XCTAssertEqual(p.summary, "")
    }
    func testQWins() {
        let p = FilterSeed.plan(["q": "oom", "pod": "web-1"])
        XCTAssertEqual(p.search, "oom"); XCTAssertEqual(p.unapplied, ["pod"])
    }
    func testPodThenNamespaceThenNode() {
        XCTAssertEqual(FilterSeed.plan(["namespace": "prod", "pod": "web-1"]).search, "web-1")
        XCTAssertEqual(FilterSeed.plan(["namespace": "prod", "node": "n1"]).search, "prod")
        XCTAssertEqual(FilterSeed.plan(["node": "n1"]).search, "n1")
    }
    func testDedicatedFieldsLeaveSearch() {
        let p = FilterSeed.plan(["direction": "egress", "pod": "web-1"], dedicated: ["direction"])
        XCTAssertEqual(p.fields, ["direction": "egress"]); XCTAssertEqual(p.search, "web-1"); XCTAssertTrue(p.unapplied.isEmpty)
    }
    func testIgnoresUnknownAndBlank() {
        let p = FilterSeed.plan(["evil": "x", "q": "  "])
        XCTAssertTrue(p.isEmpty); XCTAssertEqual(p.summary, "")
    }
    func testSummaryOrdered() {
        XCTAssertEqual(FilterSeed.plan(["pod": "a", "q": "b"]).summary, "q=b · pod=a")
    }
    func testFlowMaps() {
        XCTAssertEqual(FilterSeed.flowVerdict("Drop"), "DROPPED"); XCTAssertNil(FilterSeed.flowVerdict("x"))
        XCTAssertEqual(FilterSeed.flowDirection("Ingress"), "INGRESS"); XCTAssertNil(FilterSeed.flowDirection("x"))
    }
}
