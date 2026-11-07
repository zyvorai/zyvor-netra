// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class FuzzyMatchTests: XCTestCase {
    func testSubsequenceAndMiss() {
        XCTAssertNotNil(FuzzyMatch.match(query: "tpg", in: "Topology"))
        XCTAssertNil(FuzzyMatch.match(query: "xyz", in: "Topology"))
        XCTAssertEqual(FuzzyMatch.match(query: "", in: "a")?.score, 0)
    }
    func testPrefixBeatsScattered() {
        let a = FuzzyMatch.match(query: "flo", in: "Flows")!.score
        let b = FuzzyMatch.match(query: "flo", in: "Fleet low overhead")!.score
        XCTAssertGreaterThan(a, b)
    }
    func testRankOrdersAndFilters() {
        let items = ["Drops", "DNS", "Diagnostics", "Overview"]
        let r = FuzzyMatch.rank(items, query: "dns") { [$0] }
        XCTAssertEqual(r.first?.item, "DNS")
        XCTAssertFalse(r.contains { $0.item == "Overview" })
        XCTAssertEqual(FuzzyMatch.rank(items, query: " ") { [$0] }.map(\.item), items)
    }
    func testMatchedIndices() {
        XCTAssertEqual(FuzzyMatch.match(query: "bm", in: "BPF maps")?.matched, [0, 4])
    }
}
