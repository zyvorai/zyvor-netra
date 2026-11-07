// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class PlatformDataTests: XCTestCase {
    private func json(_ s: String) -> JSONValue { try! JSONDecoder().decode(JSONValue.self, from: Data(s.utf8)) }

    func testBoardsAreUniqueGetPathsInKnownGroups() {
        XCTAssertEqual(Set(PlatformData.boards.map(\.id)).count, PlatformData.boards.count)
        for b in PlatformData.boards {
            XCTAssertTrue(b.path.hasPrefix("api/v1/"), b.id)
            XCTAssertTrue(PlatformData.groups.contains(b.group), b.id)
        }
        for g in PlatformData.groups { XCTAssertFalse(PlatformData.boards(in: g).isEmpty) }
    }

    func testPickListDottedFallbackAndTopLevelArray() {
        XCTAssertEqual(PlatformData.pickList(json(#"{"result":{"hits":[1,2]}}"#), keys: ["hits", "result.hits"]).count, 2)
        XCTAssertEqual(PlatformData.pickList(json("[1,2,3]"), keys: ["x"]).count, 3)
        XCTAssertTrue(PlatformData.pickList(json(#"{"a":1}"#), keys: ["x"]).isEmpty)
    }

    func testRowLabelAndMeta() {
        let r = json(#"{"ja3":"abc","severity":"high","count":3,"reasons":["rare","new"],"note":"n"}"#)
        XCTAssertEqual(PlatformData.rowLabel(r), "abc")
        XCTAssertEqual(PlatformData.rowMeta(r), "high · n=3 · rare, new · n")
        XCTAssertEqual(PlatformData.rowLabel(json("{}")), "")
    }

    func testBaselines() {
        let b = PlatformData.baselines(json(#"{"behaviorPresent":true,"behaviorEntries":12,"behaviorAgeSeconds":90,"ratePresent":false,"rateEntries":0,"stale":true,"note":"old","generatedAt":"2026-09-14T10:00:00Z"}"#))
        XCTAssertTrue(b.behavior.present); XCTAssertEqual(b.behavior.entries, 12); XCTAssertEqual(b.behavior.ageSeconds, 90)
        XCTAssertFalse(b.rate.present); XCTAssertTrue(b.stale); XCTAssertEqual(b.note, "old"); XCTAssertNotNil(b.generatedAt)
        let e = PlatformData.baselines(json("{}"))
        XCTAssertFalse(e.behavior.present); XCTAssertFalse(e.stale)
    }

    func testAgentCounts() {
        let c = PlatformData.agentCounts(json(#"{"items":[{"node":"a","mode":"enforce","stale":false},{"node":"b","mode":"observe","stale":true}],"staleAfterSeconds":60}"#))
        XCTAssertEqual(c, .init(total: 2, stale: 1, enforcing: 1, staleAfter: 60))
        XCTAssertEqual(PlatformData.agentCounts(json("{}")).total, 0)
    }
}
