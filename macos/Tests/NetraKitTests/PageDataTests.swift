// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class PageDataTests: XCTestCase {
    private func json(_ s: String) -> JSONValue { try! JSONDecoder().decode(JSONValue.self, from: Data(s.utf8)) }

    func testDottedPathAndArrayIndex() {
        let v = json(#"{"a":{"b":[{"n":"x"},{"n":"y"}]},"c":3}"#)
        XCTAssertEqual(v.at("a.b.1.n")?.string, "y")
        XCTAssertEqual(v.at("c")?.asDouble, 3)
        XCTAssertNil(v.at("a.b.9.n"))
        XCTAssertEqual(v.at("")?.summary, "{2}")
    }

    func testRowsFallBackAcrossRenamedKeys() {
        let v = json(#"{"entries":[{"id":"a"},{"id":"b"}]}"#)
        XCTAssertEqual(v.rows(at: "items", fallbacks: ["entries"]).count, 2)
        XCTAssertEqual(v.rows(at: "items").count, 0)
        XCTAssertEqual(json(#"[{"name":"z"}]"#).rows(at: "").first?.id, "z#0")
    }

    func testMapRowsCarryTheKey() {
        let v = json(#"{"counts":{"tcp":{"n":5},"udp":7}}"#)
        let rows = v.mapRows(at: "counts")
        XCTAssertEqual(rows.map(\.id), ["tcp", "udp"])
        XCTAssertEqual(rows[0].text("key"), "tcp"); XCTAssertEqual(rows[0].text("n"), "5")
        XCTAssertEqual(rows[1].text("value"), "7")
    }

    func testFormatting() {
        XCTAssertEqual(CellFormat.bytes(1536), "1.5 KB"); XCTAssertEqual(CellFormat.bytes(12), "12 B")
        XCTAssertEqual(CellFormat.duration(3700), "1h 1m"); XCTAssertEqual(CellFormat.duration(59), "59s")
        XCTAssertEqual(CellFormat.text(.number(0.256), .ratio), "25.6%")
        XCTAssertEqual(CellFormat.text(.null, .int), "")
        XCTAssertEqual(CellFormat.text(.string("12"), .int), "12")
        XCTAssertEqual(CellFormat.text(.bool(true), .bool), "yes")
        XCTAssertEqual(CellFormat.text(.number(2), .millis), "2.00 ms")
    }

    func testTimeParsingAcceptsRFC3339SecondsAndMilliseconds() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        XCTAssertNotNil(CellFormat.date(.string("2026-11-07T10:00:00.123456Z")))
        XCTAssertNotNil(CellFormat.date(.string("2026-11-07T10:00:00Z")))
        XCTAssertEqual(CellFormat.date(.number(1_800_000_000))?.timeIntervalSince1970, 1_800_000_000)
        XCTAssertEqual(CellFormat.date(.number(1_800_000_000_000))?.timeIntervalSince1970, 1_800_000_000)
        XCTAssertNil(CellFormat.date(.number(0)))
        XCTAssertEqual(CellFormat.text(.number(1_799_999_940), .time, now: now), "1m 0s ago")
    }

    func testSortingUsesValuesNotDisplayText() {
        XCTAssertTrue(CellFormat.less(.number(9), .number(10), .int))                    // "9" > "10" as text
        XCTAssertTrue(CellFormat.less(.string("a2"), .string("a10"), .text))             // natural order
        XCTAssertTrue(CellFormat.less(nil, .number(1), .bytes))                          // missing sorts first
    }
}
