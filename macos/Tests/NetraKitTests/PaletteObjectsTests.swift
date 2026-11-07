// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class PaletteObjectsTests: XCTestCase {
    func j(_ s: String) -> JSONValue { try! JSONDecoder().decode(JSONValue.self, from: Data(s.utf8)) }

    func testBuildAndSearch() {
        let pods = PaletteObjects.pods(j(#"{"items":[{"name":"web-7d","namespace":"prod","podIP":"10.0.0.5"},{"name":"db-0","namespace":"prod"}]}"#))
        XCTAssertEqual(pods.map(\.title), ["web-7d", "db-0"])
        XCTAssertEqual(pods[0].query, ["q": "web-7d", "namespace": "prod"])
        let ips = PaletteObjects.ips([j(#"{"items":[{"podIP":"10.0.0.5","name":"web-7d"}]}"#), j(#"[{"ip":"10.0.0.5"},{"ip":"1.2.3.4"}]"#)])
        XCTAssertEqual(ips.map(\.title), ["10.0.0.5", "1.2.3.4"])
        let rules = PaletteObjects.rules(j(#"{"items":[{"id":"deny-evil","kind":"cidr"}]}"#))
        let inc = PaletteObjects.incidents(j(#"{"items":[{"subject":"checkout/api","severity":"high","findings":[]}]}"#))
        let all = pods + ips + rules + inc
        XCTAssertEqual(PaletteObjects.search(all, query: "chk").first?.kind, .incident)
        XCTAssertEqual(PaletteObjects.search(all, query: "1.2.3.4").first?.section, "flows")
        XCTAssertTrue(PaletteObjects.search(all, query: "").isEmpty)
        XCTAssertTrue(PaletteObjects.search(all, query: "zzzzqq").isEmpty)
    }
    func testTolerantOfJunk() {
        XCTAssertTrue(PaletteObjects.pods(nil).isEmpty)
        XCTAssertTrue(PaletteObjects.workloads(j(#"{"items":[{"x":1}]}"#)).isEmpty)
    }
}
