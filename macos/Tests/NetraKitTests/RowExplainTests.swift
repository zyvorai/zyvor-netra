// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class RowExplainTests: XCTestCase {
    private func row(_ json: String) -> JSONValue { try! JSONDecoder().decode(JSONValue.self, from: Data(json.utf8)) }
    private func body(_ page: String, _ json: String) -> [String: Any] {
        try! JSONSerialization.jsonObject(with: RowExplain.body(page: page, row: row(json))) as! [String: Any]
    }

    func testSubjectPrefersNamespaceSlashPodThenIdentityKeys() {
        XCTAssertEqual(RowExplain.subject(of: row(#"{"namespace":"shop","pod":"web-1","name":"x"}"#)), "shop/web-1")
        XCTAssertEqual(RowExplain.subject(of: row(#"{"name":"core","id":"9"}"#)), "core")
        XCTAssertEqual(RowExplain.subject(of: row(#"{"id":42}"#)), "42")
        XCTAssertEqual(RowExplain.subject(of: row(#"{"other":"v"}"#)), "")
    }

    func testMessageIsSortedPlainFieldsOnly() {
        let m = RowExplain.message(of: row(#"{"b":2,"a":"x","nested":{"k":1},"list":[1],"ok":true,"gone":null}"#))
        XCTAssertEqual(m, "a=x; b=2; ok=true")
    }

    func testSensitiveFieldsNeverLeaveTheApp() {
        let m = RowExplain.message(of: row(#"{"name":"p","apiToken":"abc","password":"p","cmdline":"curl x","argv":"a","environ":"E=1","env":"E","Authorization":"Bearer z","payload":"zz","note":"fine"}"#))
        XCTAssertEqual(m, "name=p; note=fine")
        for bad in ["abc", "curl", "Bearer", "zz", "E=1"] { XCTAssertFalse(m.contains(bad), bad) }
        XCTAssertTrue(RowExplain.isSensitive("clientSecret"))
        XCTAssertFalse(RowExplain.isSensitive("namespace"))
    }

    func testLongValuesAndFieldCountAreBounded() {
        let long = String(repeating: "x", count: 500)
        let m = RowExplain.message(of: row("{\"a\":\"\(long)\"}"))
        XCTAssertEqual(m.count, "a=".count + 80 + 1)
        var obj = "{"; for i in 0..<30 { obj += "\"k\(String(format: "%02d", i))\":\(i),"}; obj += "\"z\":1}"
        XCTAssertEqual(RowExplain.message(of: row(obj)).split(separator: ";").count, 14)
    }

    func testBodyShapeMatchesTheServerRequest() {
        let b = body("Drop reasons", #"{"namespace":"shop","pod":"web-1","severity":"high","count":7}"#)
        XCTAssertEqual(b["kind"] as? String, "row")
        XCTAssertEqual(b["subject"] as? String, "shop/web-1")
        XCTAssertEqual(b["page"] as? String, "drop-reasons")
        XCTAssertEqual(b["severity"] as? String, "high")
        XCTAssertTrue((b["message"] as? String ?? "").contains("count=7"))
        XCTAssertTrue((b["question"] as? String ?? "").contains("Drop reasons"))
        XCTAssertNil(b["preferLlm"])
    }

    func testPageSlug() {
        XCTAssertEqual(RowExplain.pageSlug("BPF attachments"), "bpf-attachments")
        XCTAssertEqual(RowExplain.pageSlug("  L7 / TLS  "), "l7-tls")
    }
}
