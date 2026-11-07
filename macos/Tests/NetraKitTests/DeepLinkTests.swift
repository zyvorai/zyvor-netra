// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class DeepLinkTests: XCTestCase {
    let valid: Set<String> = ["overview", "pods", "listenQueues", "incidents"]

    func testParseSection() throws {
        let l = try DeepLink.parse("netra://pods", validSections: valid)
        XCTAssertEqual(l, DeepLink(section: "pods"))
        XCTAssertEqual(try DeepLink.parse("netra://listenqueues/", validSections: valid).section, "listenQueues")
    }
    func testParseQuery() throws {
        let l = try DeepLink.parse("netra://pods?namespace=prod&q=web%20api", validSections: valid)
        XCTAssertEqual(l.query, ["namespace": "prod", "q": "web api"])
    }
    func testRejects() {
        func bad(_ s: String, _ e: DeepLink.ParseError? = nil, line: UInt = #line) {
            XCTAssertThrowsError(try DeepLink.parse(s, validSections: valid), s, line: line) { err in
                if let e { XCTAssertEqual(err as? DeepLink.ParseError, e, line: line) }
            }
        }
        bad("https://pods", .notNetraScheme)
        bad("netra://nope", .unknownSection("nope"))
        bad("netra://", .unknownSection(""))
        bad("netra://pods/extra", .unexpectedComponent("path"))
        bad("netra://pods#frag", .unexpectedComponent("fragment"))
        bad("netra://u:p@pods", .unexpectedComponent("userinfo"))
        bad("netra://pods?mode=enforce", .unknownKey("mode"))
        bad("netra://pods?apply=1", .unknownKey("apply"))
        bad("netra://pods?q=a&q=b", .duplicateKey("q"))
        bad("netra://pods?q=a%00b", .badValue("q"))
        bad("netra://pods?q=" + String(repeating: "a", count: 300), .badValue("q"))
    }
    func testFormatRoundTrip() throws {
        let l = DeepLink(section: "pods", query: ["q": "a b&c", "namespace": "x", "evil": "1", "pod": ""])
        let u = try XCTUnwrap(l.url)
        XCTAssertEqual(u.absoluteString, "netra://pods?namespace=x&q=a%20b%26c")
        XCTAssertEqual(try DeepLink.parse(u, validSections: valid), DeepLink(section: "pods", query: ["q": "a b&c", "namespace": "x"]))
    }
    func testWebHandoff() throws {
        let base = URL(string: "https://ctl.example:8443/")!
        let u = try XCTUnwrap(WebHandoff.url(base: base, section: "anomalies", query: ["q": "10.0.0.1", "namespace": "p"]))
        XCTAssertEqual(u.absoluteString, "https://ctl.example:8443/#page=metric-anomalies&namespace=p&query=10.0.0.1")
        let r = try XCTUnwrap(WebHandoff.parse(u))
        XCTAssertEqual(r.page, "metric-anomalies"); XCTAssertEqual(r.query, ["namespace": "p", "q": "10.0.0.1"])
        XCTAssertTrue(try XCTUnwrap(WebHandoff.url(base: base, section: "lease")).absoluteString.hasSuffix("#page=overview"))
    }
    func testWebHandoffRejectsBadBase() {
        XCTAssertNil(WebHandoff.url(base: URL(string: "ftp://x")!, section: "pods"))
        XCTAssertNil(WebHandoff.url(base: URL(string: "https://u:p@x")!, section: "pods"))
        XCTAssertNil(WebHandoff.url(base: URL(string: "file:///x")!, section: "pods"))
        XCTAssertNil(WebHandoff.parse(URL(string: "https://x/#page=bogus")!))
    }
}
