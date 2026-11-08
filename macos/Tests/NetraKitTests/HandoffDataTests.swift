// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

@MainActor
final class HandoffDataTests: XCTestCase {
    private func client() -> NetraClient {
        let cfg = URLSessionConfiguration.ephemeral; cfg.protocolClasses = [StubURLProtocol.self]
        StubURLProtocol.seen = []
        return NetraClient(profile: .init(baseURL: URL(string: "http://stub.invalid")!, token: "t"), session: URLSession(configuration: cfg))
    }

    func testHandoffIsAGetWithTheFormatQuery() async throws {
        StubURLProtocol.handler = { _ in (200, "# Netra on-call handoff\n") }
        let f = try await client().handoff(.markdown)
        XCTAssertEqual(String(decoding: f.data, as: UTF8.self), "# Netra on-call handoff\n")
        let req = StubURLProtocol.seen.last
        XCTAssertEqual(req?.httpMethod, "GET")
        XCTAssertEqual(req?.url?.path, "/api/v1/handoff")
        XCTAssertEqual(req?.url?.query, "format=markdown")
    }

    func testJSONFormatQueryAndExtension() async throws {
        StubURLProtocol.handler = { _ in (200, "{}") }
        _ = try await client().handoff(.json)
        XCTAssertEqual(StubURLProtocol.seen.last?.url?.query, "format=json")
        XCTAssertEqual(HandoffFormat.markdown.fileExtension, "md")
        XCTAssertEqual(HandoffFormat.json.fileExtension, "json")
    }

    func testHeadlineReadsTheServerFields() {
        let body = #"""
        {"generatedAt":"2026-11-08T10:00:00Z","fleet":{"agentCount":4,"staleAgents":1,"workloads":37},
         "coverage":{"detachedPrograms":2,"missingMapEntries":3,"quiet":false},
         "reasons":{"total":120,"blocked":9}}
        """#
        let h = HandoffHeadline.parse(Data(body.utf8))
        XCTAssertEqual(h.generatedAt, "2026-11-08T10:00:00Z")
        XCTAssertEqual(h.agents, 4); XCTAssertEqual(h.staleAgents, 1); XCTAssertEqual(h.workloads, 37)
        XCTAssertEqual(h.detachedPrograms, 2); XCTAssertEqual(h.missingMaps, 3); XCTAssertEqual(h.quiet, false)
        XCTAssertEqual(h.dropEvents, 120); XCTAssertEqual(h.blockedEvents, 9)
    }

    func testHeadlineToleratesMissingSectionsAndGarbage() {
        XCTAssertEqual(HandoffHeadline.parse(Data(#"{"fleet":{}}"#.utf8)).agents, nil)
        XCTAssertEqual(HandoffHeadline.parse(Data("not json".utf8)), HandoffHeadline())
    }

    func testServerErrorSurfacesAsHTTPError() async {
        StubURLProtocol.handler = { _ in (400, #"{"error":"format must be markdown or json"}"#) }
        do { _ = try await client().handoff(.markdown); XCTFail() }
        catch NetraError.http(let s, let m) { XCTAssertEqual(s, 400); XCTAssertEqual(m, "format must be markdown or json") }
        catch { XCTFail("\(error)") }
    }
}
