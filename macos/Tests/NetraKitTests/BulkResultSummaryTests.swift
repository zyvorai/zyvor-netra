// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

@MainActor
final class BulkResultSummaryTests: XCTestCase {
    private func client() -> NetraClient {
        let cfg = URLSessionConfiguration.ephemeral; cfg.protocolClasses = [StubURLProtocol.self]
        StubURLProtocol.seen = []
        return NetraClient(profile: .init(baseURL: URL(string: "http://stub.invalid")!, token: "t"), session: URLSession(configuration: cfg))
    }

    private func run(_ action: ControlAction, _ values: FormValues, phrase: String, post: String, body: String) async throws -> (MutationFlow, ActivityLog) {
        StubURLProtocol.handler = { r in r.httpMethod == "POST" && r.url!.path == post ? (200, body) : (200, #"{"items":[],"entries":[{}]}"#) }
        let c = client()
        guard case .success(let spec) = action.build(c, values) else { XCTFail("build failed"); throw FormError("build") }
        let log = ActivityLog()
        let f = MutationFlow(spec: spec, client: c, gate: .init(canMutate: true), log: log)
        await f.runPreview(); f.typedPhrase = phrase; await f.confirm()
        return (f, log)
    }

    private let partial = #"{"results":[{"index":0,"ok":true},{"index":1,"ok":false,"error":"invalid ip"},{"index":2,"ok":true}],"applied":2,"failed":1,"config":{"mode":"enforce"}}"#

    func testDenyImportPartialIsFailedWithReasons() async throws {
        let a = ControlAction.denyImport.first { $0.id == "deny-import" }!
        let (f, log) = try await run(a, ["entries": "ip 10.0.0.1\nip 10.0.0.2\nip 10.0.0.3"], phrase: "import 3 denies", post: "/api/v1/ebpf/deny/import", body: partial)
        XCTAssertEqual(log.entries.first?.outcome, .failed)
        XCTAssertEqual(log.entries.first?.detail, "Applied 2, failed 1 (entry 2: invalid ip)")
        XCTAssertEqual(f.phase, .failed("Applied 2, failed 1 (entry 2: invalid ip)"))
    }

    func testIntelApplyAllOKSucceeds() async throws {
        let a = ControlAction.intel.first { $0.id == "intel-apply" }!
        let (f, log) = try await run(a, ["matchedOnly": "false"], phrase: "apply intel feed", post: "/api/v1/intel/apply",
                                     body: #"{"results":[{"index":0,"ok":true}],"applied":12,"failed":0,"matchedOnly":false}"#)
        XCTAssertEqual(log.entries.first?.outcome, .succeeded)
        XCTAssertEqual(f.phase, .done("Applied 12, failed 0"))
    }

    func testIntelApplyNoMatchesShowsNote() async throws {
        let a = ControlAction.intel.first { $0.id == "intel-apply" }!
        let (f, _) = try await run(a, ["matchedOnly": "true"], phrase: "apply matched intel", post: "/api/v1/intel/apply",
                                   body: #"{"applied":0,"failed":0,"results":[],"note":"no live matches to apply"}"#)
        XCTAssertEqual(f.phase, .done("Applied 0, failed 0: no live matches to apply"))
    }

    func testAIDestinationsDenyAllFailed() async throws {
        let body = #"{"results":[{"index":0,"ok":false,"error":"a"},{"index":1,"ok":false,"error":"b"},{"index":2,"ok":false,"error":"c"},{"index":3,"ok":false,"error":"d"}],"applied":0,"failed":4}"#
        let (f, log) = try await run(PolicyTools.aiDestinationDeny, [:], phrase: "deny ai destinations", post: "/api/v1/ebpf/ai-destinations/deny", body: body)
        XCTAssertEqual(log.entries.first?.outcome, .failed)
        guard case .failed(let m) = f.phase else { return XCTFail("phase \(f.phase)") }
        XCTAssertTrue(m.hasPrefix("Applied 0, failed 4 (entry 1: a; entry 2: b; entry 3: c; +1 more)"), m)
    }

    func testActionWithoutSummarizerKeepsHTTPOK() async throws {
        let a = ControlAction.intel.first { $0.id == "intel-apply" }!
        guard case .success(var spec) = a.build(client(), ["matchedOnly": "true"]) else { return XCTFail() }
        spec.resultSummary = nil
        XCTAssertNil(spec.resultSummary)
        XCTAssertNil(ResultSummary.bulkApplied(.object(["ok": .bool(true)])))
    }
}
