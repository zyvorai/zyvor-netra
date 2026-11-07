// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Testing
import Foundation
@testable import NetraKit

final class ControlStub: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var seen: [URLRequest] = []
    nonisolated(unsafe) static var fail: Set<String> = []
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for r: URLRequest) -> URLRequest { r }
    override func startLoading() {
        Self.seen.append(request)
        let path = request.url?.path ?? ""
        let status = Self.fail.contains(path) ? 500 : 200
        let body = path.hasSuffix("preview") ? #"{"hitCount":3,"totalPackets":42,"agentsSeen":2}"# : #"{"ok":true}"#
        let r = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!
        client?.urlProtocol(self, didReceive: r, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

@MainActor @Suite(.serialized) struct ControlFlowTests {
    func make(canMutate: Bool, log: ActivityLog) -> MutationFlow {
        ControlStub.seen = []; ControlStub.fail = []
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [ControlStub.self]
        let c = NetraClient(profile: .init(baseURL: URL(string: "http://127.0.0.1:1")!, token: "t"), session: URLSession(configuration: cfg))
        let spec = MutationSpec(title: "Deny 10.0.0.9", risk: .high, expectedPhrase: "deny 10.0.0.9", leaseBound: true,
            preview: { c.denyPreviewRequest(ip: "10.0.0.9", direction: .egress) },
            summarize: { DenyPreview($0).summary },
            execute: { c.denyRequest(ip: "10.0.0.9", direction: .egress, confirmRisk: $0) })
        return MutationFlow(spec: spec, client: c, gate: MutationGate(canMutate: canMutate), log: log)
    }

    @Test func fullFlowPreviewThenTypedConfirm() async {
        let log = ActivityLog(); let f = make(canMutate: true, log: log)
        #expect(!f.canConfirm)
        await f.confirm()                      // no preview: nothing sent
        #expect(ControlStub.seen.isEmpty && log.entries.first?.outcome == .blocked)
        await f.runPreview()
        #expect(f.previewSummary?.contains("3 observed flow") == true)
        #expect(!f.canConfirm)                 // phrase still missing
        f.typedPhrase = "deny 10.0.0.9"
        #expect(f.canConfirm)
        await f.confirm()
        #expect(ControlStub.seen.map { $0.url!.path } == ["/api/v1/ebpf/deny/preview", "/api/v1/ebpf/deny"])
        #expect(ControlStub.seen[0].value(forHTTPHeaderField: "X-Netra-Confirm-Risk") == nil)
        #expect(ControlStub.seen[1].value(forHTTPHeaderField: "X-Netra-Confirm-Risk") == "high")
        #expect(log.entries.map(\.outcome) == [.succeeded, .attempted, .blocked])
    }

    @Test func readOnlyRoleSendsNothing() async {
        let log = ActivityLog(); let f = make(canMutate: false, log: log)
        #expect(!f.canPreview)
        await f.runPreview(); await f.confirm()
        #expect(ControlStub.seen.isEmpty)
        #expect(log.entries.count == 2 && log.entries.allSatisfy { $0.outcome == .blocked })
    }

    @Test func serverFailureIsLogged() async {
        let log = ActivityLog(); let f = make(canMutate: true, log: log)
        await f.runPreview(); f.typedPhrase = "deny 10.0.0.9"
        ControlStub.fail = ["/api/v1/ebpf/deny"]
        await f.confirm()
        #expect(log.entries.first?.outcome == .failed)
        if case .failed = f.phase {} else { Issue.record("expected failed phase") }
    }

    @Test func rowsAndRollbackRequest() {
        let v = try! JSONDecoder().decode(JSONValue.self, from: Data(#"{"items":[{"id":"r1","type":"ip4","summary":"x","spec":{"a":1}}]}"#.utf8))
        let rows = controlRows(v, listKey: "items")
        #expect(rows.count == 1 && rows[0].text("type") == "ip4" && rows[0].text("spec.a") == "1")
        let c = NetraClient(profile: .init(baseURL: URL(string: "http://127.0.0.1:1")!))
        let r = c.ruleRollbackRequest(id: "r1", revision: "7", confirmRisk: false)
        #expect(r.httpMethod == "POST" && r.url?.path == "/api/v1/ebpf/rules/r1/rollback/7")
    }
}
