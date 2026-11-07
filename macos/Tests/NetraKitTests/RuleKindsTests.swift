// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

@MainActor
final class RuleKindsTests: XCTestCase {
    private let c = NetraClient(profile: .init(baseURL: URL(string: "http://stub.invalid")!, token: "t"))

    private func draft(_ k: RuleKind, _ a: RuleAction = .deny, value: String = "", dir: String = "egress",
                       port: Int = 0, pps: Int = 0, remove: Bool = false) -> RuleDraft {
        var d = RuleDraft(); d.kind = k; d.action = a; d.value = value; d.direction = dir; d.port = port; d.pps = pps; d.removing = remove
        return d
    }
    private func keys(_ r: URLRequest) -> Set<String> {
        guard let b = r.httpBody, let o = try? JSONSerialization.jsonObject(with: b) as? [String: Any] else { return [] }
        return Set(o.keys)
    }

    /// The controller decodes with DisallowUnknownFields, so every body must carry exactly the server's fields.
    func testBodiesMatchServerStructsExactly() {
        let cases: [(RuleDraft, String, String, Set<String>)] = [
            (draft(.ip, value: "1.2.3.4"), "POST", "deny", ["ip", "direction"]),
            (draft(.ip, .allow, value: "1.2.3.4"), "POST", "allow", ["ip"]),
            (draft(.cidr, value: "10.0.0.0/8"), "POST", "cidr", ["cidr", "direction"]),
            (draft(.cidr, .allow, value: "10.0.0.0/8"), "POST", "allow-cidr", ["cidr", "direction"]),
            (draft(.port, port: 443), "POST", "port", ["protocol", "port", "direction"]),
            (draft(.port, .allow, port: 443), "POST", "allow-port", ["protocol", "port", "direction"]),
            (draft(.uid, value: "1000"), "POST", "uid", ["uid"]),
            (draft(.uid, .allow, value: "1000"), "POST", "allow-uid", ["uid"]),
            (draft(.dns, value: "evil.example"), "POST", "dns", ["name"]),
            (draft(.sni, value: "evil.example"), "POST", "sni", ["name"]),
            (draft(.process, value: "nc"), "POST", "process", ["name"]),
            (draft(.process, .allow, value: "nc"), "POST", "allow-process", ["name"]),
            (draft(.capability, value: "cap_net_raw"), "POST", "capability", ["name"]),
            (draft(.exeHash, value: String(repeating: "a", count: 64)), "POST", "exehash-deny", ["hash"]),
            (draft(.synDrop, value: "1.2.3.4"), "POST", "syn-drop", ["address", "direction"]),
            (draft(.synDropCIDR, value: "10.0.0.0/8"), "POST", "syn-drop-cidr", ["cidr", "direction"]),
            (draft(.rate, value: "1.2.3.4", pps: 100), "PUT", "rate", ["destination", "pps", "bps"]),
        ]
        for (d, method, path, expected) in cases {
            XCTAssertNil(d.validationError, "\(d.kind) \(d.action): \(d.validationError ?? "")")
            let r = d.mutationRequest(c)
            XCTAssertEqual(r.httpMethod, method, "\(d.kind)")
            XCTAssertEqual(r.url?.path, "/api/v1/ebpf/" + path, "\(d.kind) \(d.action)")
            XCTAssertEqual(keys(r), expected, "\(d.kind) \(d.action)")
        }
    }

    func testRemovalRoutes() {
        func req(_ d: RuleDraft) -> (String, String, Set<String>) { let r = d.mutationRequest(c); return (r.httpMethod!, r.url!.path, keys(r)) }
        XCTAssertEqual(req(draft(.ip, value: "1.2.3.4", remove: true)).1, "/api/v1/ebpf/deny/1.2.3.4")
        XCTAssertEqual(req(draft(.ip, .allow, value: "1.2.3.4", remove: true)).1, "/api/v1/ebpf/allow/1.2.3.4")
        XCTAssertEqual(req(draft(.uid, value: "5", remove: true)).0, "DELETE")
        XCTAssertEqual(req(draft(.rate, value: "1.2.3.4", remove: true)).1, "/api/v1/ebpf/rate/1.2.3.4")
        XCTAssertEqual(req(draft(.cidr, value: "10.0.0.0/8", remove: true)).1, "/api/v1/ebpf/cidr/delete")
        XCTAssertEqual(req(draft(.port, .allow, port: 22, remove: true)).1, "/api/v1/ebpf/allow-port/delete")
        XCTAssertEqual(req(draft(.synDrop, value: "1.2.3.4", remove: true)).1, "/api/v1/ebpf/syn-drop/delete")
    }

    func testValidationMirrorsServer() {
        XCTAssertNotNil(draft(.ip, value: "999.1.1.1").validationError)
        XCTAssertNil(draft(.ip, value: "2001:db8::1").validationError)
        XCTAssertNotNil(draft(.cidr, value: "10.0.0.0/33").validationError)
        XCTAssertNotNil(draft(.cidr, value: "10.0.0.0").validationError)
        XCTAssertNotNil(draft(.port, port: 0).validationError)
        XCTAssertNotNil(draft(.port, port: 70000).validationError)
        XCTAssertNotNil(draft(.uid, value: "-1").validationError)
        XCTAssertNotNil(draft(.dns, value: "bad..name").validationError)
        XCTAssertNotNil(draft(.dns, value: "-bad.example").validationError)
        XCTAssertNil(draft(.dns, value: "Good_name.example.").validationError)
        XCTAssertNotNil(draft(.process, value: "sixteen-bytes-xx").validationError)   // comm is at most 15 bytes
        XCTAssertNotNil(draft(.capability, value: "CAP_SYS_ADMIN").validationError)
        XCTAssertNotNil(draft(.exeHash, value: "abc").validationError)
        XCTAssertNotNil(draft(.synDrop, value: "1.2.3.4", dir: "both").validationError)   // syn-drop is per-direction
        XCTAssertNotNil(draft(.rate, value: "1.2.3.4", pps: 0).validationError)
        XCTAssertNotNil(draft(.rate, value: "1.2.3.4", pps: 10_000_001).validationError)
        XCTAssertNotNil(draft(.dns, .allow, value: "x.example").validationError)          // no DNS allow-list
    }

    func testRiskAndPhrases() {
        XCTAssertEqual(draft(.ip, value: "1.2.3.4").risk, .high)
        XCTAssertEqual(draft(.ip, .allow, value: "1.2.3.4").risk, .medium)
        XCTAssertEqual(draft(.rate, value: "1.2.3.4", pps: 5).risk, .medium)
        XCTAssertEqual(draft(.ip, value: "1.2.3.4", remove: true).risk, .medium)
        XCTAssertEqual(draft(.ip, value: "1.2.3.4").expectedPhrase, "deny 1.2.3.4")
        XCTAssertEqual(draft(.port, port: 443).expectedPhrase, "deny ANY/443")
    }

    func testPreviewUsesDryRunOnlyWhereServerHasOne() {
        XCTAssertEqual(draft(.ip, value: "1.2.3.4").previewRequest(c).url?.path, "/api/v1/ebpf/deny/preview")
        XCTAssertEqual(draft(.uid, value: "5").previewRequest(c).url?.path, "/api/v1/ebpf/rules")
        XCTAssertEqual(draft(.ip, .allow, value: "1.2.3.4").previewRequest(c).httpMethod, "GET")
        let p = draft(.port, port: 443).previewRequest(c)
        XCTAssertEqual(keys(p), ["kind", "value", "direction", "port", "protocol"])
    }

    func testRemovalFromRuleRow() throws {
        let row = ControlRow(id: "r1", value: try JSONDecoder().decode(JSONValue.self, from: Data(
            #"{"id":"r1","type":"port","port":8080,"protocol":"TCP","direction":"ingress"}"#.utf8)))
        let d = try XCTUnwrap(RuleDraft.removal(from: row))
        XCTAssertEqual(d.kind, .port); XCTAssertEqual(d.port, 8080); XCTAssertEqual(d.direction, "ingress"); XCTAssertTrue(d.removing)
        XCTAssertNil(RuleDraft.removal(from: ControlRow(id: "x", value: .object(["type": .string("mystery")]))))
    }

    func testFlowSendsNothingUntilPreviewedAndConfirmed() async {
        let cfg = URLSessionConfiguration.ephemeral; cfg.protocolClasses = [StubURLProtocol.self]
        StubURLProtocol.seen = []; StubURLProtocol.handler = { _ in (200, #"{"hitCount":3,"totalPackets":9,"agentsSeen":1}"#) }
        let client = NetraClient(profile: .init(baseURL: URL(string: "http://stub.invalid")!, token: "t"), session: URLSession(configuration: cfg))
        let flow = MutationFlow(spec: draft(.cidr, value: "10.0.0.0/8").spec(client: client), client: client, gate: .init(canMutate: true), log: ActivityLog())
        await flow.confirm(); XCTAssertTrue(StubURLProtocol.seen.isEmpty)
        await flow.runPreview(); XCTAssertEqual(StubURLProtocol.seen.count, 1)
        XCTAssertTrue(flow.previewSummary?.contains("3 observed flow") == true)
        await flow.confirm(); XCTAssertEqual(StubURLProtocol.seen.count, 1)            // phrase still missing
        flow.typedPhrase = "deny 10.0.0.0/8"; await flow.confirm()
        XCTAssertEqual(StubURLProtocol.seen.last?.url?.path, "/api/v1/ebpf/cidr")
        XCTAssertEqual(StubURLProtocol.seen.last?.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "high")
    }
}
