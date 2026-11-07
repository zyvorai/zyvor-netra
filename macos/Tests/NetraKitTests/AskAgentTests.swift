// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
import Foundation
@testable import NetraKit

final class AskAgentTests: XCTestCase {
    private let sample = #"""
    {"brief":{"headline":"Drops rising","severity":"warning","summary":"Policy drops on web.","engine":"heuristic",
      "findings":[{"severity":"warning","kind":"dns","subject":"web","message":"NXDOMAIN spike"}],
      "snapshot":{"metrics":[{"severity":"info","kind":"metric-anomaly","subject":"cpu","message":"odd"}]},"nextSteps":["Check rules"]},
     "intent":"drops","draft":{"understood":true,"kind":"deny","summary":"Deny 1.2.3.4","applyMethod":"POST","applyPath":"/api/v1/ebpf/deny","cli":"netractl deny 1.2.3.4"},
     "suggestions":["Why is DNS failing?"],
     "steps":[{"node":"classify","detail":"drops"},{"node":"draft"},{"node":"synthesize","detail":"heuristic"}],
     "engine":"heuristic","conversationId":"c1"}
    """#

    func testAgentResultDecodesStepsCitationsAndDraft() throws {
        let r = AskData.agentResult(try JSONDecoder().decode(JSONValue.self, from: Data(sample.utf8)))
        XCTAssertEqual(r.intent, "drops")
        XCTAssertEqual(r.steps.map(\.node), ["classify", "draft", "synthesize"])
        XCTAssertEqual(r.traceText, "1. classify: drops\n2. draft\n3. synthesize: heuristic")
        XCTAssertEqual(r.brief.citations.count, 2)
        XCTAssertEqual(r.suggestions, ["Why is DNS failing?"])
        XCTAssertEqual(r.draft?.applyPath, "/api/v1/ebpf/deny")
        XCTAssertEqual(r.conversationID, "c1")
    }

    func testAgentResultToleratesEmptyPayload() {
        let r = AskData.agentResult(.object([:]))
        XCTAssertTrue(r.steps.isEmpty); XCTAssertNil(r.draft); XCTAssertEqual(r.traceText, "")
    }

    func testBodies() throws {
        let a = try JSONSerialization.jsonObject(with: AskData.askBody(question: " why? ", conversationID: "c")) as! [String: String]
        XCTAssertEqual(a, ["question": "why?", "conversationId": "c"])
        let e = try JSONSerialization.jsonObject(with: AskData.explainBody(kind: "drops", subject: "web/api", page: "explain")) as! [String: String]
        XCTAssertEqual(e, ["kind": "drops", "subject": "web/api", "page": "explain"])
    }

    @MainActor func testAgentAndExplainArePostWithoutConfirmRisk() async throws {
        let cfg = URLSessionConfiguration.ephemeral; cfg.protocolClasses = [StubURLProtocol.self]
        StubURLProtocol.seen = []
        StubURLProtocol.handler = { _ in (200, self.sample) }
        let c = NetraClient(profile: .init(baseURL: URL(string: "http://stub.invalid")!, token: "t"), session: URLSession(configuration: cfg))
        for (path, body) in [("api/v1/ai/agent", AskData.askBody(question: "q", conversationID: "c")),
                             ("api/v1/ai/explain", AskData.explainBody(kind: "drops"))] {
            _ = try await c.send(c.request("POST", path, body: body))
        }
        XCTAssertEqual(StubURLProtocol.seen.map { $0.url!.path }, ["/api/v1/ai/agent", "/api/v1/ai/explain"])
        XCTAssertTrue(StubURLProtocol.seen.allSatisfy { $0.httpMethod == "POST" && $0.value(forHTTPHeaderField: "X-Netra-Confirm-Risk") == nil })
    }
}
