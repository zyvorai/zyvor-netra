// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class AskDataTests: XCTestCase {
    private func json(_ s: String) -> JSONValue { try! JSONDecoder().decode(JSONValue.self, from: Data(s.utf8)) }

    func testAskBodyExactFields() throws {
        let d = AskData.askBody(question: "  Why drops? ")
        XCTAssertEqual(String(decoding: d, as: UTF8.self), #"{"question":"Why drops?"}"#)
        let c = AskData.askBody(question: "and DNS?", conversationID: "abc")
        XCTAssertEqual(String(decoding: c, as: UTF8.self), #"{"conversationId":"abc","question":"and DNS?"}"#)
    }

    func testStatus() {
        let s = AskData.status(json(#"{"enabled":true,"provider":"https://x/v1","model":"m1","heuristicOnly":false,"mutations":"never"}"#))
        XCTAssertTrue(s.enabled); XCTAssertEqual(s.label, "LLM rewrite on (m1)")
        XCTAssertEqual(AskData.status(json("{}")).label, "Heuristic only")
    }

    private let briefJSON = """
    {"headline":"Network needs attention","severity":"warning","summary":"2 findings",
     "findings":[{"severity":"warning","kind":"dns-failure","subject":"a/b","message":"DNS errors"}],
     "nextSteps":["Check DNS"],"engine":"heuristic","generatedAt":"2026-11-07T10:00:00Z",
     "snapshot":{"healthScore":82,"agentsTotal":3,"agentsStale":1,"mode":"observe",
       "metrics":[{"severity":"critical","kind":"metric-alert","subject":"cpu-high","message":"fired"},
                  {"severity":"warning","kind":"metric-anomaly","subject":"net.tcp","message":"spike"}],
       "exposure":[{"severity":"high","kind":"exposure","subject":"x","message":"open"}]}}
    """

    func testBriefAndCitations() {
        let b = AskData.brief(json(briefJSON))
        XCTAssertEqual(b.headline, "Network needs attention"); XCTAssertEqual(b.healthScore, 82)
        XCTAssertEqual(b.agentsStale, 1); XCTAssertEqual(b.metrics.count, 2)
        XCTAssertEqual(b.citations.count, 4)
        XCTAssertEqual(b.metrics[0].sectionID, "alerts"); XCTAssertEqual(b.metrics[1].sectionID, "anomalies")
        XCTAssertNotNil(b.generatedAt)
        XCTAssertTrue(AskData.brief(json("{}")).isEmpty)
    }

    func testDigestAndSuggestions() {
        let d = AskData.digest(json(#"{"headline":"h","severity":"info","changed":true,"card":"c","suggestions":["q1"],"whyChanged":["w"],"brief":{"headline":"bh"}}"#))
        XCTAssertTrue(d.changed); XCTAssertEqual(d.whyChanged, ["w"]); XCTAssertEqual(d.brief.headline, "bh")
        XCTAssertEqual(AskData.suggestions(json(#"{"items":["a","b"]}"#)), ["a", "b"])
        XCTAssertEqual(AskData.suggestions(json("{}")), [])
    }

    func testDraftIsTextOnly() {
        let d = AskData.draft(json(#"{"understood":true,"confidence":"high","kind":"deny","summary":"Deny 1.2.3.4","applyPath":"/api/v1/rules","applyMethod":"POST","body":{"ip":"1.2.3.4"},"cli":"netractl deny 1.2.3.4","warnings":["w"],"note":"preview"}"#))
        XCTAssertTrue(d.copyText.contains("netractl deny 1.2.3.4")); XCTAssertTrue(d.copyText.contains("POST /api/v1/rules"))
        XCTAssertTrue(d.bodyText.contains("1.2.3.4")); XCTAssertEqual(d.note, "preview")
    }

    func testFleet() {
        let v = json(#"{"generatedAt":"2026-11-07T10:00:00Z","agentCount":2,"staleAgents":1,"workloads":9,"nodes":[{"node":"n1","stale":true,"programs":4,"attached":4},{"node":"n2","stale":false,"programs":4,"attached":2}]}"#)
        let s = AskData.fleetSummary(v)
        XCTAssertEqual(s.nodes, 2); XCTAssertEqual(s.stale, 1); XCTAssertEqual(s.healthyFraction, 0.5)
        let rows = v.rows(at: "nodes", idKeys: ["node"])
        XCTAssertEqual(AskData.nodeHealth(rows[0].value), "stale"); XCTAssertEqual(AskData.nodeHealth(rows[1].value), "degraded")
        XCTAssertEqual(AskData.clusterHealth(json(#"{"ok":false}"#)), "unreachable")
    }
}
