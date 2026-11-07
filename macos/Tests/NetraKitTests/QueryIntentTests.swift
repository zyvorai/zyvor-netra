// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class QueryIntentTests: XCTestCase {
    let valid: Set<String> = ["drops", "talkers", "alerts", "pods", "flows", "incidents", "workloads", "dns", "rules", "tcpEvents", "aiBrief", "policies"]
    func p(_ s: String) -> QueryIntent? { QueryIntentParser.parse(s, validSections: valid) }

    func testDropsNamespaceWindow() {
        let i = p("drops on ns payments last hour")!
        XCTAssertEqual(i.section, "drops")
        XCTAssertEqual(i.query, ["namespace": "payments"])
        XCTAssertEqual(i.window?.seconds, 3600)
        XCTAssertEqual(i.summary, "Drops · namespace payments · last hour")
    }
    func testTalkersToIP() {
        let i = p("talkers to 10.0.0.5")!
        XCTAssertEqual(i.section, "talkers"); XCTAssertEqual(i.query, ["q": "10.0.0.5"])
    }
    func testAlertsCritical() {
        let i = p("alerts critical")!
        XCTAssertEqual(i.section, "alerts"); XCTAssertEqual(i.query, ["q": "critical"])
        XCTAssertEqual(p("critical alerts")?.query, ["q": "critical"])
    }
    func testPodInNamespace() {
        let i = p("pod foo in kube-system")!
        XCTAssertEqual(i.section, "pods"); XCTAssertEqual(i.query, ["q": "foo", "namespace": "kube-system"])
        XCTAssertEqual(p("pods in kube-system")?.query, ["namespace": "kube-system"])
    }
    func testWindows() {
        XCTAssertEqual(p("drops last 15 minutes")?.window?.seconds, 900)
        XCTAssertEqual(p("drops last 15 minutes")?.window?.label, "last 15 minutes")
        XCTAssertEqual(p("flows past 2 days")?.window?.seconds, 172800)
        XCTAssertEqual(p("drops 24h")?.window?.seconds, 86400)
        XCTAssertEqual(p("drops last 1h")?.window?.seconds, 3600)
        XCTAssertEqual(p("drops today")?.window?.label, "today")
        XCTAssertNil(p("drops last 99999999999999999999 hours")?.window)
    }
    func testFiltersDirectionProtocolAction() {
        let i = p("egress udp flows")!
        XCTAssertEqual(i.section, "flows"); XCTAssertEqual(i.query, ["direction": "egress", "protocol": "UDP"])
        XCTAssertEqual(p("inbound drops")?.query, ["direction": "ingress"])
        let b = p("blocked flows")!
        XCTAssertEqual(b.section, "flows"); XCTAssertEqual(b.query["action"], "blocked")
        XCTAssertEqual(p("blocked")?.section, "drops")
    }
    func testNodeAndKeyValue() {
        XCTAssertEqual(p("drops on node worker-1")?.query, ["node": "worker-1"])
        XCTAssertEqual(p("pods ns=payments")?.query, ["namespace": "payments"])
        XCTAssertEqual(p("flows namespace:prod proto=tcp")?.query, ["namespace": "prod", "protocol": "tcp"])
    }
    func testIPForms() {
        XCTAssertEqual(p("10.0.0.5")?.section, "flows")
        XCTAssertEqual(p("10.0.0.0/24")?.query, ["q": "10.0.0.0/24"])
        XCTAssertEqual(p("flows from fe80::1")?.query, ["q": "fe80::1"])
        XCTAssertNil(p("999.1.1.1"))
        XCTAssertFalse(QueryIntentParser.isIP("10.0.0"))
        XCTAssertFalse(QueryIntentParser.isIP("10.0.0.1/99"))
    }
    func testTyposAndCase() {
        XCTAssertEqual(p("alrets")?.section, "alerts")
        XCTAssertEqual(p("Drpos")?.section, "drops")
        XCTAssertEqual(p("SHOW ME THE TALKERS")?.section, "talkers")
        XCTAssertNil(p("zzzzz"))
    }
    func testFreeTextWithNounBecomesQ() {
        XCTAssertEqual(p("incidents checkout")?.query, ["q": "checkout"])
        XCTAssertEqual(p("workloads payments-api")?.query, ["q": "payments-api"])
    }
    func testNotAnIntent() {
        XCTAssertNil(p(""))
        XCTAssertNil(p("   "))
        XCTAssertNil(p("why is checkout slow"))
        XCTAssertNil(p(String(repeating: "a ", count: 200)))
    }
    func testInvalidSectionRejected() {
        XCTAssertNil(QueryIntentParser.parse("drops", validSections: ["flows"]))
    }
    func testOnlyReadOnlyKeysAndSafeValues() {
        let all = ["drops ns x", "pod a in b", "10.1.1.1 egress tcp", "alerts high", "drops node n1 blocked"]
        for s in all { for k in p(s)!.query.keys { XCTAssertTrue(DeepLink.allowedKeys.contains(k), "\(s) \(k)") } }
        let long = "drops ns " + String(repeating: "x", count: 400)
        XCTAssertNil(p(long)?.query["namespace"])
    }
    func testLinkRoundTrips() throws {
        let i = p("drops on ns payments")!
        let url = try XCTUnwrap(i.link.url)
        let back = try DeepLink.parse(url, validSections: valid)
        XCTAssertEqual(back, i.link)
    }
    func testIdStable() {
        XCTAssertEqual(p("drops ns abc")?.id, p("drops in abc")?.id)
        XCTAssertNotEqual(p("drops ns abc")?.id, p("drops ns abd")?.id)
    }
    func testPunctuation() {
        XCTAssertEqual(p("drops, on ns payments?")?.query, ["namespace": "payments"])
    }
    func testEditDistance() {
        XCTAssertEqual(QueryIntentParser.distance(Array("alerts"), Array("alrets")), 1)
        XCTAssertEqual(QueryIntentParser.distance(Array(""), Array("ab")), 2)
    }

    // MARK: recents

    func freshDefaults() -> UserDefaults {
        let name = "netra.test.\(UUID().uuidString)"
        let d = UserDefaults(suiteName: name)!; d.removePersistentDomain(forName: name); return d
    }
    func testRecentsOrderDedupeCap() {
        let r = RecentQueries(defaults: freshDefaults())
        for n in 1...12 { r.record("drops ns n\(n)") }
        XCTAssertEqual(r.all.count, RecentQueries.maxCount)
        XCTAssertEqual(r.all.first, "drops ns n12")
        r.record("DROPS NS N10")
        XCTAssertEqual(r.all.first, "DROPS NS N10")
        XCTAssertEqual(r.all.filter { $0.lowercased() == "drops ns n10" }.count, 1)
        XCTAssertEqual(r.matching("n11").first, "drops ns n11")
        r.clear(); XCTAssertTrue(r.all.isEmpty)
    }
    func testRecentsRejectSecrets() {
        let r = RecentQueries(defaults: freshDefaults())
        XCTAssertFalse(r.record("Bearer abc123"))
        XCTAssertFalse(r.record("password=hunter2"))
        XCTAssertFalse(r.record("eyJhbGciOiJIUzI1NiJ9.x.y"))
        XCTAssertFalse(r.record("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"))
        XCTAssertFalse(r.record("x"))
        XCTAssertFalse(r.record(String(repeating: "a ", count: 80)))
        XCTAssertFalse(r.record("line\u{0007}bell"))
        XCTAssertTrue(r.record("  drops   on  ns payments "))
        XCTAssertEqual(r.all, ["drops on ns payments"])
        XCTAssertTrue(r.all.allSatisfy(RecentQueries.isStorable))
    }
    func testRecentsFilterPreexistingJunk() {
        let d = freshDefaults(); d.set(["ok query", "token=abc"], forKey: RecentQueries.key)
        XCTAssertEqual(RecentQueries(defaults: d).all, ["ok query"])
    }

    // MARK: ask fallback

    func testAskFallback() {
        XCTAssertEqual(AskFallback.title(for: " why drops? "), "Ask Netra AI: why drops?")
        XCTAssertTrue(AskFallback.title(for: String(repeating: "x", count: 100)).hasSuffix("..."))
        XCTAssertTrue(AskFallback.shouldOffer("why is checkout slow"))
        XCTAssertFalse(AskFallback.shouldOffer("ab"))
        let l = AskFallback.link(for: "why is checkout slow")
        XCTAssertEqual(l.section, "aiBrief"); XCTAssertEqual(l.query, ["q": "why is checkout slow"])
        XCTAssertNotNil(l.url)
        XCTAssertEqual(AskFallback.link(for: String(repeating: "x", count: 999)).query["q"]?.count, DeepLink.maxValueLength)
    }
}
