// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class PlatformDataTests: XCTestCase {
    private func json(_ s: String) -> JSONValue { try! JSONDecoder().decode(JSONValue.self, from: Data(s.utf8)) }

    func testBoardsAreUniqueGetPathsInKnownGroups() {
        XCTAssertEqual(Set(PlatformData.boards.map(\.id)).count, PlatformData.boards.count)
        for b in PlatformData.boards {
            XCTAssertTrue(b.path.hasPrefix("api/v1/"), b.id)
            XCTAssertTrue(PlatformData.groups.contains(b.group), b.id)
        }
        for g in PlatformData.groups { XCTAssertFalse(PlatformData.boards(in: g).isEmpty) }
    }

    func testPickListDottedFallbackAndTopLevelArray() {
        XCTAssertEqual(PlatformData.pickList(json(#"{"result":{"hits":[1,2]}}"#), keys: ["hits", "result.hits"]).count, 2)
        XCTAssertEqual(PlatformData.pickList(json("[1,2,3]"), keys: ["x"]).count, 3)
        XCTAssertTrue(PlatformData.pickList(json(#"{"a":1}"#), keys: ["x"]).isEmpty)
    }

    func testRowLabelAndMeta() {
        let r = json(#"{"ja3":"abc","severity":"high","count":3,"reasons":["rare","new"],"note":"n"}"#)
        XCTAssertEqual(PlatformData.rowLabel(r), "abc")
        XCTAssertEqual(PlatformData.rowMeta(r), "high · n=3 · rare, new · n")
        XCTAssertEqual(PlatformData.rowLabel(json("{}")), "")
    }

    func testBaselines() {
        let b = PlatformData.baselines(json(#"{"behaviorPresent":true,"behaviorEntries":12,"behaviorAgeSeconds":90,"ratePresent":false,"rateEntries":0,"stale":true,"note":"old","generatedAt":"2026-09-14T10:00:00Z"}"#))
        XCTAssertTrue(b.behavior.present); XCTAssertEqual(b.behavior.entries, 12); XCTAssertEqual(b.behavior.ageSeconds, 90)
        XCTAssertFalse(b.rate.present); XCTAssertTrue(b.stale); XCTAssertEqual(b.note, "old"); XCTAssertNotNil(b.generatedAt)
        let e = PlatformData.baselines(json("{}"))
        XCTAssertFalse(e.behavior.present); XCTAssertFalse(e.stale)
    }

    func testAgentCounts() {
        let c = PlatformData.agentCounts(json(#"{"items":[{"node":"a","mode":"enforce","stale":false},{"node":"b","mode":"observe","stale":true}],"staleAfterSeconds":60}"#))
        XCTAssertEqual(c, .init(total: 2, stale: 1, enforcing: 1, staleAfter: 60))
        XCTAssertEqual(PlatformData.agentCounts(json("{}")).total, 0)
    }

    /// Fixtures use the exact top-level json tags of each Go Result type (internal/<pkg>), not the Swift guesses.
    func testEveryBoardListKeyMatchesItsGoResult() {
        let fixtures: [String: String] = [
            "tls": #"{"fingerprints":[{"ja3":"a1","count":2}],"stats":{},"note":"n"}"#,
            "tls-risk": #"{"items":[{"ja3":"a1","severity":"high","count":1,"reasons":["rare"]}],"count":1}"#,
            "encdns": #"{"result":{"hits":[{"kind":"dot","destinationIp":"1.1.1.1","port":853}],"count":1,"dotCount":1},"note":"n"}"#,
            "ech": #"{"findings":[{"hostOrIp":"h.example","severity":"low","rationale":"r"}],"count":1}"#,
            "shadow": #"{"findings":[{"host":"x.example","category":"saas"}],"count":1}"#,
            "experience": #"{"workloads":[{"namespace":"web","pod":"p1","severity":"warning","signals":["s"]}],"count":1}"#,
            "destrisk": #"{"destinations":[{"destination":"9.9.9.9","score":70,"severity":"high","reasons":["a"]}],"count":1}"#,
            "zt": #"{"drafts":[{"id":"d1","title":"Allow X","kind":"allow_cidr","severity":"info"}],"count":1}"#,
            "microseg": #"{"ciliumDetected":false,"leaseDrafts":[{"id":"m1","title":"Deny ext","kind":"deny_external","severity":"info"}],"steps":["s"],"note":"n"}"#,
            "packs": #"{"packs":[{"id":"p1","namespace":"web","name":"saas-pack","fqdns":["a"]}],"count":1}"#,
            "identity": #"{"drafts":[{"id":"i1","title":"Identity draft","severity":"info"}],"count":1}"#,
            "exfil": #"{"findings":[{"namespace":"web","pod":"p1","score":80,"severity":"high","signals":["s"],"rationale":"r"}],"count":1}"#,
            "lateral": #"{"playbooks":[{"id":"l1","title":"Contain scan","severity":"high","steps":["s"]}],"count":1}"#,
            "catdeny": #"{"drafts":[{"id":"c1","host":"tor.example","category":"anonymizer","severity":"high"}],"count":1}"#,
            "dnsintel": #"{"hits":[{"host":"bad.example","severity":"high","rationale":"r"}],"count":1}"#,
            "intel": #"{"feed":{},"entries":[{"type":"cidr","value":"10.0.0.0/8","direction":"egress"}],"note":"n"}"#,
            "appcat": #"{"hits":[{"category":"social","label":"X","host":"x.example","kind":"sni"}],"count":1}"#,
            "compliance": #"{"packs":[{"id":"cis","title":"CIS","controls":[{"id":"c1","title":"rp_filter","status":"fail","severity":"high"},{"id":"c2","title":"syncookies","status":"pass"}]},{"id":"b","title":"B","controls":[]}],"note":"n"}"#,
            "ainet": #"{"result":{"hits":[{"category":"llm","label":"L","host":"api.example"}],"count":1},"autoApplied":false}"#,
            "automitigate": #"{"enabled":true,"recent":[{"at":"2026-11-07T10:00:00Z","kind":"syn_drop","target":"1.2.3.4"}],"note":"n"}"#,
            "prevention": #"{"headline":"h","mode":"observe","coverage":["c1"],"gaps":["g1","g2"],"note":"n"}"#,
            "clusters": #"{"clusters":[{"name":"local","ok":true,"agentCount":3}],"peerCount":0}"#,
            "tenants": #"{"tenants":[{"tenant":"acme","clusterCount":1,"risk":"low","riskScore":3}],"count":1}"#,
        ]
        XCTAssertEqual(Set(fixtures.keys), Set(PlatformData.boards.map(\.id)), "a board has no fixture")
        for b in PlatformData.boards {
            let rows = PlatformData.pickList(json(fixtures[b.id]!), keys: b.listKeys)
            XCTAssertFalse(rows.isEmpty, "\(b.id) found no rows")
            for r in rows { XCTAssertFalse(PlatformData.rowLabel(r).isEmpty, "\(b.id) row has no label: \(r)") }
        }
    }

    func testComplianceFlattensControlsAndPreventionShowsStrings() {
        let c = PlatformData.pickList(json(#"{"packs":[{"title":"CIS","controls":[{"id":"c1","title":"rp_filter","status":"fail"}]}]}"#), keys: ["packs[].controls"])
        XCTAssertEqual(c.count, 1)
        XCTAssertEqual(PlatformData.rowLabel(c[0]), "rp_filter")
        XCTAssertEqual(PlatformData.rowMeta(c[0]), "fail · CIS")
        let p = PlatformData.pickList(json(#"{"coverage":["a"],"gaps":["g"]}"#), keys: ["gaps+coverage"])
        XCTAssertEqual(p.map { PlatformData.rowLabel($0) }, ["g", "a"])
        XCTAssertEqual(PlatformData.rowMeta(p[0]), "gaps")
    }
}
