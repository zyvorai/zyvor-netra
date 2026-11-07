// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class DetectDataTests: XCTestCase {
    private func json(_ s: String) -> JSONValue { try! JSONDecoder().decode(JSONValue.self, from: Data(s.utf8)) }

    func testSeverityRankAndSymbol() {
        XCTAssertGreaterThan(DetectData.severityRank("critical"), DetectData.severityRank("high"))
        XCTAssertGreaterThan(DetectData.severityRank("high"), DetectData.severityRank("warning"))
        XCTAssertEqual(DetectData.severityRank("medium"), DetectData.severityRank("warning"))
        XCTAssertEqual(DetectData.severityRank("???"), 0)
        XCTAssertNotEqual(DetectData.severitySymbol("critical"), DetectData.severitySymbol("low"))
    }

    func testIncidentsSortedWorstFirst() {
        let v = json(#"""
        {"count":2,"items":[
         {"generatedAt":"2026-09-14T10:00:00Z","sourceKey":"workload:a","subject":"a","severity":"warning","findings":[
           {"kind":"drift","severity":"warning","subject":"a","message":"new dst","at":"2026-09-14T10:00:00Z"},
           {"kind":"health","severity":"warning","subject":"a","message":"rtt","joinConfidence":"exact","at":"2026-09-14T10:01:00Z"}]},
         {"sourceKey":"workload:b","subject":"b","severity":"critical","findings":[
           {"kind":"exposure","severity":"warning","message":"x"},{"kind":"health","severity":"critical","message":"y"},{"kind":"drift","severity":"warning","message":"z"}]}]}
        """#)
        let i = DetectData.incidents(v)
        XCTAssertEqual(i.map(\.sourceKey), ["workload:b", "workload:a"])
        XCTAssertEqual(i[0].findings.first?.severity, "critical")
        XCTAssertEqual(i[0].kinds, ["drift", "exposure", "health"])
        XCTAssertNotNil(i[1].latest)
        XCTAssertEqual(i[1].findings.last?.joinConfidence.isEmpty, false)
        XCTAssertTrue(DetectData.incidents(json("{}")).isEmpty)
    }

    func testTimelineNewestFirst() {
        let t = DetectData.timeline(json(#"{"engine":"heuristic","entries":[{"at":"2026-09-14T10:00:00Z","kind":"audit","text":"old"},{"at":"2026-09-14T11:00:00Z","kind":"digest-transition","text":"new","severity":"warning"}]}"#))
        XCTAssertEqual(t.entries.map(\.text), ["new", "old"])
        XCTAssertEqual(t.entries[0].severity, "warning"); XCTAssertEqual(t.engine, "heuristic"); XCTAssertEqual(t.prose, "")
    }

    func testSecurityReviewUnwrapsResult() {
        let r = DetectData.securityReview(json(#"""
        {"dnsEnabled":true,"scanEnabled":false,"result":{"autoApplied":false,"truncated":true,"note":"Temporal correlation","items":[
         {"id":"i1","node":"n1","namespace":"prod","pod":"api-1","lastSeen":"2026-09-14T10:05:00Z","evidence":[
           {"id":"e2","kind":"scan","message":"port-scan","at":"2026-09-14T10:05:00Z"},
           {"id":"e1","kind":"dns","message":"dga: x.example","at":"2026-09-14T10:01:00Z"},
           {"id":"e3","kind":"intel","message":"match ip 1.2.3.4","at":"2026-09-14T10:03:00Z"}]}]}}
        """#))
        XCTAssertTrue(r.dnsEnabled); XCTAssertFalse(r.scanEnabled); XCTAssertTrue(r.truncated)
        XCTAssertEqual(r.incidents.count, 1)
        let i = r.incidents[0]
        XCTAssertEqual(i.workload, "prod/api-1"); XCTAssertEqual(i.evidence.map(\.id), ["e1", "e3", "e2"])
        XCTAssertEqual(i.kinds, ["dns", "intel", "scan"]); XCTAssertEqual(i.derivedSeverity, "high")
        XCTAssertEqual(r.evidenceByKind.map(\.kind), ["dns", "intel", "scan"])
    }

    func testIntelHitsCapitalisedKeys() {
        let h = DetectData.intelHits(json(#"""
        {"feed":{"count":2,"revision":3,"empty":false},"autoApplied":false,"note":"Observe-only",
         "match":{"count":2,"capped":false,"checked":2,"hits":[
          {"Type":"ip","Value":"1.2.3.4","Kind":"flow","Node":"n1","Namespace":"prod","Pod":"api-1","Subject":"","Packets":10,"Blocked":2},
          {"Type":"domain","Value":"bad.example","Kind":"sni","Node":"n2","Namespace":"","Pod":"","Subject":"host-x","Packets":5,"Blocked":0}]}}
        """#))
        XCTAssertEqual(h.hits.count, 2); XCTAssertEqual(h.checked, 2)
        XCTAssertEqual(h.totalPackets, 15); XCTAssertEqual(h.totalBlocked, 2)
        XCTAssertEqual(h.hits[0].workload, "prod/api-1"); XCTAssertEqual(h.hits[1].workload, "host-x")
        XCTAssertEqual(h.byType.count, 2)
    }

    func testIntelHitsEmptyFeed() {
        let h = DetectData.intelHits(json(#"{"feed":{"count":0,"empty":true},"match":{"hits":[]},"note":"No active feed."}"#))
        XCTAssertTrue(h.hits.isEmpty); XCTAssertEqual(h.note, "No active feed.")
        XCTAssertEqual(DetectData.feedStatus(json(#"{"feed":{"count":0,"empty":true}}"#)).label, "Empty")
    }

    func testFeedStatusAndRevisions() {
        let v = json(#"""
        {"feed":{"count":3,"revision":2,"source":"https://feed","empty":false,"expired":true,"persistent":true,"journalUnavailable":false,"updatedAt":"2026-09-14T10:00:00Z","refreshError":"timeout"},
         "revisions":[{"revision":1,"updatedAt":"2026-09-14T09:00:00Z","source":"operator","entries":[{"type":"ip","value":"1.1.1.1"}]},
                      {"revision":2,"updatedAt":"2026-09-14T10:00:00Z","source":"https://feed","entries":[{"type":"ip","value":"1.1.1.1"},{"type":"domain","value":"a.b"},{"type":"ip","value":"2.2.2.2"}]}]}
        """#)
        let f = DetectData.feedStatus(v)
        XCTAssertEqual(f.label, "Expired"); XCTAssertEqual(f.revision, 2); XCTAssertEqual(f.refreshError, "timeout"); XCTAssertNotNil(f.updatedAt)
        let r = DetectData.revisions(v)
        XCTAssertEqual(r.map(\.revision), [2, 1]); XCTAssertEqual(r[0].entries, 3); XCTAssertEqual(r[0].byType["ip"], 2)
        XCTAssertEqual(DetectData.feedStatus(json(#"{"feed":{"journalUnavailable":true}}"#)).label, "Journal unavailable")
    }

    func testFeedEntries() {
        let e = DetectData.feedEntries(json(#"{"entries":[{"type":"cidr","value":"10.0.0.0/8","direction":"egress"},{"type":"ip","value":"1.2.3.4"}]}"#))
        XCTAssertEqual(e.count, 2); XCTAssertEqual(e[0].direction, "egress"); XCTAssertEqual(e[1].direction, "")
    }

    func testHealthTrend() {
        let t = DetectData.healthTrend(json(#"{"samples":40,"currentScore":72,"breachThreshold":50,"slopePerHour":-4.5,"timeToBreachSeconds":17000,"confidence":"low","note":"n"}"#))
        XCTAssertEqual(t.currentScore, 72); XCTAssertEqual(t.summary, "Breach in 4h 43m")
        XCTAssertEqual(DetectData.healthTrend(json(#"{"currentScore":90,"breachThreshold":50,"note":"flat"}"#)).summary, "No projection")
    }

    func testSeverityCountsAndBlast() {
        let c = DetectData.severityCounts(DetectData.rows(json(#"{"items":[{"severity":"low"},{"severity":"high"},{"severity":"high"},{"x":1}]}"#), "items"))
        XCTAssertEqual(c.map(\.severity), ["high", "low"]); XCTAssertEqual(c[0].count, 2)
        let b = DetectData.blastHops(json(#"{"nodes":[{"id":"a","hops":0},{"id":"b","hops":1},{"id":"c","hops":1}]}"#))
        XCTAssertEqual(b.map(\.hops), [0, 1]); XCTAssertEqual(b.map(\.nodes), [1, 2])
    }
}


// Fixtures copy the Go struct tags (internal/models/history.go, internal/models/insights.go, internal/securityreview,
// internal/intel, internal/watchlist, internal/api/security_review.go, internal/api/intel_live.go).
extension DetectDataTests {
    func testRateDriftWindowSecondsUsesRequestedWindowSeconds() {
        let v = json(#"{"window":{"generatedAt":"2026-11-07T10:00:00Z","requestedWindowSeconds":300,"warming":false,"metrics":[]},"findings":[]}"#)
        XCTAssertEqual(DetectData.rateDriftWindowSeconds(v), 300)
        XCTAssertNil(DetectData.rateDriftWindowSeconds(json(#"{"window":{"windowSeconds":300}}"#)))
    }

    func testSecurityReviewWrappedShape() {
        let v = json(#"""
        {"result":{"items":[{"id":"i1","node":"n1","namespace":"prod","pod":"web-1","lastSeen":"2026-11-07T10:00:00.5Z",
           "evidence":[{"id":"e1","kind":"dns","message":"m","at":"2026-11-07T09:58:00Z"},{"id":"e2","kind":"scan","message":"m2","at":"2026-11-07T09:59:00Z"}]}],
          "autoApplied":false,"truncated":true,"note":"Temporal correlation"},"dnsEnabled":true,"scanEnabled":false}
        """#)
        let r = DetectData.securityReview(v)
        XCTAssertEqual(r.incidents.count, 1); XCTAssertEqual(r.incidents[0].workload, "prod/web-1")
        XCTAssertEqual(r.incidents[0].kinds, ["dns", "scan"]); XCTAssertNotNil(r.incidents[0].lastSeen)
        XCTAssertTrue(r.truncated); XCTAssertTrue(r.dnsEnabled); XCTAssertFalse(r.scanEnabled); XCTAssertFalse(r.note.isEmpty)
    }

    func testIntelHitsUntaggedGoStructKeys() {
        // watchlist.Hit has no json tags, so Go emits the field names verbatim; Result has tags.
        let v = json(#"""
        {"feed":{"count":2,"updatedAt":"2026-11-07T09:00:00Z","source":"operator","empty":false,"revision":4,"expired":false,"persistent":true,"journalUnavailable":false,"expiresAt":"2026-11-08T09:00:00Z"},
         "match":{"hits":[{"Type":"ip","Value":"1.2.3.4","Kind":"flow","Node":"n1","Namespace":"prod","Pod":"web-1","Subject":"s","Packets":10,"Blocked":2}],"count":1,"capped":true,"checked":50},
         "autoApplied":false,"note":"Observe-only"}
        """#)
        let h = DetectData.intelHits(v)
        XCTAssertEqual(h.hits.count, 1); XCTAssertEqual(h.hits[0].value, "1.2.3.4"); XCTAssertEqual(h.hits[0].workload, "prod/web-1")
        XCTAssertEqual(h.totalPackets, 10); XCTAssertEqual(h.totalBlocked, 2); XCTAssertEqual(h.checked, 50); XCTAssertTrue(h.capped); XCTAssertFalse(h.note.isEmpty)
        let f = DetectData.feedStatus(v)
        XCTAssertEqual(f.count, 2); XCTAssertEqual(f.revision, 4); XCTAssertEqual(f.label, "Active"); XCTAssertNotNil(f.expiresAt); XCTAssertTrue(f.persistent)
    }

    func testIntelFeedAndHistoryGoShape() {
        let feed = json(#"{"feed":{"count":1,"revision":2,"empty":false,"expired":false,"persistent":false,"journalUnavailable":false},"entries":[{"type":"cidr","value":"10.0.0.0/8","direction":"egress"}],"note":"n"}"#)
        XCTAssertEqual(DetectData.feedEntries(feed).map(\.value), ["10.0.0.0/8"]); XCTAssertEqual(DetectData.feedEntries(feed)[0].direction, "egress")
        let hist = json(#"{"feed":{"count":1,"revision":2,"empty":false,"expired":false,"persistent":false,"journalUnavailable":false},"revisions":[{"revision":1,"updatedAt":"2026-11-07T09:00:00Z","source":"operator","entries":[{"type":"ip","value":"1.1.1.1"}]},{"revision":2,"updatedAt":"2026-11-07T10:00:00Z","expiresAt":"2026-11-08T10:00:00Z","source":"s","note":"n","entries":[{"type":"ip","value":"2.2.2.2"},{"type":"dns","value":"x.example"}]}]}"#)
        let r = DetectData.revisions(hist)
        XCTAssertEqual(r.map(\.revision), [2, 1]); XCTAssertEqual(r[0].entries, 2); XCTAssertEqual(r[0].byType["dns"], 1); XCTAssertNotNil(r[0].expiresAt)
    }

    func testIncidentTimelineAndTrendGoShape() {
        let t = DetectData.timeline(json(#"{"generatedAt":"2026-11-07T10:00:00Z","since":"2026-11-07T00:00:00Z","entries":[{"at":"2026-11-07T09:00:00.25Z","kind":"audit","text":"t"}],"engine":"llm","prose":"p"}"#))
        XCTAssertEqual(t.entries.count, 1); XCTAssertNotNil(t.entries[0].at); XCTAssertEqual(t.prose, "p")
        let h = DetectData.healthTrend(json(#"{"generatedAt":"2026-11-07T10:00:00Z","samples":10,"spanSeconds":3600,"slopePerHour":-2,"currentScore":80,"breachThreshold":50,"timeToBreachSeconds":54000.5,"confidence":"low","note":"n"}"#))
        XCTAssertEqual(h.currentScore, 80); XCTAssertEqual(h.threshold, 50); XCTAssertNotNil(h.timeToBreak)
    }
}
