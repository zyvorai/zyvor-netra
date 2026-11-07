// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class SnapshotDiffTests: XCTestCase {
    private func json(_ s: String) -> JSONValue { try! JSONDecoder().decode(JSONValue.self, from: Data(s.utf8)) }
    private func src(_ k: String) -> SnapshotSource { SnapshotSource.standard.first { $0.key == k }! }
    private func item(_ id: String, _ f: [String: String] = [:]) -> SnapshotItem { .init(id: id, label: id, fields: f) }
    private func snap(_ t: TimeInterval, _ s: [String: [SnapshotItem]], id: String = UUID().uuidString) -> ChangeSnapshot {
        .init(id: id, takenAt: Date(timeIntervalSince1970: t), sources: s)
    }

    // MARK: extraction

    func testFlattenNestedAndArrays() {
        let f = SnapshotExtractor.flatten(json(#"{"a":{"b":1,"c":"x"},"l":[true,{"z":2}],"e":[]}"#), ignore: [])
        XCTAssertEqual(f, ["a.b": "1", "a.c": "x", "l.0": "true", "l.1.z": "2", "e": "[]"])
    }
    func testFlattenDropsVolatileAndSecrets() {
        let f = SnapshotExtractor.flatten(json(#"{"mode":"observe","lastSeen":"t","apiToken":"s3","Password":"p","auth":{"clientSecret":"x","ok":1}}"#),
                                          ignore: SnapshotExtractor.volatileKeys)
        XCTAssertEqual(f, ["mode": "observe", "auth.ok": "1"])
    }
    func testFlattenCapsFieldCount() {
        var o = "{"; o += (0..<500).map { "\"k\($0)\":1" }.joined(separator: ","); o += "}"
        XCTAssertLessThanOrEqual(SnapshotExtractor.flatten(json(o), ignore: []).count, SnapshotExtractor.maxFields)
    }
    func testAgentsItemsUseNodeAndIgnoreHeartbeat() {
        let r = json(#"{"items":[{"node":"n2","mode":"observe","lastSeen":"1"},{"node":"n1","mode":"enforce","lastSeen":"2"}],"staleAfterSeconds":30}"#)
        let items = SnapshotExtractor.items(from: r, source: src("agents"))
        XCTAssertEqual(items.map(\.id), ["n1", "n2"])
        XCTAssertEqual(items[0].fields, ["mode": "enforce", "node": "n1"])
    }
    func testPoliciesIdIsNamespaceSlashName() {
        let r = json(#"{"items":[{"metadata":{"name":"deny-x","namespace":"prod","resourceVersion":"9"},"spec":{"p":1}}]}"#)
        let items = SnapshotExtractor.items(from: r, source: src("policies"))
        XCTAssertEqual(items.first?.id, "prod/deny-x")
        XCTAssertEqual(items.first?.label, "deny-x")
        XCTAssertNil(items.first?.fields["metadata.resourceVersion"])
    }
    func testSingleObjectSourceIsOneItem() {
        let items = SnapshotExtractor.items(from: json(#"{"stale":false,"behaviorEntries":4,"generatedAt":"x"}"#), source: src("baselines"))
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(items[0].id, "baselines")
        XCTAssertEqual(items[0].fields, ["stale": "false", "behaviorEntries": "4"])
    }
    func testMissingListGivesNoItems() {
        XCTAssertTrue(SnapshotExtractor.items(from: json(#"{"nope":1}"#), source: src("rules")).isEmpty)
        XCTAssertTrue(SnapshotExtractor.items(from: json("[1]"), source: src("baselines")).isEmpty)
    }
    func testDuplicateIDsAreKeptApart() {
        let items = SnapshotExtractor.items(from: json(#"{"items":[{"id":"r","a":1},{"id":"r","a":2}]}"#), source: src("rules"))
        XCTAssertEqual(items.map(\.id), ["r", "r#2"])
    }
    func testNoIdentityFallsBackToStableFingerprint() {
        let r = json(#"{"items":[{"a":1}]}"#)
        let a = SnapshotExtractor.items(from: r, source: src("rules"))
        let b = SnapshotExtractor.items(from: r, source: src("rules"))
        XCTAssertTrue(a[0].id.hasPrefix("fp:"))
        XCTAssertEqual(a, b)
    }
    func testEnforcementCountsModes() {
        let r = json(#"{"items":[{"mode":"observe"},{"mode":"Enforce"},{"mode":"observe"},{}]}"#)
        let items = SnapshotExtractor.items(from: r, source: src("enforcement"))
        XCTAssertEqual(items.map(\.id), ["mode:enforce", "mode:observe", "mode:unknown"])
        XCTAssertEqual(items[1].fields["agents"], "2")
    }
    func testAlertsListPathActive() {
        let r = json(#"{"active":[{"id":"a1","name":"cpu","state":"firing"}],"history":[{"id":"h"}]}"#)
        XCTAssertEqual(SnapshotExtractor.items(from: r, source: src("alerts")).map(\.id), ["a1"])
    }

    // MARK: diff

    func testIdenticalSnapshotsAreEmpty() {
        let s = ["rules": [item("a", ["x": "1"])]]
        XCTAssertTrue(SnapshotDiffEngine.diff(old: snap(1, s), new: snap(2, s)).isEmpty)
    }
    func testAddedRemovedChanged() {
        let old = snap(1, ["agents": [item("n1", ["mode": "observe"]), item("n2", ["mode": "observe"])]])
        let new = snap(2, ["agents": [item("n1", ["mode": "enforce"]), item("n3")]])
        let d = SnapshotDiffEngine.diff(old: old, new: new)
        let ch = d.sources[0].changes
        XCTAssertEqual(ch.map(\.kind), [.added, .changed, .removed])
        XCTAssertEqual(ch.map(\.id), ["n3", "n1", "n2"])
        XCTAssertEqual(ch[1].fields, [FieldChange(field: "mode", old: "observe", new: "enforce")])
        XCTAssertEqual(d.count(.added), 1); XCTAssertEqual(d.count(.removed), 1); XCTAssertEqual(d.count(.changed), 1)
        XCTAssertEqual(d.total, 3)
    }
    func testFieldAddedAndRemovedWithinItem() {
        let fc = SnapshotDiffEngine.fieldChanges(old: ["a": "1", "b": "2"], new: ["a": "1", "c": "3"])
        XCTAssertEqual(fc, [FieldChange(field: "b", old: "2", new: nil), FieldChange(field: "c", old: nil, new: "3")])
    }
    func testSourceMissingOnOneSideIsIncomparableNotRemoved() {
        let old = snap(1, ["rules": [item("a")], "alerts": [item("x")]])
        let new = snap(2, ["rules": [item("a")]])           // alerts fetch failed
        let d = SnapshotDiffEngine.diff(old: old, new: new, order: ["rules", "alerts"])
        XCTAssertEqual(d.sources.map(\.key), ["rules", "alerts"])
        XCTAssertTrue(d.sources[1].incomparable)
        XCTAssertTrue(d.sources[1].changes.isEmpty)
        XCTAssertTrue(d.isEmpty)
    }
    func testEmptyButPresentSourceReportsRemovals() {
        let d = SnapshotDiffEngine.diff(old: snap(1, ["rules": [item("a")]]), new: snap(2, ["rules": []]))
        XCTAssertFalse(d.sources[0].incomparable)
        XCTAssertEqual(d.sources[0].changes.map(\.kind), [.removed])
    }
    func testSourceOrderThenAlphabetical() {
        let s = ["z": [item("1")], "a": [item("1")], "m": [item("1")]]
        let d = SnapshotDiffEngine.diff(old: snap(1, s), new: snap(2, s), order: ["m"])
        XCTAssertEqual(d.sources.map(\.key), ["m", "a", "z"])
    }
    func testDiffIsAntisymmetric() {
        let a = snap(1, ["r": [item("x", ["v": "1"]), item("y")]])
        let b = snap(2, ["r": [item("x", ["v": "2"]), item("z")]])
        let fwd = SnapshotDiffEngine.diff(old: a, new: b), rev = SnapshotDiffEngine.diff(old: b, new: a)
        XCTAssertEqual(fwd.count(.added), rev.count(.removed))
        XCTAssertEqual(fwd.count(.removed), rev.count(.added))
        XCTAssertEqual(rev.sources[0].changes.first { $0.kind == .changed }?.fields, [FieldChange(field: "v", old: "2", new: "1")])
    }
    func testDiffCarriesTimestamps() {
        let d = SnapshotDiffEngine.diff(old: snap(10, [:]), new: snap(20, [:]))
        XCTAssertEqual(d.from.timeIntervalSince1970, 10); XCTAssertEqual(d.to.timeIntervalSince1970, 20)
    }
    func testEndToEndFromJSON() {
        let before = json(#"{"items":[{"id":"r1","action":"deny","ip":"1.1.1.1"}]}"#)
        let after = json(#"{"items":[{"id":"r1","action":"deny","ip":"2.2.2.2"},{"id":"r2","action":"allow"}]}"#)
        let s = src("rules")
        let d = SnapshotDiffEngine.diff(old: snap(1, ["rules": SnapshotExtractor.items(from: before, source: s)]),
                                        new: snap(2, ["rules": SnapshotExtractor.items(from: after, source: s)]))
        XCTAssertEqual(d.sources[0].changes.map(\.id), ["r2", "r1"])
        XCTAssertEqual(d.sources[0].changes[1].fields.map(\.field), ["ip"])
    }

    // MARK: history

    func testHistoryCapsOldestFirst() {
        var h = SnapshotHistory(capacity: 3)
        for i in 1...5 { h.append(snap(TimeInterval(i), [:], id: "s\(i)")) }
        XCTAssertEqual(h.snapshots.map(\.id), ["s3", "s4", "s5"])
    }
    func testHistorySortsOutOfOrderAppends() {
        var h = SnapshotHistory()
        h.append(snap(5, [:], id: "b")); h.append(snap(1, [:], id: "a"))
        XCTAssertEqual(h.snapshots.map(\.id), ["a", "b"])
    }
    func testDiffToLatestDefaultsToPrevious() {
        var h = SnapshotHistory()
        XCTAssertNil(h.diffToLatest(baselineID: nil))
        h.append(snap(1, ["r": [item("a")]], id: "1"))
        XCTAssertNil(h.diffToLatest(baselineID: nil))
        h.append(snap(2, ["r": [item("a"), item("b")]], id: "2"))
        h.append(snap(3, ["r": [item("a"), item("b"), item("c")]], id: "3"))
        XCTAssertEqual(h.diffToLatest(baselineID: nil)?.total, 1)
        XCTAssertEqual(h.diffToLatest(baselineID: "1")?.total, 2)
        XCTAssertEqual(h.diffToLatest(baselineID: "nonexistent")?.total, 1)
        XCTAssertNil(h.diffToLatest(baselineID: "3"))
    }
    func testPersistenceRoundTripAndCorruption() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("netra-snap-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("sub/changes.json")
        var h = SnapshotHistory(capacity: 4)
        h.append(snap(1, ["r": [item("a", ["k": "v"])]], id: "x"))
        try h.write(to: url)
        let back = SnapshotHistory.read(from: url, capacity: 4)
        XCTAssertEqual(back.snapshots, h.snapshots)
        try Data("not json".utf8).write(to: url)
        XCTAssertTrue(SnapshotHistory.read(from: url).snapshots.isEmpty)
        XCTAssertTrue(SnapshotHistory.read(from: dir.appendingPathComponent("missing.json")).snapshots.isEmpty)
    }
    func testReadAppliesSmallerCapacity() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("netra-snap-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }
        var h = SnapshotHistory(capacity: 10)
        for i in 1...6 { h.append(snap(TimeInterval(i), [:], id: "s\(i)")) }
        try h.write(to: url)
        XCTAssertEqual(SnapshotHistory.read(from: url, capacity: 3).snapshots.map(\.id), ["s4", "s5", "s6"])
    }
}
