// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Capped, ordered history of snapshots (oldest first). Optionally persisted as small JSON; contains only
/// flattened observe fields with secret-looking keys already dropped by the extractor.
public struct SnapshotHistory: Codable, Equatable, Sendable {
    public private(set) var snapshots: [ChangeSnapshot]
    public let capacity: Int

    public init(capacity: Int = 60, snapshots: [ChangeSnapshot] = []) {
        self.capacity = max(2, capacity)
        self.snapshots = Array(snapshots.sorted { $0.takenAt < $1.takenAt }.suffix(max(2, capacity)))
    }

    public mutating func append(_ s: ChangeSnapshot) {
        snapshots.append(s)
        snapshots.sort { $0.takenAt < $1.takenAt }
        if snapshots.count > capacity { snapshots.removeFirst(snapshots.count - capacity) }
    }
    public mutating func clear() { snapshots = [] }
    public func snapshot(id: String) -> ChangeSnapshot? { snapshots.first { $0.id == id } }

    /// Diff of the newest snapshot against `baselineID` (default: the one before the newest). Nil with <2 snapshots
    /// or when the baseline is the newest itself.
    public func diffToLatest(baselineID: String?, order: [String] = []) -> SnapshotDiff? {
        guard let latest = snapshots.last, snapshots.count >= 2 else { return nil }
        let base = baselineID.flatMap(snapshot(id:)) ?? snapshots[snapshots.count - 2]
        guard base.id != latest.id else { return nil }
        return SnapshotDiffEngine.diff(old: base, new: latest, order: order)
    }

    // MARK: Persistence

    public func write(to url: URL) throws {
        let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try e.encode(self).write(to: url, options: .atomic)
    }

    /// Missing or unreadable file yields an empty history: a corrupt cache must never block the page.
    public static func read(from url: URL, capacity: Int = 60) -> SnapshotHistory {
        let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601
        guard let data = try? Data(contentsOf: url), let h = try? d.decode(SnapshotHistory.self, from: data) else {
            return SnapshotHistory(capacity: capacity)
        }
        return SnapshotHistory(capacity: capacity, snapshots: h.snapshots)
    }
}
