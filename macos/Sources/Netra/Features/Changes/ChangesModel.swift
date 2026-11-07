// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Holds the snapshot history for the connected controller. Read-only: it only issues GETs. Lives for the
/// app session (so leaving the page keeps the timeline) and polls only while the Changes page is open.
@MainActor @Observable
final class ChangesModel {
    static let shared = ChangesModel()
    static let capacity = 60

    private(set) var history = SnapshotHistory(capacity: ChangesModel.capacity)
    private(set) var failures: [String: String] = [:]
    private(set) var busy = false
    private var profileKey: String?

    /// Called by the view with the active profile so history never mixes controllers.
    func bind(profileID: String?) {
        let key = profileID ?? "none"
        guard key != profileKey else { return }
        profileKey = key
        history = SnapshotHistory.read(from: fileURL(key), capacity: Self.capacity)
    }

    func clear() { history.clear(); persist() }

    func capture(using client: NetraClient) async {
        guard !busy else { return }
        busy = true; defer { busy = false }
        var sources: [String: [SnapshotItem]] = [:]
        var fails: [String: String] = [:]
        var cache: [String: JSONValue] = [:]   // agents and enforcement share one fetch
        for s in SnapshotSource.standard {
            let ck = s.endpoint + s.query.map { "\($0.name)=\($0.value ?? "")" }.joined(separator: "&")
            do {
                let v: JSONValue
                if let hit = cache[ck] { v = hit } else {
                    var req = client.request("GET", s.endpoint, query: s.query)
                    req.timeoutInterval = 15
                    v = try JSONDecoder().decode(JSONValue.self, from: await client.send(req))
                    cache[ck] = v
                }
                sources[s.key] = SnapshotExtractor.items(from: v, source: s)
            } catch { fails[s.key] = error.localizedDescription }
        }
        failures = fails
        guard !sources.isEmpty else { return }
        history.append(ChangeSnapshot(sources: sources))
        persist()
    }

    private func persist() {
        guard let key = profileKey else { return }
        try? history.write(to: fileURL(key))
    }

    private func fileURL(_ key: String) -> URL {
        let safe = String(key.map { $0.isLetter || $0.isNumber || $0 == "-" ? $0 : "_" })
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return base.appendingPathComponent("Netra/changes-\(safe).json")
    }
}
