// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Pure helpers behind the policy tools: result summaries and a local check of a history archive.
/// Nothing here talks to the network and nothing shows manifests' secrets: only counts and identities.
public enum PolicyToolsData {

    public static func pretty(_ v: JSONValue) -> String {
        let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return (try? e.encode(v)).map { String(decoding: $0, as: UTF8.self) } ?? v.summary
    }

    // MARK: Build (POST /policies/build returns the manifest only; nothing is applied)

    public struct BuiltManifest: Sendable, Equatable {
        public var kind: String, namespace: String, name: String
        public var text: String            // pretty JSON, ready to paste into Simulate or Apply
        public var summary: String { "\(kind) \(namespace)/\(name): a manifest only. Nothing was applied or saved." }
    }

    public static func builtManifest(_ data: Data) -> BuiltManifest? {
        guard let v = try? JSONDecoder().decode(JSONValue.self, from: data), v["kind"] != nil else { return nil }
        return BuiltManifest(kind: v["kind"]?.string ?? "policy",
                             namespace: v["metadata"]?["namespace"]?.string ?? "",
                             name: v["metadata"]?["name"]?.string ?? "",
                             text: pretty(v))
    }

    // MARK: Simulate (POST /policies/simulate: read-only analysis, no receipt)

    /// The simulation has no fixed schema across versions, so show the scalar and list headlines it carries.
    public static func simulateSummary(_ v: JSONValue) -> String {
        guard case .object(let o) = v else { return v.summary }
        var parts: [String] = []
        for key in o.keys.sorted() {
            switch o[key]! {
            case .array(let a): parts.append("\(key): \(a.count)")
            case .number, .bool: parts.append("\(key): \(o[key]!.summary)")
            case .string(let s) where s.count <= 40: parts.append("\(key): \(s)")
            default: break
            }
        }
        return parts.isEmpty ? "Simulation returned no headline fields." : parts.joined(separator: " · ")
    }

    // MARK: Deny replay (POST /ebpf/deny/preview-history)

    public static func denyHistorySummary(_ v: JSONValue) -> String {
        let r = v["result"]
        let seen = r?["flowsSeen"]?.controlInt ?? 0
        let denials = r?["denials"]?.controlItems ?? []
        let hits = denials.reduce(0) { $0 + ($1["flowCount"]?.controlInt ?? 0) }
        let breakage = r?["breakage"]?.controlItems.count ?? 0
        var s = "Of \(seen) retained flow(s) in the last \(v["since"]?.string ?? "window"), the deny would have matched \(hits) in \(denials.count) group(s); \(breakage) workload(s) affected."
        if let c = v["caveat"]?.string { s += " " + c }
        return s
    }

    // MARK: Watchlist match (POST /watchlist/match)

    public static func watchlistSummary(_ v: JSONValue) -> String {
        let m = v["match"]
        let entries = v["preview"]?["count"]?.controlInt ?? 0
        let skipped = v["preview"]?["skipped"]?.controlItems.count ?? 0
        let n = m?["count"]?.controlInt ?? m?["hits"]?.controlItems.count ?? 0
        var s = "\(entries) entr\(entries == 1 ? "y" : "ies") parsed"
        if skipped > 0 { s += " (\(skipped) skipped)" }
        s += "; \(n) observed hit(s) across \(m?["checked"]?.controlInt ?? 0) checked."
        if case .bool(true)? = m?["capped"] { s += " Results were capped." }
        return s
    }

    // MARK: AI destinations (GET /ebpf/ai-destinations is the preview of the deny)

    public static func aiDestinationSummary(_ v: JSONValue) -> String {
        let hits = v["result"]?["hits"]?.controlItems ?? []
        let hosts = Set(hits.compactMap { $0["host"]?.string }).sorted()
        guard !hosts.isEmpty else { return "No AI/MCP destinations observed: the deny would add nothing." }
        let shown = hosts.prefix(8).joined(separator: ", ")
        return "\(hosts.count) host(s) observed, each would get an SNI deny: \(shown)\(hosts.count > 8 ? ", …" : ""). Requires mode=enforce with an active lease; entries stop applying when the lease ends."
    }

    // MARK: History archive (GET /policies/history/export, POST /policies/history/import)

    public static let archiveRevisionLimit = 1000
    public static let archiveByteLimit = 16 << 20
    private static let archiveKeys: Set<String> = ["schemaVersion", "exportedAt", "revisions"]
    private static let revisionKeys: Set<String> = ["id", "at", "actor", "namespace", "name", "action", "manifest"]

    public struct ArchiveInfo: Sendable, Equatable {
        public var revisions: Int
        public var policies: Int
        public var exportedAt: String?
    }

    /// Mirrors the server's checks (DisallowUnknownFields, schema 1, <=1000 revisions, identity fields).
    public static func inspectArchive(_ text: String) -> Result<ArchiveInfo, FormError> {
        let raw = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if raw.isEmpty { return .failure(.init("Choose or paste an exported policy history archive")) }
        if raw.utf8.count > archiveByteLimit { return .failure(.init("Archive is larger than 16 MB")) }
        guard let obj = (try? JSONSerialization.jsonObject(with: Data(raw.utf8))) as? [String: Any] else {
            return .failure(.init("Archive must be a JSON object exported by Netra"))
        }
        if let bad = Set(obj.keys).subtracting(archiveKeys).sorted().first { return .failure(.init("Unknown archive field \"\(bad)\": the server rejects it")) }
        guard (obj["schemaVersion"] as? Int) == 1 else { return .failure(.init("Unsupported archive schemaVersion: only 1 is accepted")) }
        guard let revs = obj["revisions"] as? [[String: Any]] else { return .failure(.init("Archive has no revisions array")) }
        if revs.count > archiveRevisionLimit { return .failure(.init("Archive has \(revs.count) revisions; the maximum import is \(archiveRevisionLimit)")) }
        var ids = Set<String>()
        for (i, r) in revs.enumerated() {
            if let bad = Set(r.keys).subtracting(revisionKeys).sorted().first { return .failure(.init("Revision \(i) has unknown field \"\(bad)\"")) }
            let ns = r["namespace"] as? String ?? "", name = r["name"] as? String ?? "", action = r["action"] as? String ?? ""
            if ns.isEmpty || name.isEmpty || action.isEmpty { return .failure(.init("Revision \(i) requires namespace, name and action")) }
            guard r["manifest"] is [String: Any] else { return .failure(.init("Revision \(i) has no manifest object")) }
            ids.insert(ns + "/" + name)
        }
        return .success(.init(revisions: revs.count, policies: ids.count, exportedAt: obj["exportedAt"] as? String))
    }

    public static func importSummary(_ info: ArchiveInfo, replace: Bool, current: JSONValue) -> String {
        let have = current["items"]?.controlItems.count ?? 0
        let verb = replace
            ? "REPLACE: all recorded history (\(have) recent revision(s) listed) is discarded and replaced"
            : "Merge: appends to the recorded history (\(have) recent revision(s) listed now)"
        return "\(verb) with \(info.revisions) revision(s) across \(info.policies) policy(ies). Only the controller's rollback history changes: nothing is applied to the cluster. The server re-checks every manifest."
    }

    // MARK: Baselines

    public static func baselineSummary(_ v: JSONValue, what: String) -> String {
        if case .bool(true)? = v["captured"] {
            let at = v["baseline"]?["capturedAt"]?.string ?? "an unknown time"
            return "A \(what) baseline captured at \(at) exists."
        }
        return "No \(what) baseline is captured yet."
    }

    /// 30s to 2h, as Go's time.ParseDuration reads simple h/m/s values (the server silently falls back to 5m otherwise).
    public static func rateWindowSeconds(_ s: String) -> Int? {
        let t = s.trimmingCharacters(in: .whitespaces).lowercased()
        guard !t.isEmpty else { return nil }
        var total = 0, num = ""
        for ch in t {
            if ch.isNumber { num.append(ch); continue }
            guard let n = Int(num), let unit = ["h": 3600, "m": 60, "s": 1][String(ch)] else { return nil }
            total += n * unit; num = ""
        }
        guard num.isEmpty, (30...7200).contains(total) else { return nil }
        return total
    }

    public static func exportFilename(_ f: DownloadedFile) -> String { f.filename ?? "netra-policy-history.json" }
}
