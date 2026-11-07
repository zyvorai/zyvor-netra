// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// One comparable thing in a snapshot (an agent, a rule, a policy, an alert...): a stable id, a display
/// label and its flattened scalar fields. Only values the server already returns to the operator; the
/// extractor drops secret-looking keys, so nothing here is a credential.
public struct SnapshotItem: Codable, Equatable, Sendable {
    public var id: String
    public var label: String
    public var fields: [String: String]
    public init(id: String, label: String, fields: [String: String]) { self.id = id; self.label = label; self.fields = fields }
}

/// Where a source's items come from. Pure description: the app fetches `endpoint` read-only (GET).
public struct SnapshotSource: Sendable, Equatable, Identifiable {
    public var key: String
    public var title: String
    public var endpoint: String
    public var query: [URLQueryItem] = []
    /// Dotted path to the array of items ("" when the response is the array, nil when the whole response is one item).
    public var listPath: String?
    /// Candidate identities, tried in order; each is a list of dotted paths joined with "/".
    public var idCandidates: [[String]] = [["id"], ["name"]]
    public var labelPaths: [String] = ["name", "id"]
    /// Leaf key names that change on every poll (timestamps, ages, counters) and would drown real changes.
    public var ignore: Set<String> = SnapshotExtractor.volatileKeys
    public var id: String { key }

    public init(key: String, title: String, endpoint: String, query: [URLQueryItem] = [], listPath: String?,
                idCandidates: [[String]] = [["id"], ["name"]], labelPaths: [String] = ["name", "id"],
                ignore: Set<String> = SnapshotExtractor.volatileKeys) {
        self.key = key; self.title = title; self.endpoint = endpoint; self.query = query; self.listPath = listPath
        self.idCandidates = idCandidates; self.labelPaths = labelPaths; self.ignore = ignore
    }

    /// The sources the Changes page snapshots: all GET, all already read elsewhere in the app.
    public static let standard: [SnapshotSource] = [
        .init(key: "agents", title: "Agents", endpoint: "api/v1/agents", listPath: "items",
              idCandidates: [["node"], ["name"], ["id"]], labelPaths: ["node", "name"]),
        .init(key: "rules", title: "Rules", endpoint: "api/v1/ebpf/rules", listPath: "items",
              idCandidates: [["id"], ["name"]], labelPaths: ["name", "id"]),
        .init(key: "policies", title: "Policies", endpoint: "api/v1/policies", query: [.init(name: "namespace", value: "default")],
              listPath: "items", idCandidates: [["metadata.namespace", "metadata.name"], ["metadata.name"]],
              labelPaths: ["metadata.name"]),
        .init(key: "baselines", title: "Baselines", endpoint: "api/v1/baselines", listPath: nil),
        .init(key: "alerts", title: "Metric alerts", endpoint: "api/v1/metrics/alerts", listPath: "active",
              idCandidates: [["id"], ["fingerprint"], ["rule", "metric"]], labelPaths: ["name", "rule", "id"]),
        // Derived from the agents document (see SnapshotExtractor.enforcement): the fleet's enforcement posture.
        .init(key: "enforcement", title: "Enforcement mode", endpoint: "api/v1/agents", listPath: "items"),
    ]
}

public enum SnapshotExtractor {
    /// Leaf names that move on every poll without meaning anything changed.
    public static let volatileKeys: Set<String> = [
        "lastSeen", "lastSeenAt", "updatedAt", "generatedAt", "now", "ageSeconds", "age", "uptime", "uptimeSeconds",
        "resourceVersion", "managedFields", "lastReportAt", "lastHeartbeat", "heartbeat", "since", "staleSeconds",
        "behaviorAgeSeconds", "rateAgeSeconds", "observedAt", "timestamp", "ts", "lastUpdate",
    ]
    static let secretWords = ["token", "secret", "password", "passwd", "credential", "apikey", "api_key", "authorization", "privatekey", "cookie"]
    static let maxFields = 200
    static let maxDepth = 8

    static func isSecretKey(_ k: String) -> Bool {
        let l = k.lowercased()
        return secretWords.contains { l.contains($0) }
    }

    /// Flatten scalar leaves to dotted keys. Arrays index as `path.0`. Null leaves are kept as "null".
    public static func flatten(_ v: JSONValue, ignore: Set<String>) -> [String: String] {
        var out: [String: String] = [:]
        func walk(_ v: JSONValue, _ path: String, _ depth: Int) {
            if out.count >= maxFields || depth > maxDepth { return }
            switch v {
            case .object(let o):
                for k in o.keys.sorted() where !ignore.contains(k) && !isSecretKey(k) {
                    walk(o[k]!, path.isEmpty ? k : path + "." + k, depth + 1)
                }
            case .array(let a):
                if a.isEmpty { out[path] = "[]" }
                for (i, e) in a.enumerated() { walk(e, path.isEmpty ? "\(i)" : "\(path).\(i)", depth + 1) }
            default:
                if !path.isEmpty { out[path] = v.summary }
            }
        }
        walk(v, "", 0)
        return out
    }

    static func scalar(_ v: JSONValue?) -> String? {
        guard let v else { return nil }
        switch v {
        case .null, .array, .object: return nil
        default: let s = v.summary; return s.isEmpty ? nil : s
        }
    }

    /// Items for a source from its raw response. Duplicate ids get a `#n` suffix so none is silently merged.
    public static func items(from json: JSONValue, source: SnapshotSource) -> [SnapshotItem] {
        if source.key == "enforcement" { return enforcement(from: json, listPath: source.listPath ?? "items") }
        let raw: [JSONValue]
        if let lp = source.listPath {
            if case .array(let a)? = json.at(lp) { raw = a } else { raw = [] }
        } else {
            guard case .object = json else { return [] }
            raw = [json]
        }
        var seen: [String: Int] = [:]
        var out: [SnapshotItem] = []
        for el in raw {
            let fields = flatten(el, ignore: source.ignore)
            var id: String?
            for cand in source.idCandidates {
                let parts = cand.compactMap { scalar(el.at($0)) }
                if parts.count == cand.count { id = parts.joined(separator: "/"); break }
            }
            if source.listPath == nil { id = source.key }
            let base = id ?? "fp:" + String(fingerprint(fields), radix: 16)
            let n = seen[base, default: 0]; seen[base] = n + 1
            let finalID = n == 0 ? base : "\(base)#\(n + 1)"
            let label = source.labelPaths.compactMap { scalar(el.at($0)) }.first ?? (source.listPath == nil ? source.title : finalID)
            out.append(SnapshotItem(id: finalID, label: label, fields: fields))
        }
        return out.sorted { $0.id < $1.id }
    }

    /// Fleet enforcement posture from the agents document: one item per mode with how many agents run it,
    /// so a flip from observe to enforce shows as a count change rather than a churn of agent rows.
    public static func enforcement(from json: JSONValue, listPath: String = "items") -> [SnapshotItem] {
        guard case .array(let a)? = json.at(listPath) else { return [] }
        var counts: [String: Int] = [:]
        for el in a {
            let m = (scalar(el["mode"]) ?? "unknown").lowercased()
            counts[m, default: 0] += 1
        }
        return counts.keys.sorted().map { SnapshotItem(id: "mode:\($0)", label: $0, fields: ["agents": String(counts[$0]!)]) }
    }

    /// Stable (FNV-1a) hash: Swift's Hasher is seeded per process, which would make ids differ between runs.
    static func fingerprint(_ f: [String: String]) -> UInt64 {
        var h: UInt64 = 14695981039346656037
        for k in f.keys.sorted() {
            for b in (k + "=" + f[k]! + ";").utf8 { h = (h ^ UInt64(b)) &* 1099511628211 }
        }
        return h
    }
}

/// A point-in-time capture. A source that failed to fetch is absent from `sources`, never empty, so an
/// outage is not reported as "everything removed".
public struct ChangeSnapshot: Codable, Equatable, Sendable, Identifiable {
    public var id: String
    public var takenAt: Date
    public var sources: [String: [SnapshotItem]]
    public init(id: String = UUID().uuidString, takenAt: Date = Date(), sources: [String: [SnapshotItem]]) {
        self.id = id; self.takenAt = takenAt; self.sources = sources
    }
    public var itemCount: Int { sources.values.reduce(0) { $0 + $1.count } }
}

public enum ChangeKind: String, Sendable, Equatable, CaseIterable { case added, removed, changed }

public struct FieldChange: Equatable, Sendable {
    public let field: String
    public let old: String?
    public let new: String?
}

public struct ItemChange: Equatable, Sendable, Identifiable {
    public let kind: ChangeKind
    public let id: String
    public let label: String
    public let fields: [FieldChange]
}

public struct SourceDiff: Equatable, Sendable, Identifiable {
    public let key: String
    public let changes: [ItemChange]
    /// True when one side has no data for this source (fetch failed or source did not exist yet).
    public let incomparable: Bool
    public var id: String { key }
    public func count(_ k: ChangeKind) -> Int { changes.filter { $0.kind == k }.count }
    public var isEmpty: Bool { changes.isEmpty }
}

public struct SnapshotDiff: Equatable, Sendable {
    public let from: Date
    public let to: Date
    public let sources: [SourceDiff]
    public var total: Int { sources.reduce(0) { $0 + $1.changes.count } }
    public func count(_ k: ChangeKind) -> Int { sources.reduce(0) { $0 + $1.count(k) } }
    public var isEmpty: Bool { total == 0 }
}

public enum SnapshotDiffEngine {
    /// Diff `new` against `old`. Sources are reported in `order` first, then any others alphabetically.
    public static func diff(old: ChangeSnapshot, new: ChangeSnapshot, order: [String] = []) -> SnapshotDiff {
        let keys = Set(old.sources.keys).union(new.sources.keys)
        let ordered = order.filter(keys.contains) + keys.subtracting(order).sorted()
        let sources = ordered.map { key -> SourceDiff in
            guard let o = old.sources[key], let n = new.sources[key] else { return SourceDiff(key: key, changes: [], incomparable: true) }
            return SourceDiff(key: key, changes: diffItems(old: o, new: n), incomparable: false)
        }
        return SnapshotDiff(from: old.takenAt, to: new.takenAt, sources: sources)
    }

    public static func diffItems(old: [SnapshotItem], new: [SnapshotItem]) -> [ItemChange] {
        let o = Dictionary(old.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        let n = Dictionary(new.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        var out: [ItemChange] = []
        for id in n.keys.sorted() {
            let item = n[id]!
            guard let prev = o[id] else {
                out.append(.init(kind: .added, id: id, label: item.label, fields: []))
                continue
            }
            let fc = fieldChanges(old: prev.fields, new: item.fields)
            if !fc.isEmpty { out.append(.init(kind: .changed, id: id, label: item.label, fields: fc)) }
        }
        for id in o.keys.sorted() where n[id] == nil { out.append(.init(kind: .removed, id: id, label: o[id]!.label, fields: [])) }
        let rank: [ChangeKind: Int] = [.added: 0, .changed: 1, .removed: 2]
        return out.sorted { (rank[$0.kind]!, $0.id) < (rank[$1.kind]!, $1.id) }
    }

    public static func fieldChanges(old: [String: String], new: [String: String]) -> [FieldChange] {
        Set(old.keys).union(new.keys).sorted().compactMap { k in
            old[k] == new[k] ? nil : FieldChange(field: k, old: old[k], new: new[k])
        }
    }
}
