// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// A searchable object for the command palette, built only from already-fetched read-only API data.
/// Titles and identifiers only: no payloads, command lines or secrets.
public struct PaletteObject: Identifiable, Hashable, Sendable {
    public enum Kind: String, Sendable, CaseIterable { case pod, workload, ip, rule, incident
        public var label: String { rawValue.capitalized }
        public var symbol: String {
            switch self {
            case .pod: "cube"
            case .workload: "shippingbox"
            case .ip: "network"
            case .rule: "hand.raised"
            case .incident: "exclamationmark.triangle"
            }
        }
    }
    public let kind: Kind
    public let title: String
    public let subtitle: String
    /// Target section id (NavSection raw value) and read-only filter to apply there.
    public let section: String
    public let query: [String: String]
    public var id: String { "\(kind.rawValue)|\(section)|\(title)|\(subtitle)" }
}

public enum PaletteObjects {
    public static let perKindLimit = 300

    private static func s(_ v: JSONValue?, _ keys: String...) -> String {
        for k in keys { if case .string(let x)? = v?[k], !x.isEmpty { return x } }
        return ""
    }
    private static func list(_ v: JSONValue?) -> [JSONValue] {
        if case .array(let a)? = v { return a }
        for k in ["items", "pods", "workloads", "rules", "talkers", "top"] { if case .array(let a)? = v?[k] { return a } }
        return []
    }

    public static func pods(_ v: JSONValue?) -> [PaletteObject] {
        var out: [PaletteObject] = []
        for p in list(v).prefix(perKindLimit) {
            let name = s(p, "name"), ns = s(p, "namespace")
            guard !name.isEmpty else { continue }
            out.append(.init(kind: .pod, title: name, subtitle: ns, section: "pods", query: ["q": name] .merging(ns.isEmpty ? [:] : ["namespace": ns]) { a, _ in a }))
        }
        return out
    }

    public static func workloads(_ v: JSONValue?) -> [PaletteObject] {
        list(v).prefix(perKindLimit).compactMap { w in
            let name = s(w, "workloadName", "name"), ns = s(w, "namespace"), kind = s(w, "workloadKind", "kind")
            guard !name.isEmpty else { return nil }
            return .init(kind: .workload, title: name, subtitle: [kind, ns].filter { !$0.isEmpty }.joined(separator: " · "),
                         section: "workloads", query: ["q": name])
        }
    }

    /// Distinct IPs from pod and talker rows (any of the usual ip keys).
    public static func ips(_ sources: [JSONValue?]) -> [PaletteObject] {
        var seen = Set<String>(), out: [PaletteObject] = []
        for src in sources {
            for r in list(src) {
                for k in ["podIP", "podIp", "ip", "sourceIp", "destinationIp", "srcIp", "dstIp", "address"] {
                    let ip = s(r, k)
                    guard !ip.isEmpty, ip.count <= 64, seen.insert(ip).inserted, out.count < perKindLimit else { continue }
                    let who = [s(r, "namespace"), s(r, "name", "pod")].filter { !$0.isEmpty }.joined(separator: "/")
                    out.append(.init(kind: .ip, title: ip, subtitle: who, section: "flows", query: ["q": ip]))
                }
            }
        }
        return out
    }

    public static func rules(_ v: JSONValue?) -> [PaletteObject] {
        list(v).prefix(perKindLimit).compactMap { r in
            let id = s(r, "id", "name")
            guard !id.isEmpty else { return nil }
            return .init(kind: .rule, title: id, subtitle: [s(r, "kind", "type"), s(r, "action")].filter { !$0.isEmpty }.joined(separator: " · "),
                         section: "rules", query: ["q": id])
        }
    }

    public static func incidents(_ v: JSONValue?) -> [PaletteObject] {
        guard let v else { return [] }
        return DetectData.incidents(v).prefix(perKindLimit).map {
            .init(kind: .incident, title: $0.subject, subtitle: [$0.severity, $0.kinds.joined(separator: ", ")].filter { !$0.isEmpty }.joined(separator: " · "),
                  section: "incidents", query: ["q": $0.subject])
        }
    }

    /// Fuzzy-ranked search over title and subtitle. Empty query returns nothing (sections are listed separately).
    public static func search(_ objects: [PaletteObject], query: String, limit: Int = 40) -> [PaletteObject] {
        guard !query.trimmingCharacters(in: .whitespaces).isEmpty else { return [] }
        return FuzzyMatch.rank(objects, query: query) { [$0.title, $0.subtitle, "\($0.kind.rawValue) \($0.title)"] }
            .prefix(limit).map(\.item)
    }
}
