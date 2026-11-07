// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Pure helpers for the Platform/Detect read-only pages: surfaces catalog, baselines, agents, playbooks.
public enum PlatformData {
    // MARK: Surfaces (P0-P5 observe boards; mirrors web/src/pages/Surfaces.tsx, all GET)

    public struct Board: Identifiable, Equatable, Sendable {
        public let id, label, group, path: String
        public let listKeys: [String]
    }

    public static let groups = ["Encrypted", "Fit", "Threat", "Ops", "Fleet"]

    public static let boards: [Board] = [
        .init(id: "tls", label: "TLS fingerprints", group: "Encrypted", path: "api/v1/ebpf/tls-fingerprints?limit=100", listKeys: ["fingerprints"]),
        .init(id: "tls-risk", label: "JA3 risk", group: "Encrypted", path: "api/v1/ebpf/tls-fingerprints/risk?limit=100", listKeys: ["items"]),
        .init(id: "encdns", label: "Encrypted DNS", group: "Encrypted", path: "api/v1/ebpf/encrypted-dns?limit=100", listKeys: ["result.hits", "result.items", "hits"]),
        .init(id: "ech", label: "ECH / missing SNI", group: "Encrypted", path: "api/v1/insights/ech-blind?limit=100", listKeys: ["findings", "items"]),
        .init(id: "shadow", label: "Shadow SaaS", group: "Fit", path: "api/v1/insights/shadow-saas?limit=100", listKeys: ["findings", "items"]),
        .init(id: "experience", label: "Experience", group: "Fit", path: "api/v1/insights/experience?limit=100", listKeys: ["rows", "items"]),
        .init(id: "destrisk", label: "Destination risk", group: "Fit", path: "api/v1/insights/destination-risk?limit=100", listKeys: ["items"]),
        .init(id: "zt", label: "Zero Trust drafts", group: "Fit", path: "api/v1/insights/zero-trust?limit=50", listKeys: ["drafts", "items"]),
        .init(id: "microseg", label: "Microseg", group: "Fit", path: "api/v1/insights/microseg?limit=50", listKeys: ["suggestions", "items", "drafts"]),
        .init(id: "packs", label: "Policy packs", group: "Fit", path: "api/v1/insights/policy-packs?limit=50", listKeys: ["packs", "items"]),
        .init(id: "identity", label: "Identity drafts", group: "Fit", path: "api/v1/insights/identity-drafts?limit=50", listKeys: ["drafts", "items"]),
        .init(id: "exfil", label: "Exfil heuristics", group: "Threat", path: "api/v1/insights/exfil?limit=100", listKeys: ["findings", "items"]),
        .init(id: "lateral", label: "Lateral playbooks", group: "Threat", path: "api/v1/insights/lateral?limit=50", listKeys: ["playbooks", "items"]),
        .init(id: "catdeny", label: "Category deny", group: "Threat", path: "api/v1/insights/category-deny?limit=50", listKeys: ["drafts", "items"]),
        .init(id: "dnsintel", label: "DNS intel hits", group: "Threat", path: "api/v1/intel/dns-hits?limit=100", listKeys: ["hits", "items"]),
        .init(id: "intel", label: "Threat intel feed", group: "Threat", path: "api/v1/intel/feed", listKeys: ["entries", "items"]),
        .init(id: "appcat", label: "App categories", group: "Ops", path: "api/v1/ebpf/app-categories?limit=100", listKeys: ["hits", "items"]),
        .init(id: "compliance", label: "Compliance", group: "Ops", path: "api/v1/compliance?limit=100", listKeys: ["checks", "items", "findings"]),
        .init(id: "ainet", label: "AI destinations", group: "Ops", path: "api/v1/ebpf/ai-destinations?limit=100", listKeys: ["hits", "items", "destinations"]),
        .init(id: "automitigate", label: "Auto-mitigate", group: "Ops", path: "api/v1/ebpf/auto-mitigate", listKeys: ["recent", "actions", "items"]),
        .init(id: "prevention", label: "Prevention report", group: "Ops", path: "api/v1/report/prevention", listKeys: ["sections", "items"]),
        .init(id: "clusters", label: "Fleet clusters", group: "Fleet", path: "api/v1/fleet/clusters", listKeys: ["clusters", "items"]),
        .init(id: "tenants", label: "Fleet tenants", group: "Fleet", path: "api/v1/fleet/tenants", listKeys: ["tenants", "items"]),
    ]

    public static func boards(in group: String) -> [Board] { boards.filter { $0.group == group } }

    /// First array found at one of `keys` (dotted), else the response itself when it is an array, else empty.
    public static func pickList(_ v: JSONValue, keys: [String]) -> [JSONValue] {
        for k in keys { if case .array(let a)? = v.at(k) { return a } }
        if case .array(let a) = v { return a }
        return []
    }

    private static func s(_ v: JSONValue, _ keys: [String]) -> String {
        for k in keys { if let x = v[k], x != .null, case let t = x.summary, !t.isEmpty { return t } }
        return ""
    }

    /// Headline for a generic board row (never payload fields).
    public static func rowLabel(_ row: JSONValue) -> String {
        s(row, ["ja3", "sni", "host", "hostname", "name", "title", "id", "source", "destination", "category", "node", "tenant", "cluster", "check", "domain", "value"])
    }

    /// One-line meta for a generic board row.
    public static func rowMeta(_ row: JSONValue) -> String {
        var p: [String] = []
        for (k, label) in [("severity", ""), ("ja4", "ja4 "), ("count", "n="), ("score", "score "), ("riskScore", "risk "), ("category", ""), ("mode", ""), ("message", "")] {
            let t = s(row, [k]); if !t.isEmpty { p.append(label + t) }
        }
        if case .array(let r)? = row["reasons"], !r.isEmpty { p.append(r.map(\.summary).joined(separator: ", ")) }
        if row["message"] == nil, case let n = s(row, ["note"]), !n.isEmpty { p.append(n) }
        return p.joined(separator: " · ")
    }

    // MARK: Baselines (GET /api/v1/baselines, baselineage.Status)

    public struct BaselineSide: Equatable, Sendable {
        public let name: String
        public let present: Bool
        public let entries: Int
        public let capturedAt: Date?
        public let ageSeconds: Double
    }
    public struct Baselines: Equatable, Sendable {
        public let behavior, rate: BaselineSide
        public let stale: Bool
        public let note: String
        public let generatedAt: Date?
    }

    public static func baselines(_ v: JSONValue) -> Baselines {
        func side(_ name: String, _ p: String) -> BaselineSide {
            .init(name: name, present: { if case .bool(let b)? = v[p + "Present"] { return b }; return false }(),
                  entries: Int(v[p + "Entries"]?.asDouble ?? 0), capturedAt: CellFormat.date(v[p + "CapturedAt"]),
                  ageSeconds: v[p + "AgeSeconds"]?.asDouble ?? 0)
        }
        var stale = false
        if case .bool(let b)? = v["stale"] { stale = b }
        return .init(behavior: side("Behavior", "behavior"), rate: side("Rate", "rate"), stale: stale,
                     note: s(v, ["note"]), generatedAt: CellFormat.date(v["generatedAt"]))
    }

    // MARK: Agents (GET /api/v1/agents -> {items, staleAfterSeconds})

    public struct AgentCounts: Equatable, Sendable { public let total, stale, enforcing: Int; public let staleAfter: Double }

    public static func agentCounts(_ v: JSONValue) -> AgentCounts {
        let items = pickList(v, keys: ["items"])
        func isTrue(_ x: JSONValue?) -> Bool { if case .bool(let b)? = x { return b }; return false }
        return .init(total: items.count, stale: items.filter { isTrue($0["stale"]) }.count,
                     enforcing: items.filter { s($0, ["mode"]).lowercased() == "enforce" }.count,
                     staleAfter: v["staleAfterSeconds"]?.asDouble ?? 0)
    }
}
