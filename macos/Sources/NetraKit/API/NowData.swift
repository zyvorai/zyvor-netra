// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Normalised severity/status shared by the Health, SLO, Compliance and Scorecard pages.
/// Always shown with a symbol and a word, never colour alone.
public enum NowSeverity: Int, Sendable, Comparable, CaseIterable {
    case ok, info, warning, high, critical, unknown

    public init(_ raw: String?) {
        switch (raw ?? "").lowercased() {
        case "ok", "pass", "green", "none", "healthy": self = .ok
        case "info", "informational": self = .info
        case "warn", "warning", "amber", "ticket": self = .warning
        case "high", "page": self = .high
        case "critical", "fail", "red": self = .critical
        default: self = .unknown
        }
    }
    public static func < (a: NowSeverity, b: NowSeverity) -> Bool { a.rank < b.rank }
    /// Worst-first ordering key (unknown sits between info and warning).
    public var rank: Int {
        switch self { case .ok: 0; case .info: 1; case .unknown: 2; case .warning: 3; case .high: 4; case .critical: 5 }
    }
    public var label: String {
        switch self {
        case .ok: "OK"; case .info: "Info"; case .warning: "Warning"
        case .high: "High"; case .critical: "Critical"; case .unknown: "Unknown"
        }
    }
    public var symbol: String {
        switch self {
        case .ok: "checkmark.circle.fill"; case .info: "info.circle.fill"
        case .warning: "exclamationmark.triangle.fill"; case .high: "exclamationmark.octagon.fill"
        case .critical: "xmark.octagon.fill"; case .unknown: "questionmark.circle"
        }
    }
}

public struct SLOItem: Identifiable, Sendable, Equatable {
    public var id: String
    public var name: String, sli: String, scope: String, window: String
    public var severity: NowSeverity
    public var targetPct: Double, compliancePct: Double, budgetRemaining: Double
    public var hasData: Bool
    public var total: Double, errors: Double
    public var windows: [SLOWindow]
    public var firing: Bool { windows.contains { $0.firing } }
}
public struct SLOWindow: Identifiable, Sendable, Equatable {
    public var id: String { kind }
    public var kind: String, long: String, short: String
    public var longBurn: Double, shortBurn: Double, threshold: Double, firing: Bool
}

public struct ControlItem: Identifiable, Sendable, Equatable {
    public var id: String
    public var pack: String, title: String, cisRef: String
    public var status: NowSeverity, statusRaw: String
    public var severity: String, evidence: String, remediation: String
    public var nodes: Int
}

public struct PackSummary: Identifiable, Sendable, Equatable {
    public var id: String
    public var title: String, description: String
    public var passed: Int, failed: Int, warned: Int, total: Int
}

public struct NamedValue: Identifiable, Sendable, Equatable {
    public var id: String { name }
    public var name: String
    public var value: Double
    public init(name: String, value: Double) { self.name = name; self.value = value }
}

public enum NowData {
    private static func d(_ v: JSONValue?) -> Double { v?.asDouble ?? 0 }
    private static func s(_ v: JSONValue?) -> String { (v?.string) ?? (v.flatMap { $0 == .null ? nil : $0.summary } ?? "") }
    private static func arr(_ v: JSONValue?) -> [JSONValue] { if case .array(let a)? = v { a } else { [] } }

    /// A server zero-time ("0001-01-01T00:00:00Z") means "unset": returns nil for anything before 2000.
    public static func realDate(_ v: JSONValue?) -> Date? {
        guard let dt = CellFormat.date(v), dt.timeIntervalSince1970 > 946_684_800 else { return nil }
        return dt
    }

    // MARK: Health (/api/v1/ebpf/health)

    /// Anomaly counts by severity, worst first, only severities present.
    public static func anomalyCounts(_ health: JSONValue) -> [(NowSeverity, Int)] {
        var c: [NowSeverity: Int] = [:]
        for a in arr(health.at("summary.anomalies")) { c[NowSeverity(s(a["severity"])), default: 0] += 1 }
        return c.sorted { $0.key > $1.key }.map { ($0.key, $0.value) }
    }

    /// Worst anomaly severity, or .ok when there are none.
    public static func worstAnomaly(_ health: JSONValue) -> NowSeverity {
        anomalyCounts(health).first?.0 ?? .ok
    }

    /// Top TCP problem endpoints by retransmissions: label is "remote:port (comm)".
    public static func topRetransmitters(_ health: JSONValue, limit: Int = 8) -> [NamedValue] {
        arr(health.at("summary.topTcpProblems")).compactMap { t -> NamedValue? in
            let n = d(t["retransmissions"]); guard n > 0 else { return nil }
            var label = "\(s(t["remoteIp"])):\(Int(d(t["remotePort"])))"
            let comm = s(t["comm"]); if !comm.isEmpty { label += " (\(comm))" }
            return NamedValue(name: label, value: n)
        }.sorted { $0.value > $1.value }.prefix(limit).map { $0 }
    }

    /// Top DNS names by failures.
    public static func topDNSFailures(_ health: JSONValue, limit: Int = 8) -> [NamedValue] {
        arr(health.at("summary.topDnsProblems")).compactMap { t -> NamedValue? in
            let n = d(t["failures"]); guard n > 0 else { return nil }
            return NamedValue(name: s(t["name"]), value: n)
        }.sorted { $0.value > $1.value }.prefix(limit).map { $0 }
    }

    /// Score band: >=90 ok, >=70 warning, else critical. (Mirrors the scorecard's green/amber/red idea.)
    public static func scoreSeverity(_ score: Double) -> NowSeverity { score >= 90 ? .ok : score >= 70 ? .warning : .critical }

    // MARK: Scorecard (/api/v1/scorecard)

    public static func scorecardCounters(_ sc: JSONValue) -> [NamedValue] {
        [("Health score", "healthScore"), ("Stale agents", "staleAgents"), ("Detached programs", "detachedPrograms"),
         ("Missing maps", "missingMaps"), ("Blocked events", "blockedEvents")]
            .map { NamedValue(name: $0.0, value: d(sc[$0.1])) }
    }

    // MARK: SLO (/api/v1/slo)

    public static func sloItems(_ v: JSONValue) -> [SLOItem] {
        arr(v["items"]).enumerated().map { i, it in
            let scope = [s(it["namespace"]), s(it["workload"])].filter { !$0.isEmpty }.joined(separator: "/")
            let ws = arr(it["windows"]).map {
                SLOWindow(kind: s($0["kind"]), long: s($0["long"]), short: s($0["short"]), longBurn: d($0["longBurn"]),
                          shortBurn: d($0["shortBurn"]), threshold: d($0["threshold"]), firing: $0["firing"] == .bool(true))
            }
            return SLOItem(id: "\(s(it["name"]))#\(i)", name: s(it["name"]), sli: s(it["sli"]), scope: scope, window: s(it["window"]),
                           severity: NowSeverity(s(it["severity"])), targetPct: d(it["targetPct"]), compliancePct: d(it["compliancePct"]),
                           budgetRemaining: d(it["budgetRemaining"]), hasData: it["hasData"] == .bool(true),
                           total: d(it["total"]), errors: d(it["errors"]), windows: ws)
        }
    }

    // MARK: Compliance (/api/v1/compliance)

    public static func packSummaries(_ v: JSONValue) -> [PackSummary] {
        arr(v["packs"]).enumerated().map { i, p in
            let controls = arr(p["controls"])
            return PackSummary(id: s(p["id"]).isEmpty ? "pack\(i)" : s(p["id"]), title: s(p["title"]), description: s(p["description"]),
                               passed: Int(d(p["passed"])), failed: Int(d(p["failed"])), warned: Int(d(p["warned"])), total: controls.count)
        }
    }

    public static func controls(_ v: JSONValue) -> [ControlItem] {
        arr(v["packs"]).flatMap { p -> [ControlItem] in
            let pack = s(p["title"]).isEmpty ? s(p["id"]) : s(p["title"])
            return arr(p["controls"]).enumerated().map { i, c in
                ControlItem(id: "\(s(p["id"]))/\(s(c["id"]))#\(i)", pack: pack, title: s(c["title"]), cisRef: s(c["cisRef"]),
                            status: NowSeverity(s(c["status"])), statusRaw: s(c["status"]), severity: s(c["severity"]),
                            evidence: s(c["evidence"]), remediation: s(c["remediation"]), nodes: Int(d(c["nodes"])))
            }
        }
    }

    // MARK: Audit (/api/v1/audit, /api/v1/audit/summary)

    /// Events per hour bucket with the parsed hour; unparseable buckets are dropped.
    public static func auditHours(_ summary: JSONValue) -> [(Date, Int)] {
        arr(summary["byHour"]).compactMap { b in
            guard let t = CellFormat.date(b["hour"]) else { return nil }
            return (t, Int(d(b["count"])))
        }.sorted { $0.0 < $1.0 }
    }

    public static func auditTop(_ summary: JSONValue, key: String, limit: Int = 6) -> [NamedValue] {
        arr(summary[key]).map { NamedValue(name: s($0["key"]), value: d($0["count"])) }
            .sorted { $0.value > $1.value }.prefix(limit).map { $0 }
    }

    /// Compact "key=value" rendering of an audit event's details (sorted, scalars only).
    public static func auditDetails(_ ev: JSONValue) -> String {
        guard case .object(let o)? = ev["details"] else { return "" }
        return o.keys.sorted().compactMap { k in
            switch o[k] { case .some(.string), .some(.number), .some(.bool): "\(k)=\(o[k]!.summary)"; default: nil }
        }.joined(separator: " ")
    }
}
