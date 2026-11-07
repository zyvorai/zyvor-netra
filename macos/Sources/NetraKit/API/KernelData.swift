// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Pure mapping/aggregation for the kernel pages (listen queues, sysctl, node resources, netlink,
/// BPF attachments, BPF maps). Everything here is read-only and tolerant of missing fields.
public enum KernelData {
    // MARK: severity and pressure

    public enum Severity: Int, Sendable, Comparable, CaseIterable {
        case critical, warning, info, ok
        public init(_ s: String?) {
            switch (s ?? "").lowercased() {
            case "critical", "crit", "error", "high": self = .critical
            case "warning", "warn", "medium": self = .warning
            case "ok", "pass", "good": self = .ok
            default: self = .info
            }
        }
        public static func < (a: Severity, b: Severity) -> Bool { a.rawValue < b.rawValue }
        public var label: String { ["Critical", "Warning", "Info", "OK"][rawValue] }
        public var symbol: String { ["xmark.octagon.fill", "exclamationmark.triangle.fill", "info.circle.fill", "checkmark.circle.fill"][rawValue] }
    }

    /// Fill ratio of a bounded resource (map entries, accept queue). nil when the limit is unknown.
    public static func ratio(_ count: Double, _ limit: Double) -> Double? {
        limit > 0 ? max(0, count / limit) : nil
    }

    public static func pressure(_ ratio: Double?) -> Severity {
        guard let r = ratio else { return .info }
        return r >= 0.9 ? .critical : r >= 0.7 ? .warning : .ok
    }

    // MARK: listen queues

    public static let listenBucketOrder = ["empty", "le_25", "le_50", "le_75", "lt_100", "full"]
    public static let listenBucketLabels = ["empty": "Empty", "le_25": "≤25%", "le_50": "≤50%", "le_75": "≤75%", "lt_100": "<100%", "full": "Full"]

    public struct Bucket: Identifiable, Sendable, Equatable { public let id: String; public let label: String; public let count: Double }

    /// Fill histogram in fixed order; unknown bins are appended. Empty when the response has no buckets.
    public static func listenBuckets(_ v: JSONValue) -> [Bucket] {
        guard case .object(let o)? = v.at("buckets") else { return [] }
        let extra = o.keys.filter { !listenBucketOrder.contains($0) }.sorted()
        return (listenBucketOrder + extra).compactMap { k in
            o[k].flatMap(\.asDouble).map { Bucket(id: k, label: listenBucketLabels[k] ?? k, count: $0) }
        }
    }

    /// Current fill of one listener row (`queue`/`max`), 0...1+.
    public static func listenFill(_ row: JSONValue) -> Double? {
        ratio(row.at("queue")?.asDouble ?? 0, row.at("max")?.asDouble ?? 0)
    }

    // MARK: BPF maps

    public struct MapPressure: Identifiable, Sendable, Equatable {
        public let id: String, title: String, group: String, bpfMap: String
        public let count: Int, limit: Int
        public let entries: [String]
        public var ratio: Double? { KernelData.ratio(Double(count), Double(limit)) }
        public var level: Severity { KernelData.pressure(ratio) }
    }

    /// Map families, fullest first (unknown limits last, then by count).
    public static func mapPressures(_ v: JSONValue) -> [MapPressure] {
        guard case .array(let a)? = v.at("maps") else { return [] }
        let all = a.enumerated().map { i, m in
            MapPressure(id: m.at("id")?.string ?? "map#\(i)", title: m.at("title")?.string ?? m.at("id")?.string ?? "map",
                        group: m.at("group")?.string ?? "", bpfMap: m.at("bpfMap")?.string ?? "",
                        count: Int(m.at("count")?.asDouble ?? 0), limit: Int(m.at("limit")?.asDouble ?? 0),
                        entries: { if case .array(let e)? = m.at("entries") { return e.map(\.summary) } else { return [] } }())
        }
        return all.sorted {
            switch ($0.ratio, $1.ratio) {
            case let (a?, b?) where a != b: return a > b
            case (.some, .none): return true
            case (.none, .some): return false
            default: return $0.count != $1.count ? $0.count > $1.count : $0.id < $1.id
            }
        }
    }

    // MARK: BPF attachments

    public struct AttachNode: Identifiable, Sendable, Equatable {
        public var id: String { node }
        public let node: String
        public let reporting: Bool, stale: Bool, tcxSupported: Bool
        public let unavailable: String, error: String
        public let total: Int, truncated: Int
        public let failed: [String], hooks: [String], configured: [String]
        /// Configured interfaces that the kernel shows with no Netra program. Empty when the list is
        /// unreliable (not reporting, truncated) because absence then means "unknown", not "detached".
        public let missing: [String]
        public var drift: Bool { !missing.isEmpty }
    }

    public struct AttachRow: Identifiable, Sendable, Equatable {
        public let id: String
        public let node: String, iface: String, index: Int, type: String, state: String
        public let xdp: String, tcxIngress: String, tcxEgress: String, tcIngress: String, tcEgress: String
        public let programs: Int, netra: Int, cilium: Int, other: Int
    }

    private static func programs(_ v: JSONValue?) -> [JSONValue] { if case .array(let a)? = v { a } else { [] } }
    private static func progText(_ p: JSONValue) -> String {
        let name = p.at("name")?.string ?? "id \(p.at("id")?.summary ?? "?")"
        let owner = p.at("owner")?.string ?? "other"
        let mode = p.at("mode")?.string.map { ", \($0)" } ?? ""
        return "\(name) (\(owner)\(mode))"
    }

    public static func attachNodes(_ v: JSONValue) -> [AttachNode] {
        programs(v.at("nodes")).map { n in
            let strs: (String) -> [String] = { k in programs(n.at(k)).compactMap(\.string) }
            let reporting = { if case .bool(let b)? = n.at("reporting") { return b } else { return false } }()
            let truncated = Int(n.at("truncated")?.asDouble ?? 0)
            let failed = strs("failed")
            let attached = programs(n.at("attached"))
            let withNetra = Set(attached.filter { i in
                [i.at("xdp")].compactMap { $0 }.filter { $0 != .null }.contains { $0.at("owner")?.string == "netra" }
                || ["tcxIngress", "tcxEgress", "tcIngress", "tcEgress"].contains { programs(i.at($0)).contains { $0.at("owner")?.string == "netra" } }
            }.compactMap { $0.at("name")?.string })
            let configured = strs("configuredInterfaces")
            let missing = (reporting && truncated == 0) ? configured.filter { !withNetra.contains($0) && !failed.contains($0) } : []
            return AttachNode(node: n.at("node")?.string ?? "?", reporting: reporting,
                              stale: { if case .bool(let b)? = n.at("stale") { return b } else { return false } }(),
                              tcxSupported: { if case .bool(let b)? = n.at("tcxSupported") { return b } else { return false } }(),
                              unavailable: n.at("unavailable")?.string ?? "", error: n.at("error")?.string ?? "",
                              total: Int(n.at("total")?.asDouble ?? 0), truncated: truncated,
                              failed: failed, hooks: strs("hooks"), configured: configured, missing: missing)
        }.sorted { ($0.drift ? 0 : 1, $0.node) < ($1.drift ? 0 : 1, $1.node) }
    }

    public static func attachRows(_ v: JSONValue) -> [AttachRow] {
        var out: [AttachRow] = []
        for n in programs(v.at("nodes")) {
            let node = n.at("node")?.string ?? "?"
            for i in programs(n.at("attached")) {
                let xdp = (i.at("xdp").flatMap { $0 == .null ? nil : $0 }).map { [$0] } ?? []
                let lists = [xdp, programs(i.at("tcxIngress")), programs(i.at("tcxEgress")), programs(i.at("tcIngress")), programs(i.at("tcEgress"))]
                let all = lists.flatMap { $0 }
                let owners = all.map { $0.at("owner")?.string ?? "other" }
                let name = i.at("name")?.string ?? "?"
                out.append(AttachRow(id: "\(node)/\(name)", node: node, iface: name, index: Int(i.at("index")?.asDouble ?? 0),
                                     type: i.at("type")?.string ?? "", state: i.at("state")?.string ?? "",
                                     xdp: xdp.map(progText).joined(separator: ", "),
                                     tcxIngress: lists[1].map(progText).joined(separator: " → "), tcxEgress: lists[2].map(progText).joined(separator: " → "),
                                     tcIngress: lists[3].map(progText).joined(separator: ", "), tcEgress: lists[4].map(progText).joined(separator: ", "),
                                     programs: all.count, netra: owners.filter { $0 == "netra" }.count,
                                     cilium: owners.filter { $0 == "cilium" }.count, other: owners.filter { $0 != "netra" && $0 != "cilium" }.count))
            }
        }
        return out.sorted { ($0.node, $0.iface) < ($1.node, $1.iface) }
    }

    // MARK: findings (attachments, netlink)

    public struct Finding: Identifiable, Sendable, Equatable {
        public let id: String
        public let severity: Severity
        public let kind: String, node: String, message: String
        public let value: Double?
        public let interfaces: [String]
        public let firstObserved: Date?, lastObserved: Date?
        public let raw: JSONValue
    }

    /// Findings from the attachments or netlink-findings response, worst first.
    public static func findings(_ v: JSONValue) -> [Finding] {
        programs(v.at("findings")).enumerated().map { i, f in
            Finding(id: "\(f.at("node")?.string ?? "")/\(f.at("kind")?.string ?? "")#\(i)",
                    severity: Severity(f.at("severity")?.string), kind: f.at("kind")?.string ?? "",
                    node: f.at("node")?.string ?? "", message: f.at("message")?.string ?? "",
                    value: f.at("value")?.asDouble, interfaces: programs(f.at("interfaces")).compactMap(\.string),
                    firstObserved: CellFormat.date(f.at("firstObserved")), lastObserved: CellFormat.date(f.at("lastObserved")), raw: f)
        }.sorted { ($0.severity, $0.node, $0.kind) < ($1.severity, $1.node, $1.kind) }
    }

    // MARK: netlink

    public static let netlinkKinds = ["link", "address", "route", "neighbor", "overrun"]

    public struct NetlinkRow: Identifiable, Sendable, Equatable {
        public let id: String
        public let time: Date?
        public let node: String, kind: String, action: String, iface: String, subject: String
        public let origin: String, comm: String, pid: Int?, cgroup: Int?, confidence: String
        public let raw: JSONValue
        /// "comm (pid)" for a process, "kernel" or "unattributed" otherwise. Never argv or environment.
        public var requester: String {
            if !comm.isEmpty || pid != nil { return comm + (pid.map { " (\($0))" } ?? "") }
            return origin == "kernel" ? "kernel" : "unattributed"
        }
    }

    private static func str(_ v: JSONValue, _ k: String) -> String { v.at(k)?.string ?? "" }

    public static func netlinkRows(_ v: JSONValue) -> [NetlinkRow] {
        programs(v.at("events")).map { e in
            let kind = str(e, "kind")
            let subject: String
            switch kind {
            case "route": subject = [str(e, "destination"), str(e, "gateway").isEmpty ? "" : "via " + str(e, "gateway")].filter { !$0.isEmpty }.joined(separator: " ")
            case "neighbor": subject = [str(e, "address"), str(e, "mac"), str(e, "state")].filter { !$0.isEmpty }.joined(separator: " ")
            case "address": subject = str(e, "address")
            case "link": subject = [str(e, "state"), e.at("mtu").map { "mtu \($0.summary)" } ?? ""].filter { !$0.isEmpty }.joined(separator: " ")
            default: subject = str(e, "detail")
            }
            let node = str(e, "node")
            let seq = e.at("sequence")?.summary ?? "0"
            return NetlinkRow(id: "\(node)/\(e.at("epoch")?.summary ?? "0")/\(seq)", time: CellFormat.date(e.at("observedAt")),
                              node: node, kind: kind, action: str(e, "action"),
                              iface: str(e, "interface").isEmpty ? (e.at("interfaceIndex").map { "if\($0.summary)" } ?? "") : str(e, "interface"),
                              subject: subject, origin: str(e, "origin"), comm: str(e, "actor.comm"),
                              pid: e.at("actor.pid")?.asDouble.map { Int($0) }, cgroup: e.at("actor.cgroupId")?.asDouble.map { Int($0) },
                              confidence: str(e, "actor.confidence"), raw: e)
        }.sorted { ($0.time ?? .distantPast) > ($1.time ?? .distantPast) }
    }

    public struct TimeBin: Identifiable, Sendable, Equatable {
        public var id: String { "\(start.timeIntervalSince1970)/\(kind)" }
        public let start: Date, kind: String, count: Int
    }

    /// Events per time bin and kind, for a stacked timeline chart.
    public static func netlinkTimeline(_ rows: [NetlinkRow], binSeconds: Double = 60) -> [TimeBin] {
        var m: [String: (Date, String, Int)] = [:]
        for r in rows {
            guard let t = r.time else { continue }
            let s = Date(timeIntervalSince1970: (t.timeIntervalSince1970 / binSeconds).rounded(.down) * binSeconds)
            let k = "\(s.timeIntervalSince1970)/\(r.kind)"
            m[k] = (s, r.kind, (m[k]?.2 ?? 0) + 1)
        }
        return m.values.map { TimeBin(start: $0.0, kind: $0.1, count: $0.2) }.sorted { ($0.start, $0.kind) < ($1.start, $1.kind) }
    }

    public struct NetlinkNode: Identifiable, Sendable, Equatable {
        public var id: String { node }
        public let node: String, reporting: Bool, stale: Bool, unavailable: String, error: String
        public let dropped: Int, missed: Int, overruns: Int, resubscribes: Int, events: Int
        public let actorAvailable: Bool, actorUnavailable: String
        public let links: Int, addresses: Int, routes: Int, neighbors: Int
        public let historySince: Date?
        /// Lost messages make the recorded history incomplete.
        public var lossy: Bool { dropped + missed + overruns > 0 }
    }

    public static func netlinkNodes(_ v: JSONValue) -> [NetlinkNode] {
        programs(v.at("nodes")).map { n in
            let i: (String) -> Int = { Int(n.at($0)?.asDouble ?? 0) }
            return NetlinkNode(node: str(n, "node"), reporting: { if case .bool(let b)? = n.at("reporting") { return b } else { return false } }(),
                               stale: { if case .bool(let b)? = n.at("stale") { return b } else { return false } }(),
                               unavailable: str(n, "unavailable"), error: str(n, "error"),
                               dropped: i("dropped"), missed: i("missed"), overruns: i("overruns"), resubscribes: i("resubscribes"),
                               events: i("sequence"),
                               actorAvailable: { if case .bool(let b)? = n.at("actor.available") { return b } else { return false } }(),
                               actorUnavailable: str(n, "actor.unavailable"),
                               links: i("counts.links"), addresses: i("counts.addresses"), routes: i("counts.routes"), neighbors: i("counts.neighbors"),
                               historySince: CellFormat.date(n.at("historySince")))
        }.sorted { $0.node < $1.node }
    }

    // MARK: sysctl audit

    public struct SysctlRow: Identifiable, Sendable, Equatable {
        public let id: String
        public let severity: Severity
        public let node: String, category: String, name: String, iface: String
        public let current: String, expected: String, rationale: String
        public var deviates: Bool { !expected.isEmpty && expected != current }
    }

    public static func sysctlRows(_ v: JSONValue) -> [SysctlRow] {
        var out: [SysctlRow] = []
        for n in programs(v.at("nodes")) {
            let node = str(n, "node")
            for (i, f) in programs(n.at("findings")).enumerated() {
                out.append(SysctlRow(id: "\(node)/\(str(f, "name"))/\(str(f, "interface"))#\(i)", severity: Severity(str(f, "severity")),
                                     node: node, category: str(f, "category"), name: str(f, "name"), iface: str(f, "interface"),
                                     current: str(f, "currentValue"), expected: str(f, "expectedValue"), rationale: str(f, "rationale")))
            }
        }
        return out.sorted { ($0.severity, $0.name, $0.node) < ($1.severity, $1.name, $1.node) }
    }

    public struct SysctlOutlier: Identifiable, Sendable, Equatable {
        public var id: String { name + "/" + iface }
        public let name: String, iface: String, category: String, majority: String, nodes: [String]
    }

    public static func sysctlOutliers(_ v: JSONValue) -> [SysctlOutlier] {
        programs(v.at("outliers")).map {
            SysctlOutlier(name: str($0, "name"), iface: str($0, "interface"), category: str($0, "category"),
                          majority: str($0, "majorityValue"), nodes: programs($0.at("outlierNodes")).compactMap(\.string))
        }
    }

    // MARK: node resources

    public struct NodeRes: Identifiable, Sendable, Equatable {
        public var id: String { node }
        public let node: String, stale: Bool, ageSeconds: Double
        public let cpuPercent: Double, cores: Int, load1: Double, load5: Double, load15: Double
        public let memTotal: Double, memUsed: Double, memCached: Double, uptime: Double, kernel: String
        public var memRatio: Double? { KernelData.ratio(memUsed, memTotal) }
        /// CPU% is not core-normalised server-side; this is utilisation of all cores.
        public var cpuRatio: Double? { cores > 0 ? cpuPercent / 100 / Double(cores) : nil }
        public var loadRatio: Double? { cores > 0 ? load1 / Double(cores) : nil }
    }

    public static func nodeResources(_ v: JSONValue) -> [NodeRes] {
        programs(v.at("nodes")).map { n in
            let d: (String) -> Double = { n.at("host." + $0)?.asDouble ?? 0 }
            return NodeRes(node: str(n, "node"), stale: { if case .bool(let b)? = n.at("stale") { return b } else { return false } }(),
                           ageSeconds: n.at("ageSeconds")?.asDouble ?? 0, cpuPercent: d("cpuPercent"), cores: Int(d("cpuCores")),
                           load1: d("loadAvg1"), load5: d("loadAvg5"), load15: d("loadAvg15"),
                           memTotal: d("memoryTotalBytes"), memUsed: d("memoryUsedBytes"), memCached: d("memoryCachedBytes"),
                           uptime: d("uptimeSeconds"), kernel: n.at("host.kernelRelease")?.string ?? "")
        }.sorted { $0.node < $1.node }
    }
}
