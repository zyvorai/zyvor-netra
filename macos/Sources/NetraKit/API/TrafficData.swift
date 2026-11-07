// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// One ranked bar: `value` is the total, `blocked` the part of it that was blocked (0 when not applicable).
public struct RankedBar: Identifiable, Sendable, Equatable {
    public let label: String
    public let value: Double
    public let blocked: Double
    public var id: String { label }
    public var allowed: Double { max(value - blocked, 0) }
    public init(label: String, value: Double, blocked: Double = 0) { self.label = label; self.value = value; self.blocked = blocked }
}

/// Pure aggregation for the Traffic pages (talkers, ports, protocols, drops, DNS). Tolerates missing fields.
public enum TrafficData {
    /// Sum of `key` over the array at `path`.
    public static func sum(_ v: JSONValue, at path: String = "rows", key: String) -> Double {
        guard case .array(let a)? = v.at(path) else { return 0 }
        return a.reduce(0) { $0 + ($1[key]?.asDouble ?? 0) }
    }

    /// Top-`top` rows of the array at `path`, ranked by `valueKey` descending. Rows without a label are skipped.
    public static func rankedBars(_ v: JSONValue, at path: String = "rows", top: Int = 10,
                                  valueKey: String, blockedKey: String? = nil,
                                  label: (JSONValue) -> String?) -> [RankedBar] {
        guard case .array(let a)? = v.at(path) else { return [] }
        let bars: [RankedBar] = a.compactMap { row in
            guard let l = label(row), !l.isEmpty else { return nil }
            return RankedBar(label: l, value: row[valueKey]?.asDouble ?? 0, blocked: blockedKey.flatMap { row[$0]?.asDouble } ?? 0)
        }
        return Array(bars.sorted { $0.value > $1.value }.prefix(max(top, 0)))
    }

    public static func talkerBars(_ v: JSONValue, top: Int = 10) -> [RankedBar] {
        rankedBars(v, top: top, valueKey: "packets", blockedKey: "blocked") { $0["destination"]?.string }
    }

    /// Label is `proto/port` (the server also sends it as `key`).
    public static func portBars(_ v: JSONValue, top: Int = 10) -> [RankedBar] {
        rankedBars(v, top: top, valueKey: "packets", blockedKey: "blocked") { row in
            guard let port = row["port"]?.asDouble else { return row["key"]?.string }
            return "\(row["protocol"]?.string ?? "?")/\(Int(port))"
        }
    }

    public static func protocolBars(_ v: JSONValue, top: Int = 8) -> [RankedBar] {
        rankedBars(v, top: top, valueKey: "packets", blockedKey: "blocked") { $0["protocol"]?.string }
    }

    /// DNS names ranked by failures (falls back to queries when nothing failed).
    public static func dnsBars(_ v: JSONValue, top: Int = 10) -> [RankedBar] {
        let anyFailures = sum(v, key: "failures") > 0
        return rankedBars(v, top: top, valueKey: anyFailures ? "failures" : "queries") { $0["name"]?.string }
    }

    /// Kernel skb drops summed across nodes by reason name (`/api/v1/ebpf/drops`: nodes[].kernelDrops[]).
    public static func kernelReasonBars(_ drops: JSONValue, top: Int = 12) -> [RankedBar] {
        guard case .array(let nodes)? = drops["nodes"] else { return [] }
        var totals: [String: Double] = [:]
        for n in nodes {
            guard case .array(let ds)? = n["kernelDrops"] else { continue }
            for d in ds {
                let name = d["reasonName"]?.string.flatMap { $0.isEmpty ? nil : $0 } ?? "reason #\(Int(d["reason"]?.asDouble ?? 0))"
                totals[name, default: 0] += d["count"]?.asDouble ?? 0
            }
        }
        let bars = totals.map { RankedBar(label: $0.key, value: $0.value) }.sorted { $0.value > $1.value }
        return Array(bars.prefix(top))
    }

    /// Rank used to sort and to pick a symbol: info < warning < critical (also tolerates low/medium/high).
    public static func severityRank(_ s: String?) -> Int {
        switch s?.lowercased() {
        case "critical", "high", "exact": 3
        case "warning", "medium", "probable": 2
        case "info", "low": 1
        default: 0
        }
    }

    /// SF Symbol that carries severity without relying on color.
    public static func severitySymbol(_ s: String?) -> String {
        switch severityRank(s) {
        case 3: "exclamationmark.octagon.fill"
        case 2: "exclamationmark.triangle.fill"
        case 1: "info.circle.fill"
        default: "checkmark.circle"
        }
    }

    /// DNS failure-rate bands (rate is 0...1): <5% ok, <20% elevated, otherwise high.
    public static func dnsHealth(failRate: Double) -> String {
        failRate >= 0.2 ? "high" : failRate >= 0.05 ? "elevated" : "ok"
    }

    /// 1234 -> "1.2K", 1_500_000 -> "1.5M".
    public static func compact(_ n: Double) -> String {
        let a = abs(n)
        if a < 1000 { return String(Int(n.rounded())) }
        let units: [(Double, String)] = [(1e12, "T"), (1e9, "G"), (1e6, "M"), (1e3, "K")]
        for (d, u) in units where a >= d { return String(format: "%.1f%@", n / d, u) }
        return String(Int(n))
    }

    /// "12.5%" of part over total; "–" when total is 0.
    public static func percent(_ part: Double, of total: Double) -> String {
        total > 0 ? String(format: "%.1f%%", part / total * 100) : "–"
    }
}
