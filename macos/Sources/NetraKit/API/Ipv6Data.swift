// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Pure mapping for GET /api/v1/ebpf/ipv6 and GET /api/v1/ebpf/kernel-network. Read-only and tolerant of
/// missing fields; the kernel-network "apply" and "rollback" commands are operator guidance text only.
public enum Ipv6Data {
    private static func items(_ v: JSONValue, _ path: String) -> [JSONValue] {
        if case .array(let a)? = v.at(path) { a } else { [] }
    }

    // MARK: IPv6 extension headers

    public struct ExtRow: Identifiable, Sendable, Equatable {
        public let node: String, direction: String, hook: String
        public let packets: Double, extHeaderPackets: Double, totalExtHeaders: Double
        public let fragmented: Double, nonFirstFragments: Double, moreFragments: Double, chainTruncated: Double
        public var id: String { "\(node)|\(direction)|\(hook)" }
        /// Fraction of packets that were fragments; nil with no packets.
        public var fragmentRate: Double? { packets > 0 ? fragmented / packets : nil }
        public var extHeaderRate: Double? { packets > 0 ? extHeaderPackets / packets : nil }
    }

    /// One row per node, direction and hook, highest fragmentation then truncation first.
    public static func extRows(_ v: JSONValue) -> [ExtRow] {
        var out: [ExtRow] = []
        for n in items(v, "nodes") {
            let node = n.at("node")?.string ?? "?"
            for e in items(n, "extHeaders") {
                func d(_ k: String) -> Double { e.at(k)?.asDouble ?? 0 }
                out.append(ExtRow(node: node, direction: e.at("direction")?.string ?? "", hook: e.at("hook")?.string ?? "",
                                  packets: d("packets"), extHeaderPackets: d("extHeaderPackets"), totalExtHeaders: d("totalExtHeaders"),
                                  fragmented: d("fragmented"), nonFirstFragments: d("nonFirstFragments"),
                                  moreFragments: d("moreFragments"), chainTruncated: d("chainTruncated")))
            }
        }
        return out.sorted { ($0.fragmented, $0.chainTruncated, $0.id) > ($1.fragmented, $1.chainTruncated, $1.id) }
    }

    public struct Anomaly: Identifiable, Sendable, Equatable {
        public let severity: KernelData.Severity
        public let kind: String, subject: String, message: String
        public let value: Double?
        public var id: String { "\(kind)|\(subject)|\(message)" }
    }

    /// `summary.anomalies`, most severe first (stable otherwise).
    public static func anomalies(_ v: JSONValue) -> [Anomaly] {
        items(v, "summary.anomalies").map {
            Anomaly(severity: .init($0.at("severity")?.string), kind: $0.at("kind")?.string ?? "",
                    subject: $0.at("subject")?.string ?? "", message: $0.at("message")?.string ?? "", value: $0.at("value")?.asDouble)
        }.enumerated().sorted { ($0.element.severity, $0.offset) < ($1.element.severity, $1.offset) }.map(\.element)
    }

    // MARK: kernel network

    public struct Finding: Identifiable, Sendable, Equatable {
        public let node: String
        public let severity: KernelData.Severity
        public let layer: String, signal: String, explanation: String, recommendation: String, risk: String
        public let evidence: [String]
        public let tunable: String, currentValue: String, suggestedValue: String, applyCommand: String, rollbackCommand: String
        public let windowSeconds: Double?
        public var id: String { "\(node)|\(layer)|\(signal)" }
    }

    /// All findings across nodes, most severe first, then by node and layer.
    public static func findings(_ v: JSONValue) -> [Finding] {
        var out: [Finding] = []
        for n in items(v, "nodes") {
            let node = n.at("node")?.string ?? "?"
            for f in items(n, "findings") {
                func s(_ k: String) -> String { f.at(k)?.string ?? "" }
                out.append(Finding(node: node, severity: .init(s("severity")), layer: s("layer"), signal: s("signal"),
                                   explanation: s("explanation"), recommendation: s("recommendation"), risk: s("risk"),
                                   evidence: items(f, "evidence").compactMap(\.string),
                                   tunable: s("tunable"), currentValue: s("currentValue"), suggestedValue: s("suggestedValue"),
                                   applyCommand: s("applyCommand"), rollbackCommand: s("rollbackCommand"),
                                   windowSeconds: f.at("windowSeconds")?.asDouble))
            }
        }
        return out.sorted { ($0.severity, $0.node, $0.layer) < ($1.severity, $1.node, $1.layer) }
    }

    public struct NodeWindow: Identifiable, Sendable, Equatable {
        public let node: String
        public let warming: Bool, reset: Bool
        public let seconds: Double?
        /// Drop rates per second keyed by a readable label, in fixed order.
        public let rates: [(label: String, perSecond: Double)]
        public let counters: Int
        public var id: String { node }
        public static func == (a: NodeWindow, b: NodeWindow) -> Bool {
            a.node == b.node && a.warming == b.warming && a.reset == b.reset && a.seconds == b.seconds && a.counters == b.counters
                && a.rates.map(\.label) == b.rates.map(\.label) && a.rates.map(\.perSecond) == b.rates.map(\.perSecond)
        }
    }

    /// One row per node. Warming nodes carry no rates, because their interval has not been measured yet.
    public static func windows(_ v: JSONValue) -> [NodeWindow] {
        let keys: [(String, String)] = [("Softnet drops", "softnetDroppedPerSecond"), ("Softnet squeeze", "softnetTimeSqueezePerSecond"),
                                        ("RX dropped", "rxDroppedPerSecond"), ("TX dropped", "txDroppedPerSecond"),
                                        ("RX missed", "rxMissedPerSecond"), ("Qdisc drops", "qdiscDropsPerSecond")]
        return items(v, "nodes").map { n in
            let w = n.at("window")
            let warming = w == nil || w?.at("warming") == .bool(true)
            return NodeWindow(node: n.at("node")?.string ?? "?", warming: warming, reset: w?.at("resetDetected") == .bool(true),
                              seconds: w?.at("seconds")?.asDouble,
                              rates: warming ? [] : keys.map { ($0.0, w?.at($0.1)?.asDouble ?? 0) },
                              counters: items(n, "snapshot.counters").count)
        }
    }

    /// Counter and tunable rows for one node's boot-lifetime snapshot.
    public static func snapshotRows(_ v: JSONValue, node: String) -> [(name: String, value: String, kind: String)] {
        guard let n = items(v, "nodes").first(where: { $0.at("node")?.string == node }), let s = n.at("snapshot") else { return [] }
        let t = items(s, "tunables").map { (name: $0.at("name")?.string ?? "", value: $0.at("value")?.summary ?? "", kind: "tunable") }
        let c = items(s, "counters").map { (name: $0.at("name")?.string ?? "", value: $0.at("value")?.summary ?? "", kind: "counter") }
        return (t + c).sorted { $0.name < $1.name }
    }
}
