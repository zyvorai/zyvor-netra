// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

// Read models for /api/v1/metrics/*. Observe-only; ack/silence change notification state only.

/// Decodes `null` or a missing array as empty (Go nil slices encode as null).
private extension KeyedDecodingContainer {
    func list<T: Decodable>(_ k: Key) -> [T] { (try? decodeIfPresent([T].self, forKey: k)) ?? [] }
}

public struct MetricsSummary: Decodable, Sendable, Equatable {
    public var available: Bool
    public var nodes: Int
    public var staleNodes: Int
    public var series: Int
    public var anomalyRate: Double
    public var alertsCritical: Int
    public var alertsWarning: Int
    public var topAlerts: [MetricAlertRef]
    public var topAnomalous: [MetricRef]
    enum K: String, CodingKey { case available, nodes, staleNodes, series, anomalyRate, alertsCritical, alertsWarning, topAlerts, topAnomalous }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: K.self)
        func n(_ k: K) -> Int { LenientDecode.double(c, k).flatMap(LenientDecode.int64).map { Int(clamping: $0) } ?? 0 }
        available = LenientDecode.bool(c, .available) ?? false
        nodes = n(.nodes); staleNodes = n(.staleNodes); series = n(.series)
        anomalyRate = LenientDecode.double(c, .anomalyRate) ?? 0
        alertsCritical = n(.alertsCritical); alertsWarning = n(.alertsWarning)
        topAlerts = c.list(.topAlerts); topAnomalous = c.list(.topAnomalous)
    }
}

public struct MetricAlertRef: Decodable, Sendable, Equatable {
    public var rule: String
    public var status: String
    public var node: String?
    public var chart: String?
}

public struct MetricRef: Decodable, Sendable, Equatable {
    public var node: String?
    public var chart: String?
    public var dimension: String?
    public var anomalyRate: Double
}

public struct MetricNodeInfo: Decodable, Sendable, Equatable, Identifiable {
    public struct Stats: Decodable, Sendable, Equatable {
        public var series: Int
        public var memoryBytes: Int64?
        public var diskBytes: Int64?
        public var oldestT: Int64?
        public var newestT: Int64?
    }
    public var node: String
    public var lastIngest: String?
    public var stats: Stats?
    public var id: String { node }
}
struct MetricNodesResponse: Decodable { var nodes: [MetricNodeInfo] }

public struct MetricChartInfo: Decodable, Sendable, Equatable {
    public var node: String
    public var chart: String
    public var labels: [String: String]?
    public var dimensions: [String]
    enum K: String, CodingKey { case node, chart, labels, dimensions }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: K.self)
        node = try c.decode(String.self, forKey: .node); chart = try c.decode(String.self, forKey: .chart)
        labels = try? c.decodeIfPresent([String: String].self, forKey: .labels)
        dimensions = c.list(.dimensions)
    }
}

public struct MetricContext: Decodable, Sendable, Equatable, Identifiable, Hashable {
    public var context: String
    public var family: String?
    public var title: String?
    public var units: String?
    public var chartType: String?
    public var charts: [MetricChartInfo]
    public var firstT: Int64?
    public var lastT: Int64?
    public var id: String { context }
    enum K: String, CodingKey { case context, family, title, units, chartType, charts, firstT, lastT }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: K.self)
        context = try c.decode(String.self, forKey: .context)
        family = try? c.decodeIfPresent(String.self, forKey: .family)
        title = try? c.decodeIfPresent(String.self, forKey: .title)
        units = try? c.decodeIfPresent(String.self, forKey: .units)
        chartType = try? c.decodeIfPresent(String.self, forKey: .chartType)
        charts = c.list(.charts)
        firstT = try? c.decodeIfPresent(Int64.self, forKey: .firstT)
        lastT = try? c.decodeIfPresent(Int64.self, forKey: .lastT)
    }
    public static func == (a: Self, b: Self) -> Bool { a.context == b.context && a.lastT == b.lastT }
    public func hash(into h: inout Hasher) { h.combine(context) }
}
struct MetricContextsResponse: Decodable { var contexts: [MetricContext] }

/// JSON `null` (NaN/Inf server side) decodes to nil.
public struct MetricDimension: Decodable, Sendable, Equatable, Identifiable {
    public var name: String
    public var labels: [String: String]?
    public var values: [Double?]
    public var anomalyRate: [Double?]
    public var series: Int
    public var id: String { name }
    enum K: String, CodingKey { case name, labels, values, anomalyRate, series }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: K.self)
        name = try c.decode(String.self, forKey: .name)
        labels = try? c.decodeIfPresent([String: String].self, forKey: .labels)
        values = (try? c.decodeIfPresent([Double?].self, forKey: .values)) ?? []
        anomalyRate = (try? c.decodeIfPresent([Double?].self, forKey: .anomalyRate)) ?? []
        series = (try? c.decodeIfPresent(Int.self, forKey: .series)) ?? 0
    }
}

public struct MetricResult: Decodable, Sendable, Equatable {
    public var context: String
    public var title: String?
    public var units: String?
    public var family: String?
    public var chartType: String?
    public var tier: Int
    public var interval: Int64
    public var after: Int64
    public var before: Int64
    public var timestamps: [Int64]
    public var dimensions: [MetricDimension]
    public var matched: Int
    enum K: String, CodingKey { case context, title, units, family, chartType, tier, interval, after, before, timestamps, dimensions, matched }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: K.self)
        context = try c.decode(String.self, forKey: .context)
        title = try? c.decodeIfPresent(String.self, forKey: .title)
        units = try? c.decodeIfPresent(String.self, forKey: .units)
        family = try? c.decodeIfPresent(String.self, forKey: .family)
        chartType = try? c.decodeIfPresent(String.self, forKey: .chartType)
        tier = (try? c.decode(Int.self, forKey: .tier)) ?? 0
        interval = (try? c.decode(Int64.self, forKey: .interval)) ?? 1
        after = (try? c.decode(Int64.self, forKey: .after)) ?? 0
        before = (try? c.decode(Int64.self, forKey: .before)) ?? 0
        timestamps = c.list(.timestamps); dimensions = c.list(.dimensions)
        matched = (try? c.decode(Int.self, forKey: .matched)) ?? 0
    }
}

public struct MetricRanked: Decodable, Sendable, Equatable, Identifiable {
    public var node: String
    public var context: String
    public var chart: String
    public var dimension: String
    public var units: String?
    public var labels: [String: String]?
    public var anomalyRate: Double
    public var score: Double
    public var id: String { "\(node)|\(context)|\(chart)|\(dimension)" }

    public enum Severity: String, Sendable { case high, elevated, low
        public var label: String { rawValue.capitalized }
    }
    /// Anomaly rate is a percent of samples flagged.
    public var severity: Severity { anomalyRate >= 50 ? .high : anomalyRate >= 10 ? .elevated : .low }
}

public struct MetricNodeRate: Decodable, Sendable, Equatable, Identifiable {
    public var node: String
    public var anomalyRate: Double
    public var dimensions: Int
    public var anomalousDimensions: Int
    public var id: String { node }
}

public struct AnomalySummary: Decodable, Sendable, Equatable {
    public var after: Int64
    public var before: Int64
    public var nodes: [MetricNodeRate]
    public var ranked: [MetricRanked]
    public var correlated: [MetricRanked]
    enum K: String, CodingKey { case after, before, nodes, ranked, correlated }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: K.self)
        after = (try? c.decode(Int64.self, forKey: .after)) ?? 0
        before = (try? c.decode(Int64.self, forKey: .before)) ?? 0
        nodes = c.list(.nodes); ranked = c.list(.ranked); correlated = c.list(.correlated)
    }
}

public struct EvidenceLink: Decodable, Sendable, Equatable {
    public var kind: String
    public var title: String
    public var href: String
    public var why: String
}
public struct EvidencePeer: Decodable, Sendable, Equatable {
    public var namespace: String?
    public var workload: String?
    public var peer: String
    public var port: Int
    public var protocolName: String?
    public var packets: Int
    public var bytes: Int
    public var blocked: Int?
    public var retransmissions: Int?
    public var rtos: Int?
    enum CodingKeys: String, CodingKey { case namespace, workload, peer, port, protocolName = "protocol", packets, bytes, blocked, retransmissions, rtos }
}
public struct EvidenceCount: Decodable, Sendable, Equatable { public var name: String; public var count: Int }

public struct MetricEvidence: Decodable, Sendable, Equatable {
    public var context: String
    public var node: String?
    public var kinds: [String]
    public var links: [EvidenceLink]
    public var flowRecords: Int
    public var topPeers: [EvidencePeer]
    public var kernelDrops: [EvidenceCount]
    public var anomalous: [MetricRanked]
    public var limitations: [String]
    enum K: String, CodingKey { case context, node, kinds, links, flowRecords, topPeers, kernelDrops, anomalous, limitations }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: K.self)
        context = try c.decode(String.self, forKey: .context)
        node = try? c.decodeIfPresent(String.self, forKey: .node)
        kinds = c.list(.kinds); links = c.list(.links); topPeers = c.list(.topPeers)
        kernelDrops = c.list(.kernelDrops); anomalous = c.list(.anomalous); limitations = c.list(.limitations)
        flowRecords = (try? c.decode(Int.self, forKey: .flowRecords)) ?? 0
    }
}

public struct MetricAlert: Decodable, Sendable, Equatable, Identifiable {
    public var id: String
    public var rule: String
    public var node: String
    public var context: String?
    public var chart: String
    public var dimension: String?
    public var status: String
    public var value: Double?
    public var units: String?
    public var info: String?
    public var since: String?
    public var silenced: Bool?
    public var acked: Bool?
    public var ackedBy: String?
}

public struct MetricAlertRule: Decodable, Sendable, Equatable {
    public var name: String
    public var context: String?
    public var warn: String?
    public var crit: String?
}

public struct MetricAlertTransition: Decodable, Sendable, Equatable, Identifiable {
    public var time: String
    public var id: String
    public var rule: String
    public var node: String
    public var chart: String
    public var from: String
    public var to: String
    public var value: Double?
    public var units: String?
    public var rowID: String { "\(time)|\(id)|\(to)" }
}

public struct MetricSilence: Decodable, Sendable, Equatable, Identifiable {
    public var id: String
    public var rule: String?
    public var node: String?
    public var chart: String?
    public var until: String
    public var comment: String?
    public var createdBy: String?
    public var created: String?
}

public struct MetricAlertStats: Decodable, Sendable, Equatable {
    public var rules: Int
    public var instances: Int
    public var warning: Int
    public var critical: Int
}

/// GET /api/v1/metrics/alerts: raised alerts, transition history, rules and silences in one document
/// (there is no separate GET for silences).
public struct MetricAlertSnapshot: Decodable, Sendable, Equatable {
    public var active: [MetricAlert]
    public var history: [MetricAlertTransition]
    public var rules: [MetricAlertRule]
    public var silences: [MetricSilence]
    public var stats: MetricAlertStats?
    enum K: String, CodingKey { case active, history, rules, silences, stats }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: K.self)
        active = c.list(.active); history = c.list(.history); rules = c.list(.rules); silences = c.list(.silences)
        stats = try? c.decodeIfPresent(MetricAlertStats.self, forKey: .stats)
    }
}

// MARK: - Lenient decoding
// Go always sends these fields, but one wrong type or null must never blank a whole table, so every
// field falls back to a default. Declared in extensions so the memberwise initialisers stay available.

private struct LK: CodingKey {
    var stringValue: String; var intValue: Int? { nil }
    init(_ s: String) { stringValue = s }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { nil }
}
private struct Lx {
    let c: KeyedDecodingContainer<LK>
    init(_ d: Decoder) throws { c = try d.container(keyedBy: LK.self) }
    func s(_ k: String) -> String { LenientDecode.string(c, LK(k)) ?? "" }
    func os(_ k: String) -> String? { LenientDecode.string(c, LK(k)) }
    func d(_ k: String) -> Double { LenientDecode.double(c, LK(k)) ?? 0 }
    func od(_ k: String) -> Double? { LenientDecode.double(c, LK(k)) }
    func i(_ k: String) -> Int { LenientDecode.double(c, LK(k)).flatMap(LenientDecode.int64).map { Int(clamping: $0) } ?? 0 }
    func i64(_ k: String) -> Int64 { LenientDecode.double(c, LK(k)).flatMap(LenientDecode.int64) ?? 0 }
    func oi64(_ k: String) -> Int64? { LenientDecode.double(c, LK(k)).flatMap(LenientDecode.int64) }
    func b(_ k: String) -> Bool? { LenientDecode.bool(c, LK(k)) }
    func labels(_ k: String) -> [String: String]? { try? c.decodeIfPresent([String: String].self, forKey: LK(k)) }
}

extension MetricAlertRef {
    public init(from d: Decoder) throws { let x = try Lx(d); rule = x.s("rule"); status = x.s("status"); node = x.os("node"); chart = x.os("chart") }
}
extension MetricRef {
    public init(from d: Decoder) throws { let x = try Lx(d); node = x.os("node"); chart = x.os("chart"); dimension = x.os("dimension"); anomalyRate = x.d("anomalyRate") }
}
extension MetricNodeInfo.Stats {
    public init(from d: Decoder) throws {
        let x = try Lx(d)
        series = x.i("series"); memoryBytes = x.oi64("memoryBytes"); diskBytes = x.oi64("diskBytes"); oldestT = x.oi64("oldestT"); newestT = x.oi64("newestT")
    }
}
extension MetricNodeInfo {
    public init(from d: Decoder) throws {
        let x = try Lx(d)
        node = x.s("node"); lastIngest = x.os("lastIngest")
        stats = try? x.c.decodeIfPresent(Stats.self, forKey: LK("stats"))
    }
}
extension MetricRanked {
    public init(from d: Decoder) throws {
        let x = try Lx(d)
        node = x.s("node"); context = x.s("context"); chart = x.s("chart"); dimension = x.s("dimension"); units = x.os("units")
        labels = x.labels("labels"); anomalyRate = x.d("anomalyRate"); score = x.d("score")
    }
}
extension MetricNodeRate {
    public init(from d: Decoder) throws {
        let x = try Lx(d)
        node = x.s("node"); anomalyRate = x.d("anomalyRate"); dimensions = x.i("dimensions"); anomalousDimensions = x.i("anomalousDimensions")
    }
}
extension EvidenceLink {
    public init(from d: Decoder) throws { let x = try Lx(d); kind = x.s("kind"); title = x.s("title"); href = x.s("href"); why = x.s("why") }
}
extension EvidencePeer {
    public init(from d: Decoder) throws {
        let x = try Lx(d)
        namespace = x.os("namespace"); workload = x.os("workload"); peer = x.s("peer"); port = x.i("port"); protocolName = x.os("protocol")
        packets = x.i("packets"); bytes = x.i("bytes")
        blocked = x.od("blocked").flatMap(LenientDecode.int64).map { Int(clamping: $0) }
        retransmissions = x.od("retransmissions").flatMap(LenientDecode.int64).map { Int(clamping: $0) }
        rtos = x.od("rtos").flatMap(LenientDecode.int64).map { Int(clamping: $0) }
    }
}
extension EvidenceCount {
    public init(from d: Decoder) throws { let x = try Lx(d); name = x.s("name"); count = x.i("count") }
}
extension MetricAlert {
    public init(from d: Decoder) throws {
        let x = try Lx(d)
        id = x.s("id"); rule = x.s("rule"); node = x.s("node"); context = x.os("context"); chart = x.s("chart"); dimension = x.os("dimension")
        status = x.s("status"); value = x.od("value"); units = x.os("units"); info = x.os("info"); since = x.os("since")
        silenced = x.b("silenced"); acked = x.b("acked"); ackedBy = x.os("ackedBy")
    }
}
extension MetricAlertRule {
    public init(from d: Decoder) throws { let x = try Lx(d); name = x.s("name"); context = x.os("context"); warn = x.os("warn"); crit = x.os("crit") }
}
extension MetricAlertTransition {
    public init(from d: Decoder) throws {
        let x = try Lx(d)
        time = x.s("time"); id = x.s("id"); rule = x.s("rule"); node = x.s("node"); chart = x.s("chart")
        from = x.s("from"); to = x.s("to"); value = x.od("value"); units = x.os("units")
    }
}
extension MetricSilence {
    public init(from d: Decoder) throws {
        let x = try Lx(d)
        id = x.s("id"); rule = x.os("rule"); node = x.os("node"); chart = x.os("chart"); until = x.s("until")
        comment = x.os("comment"); createdBy = x.os("createdBy"); created = x.os("created")
    }
}
extension MetricAlertStats {
    public init(from d: Decoder) throws { let x = try Lx(d); rules = x.i("rules"); instances = x.i("instances"); warning = x.i("warning"); critical = x.i("critical") }
}

public enum MetricRange: String, CaseIterable, Identifiable, Sendable {
    case m5 = "5m", m15 = "15m", h1 = "1h", h6 = "6h", h24 = "24h"
    public var id: String { rawValue }
    public var seconds: Int { switch self { case .m5: 300; case .m15: 900; case .h1: 3600; case .h6: 21600; case .h24: 86400 } }
}

public enum MetricsFormat {
    public static func parseTime(_ s: String?) -> Date? {
        guard let s else { return nil }
        return NetraDate.parse(s)
    }
    /// Index of the timestamp closest to `t` (timestamps ascending); nil when empty.
    public static func nearestIndex(_ timestamps: [Int64], to t: Double) -> Int? {
        guard !timestamps.isEmpty else { return nil }
        var best = 0, bd = Double.infinity
        for (i, x) in timestamps.enumerated() { let d = abs(Double(x) - t); if d < bd { bd = d; best = i } }
        return best
    }
    public static func value(_ v: Double, units: String?) -> String {
        let u = units ?? ""
        let a = abs(v)
        let n: String
        if a >= 1e9 { n = String(format: "%.2fG", v / 1e9) }
        else if a >= 1e6 { n = String(format: "%.2fM", v / 1e6) }
        else if a >= 1e3 { n = String(format: "%.2fk", v / 1e3) }
        else if a >= 100 || v == v.rounded() { n = String(format: "%.0f", v) }
        else { n = String(format: "%.2f", v) }
        return u.isEmpty ? n : (u == "%" ? n + "%" : n + " " + u)
    }
}

extension NetraClient {
    public func metricsSummary() async throws -> MetricsSummary { try await get("api/v1/metrics/summary") }
    public func metricsNodes() async throws -> [MetricNodeInfo] {
        (try await get("api/v1/metrics/nodes", as: MetricNodesResponse.self)).nodes
    }
    public func metricsContexts() async throws -> [MetricContext] {
        (try await get("api/v1/metrics/contexts", as: MetricContextsResponse.self)).contexts
    }
    public func metricsData(context: String, seconds: Int, points: Int = 300, nodes: [String] = [], groupBy: String? = nil) async throws -> MetricResult {
        var q = [URLQueryItem(name: "context", value: context),
                 URLQueryItem(name: "after", value: String(-seconds)),
                 URLQueryItem(name: "points", value: String(points))]
        if !nodes.isEmpty { q.append(.init(name: "nodes", value: nodes.joined(separator: ","))) }
        if let groupBy { q.append(.init(name: "group_by", value: groupBy)) }
        return try await get("api/v1/metrics/data", query: q)
    }
    public func metricsAnomalies(seconds: Int, top: Int = 50) async throws -> AnomalySummary {
        try await get("api/v1/metrics/anomalies", query: [.init(name: "after", value: String(-seconds)), .init(name: "top", value: String(top))])
    }
    /// `labels` become the server's `labels` filter (`k:v,k:v`); `before` is left to the server (now).
    public func metricsEvidence(context: String, node: String?, seconds: Int, labels: [String: String] = [:]) async throws -> MetricEvidence {
        var q = [URLQueryItem(name: "context", value: context), .init(name: "after", value: String(-seconds))]
        if let node, !node.isEmpty { q.append(.init(name: "node", value: node)) }
        if let l = MetricsMore.labelsParam(labels) { q.append(.init(name: "labels", value: l)) }
        return try await get("api/v1/metrics/evidence", query: q)
    }
    public func metricsAlerts(all: Bool = false, history: Int = 100) async throws -> MetricAlertSnapshot {
        try await get("api/v1/metrics/alerts", query: [.init(name: "all", value: all ? "true" : "false"), .init(name: "history", value: String(history))])
    }
    /// Notification state only: marks the alert acknowledged. Changes no rule, mode or policy.
    public func ackMetricAlert(id: String) async throws {
        // IDs are hex; request() percent-encodes path components itself.
        _ = try await send(request("POST", "api/v1/metrics/alerts/\(id)/ack"))
    }
    /// Notification state only: suppresses notifications for matching alerts until the duration elapses.
    public func addMetricSilence(rule: String, node: String, chart: String, duration: String, comment: String) async throws -> MetricSilence {
        let body = try JSONSerialization.data(withJSONObject: ["rule": rule, "node": node, "chart": chart, "duration": duration, "comment": comment])
        return try JSONDecoder().decode(MetricSilence.self, from: try await send(request("POST", "api/v1/metrics/alerts/silences", body: body)))
    }
    public func deleteMetricSilence(id: String) async throws {
        _ = try await send(request("DELETE", "api/v1/metrics/alerts/silences/\(id)"))
    }
}
