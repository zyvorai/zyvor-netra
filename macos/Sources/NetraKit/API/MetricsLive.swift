// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

// Wire model for GET /api/v1/metrics/stream (internal/api/metrics_platform.go, metricsStream).
// Client -> server: {"subscribe":[streamQuery...]} replaces all subscriptions (server keeps at most 50).
// Server -> client, once per second while subscribed: {"t":<unix>,"results":{<id>:<tsdb.Result>}}.
// Queries the server rejects or fails are simply absent from "results". Observe-only.

public struct LiveSubscription: Encodable, Sendable, Equatable {
    public var id: String
    public var context: String
    public var charts: [String]?
    public var nodes: [String]?
    public var labels: [String: String]?
    public var window: Int64
    public var points: Int
    public var groupBy: String?

    public init(id: String, context: String, charts: [String]? = nil, nodes: [String]? = nil,
                labels: [String: String]? = nil, window: Int64, points: Int = 300, groupBy: String? = nil) {
        self.id = id; self.context = context; self.charts = charts; self.nodes = nodes
        self.labels = labels; self.window = window; self.points = points; self.groupBy = groupBy
    }

    /// Same id scheme as web/src/lib/metrics.ts streamId: context|node|chart.
    public static func id(context: String, node: String?, chart: String?) -> String {
        [context, (node?.isEmpty ?? true) ? "*" : node!, (chart?.isEmpty ?? true) ? "*" : chart!].joined(separator: "|")
    }
}

public struct LiveFrame: Sendable, Equatable {
    public var t: Int64
    public var results: [String: MetricResult]
    public init(t: Int64, results: [String: MetricResult]) { self.t = t; self.results = results }
}

public enum MetricsLive {
    /// Server cap on subscriptions per message.
    public static let maxSubscriptions = 50
    /// The web client streams up to one hour; longer windows should poll.
    public static let maxStreamWindow = 3600

    /// `ws(s)://host/api/v1/metrics/stream` for an http(s) controller base URL.
    public static func socketURL(base: URL) -> URL? {
        guard var c = URLComponents(url: base.appendingPathComponent("api/v1/metrics/stream"), resolvingAgainstBaseURL: false) else { return nil }
        switch c.scheme?.lowercased() {
        case "https", "wss": c.scheme = "wss"
        case "http", "ws": c.scheme = "ws"
        default: return nil
        }
        return c.url
    }

    public static func subscribeMessage(_ subs: [LiveSubscription]) -> String {
        struct Msg: Encodable { let subscribe: [LiveSubscription] }
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        let data = (try? enc.encode(Msg(subscribe: Array(subs.prefix(maxSubscriptions))))) ?? Data("{\"subscribe\":[]}".utf8)
        return String(decoding: data, as: UTF8.self)
    }

    private struct Lossy: Decodable {
        let value: MetricResult?
        init(from d: Decoder) throws { value = try? MetricResult(from: d) }
    }
    private struct Raw: Decodable { let t: Int64?; let results: [String: Lossy]? }

    /// Parses one server message. A single undecodable result is dropped, not the whole frame.
    public static func parseFrame(_ data: Data) -> LiveFrame? {
        guard let raw = try? JSONDecoder().decode(Raw.self, from: data) else { return nil }
        var out: [String: MetricResult] = [:]
        for (k, v) in raw.results ?? [:] { if let r = v.value { out[k] = r } }
        return LiveFrame(t: raw.t ?? 0, results: out)
    }
}
