// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// GET /api/v1/metrics/fleet: read-only roll-up of each cluster's metrics summary.
public struct MetricsFleet: Decodable, Sendable, Equatable {
    public struct Cluster: Decodable, Sendable, Equatable, Identifiable {
        public var name: String
        public var url: String?
        public var tenant: String?
        public var local: Bool?
        public var ok: Bool
        public var error: String?
        public var fetchedAt: String?
        public var summary: MetricsSummary?
        public var id: String { name + "|" + (url ?? "") }
    }
    public struct Totals: Decodable, Sendable, Equatable {
        public var clusters: Int
        public var okClusters: Int
        public var nodes: Int
        public var series: Int
        public var anomalyRate: Double
        public var alertsCritical: Int
        public var alertsWarning: Int
    }
    public var generatedAt: String?
    public var clusters: [Cluster]
    public var totals: Totals?
    public var note: String?
    enum K: String, CodingKey { case generatedAt, clusters, totals, note }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: K.self)
        generatedAt = try? c.decodeIfPresent(String.self, forKey: .generatedAt)
        clusters = (try? c.decodeIfPresent([Cluster].self, forKey: .clusters)) ?? []
        totals = try? c.decodeIfPresent(Totals.self, forKey: .totals)
        note = try? c.decodeIfPresent(String.self, forKey: .note)
    }
}

public enum MetricsMore {
    /// The server's `labels` query format: comma separated `key:value`, sorted for stable URLs.
    public static func labelsParam(_ labels: [String: String]) -> String? {
        let items = labels.filter { !$0.key.isEmpty && !$0.value.isEmpty && !$0.key.contains(where: { ",:=".contains($0) }) && !$0.value.contains(",") }
            .sorted { $0.key < $1.key }.map { "\($0.key):\($0.value)" }
        return items.isEmpty ? nil : items.joined(separator: ",")
    }

    /// Contexts grouped by family (empty family sorts last as "other"), each group sorted by context.
    public static func groupByFamily(_ ctxs: [MetricContext]) -> [(family: String, contexts: [MetricContext])] {
        let g = Dictionary(grouping: ctxs) { ($0.family ?? "").isEmpty ? "other" : $0.family! }
        return g.keys.sorted { a, b in a == "other" ? false : b == "other" ? true : a < b }
            .map { ($0, g[$0]!.sorted { $0.context < $1.context }) }
    }

    /// Nodes whose last ingest is older than the server's 2 minute stale window.
    public static func isStale(_ n: MetricNodeInfo, now: Date = Date()) -> Bool {
        guard let t = MetricsFormat.parseTime(n.lastIngest) else { return true }
        return now.timeIntervalSince(t) > 120
    }

    public static func bytes(_ v: Int64?) -> String {
        guard let v else { return "n/a" }
        return ByteCountFormatter.string(fromByteCount: v, countStyle: .binary)
    }
}

extension NetraClient {
    public func metricsFleet() async throws -> MetricsFleet { try await get("api/v1/metrics/fleet") }
}
