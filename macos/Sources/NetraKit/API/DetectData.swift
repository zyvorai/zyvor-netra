// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Pure mapping for the read-only Detect pages (Insights, Incidents, Security, Intel).
/// Shapes come from the Go structs: models.IncidentCluster, models.Timeline, securityreview.Incidents,
/// intel.Status/Revision and watchlist.Result (whose Hit has no json tags, so its keys are Capitalised).
public enum DetectData {
    // MARK: Severity

    /// Higher is worse. Unknown severities rank 0 so they sort last.
    public static func severityRank(_ s: String?) -> Int {
        switch (s ?? "").lowercased() {
        case "critical": 4
        case "high": 3
        case "warning", "medium": 2
        case "low", "info": 1
        default: 0
        }
    }

    /// SF Symbol that carries severity without relying on colour.
    public static func severitySymbol(_ s: String?) -> String {
        switch severityRank(s) {
        case 4: "exclamationmark.octagon.fill"
        case 3: "exclamationmark.triangle.fill"
        case 2: "exclamationmark.circle.fill"
        case 1: "info.circle.fill"
        default: "questionmark.circle"
        }
    }

    public static func str(_ v: JSONValue?, _ keys: String...) -> String {
        for k in keys { if case .string(let s)? = v?[k], !s.isEmpty { return s } }
        return ""
    }
    public static func num(_ v: JSONValue?, _ keys: String...) -> Double {
        for k in keys { if let d = v?[k]?.asDouble { return d } }
        return 0
    }
    private static func items(_ v: JSONValue?) -> [JSONValue] { if case .array(let a)? = v { a } else { [] } }

    // MARK: Incidents (GET /api/v1/incidents)

    public struct IncidentFinding: Equatable, Sendable {
        public let kind, severity, subject, message, joinConfidence: String
        public let at: Date?
    }
    public struct Incident: Identifiable, Equatable, Sendable {
        public var id: String { sourceKey }
        public let sourceKey, subject, severity: String
        public let findings: [IncidentFinding]
        public var kinds: [String] { Array(Set(findings.map(\.kind))).sorted() }
        public var latest: Date? { findings.compactMap(\.at).max() }
    }

    /// Clusters sorted worst-first (the server already does; re-sorted so a stale server cannot break the page).
    public static func incidents(_ v: JSONValue) -> [Incident] {
        items(v["items"]).map { c in
            let fs = items(c["findings"]).map {
                IncidentFinding(kind: str($0, "kind"), severity: str($0, "severity"), subject: str($0, "subject"),
                                message: str($0, "message"), joinConfidence: str($0, "joinConfidence"), at: CellFormat.date($0["at"]))
            }.sorted { severityRank($0.severity) > severityRank($1.severity) }
            let key = str(c, "sourceKey"), subject = str(c, "subject")
            return Incident(sourceKey: key.isEmpty ? subject : key, subject: subject.isEmpty ? key : subject,
                            severity: str(c, "severity"), findings: fs)
        }.sorted { severityRank($0.severity) > severityRank($1.severity) || (severityRank($0.severity) == severityRank($1.severity) && $0.findings.count > $1.findings.count) }
    }

    // MARK: Timeline (GET /api/v1/incidents/timeline)

    public struct TimelineItem: Identifiable, Equatable, Sendable {
        public let id: Int
        public let at: Date?
        public let kind, text, severity: String
    }
    public struct TimelineInfo: Equatable, Sendable {
        public let entries: [TimelineItem]   // newest first
        public let prose, engine: String
    }

    public static func timeline(_ v: JSONValue) -> TimelineInfo {
        let e = items(v["entries"]).map { (str($0, "kind"), str($0, "text"), str($0, "severity"), CellFormat.date($0["at"])) }
            .sorted { ($0.3 ?? .distantPast) > ($1.3 ?? .distantPast) }
            .enumerated().map { TimelineItem(id: $0.offset, at: $0.element.3, kind: $0.element.0, text: $0.element.1, severity: $0.element.2) }
        return TimelineInfo(entries: e, prose: str(v, "prose"), engine: str(v, "engine"))
    }

    // MARK: Security (GET /api/v1/security/incidents)

    public struct Evidence: Identifiable, Equatable, Sendable {
        public let id, kind, message: String
        public let at: Date?
    }
    public struct SecurityIncident: Identifiable, Equatable, Sendable {
        public let id, node, namespace, pod: String
        public let lastSeen: Date?
        public let evidence: [Evidence]
        public var kinds: [String] { Array(Set(evidence.map(\.kind))).sorted() }
        /// The server sends no severity for these (they are temporal correlations of independent evidence
        /// kinds). This is a display heuristic only: 3+ kinds = high, otherwise medium.
        public var derivedSeverity: String { kinds.count >= 3 ? "high" : "medium" }
        public var workload: String { namespace.isEmpty ? pod : "\(namespace)/\(pod)" }
    }
    public struct SecurityReview: Equatable, Sendable {
        public let incidents: [SecurityIncident]
        public let note: String
        public let truncated, dnsEnabled, scanEnabled: Bool
        public var evidenceByKind: [(kind: String, count: Int)] {
            Dictionary(grouping: incidents.flatMap(\.evidence), by: \.kind).map { ($0.key, $0.value.count) }.sorted { $0.kind < $1.kind }
        }
        public static func == (l: SecurityReview, r: SecurityReview) -> Bool { l.incidents == r.incidents && l.note == r.note }
    }

    /// The payload is wrapped: `{"result": {items, note, truncated}, "dnsEnabled", "scanEnabled"}`.
    public static func securityReview(_ v: JSONValue) -> SecurityReview {
        let r = v["result"] ?? v
        let inc = items(r["items"]).map { i in
            SecurityIncident(id: str(i, "id"), node: str(i, "node"), namespace: str(i, "namespace"), pod: str(i, "pod"),
                             lastSeen: CellFormat.date(i["lastSeen"]),
                             evidence: items(i["evidence"]).map { Evidence(id: str($0, "id"), kind: str($0, "kind"), message: str($0, "message"), at: CellFormat.date($0["at"])) }
                                .sorted { ($0.at ?? .distantPast) < ($1.at ?? .distantPast) })
        }.sorted { ($0.lastSeen ?? .distantPast) > ($1.lastSeen ?? .distantPast) }
        func flag(_ k: String) -> Bool { if case .bool(let b)? = v[k] { b } else { false } }
        var trunc = false; if case .bool(let b)? = r["truncated"] { trunc = b }
        return SecurityReview(incidents: inc, note: str(r, "note"), truncated: trunc, dnsEnabled: flag("dnsEnabled"), scanEnabled: flag("scanEnabled"))
    }

    // MARK: Intel (GET /api/v1/intel/hits, /feed, /history)

    public struct IntelHit: Identifiable, Equatable, Sendable {
        public let id: Int
        public let type, value, kind, node, namespace, pod, subject: String
        public let packets, blocked: Double
        public var workload: String { pod.isEmpty ? subject : (namespace.isEmpty ? pod : "\(namespace)/\(pod)") }
    }
    public struct IntelHits: Equatable, Sendable {
        public let hits: [IntelHit]
        public let checked: Int
        public let capped: Bool
        public let note: String
        public var totalPackets: Double { hits.reduce(0) { $0 + $1.packets } }
        public var totalBlocked: Double { hits.reduce(0) { $0 + $1.blocked } }
        public var byType: [(type: String, count: Int)] {
            Dictionary(grouping: hits, by: \.type).map { ($0.key, $0.value.count) }.sorted { $0.count > $1.count || ($0.count == $1.count && $0.type < $1.type) }
        }
    }

    /// Hit has no json tags in Go, so the keys are `Type`, `Value`, ... ; lower-case is accepted too.
    public static func intelHits(_ v: JSONValue) -> IntelHits {
        let m = v["match"]
        let hits = items(m?["hits"]).enumerated().map { i, h in
            IntelHit(id: i, type: str(h, "Type", "type"), value: str(h, "Value", "value"), kind: str(h, "Kind", "kind"),
                     node: str(h, "Node", "node"), namespace: str(h, "Namespace", "namespace"), pod: str(h, "Pod", "pod"),
                     subject: str(h, "Subject", "subject"), packets: num(h, "Packets", "packets"), blocked: num(h, "Blocked", "blocked"))
        }
        var capped = false; if case .bool(let b)? = m?["capped"] { capped = b }
        return IntelHits(hits: hits, checked: Int(num(m, "checked")), capped: capped, note: str(v, "note"))
    }

    public struct FeedStatus: Equatable, Sendable {
        public let count, revision: Int
        public let source, note, refreshError: String
        public let empty, expired, persistent, journalUnavailable: Bool
        public let updatedAt, expiresAt, lastRefresh: Date?
        /// One word for the card: Empty / Expired / Journal unavailable / Active.
        public var label: String { journalUnavailable ? "Journal unavailable" : empty ? "Empty" : expired ? "Expired" : "Active" }
    }

    /// Reads `feed` from a hits/feed/history response (or the status object itself).
    public static func feedStatus(_ v: JSONValue) -> FeedStatus {
        let f = v["feed"] ?? v
        func b(_ k: String) -> Bool { if case .bool(let x)? = f[k] { x } else { false } }
        return FeedStatus(count: Int(num(f, "count")), revision: Int(num(f, "revision")), source: str(f, "source"), note: str(f, "note"),
                          refreshError: str(f, "refreshError"), empty: b("empty"), expired: b("expired"), persistent: b("persistent"),
                          journalUnavailable: b("journalUnavailable"), updatedAt: CellFormat.date(f["updatedAt"]),
                          expiresAt: CellFormat.date(f["expiresAt"]), lastRefresh: CellFormat.date(f["lastRefresh"]))
    }

    public struct Revision: Identifiable, Equatable, Sendable {
        public var id: Int { revision }
        public let revision: Int
        public let updatedAt, expiresAt: Date?
        public let source, note: String
        public let entries: Int
        public let byType: [String: Int]
    }

    /// Revisions newest first; `entries` is the entry count (values are not retained in the model).
    public static func revisions(_ v: JSONValue) -> [Revision] {
        items(v["revisions"]).map { r in
            let es = items(r["entries"])
            return Revision(revision: Int(num(r, "revision")), updatedAt: CellFormat.date(r["updatedAt"]), expiresAt: CellFormat.date(r["expiresAt"]),
                            source: str(r, "source"), note: str(r, "note"), entries: es.count,
                            byType: Dictionary(es.map { (str($0, "type"), 1) }, uniquingKeysWith: +))
        }.sorted { $0.revision > $1.revision }
    }

    public struct FeedEntry: Identifiable, Equatable, Sendable {
        public var id: Int
        public let type, value, direction: String
    }
    public static func feedEntries(_ v: JSONValue) -> [FeedEntry] {
        items(v["entries"]).enumerated().map { FeedEntry(id: $0.offset, type: str($0.element, "type"), value: str($0.element, "value"), direction: str($0.element, "direction")) }
    }

    // MARK: Insights

    public struct HealthTrend: Equatable, Sendable {
        public let currentScore, threshold, samples: Int
        public let slopePerHour: Double
        public let timeToBreak: Double?   // seconds
        public let confidence, note: String
        public var summary: String {
            guard let t = timeToBreak else { return "No projection" }
            return "Breach in " + CellFormat.duration(t)
        }
    }
    public static func healthTrend(_ v: JSONValue) -> HealthTrend {
        HealthTrend(currentScore: Int(num(v, "currentScore")), threshold: Int(num(v, "breachThreshold")), samples: Int(num(v, "samples")),
                    slopePerHour: num(v, "slopePerHour"), timeToBreak: v["timeToBreachSeconds"]?.asDouble,
                    confidence: str(v, "confidence"), note: str(v, "note"))
    }

    /// Counts per severity for any list of rows keyed by `severity` (drift, exposure, exfil, lateral, ...).
    public static func severityCounts(_ rows: [JSONValue]) -> [(severity: String, count: Int)] {
        Dictionary(grouping: rows, by: { str($0, "severity").lowercased() }).filter { !$0.key.isEmpty }
            .map { ($0.key, $0.value.count) }.sorted { severityRank($0.severity) > severityRank($1.severity) }
    }
    public static func rows(_ v: JSONValue, _ path: String) -> [JSONValue] { items(v.at(path)) }

    /// Requested rate window in seconds from GET insights/rate-drift (`models.RateDriftResponse.window` is a
    /// `RateWindow`, whose seconds field is `requestedWindowSeconds`).
    public static func rateDriftWindowSeconds(_ v: JSONValue) -> Double? { v.at("window.requestedWindowSeconds")?.asDouble }

    /// Blast-radius hop histogram: [(hops, nodes)].
    public static func blastHops(_ v: JSONValue) -> [(hops: Int, nodes: Int)] {
        Dictionary(grouping: items(v["nodes"]), by: { Int(num($0, "hops")) }).map { ($0.key, $0.value.count) }.sorted { $0.hops < $1.hops }
    }
}
