// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

public enum NotifyCategory: String, CaseIterable, Sendable, Identifiable {
    case alerts, incidents, intel, lease
    public var id: String { rawValue }
    public var title: String {
        switch self {
        case .alerts: "Metric alerts"
        case .incidents: "Incidents"
        case .intel: "Threat intel hits"
        case .lease: "Enforcement lease"
        }
    }
}

/// One thing worth a desktop notification. Carries only rule/title, severity and node: never payloads,
/// command lines, indicator values or secrets.
public struct NotifyEvent: Equatable, Sendable, Identifiable {
    public let id: String
    public let category: NotifyCategory
    public let title: String
    public let body: String
    public let severity: String
    /// Set only for metric alerts; enables the Acknowledge action (notification state only).
    public let alertID: String?
    public init(id: String, category: NotifyCategory, title: String, body: String, severity: String, alertID: String? = nil) {
        self.id = id; self.category = category; self.title = title; self.body = body; self.severity = severity; self.alertID = alertID
    }
}

/// Pure diff logic over successive polls. The first ingest of each source only primes the baseline so
/// connecting to a busy controller does not fire a burst. Nothing here performs I/O or any mutation.
public struct AlertWatcher: Sendable {
    public var maxPerTick: Int
    public var leaseWarnSeconds: TimeInterval
    private var seenAlerts: Set<String> = []
    private var seenIncidents: Set<String> = []
    private var seenIntel: Set<String> = []
    private var primed: Set<NotifyCategory> = []
    private var warnedLease: Set<Date> = []
    private var expiredLease: Set<Date> = []
    private var activeLeaseExpiry: Date?

    public init(maxPerTick: Int = 5, leaseWarnSeconds: TimeInterval = 120) {
        self.maxPerTick = max(1, maxPerTick); self.leaseWarnSeconds = leaseWarnSeconds
    }

    /// Forget everything (new connection).
    public mutating func reset() { self = AlertWatcher(maxPerTick: maxPerTick, leaseWarnSeconds: leaseWarnSeconds) }

    private func capped(_ events: [NotifyEvent], _ cat: NotifyCategory) -> [NotifyEvent] {
        guard events.count > maxPerTick else { return events }
        let extra = events.count - (maxPerTick - 1)
        return Array(events.prefix(maxPerTick - 1)) + [
            NotifyEvent(id: "\(cat.rawValue)-more-\(events.count)", category: cat, title: "\(extra) more \(cat.title.lowercased())",
                        body: "Open Netra to review them.", severity: "info")]
    }

    // MARK: Metric alerts (GET /api/v1/metrics/alerts, `active`)

    public mutating func ingest(alerts: [MetricAlert]) -> [NotifyEvent] {
        var current = Set<String>(), fresh: [(Int, NotifyEvent)] = []
        for a in alerts {
            let sev = a.status.lowercased()
            guard sev == "warning" || sev == "critical" else { continue }
            guard a.acked != true, a.silenced != true else { continue }
            guard MetricAlertActions.isSafeID(a.id) else { continue }
            let key = "\(a.id)|\(sev)"
            current.insert(key)
            if !seenAlerts.contains(key) {
                fresh.append((DetectData.severityRank(sev), NotifyEvent(
                    id: "alert-\(key)", category: .alerts, title: "\(sev.capitalized): \(a.rule)",
                    body: a.node.isEmpty ? "Metric alert raised" : "on \(a.node)", severity: sev, alertID: a.id)))
            }
        }
        // Dropping resolved/acked keys lets a re-raise notify again.
        seenAlerts = current
        guard primed.contains(.alerts) else { primed.insert(.alerts); return [] }
        return capped(fresh.sorted { $0.0 > $1.0 }.map(\.1), .alerts)
    }

    // MARK: Incidents (GET /api/v1/incidents)

    public mutating func ingest(incidents: [DetectData.Incident]) -> [NotifyEvent] {
        var fresh: [(Int, NotifyEvent)] = []
        var current = Set<String>()
        for i in incidents {
            let key = "\(i.id)|\(i.severity.lowercased())"
            current.insert(key)
            if !seenIncidents.contains(key) {
                fresh.append((DetectData.severityRank(i.severity), NotifyEvent(
                    id: "incident-\(key)", category: .incidents,
                    title: "Incident (\(i.severity.isEmpty ? "unrated" : i.severity))",
                    body: "\(i.subject) · \(i.findings.count) finding(s)", severity: i.severity.lowercased())))
            }
        }
        seenIncidents = current
        guard primed.contains(.incidents) else { primed.insert(.incidents); return [] }
        return capped(fresh.sorted { $0.0 > $1.0 }.map(\.1), .incidents)
    }

    // MARK: Intel hits (GET /api/v1/intel/hits)

    public mutating func ingest(intel: DetectData.IntelHits) -> [NotifyEvent] {
        var fresh: [NotifyEvent] = []
        var current = Set<String>()
        for h in intel.hits {
            // The indicator value is only part of the dedupe key; it is never shown.
            let key = [h.type, h.value, h.node, h.namespace, h.pod, h.subject].joined(separator: "|")
            current.insert(key)
            if !seenIntel.contains(key) {
                fresh.append(NotifyEvent(id: "intel-\(key)", category: .intel, title: "Threat intel hit",
                                         body: h.node.isEmpty ? (h.type.isEmpty ? "Watchlist match" : h.type) : "\(h.type.isEmpty ? "match" : h.type) on \(h.node)",
                                         severity: "high"))
            }
        }
        seenIntel = current
        guard primed.contains(.intel) else { primed.insert(.intel); return [] }
        return capped(fresh, .intel)
    }

    // MARK: Lease (GET /api/v1/lease)

    public mutating func ingest(lease: LeaseStatus?, now: Date = Date()) -> [NotifyEvent] {
        guard let l = lease else { return [] }
        var out: [NotifyEvent] = []
        let expiry = l.leaseExpiresAt
        let enforcing = l.mode == "enforce" && l.active && !l.expired
        if enforcing, let e = expiry {
            let left = LeaseTracker(expiresAt: e).remaining(now: now)
            if left > 0 {
                activeLeaseExpiry = e
                if left <= leaseWarnSeconds, !warnedLease.contains(e) {
                    warnedLease.insert(e)
                    out.append(NotifyEvent(id: "lease-soon-\(e.timeIntervalSince1970)", category: .lease, title: "Enforce lease ending soon",
                                           body: "Reverts to observe in about \(max(1, Int((left / 60).rounded(.up)))) min.", severity: "warning"))
                }
                return out
            }
        }
        if let e = activeLeaseExpiry, !expiredLease.contains(e) {
            expiredLease.insert(e); activeLeaseExpiry = nil
            out.append(NotifyEvent(id: "lease-expired-\(e.timeIntervalSince1970)", category: .lease, title: "Enforce lease expired",
                                   body: "Netra failed open to observe.", severity: "info"))
        }
        return out
    }
}
