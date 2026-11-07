// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Pure, read-only formatting of what the Shortcuts / App Intents say. Inputs are decoded GET responses.
public enum IntentSummaries {
    /// "Netra is in observe mode (no lease)." / "enforce mode, lease 4m 5s left." / "lease expired, failing open to observe."
    public static func modeAndLease(_ l: LeaseStatus) -> String {
        let mode = l.mode.isEmpty ? "unknown" : l.mode
        if l.expired { return "Netra lease expired in \(mode) mode; it fails open to observe." }
        if l.active {
            return "Netra is in \(mode) mode, lease \(duration(l.remainingSeconds)) left."
        }
        return "Netra is in \(mode) mode (no active lease)."
    }

    /// Counts alerts that are raised (warning/critical) and not silenced.
    public static func activeAlertCount(_ s: MetricAlertSnapshot) -> Int {
        s.active.filter { $0.silenced != true && isRaised($0.status) }.count
    }

    public static func alertSummary(_ s: MetricAlertSnapshot) -> String {
        let live = s.active.filter { $0.silenced != true && isRaised($0.status) }
        guard !live.isEmpty else { return "No active metric alerts." }
        let crit = live.filter { $0.status.lowercased() == "critical" }.count
        let warn = live.count - crit
        var parts: [String] = []
        if crit > 0 { parts.append("\(crit) critical") }
        if warn > 0 { parts.append("\(warn) warning") }
        return "\(live.count) active metric alert\(live.count == 1 ? "" : "s"): \(parts.joined(separator: ", "))."
    }

    /// "1. 10.0.0.5 (100 packets, 10 blocked)" lines for the top talkers.
    public static func topTalkers(_ bars: [RankedBar], limit: Int = 5) -> String {
        let top = Array(bars.prefix(max(limit, 0)))
        guard !top.isEmpty else { return "No talkers reported." }
        let lines = top.enumerated().map { i, b -> String in
            let blocked = b.blocked > 0 ? ", \(count(b.blocked)) blocked" : ""
            return "\(i + 1). \(b.label) (\(count(b.value)) packets\(blocked))"
        }
        return "Top talkers:\n" + lines.joined(separator: "\n")
    }

    static func isRaised(_ status: String) -> Bool { ["warning", "critical"].contains(status.lowercased()) }

    static func count(_ d: Double) -> String { String(Int(d.isFinite ? d : 0)) }

    static func duration(_ secs: Int64) -> String {
        let s = max(secs, 0)
        if s >= 3600 { return "\(s / 3600)h \((s % 3600) / 60)m" }
        if s >= 60 { return "\(s / 60)m \(s % 60)s" }
        return "\(s)s"
    }
}
