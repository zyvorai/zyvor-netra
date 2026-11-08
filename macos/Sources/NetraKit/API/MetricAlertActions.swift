// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Guarded specs for metric alert acknowledge and silence. They change notification state ONLY:
/// nothing here touches mode, rules or policy. Every spec previews with a read of
/// GET /api/v1/metrics/alerts and goes through `MutationFlow` like the other actions.
public enum MetricAlertActions {

    /// Alert and silence ids are hex strings. Anything else is refused so an id can never inject a path.
    public static func isSafeID(_ s: String) -> Bool {
        !s.isEmpty && s.count <= 64 && s.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }
    }

    /// Accepts a Go `time.ParseDuration` string such as `90m`, `2h`, `1h30m` or `1.5s`, with the same
    /// units (ns, us, µs, μs, ms, s, m, h), an optional sign, and bare `0`. The server allows up to 30 days.
    public static func parseDuration(_ s: String) -> TimeInterval? {
        var t = Substring(s.trimmingCharacters(in: .whitespaces))
        var sign = 1.0
        if let f = t.first, f == "+" || f == "-" { if f == "-" { sign = -1 }; t = t.dropFirst() }
        guard !t.isEmpty else { return nil }
        if t == "0" { return 0 }
        let units: [String: Double] = ["ns": 1e-9, "us": 1e-6, "\u{00B5}s": 1e-6, "\u{03BC}s": 1e-6,
                                       "ms": 1e-3, "s": 1, "m": 60, "h": 3600]
        var total = 0.0
        var i = t.startIndex
        while i < t.endIndex {
            var num = ""
            while i < t.endIndex, let c = t[i].asciiValue, (c >= 48 && c <= 57) || c == 46 { num.append(t[i]); i = t.index(after: i) }
            guard !num.isEmpty, num != ".", let n = Double(num) else { return nil }
            var unit = ""
            while i < t.endIndex, !(t[i].asciiValue.map { ($0 >= 48 && $0 <= 57) || $0 == 46 } ?? false) { unit.append(t[i]); i = t.index(after: i) }
            guard let u = units[unit] else { return nil }
            total += n * u
        }
        return sign * total
    }

    public static let maxSilence: TimeInterval = 30 * 24 * 3600

    public static func ack(alertID: String, label: String) -> ControlAction {
        ControlAction(
            id: "metric-alert-ack", group: "Metric alerts", title: "Acknowledge \(label)",
            summary: "Marks the alert acknowledged. Notification state only: it changes no rule, mode or policy and does not resolve the alert.",
            symbol: "checkmark.bubble", maxRisk: .low,
            fields: [.init("id", "Alert id", initial: alertID, help: "Read from the alert row")],
            build: { c, v in
                let id = Form.str(v, "id")
                guard isSafeID(id) else { return .failure(.init("That is not a valid alert id")) }
                return .success(MutationSpec(
                    title: "Acknowledge metric alert \(label)", risk: .low, expectedPhrase: "", leaseBound: false,
                    preview: { c.request("GET", "api/v1/metrics/alerts") },
                    summarize: { r in
                        guard let a = r["active"]?.controlItems.first(where: { $0["id"]?.string == id }) else {
                            return "This alert is no longer raised; the server will answer 404."
                        }
                        return "\(a["rule"]?.string ?? "alert") on \(a["node"]?.string ?? "?") is \(a["status"]?.string ?? "raised"). Acknowledging only records who saw it."
                    },
                    execute: { _ in c.request("POST", "api/v1/metrics/alerts/\(id)/ack") }))
            })
    }

    public static func silence(rule: String = "", node: String = "", chart: String = "") -> ControlAction {
        ControlAction(
            id: "metric-silence-add", group: "Metric alerts", title: "Silence alerts",
            summary: "Suppresses notifications for matching alerts until the time is up. Alerts are still tracked. Notification state only; it changes no rule, mode or policy.",
            symbol: "bell.slash", maxRisk: .low,
            fields: [
                .init("rule", "Rule", initial: rule, help: "Rule name or glob"),
                .init("node", "Node", initial: node, help: "Node name or glob"),
                .init("chart", "Chart", initial: chart, help: "Chart name or glob"),
                .init("duration", "Duration", initial: "2h", help: "Go duration such as 30m or 2h; at most 30 days"),
                .init("comment", "Comment", help: "Up to 500 characters"),
            ],
            build: { c, v in
                let r = Form.str(v, "rule"), n = Form.str(v, "node"), ch = Form.str(v, "chart")
                guard !(r + n + ch).isEmpty else { return .failure(.init("Set a rule, node or chart to match")) }
                let dur = Form.str(v, "duration")
                guard let secs = parseDuration(dur), secs > 0 else { return .failure(.init("Duration must look like 30m or 2h")) }
                guard secs <= maxSilence else { return .failure(.init("A silence can last at most 30 days")) }
                let comment = Form.str(v, "comment")
                guard comment.count <= 500 else { return .failure(.init("Comment is longer than 500 characters")) }
                let body = Form.json(["rule": r, "node": n, "chart": ch, "duration": dur, "comment": comment])
                let what = [r, n, ch].filter { !$0.isEmpty }.joined(separator: " · ")
                return .success(MutationSpec(
                    title: "Silence \(what) for \(dur)", risk: .low, expectedPhrase: "", leaseBound: false,
                    preview: { c.request("GET", "api/v1/metrics/alerts") },
                    summarize: { res in
                        let all = res["active"]?.controlItems ?? []
                        let hit = all.filter { a in
                            func m(_ pat: String, _ val: String?) -> Bool { pat.isEmpty || MetricAlertActions.glob(pat, val ?? "") }
                            return m(r, a["rule"]?.string) && m(n, a["node"]?.string) && m(ch, a["chart"]?.string)
                        }.count
                        return "\(hit) raised alert(s) match now. They stay tracked; only notifications are suppressed for \(dur)."
                    },
                    execute: { _ in c.request("POST", "api/v1/metrics/alerts/silences", body: body) }))
            })
    }

    public static func removeSilence(id: String, label: String) -> ControlAction {
        ControlAction(
            id: "metric-silence-delete", group: "Metric alerts", title: "Remove silence",
            summary: "Ends the silence now so matching alerts notify again. Notification state only.",
            symbol: "bell", maxRisk: .low,
            fields: [.init("id", "Silence id", initial: id)],
            build: { c, v in
                let sid = Form.str(v, "id")
                guard isSafeID(sid) else { return .failure(.init("That is not a valid silence id")) }
                return .success(MutationSpec(
                    title: "Remove silence \(label)", risk: .low, expectedPhrase: "", leaseBound: false,
                    preview: { c.request("GET", "api/v1/metrics/alerts") },
                    summarize: { res in
                        let found = res["silences"]?.controlItems.contains { $0["id"]?.string == sid } ?? false
                        return found ? "Matching alerts will notify again." : "This silence is not listed; it may have expired."
                    },
                    execute: { _ in c.request("DELETE", "api/v1/metrics/alerts/silences/\(sid)") }))
            })
    }

    /// `*` wildcard match (the server supports simple globs); used only for the preview count.
    static func glob(_ pattern: String, _ s: String) -> Bool {
        let p = Array(pattern), t = Array(s)
        var memo: [[Bool?]] = Array(repeating: Array(repeating: nil, count: t.count + 1), count: p.count + 1)
        func go(_ i: Int, _ j: Int) -> Bool {
            if let m = memo[i][j] { return m }
            let r: Bool
            if i == p.count { r = j == t.count }
            else if p[i] == "*" { r = go(i + 1, j) || (j < t.count && go(i, j + 1)) }
            else { r = j < t.count && p[i] == t[j] && go(i + 1, j + 1) }
            memo[i][j] = r; return r
        }
        return go(0, 0)
    }
}
