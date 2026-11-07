// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// A navigation target parsed from typed palette text ("drops on ns payments last hour").
/// Deterministic and local: no network, no model. The result is a section plus read-only link filters
/// (only `DeepLink.allowedKeys`), so choosing it can only navigate.
public struct QueryIntent: Hashable, Sendable, Identifiable {
    public struct Window: Hashable, Sendable {
        public let seconds: Int
        public let label: String
    }
    public let section: String
    public let query: [String: String]
    /// Parsed time window. There is no read-only link key for time, so it is shown, not sent as a filter.
    public let window: Window?
    /// Human summary, e.g. "Drops · namespace payments · last hour".
    public let summary: String
    public var id: String { "intent|\(section)|\(query.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: "&"))" }
    public var link: DeepLink { DeepLink(section: section, query: query) }
}

public enum QueryIntentParser {
    /// Noun -> (section, title). Keys are canonical lowercase words; `typoCandidates` derives from them.
    static let nouns: [String: (section: String, title: String)] = [
        "drops": ("drops", "Drops"), "drop": ("drops", "Drops"), "dropped": ("drops", "Drops"), "blocked": ("drops", "Drops"),
        "talkers": ("talkers", "Talkers"), "talker": ("talkers", "Talkers"),
        "alerts": ("alerts", "Alerts"), "alert": ("alerts", "Alerts"),
        "incidents": ("incidents", "Incidents"), "incident": ("incidents", "Incidents"),
        "pods": ("pods", "Pods"), "pod": ("pods", "Pods"),
        "flows": ("flows", "Flows"), "flow": ("flows", "Flows"), "traffic": ("flows", "Flows"),
        "workloads": ("workloads", "Workloads"), "workload": ("workloads", "Workloads"), "deployments": ("workloads", "Workloads"),
        "dns": ("dns", "DNS"), "rules": ("rules", "Rules"), "rule": ("rules", "Rules"),
        "policies": ("policies", "Policies"), "policy": ("policies", "Policies"),
        "topology": ("topology", "Topology"), "metrics": ("metrics", "Metrics"),
        "anomalies": ("anomalies", "Anomalies"), "anomaly": ("anomalies", "Anomalies"),
        "capture": ("capture", "Capture"), "security": ("security", "Security"), "audit": ("audit", "Audit"),
        "connections": ("connections", "Connections"), "retransmits": ("tcpEvents", "TCP events"),
    ]
    static let severities: Set<String> = ["critical", "high", "medium", "low", "warning", "info"]
    static let directions: [String: String] = ["ingress": "ingress", "inbound": "ingress", "incoming": "ingress",
                                               "egress": "egress", "outbound": "egress", "outgoing": "egress"]
    static let protocols: Set<String> = ["tcp", "udp", "icmp", "sctp", "icmpv6"]
    static let actions: [String: String] = ["blocked": "blocked", "denied": "blocked", "allowed": "allowed", "passed": "allowed"]
    static let stop: Set<String> = ["show", "me", "go", "to", "open", "find", "the", "a", "an", "of", "for", "with", "by", "on", "in", "at",
                                    "from", "all", "any", "my", "what", "are", "is", "there", "whats", "see", "list", "get", "and", "that", "were", "was"]
    static let keyAliases: [String: String] = ["ns": "namespace", "namespace": "namespace", "pod": "pod", "node": "node",
                                               "dir": "direction", "direction": "direction", "proto": "protocol", "protocol": "protocol",
                                               "action": "action", "q": "q"]
    static let units: [String: Int] = ["s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
                                       "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
                                       "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600,
                                       "d": 86400, "day": 86400, "days": 86400, "w": 604800, "week": 604800, "weeks": 604800]

    /// Parses `text`. Returns nil when nothing recognisable is present (the caller then falls back to fuzzy search).
    /// `validSections` rejects intents whose section the app does not have.
    public static func parse(_ text: String, validSections: Set<String>) -> QueryIntent? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= 200 else { return nil }
        let toks = trimmed.lowercased().split(whereSeparator: { $0.isWhitespace }).map {
            String($0).trimmingCharacters(in: CharacterSet(charactersIn: ",;?!\"'"))
        }.filter { !$0.isEmpty }

        var section: (section: String, title: String)?
        var f: [String: String] = [:]
        var window: QueryIntent.Window?
        var podSubject = false
        var recognised = false
        var leftovers: [String] = []

        func isKeyword(_ t: String) -> Bool {
            stop.contains(t) || nouns[t] != nil || keyAliases[t] != nil || directions[t] != nil || protocols.contains(t)
                || actions[t] != nil || severities.contains(t) || ["last", "past", "today", "hour"].contains(t)
        }
        func setNoun(_ t: String) {
            guard let n = nouns[t] ?? fuzzyNoun(t) else { return }
            if section == nil || (t == "blocked" ? false : section?.section == "pods" && n.section != "pods" && !podSubject) { section = n }
        }

        var i = 0
        while i < toks.count {
            let t = toks[i]
            let next: String? = i + 1 < toks.count ? toks[i + 1] : nil

            // key=value / key:value
            if let r = t.firstIndex(where: { $0 == "=" || $0 == ":" }), !t.contains("::"), t.filter({ $0 == ":" }).count <= 1,
               let key = keyAliases[String(t[..<r])], r != t.index(before: t.endIndex) {
                f[key] = String(t[t.index(after: r)...]); recognised = true; i += 1; continue
            }
            // time windows
            if let (w, used) = parseWindow(toks, at: i) { window = w; recognised = true; i += used; continue }
            // ip / cidr
            if isIP(t) { if f["q"] == nil { f["q"] = t }; recognised = true; i += 1; continue }
            // keyword + value
            if let key = keyAliases[t], key != "q", let v = next, nouns[v] == nil || key == "pod" {
                if key == "pod" { podSubject = true; section = nouns["pod"] }
                if !(key == "pod" && (nouns[v] != nil && v != "pod")) {
                    f[key] = v; recognised = true; i += 2; continue
                }
            }
            if let d = directions[t] { f["direction"] = d; recognised = true; i += 1; continue }
            if protocols.contains(t) { f["protocol"] = t.uppercased(); recognised = true; i += 1; continue }
            if severities.contains(t) { if f["q"] == nil { f["q"] = t }; recognised = true; i += 1; continue }
            if let a = actions[t] {
                f["action"] = a; recognised = true
                i += 1; continue
            }
            // "in X" / "on X": namespace
            if (t == "in" || t == "on" || t == "@"), let v = next, !isKeyword(v), !isIP(v), parseWindow(toks, at: i + 1) == nil {
                if f["namespace"] == nil { f["namespace"] = v; recognised = true; i += 2; continue }
            }
            if nouns[t] != nil { setNoun(t); recognised = true; i += 1; continue }
            if stop.contains(t) || t == "last" || t == "past" { i += 1; continue }
            if t.count >= 5, fuzzyNoun(t) != nil { setNoun(t); recognised = true; i += 1; continue }
            leftovers.append(t); i += 1
        }

        // Remaining free words become the search term only when a noun anchors the intent (avoids hijacking plain searches).
        if section != nil, f["q"] == nil, !leftovers.isEmpty, !podSubject { f["q"] = leftovers.joined(separator: " ") }
        // Only a time window or only filters: pick a sensible landing page.
        if section == nil {
            if f["q"] != nil, f.count == 1, leftovers.isEmpty { section = nouns["flows"] }          // bare IP / severity
            else if f["namespace"] != nil || f["pod"] != nil { section = nouns["pods"] }
            else if f["action"] != nil { section = nouns["drops"] }
            else if f["direction"] != nil || f["protocol"] != nil { section = nouns["flows"] }
            else if window != nil { section = nouns["flows"] }
        }
        // A severity word with an alert/incident noun is q; with anything else it is noise unless it was the whole query.
        guard recognised, var sec = section else { return nil }
        // Plain pod lookups ("pod foo in kube-system") use q for the name, matching PaletteObjects.pods.
        if sec.section == "pods", let p = f["pod"], podSubject { f["q"] = p; f["pod"] = nil; sec = nouns["pod"]! }
        // Loose words with no real structure ("random text") are not an intent.
        guard validSections.contains(sec.section) else { return nil }

        var clean: [String: String] = [:]
        for (k, v) in f where DeepLink.allowedKeys.contains(k) {
            let val = v.trimmingCharacters(in: .whitespaces)
            guard !val.isEmpty, val.count <= DeepLink.maxValueLength,
                  !val.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else { continue }
            clean[k] = val
        }
        var parts = [sec.title]
        for k in ["q", "pod", "namespace", "node", "direction", "protocol", "action"] { if let v = clean[k] { parts.append(k == "q" ? v : "\(k) \(v)") } }
        if let w = window { parts.append(w.label) }
        return QueryIntent(section: sec.section, query: clean, window: window, summary: parts.joined(separator: " · "))
    }

    // MARK: helpers

    /// "last hour", "last 15 minutes", "past 2 days", "15m", "24h", "today". Returns the window and tokens consumed.
    static func parseWindow(_ t: [String], at i: Int) -> (QueryIntent.Window, Int)? {
        let w = t[i]
        if w == "today" { return (.init(seconds: 86400, label: "today"), 1) }
        if w == "last" || w == "past" {
            guard i + 1 < t.count else { return nil }
            let a = t[i + 1]
            if let s = units[a] { return (.init(seconds: s, label: "last \(unitName(a, 1))"), 2) }
            if let n = Int(a), n > 0, n <= 100_000, i + 2 < t.count, let s = units[t[i + 2]] {
                return (.init(seconds: n * s, label: "last \(n) \(unitName(t[i + 2], n))"), 3)
            }
            if let (c, s) = compact(a) { return (.init(seconds: c, label: "last \(s)"), 2) }
            return nil
        }
        if let (c, s) = compact(w), w.first!.isNumber { return (.init(seconds: c, label: "last \(s)"), 1) }
        return nil
    }

    private static func compact(_ s: String) -> (Int, String)? {
        let digits = s.prefix { $0.isNumber }
        let unit = String(s.dropFirst(digits.count))
        guard let n = Int(digits), n > 0, n <= 100_000, let u = units[unit] else { return nil }
        return (n * u, "\(n) \(unitName(unit, n))")
    }

    private static func unitName(_ u: String, _ n: Int) -> String {
        let base: String
        switch units[u] ?? 0 { case 1: base = "second"; case 60: base = "minute"; case 3600: base = "hour"; case 86400: base = "day"; default: base = "week" }
        return n == 1 ? base : base + "s"
    }

    static func isIP(_ t: String) -> Bool {
        let core = t.split(separator: "/", maxSplits: 1).map(String.init)
        guard core.count <= 2, let host = core.first else { return false }
        let p = host.split(separator: ".", omittingEmptySubsequences: false)
        let maxPrefix = p.count == 4 ? 32 : 128
        if core.count == 2, !(Int(core[1]).map { (0...maxPrefix).contains($0) } ?? false) { return false }
        if p.count == 4 { return p.allSatisfy { Int($0).map { (0...255).contains($0) } ?? false && $0.count <= 3 } }
        // IPv6: needs at least two colons and only hex digits / colons.
        return host.filter { $0 == ":" }.count >= 2 && host.allSatisfy { $0 == ":" || $0.isHexDigit } && host.contains(where: \.isHexDigit)
    }

    /// Edit-distance <= 1 (2 for long words) against the noun table: "alrets" -> alerts, "toppers" no.
    static func fuzzyNoun(_ t: String) -> (section: String, title: String)? {
        guard t.count >= 5, t.allSatisfy(\.isLetter) else { return nil }
        let limit = t.count >= 8 ? 2 : 1
        var best: (d: Int, n: (section: String, title: String))?
        for (k, v) in nouns.sorted(by: { $0.key < $1.key }) where abs(k.count - t.count) <= limit && k.first == t.first {
            let d = distance(Array(t), Array(k))
            if d <= limit, best == nil || d < best!.d { best = (d, v) }
        }
        return best?.n
    }

    /// Optimal-string-alignment distance (adjacent transposition counts 1).
    static func distance(_ a: [Character], _ b: [Character]) -> Int {
        if a.isEmpty { return b.count }; if b.isEmpty { return a.count }
        var d = Array(repeating: Array(repeating: 0, count: b.count + 1), count: a.count + 1)
        for i in 0...a.count { d[i][0] = i }
        for j in 0...b.count { d[0][j] = j }
        for i in 1...a.count {
            for j in 1...b.count {
                let c = a[i - 1] == b[j - 1] ? 0 : 1
                d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c)
                if i > 1, j > 1, a[i - 1] == b[j - 2], a[i - 2] == b[j - 1] { d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1) }
            }
        }
        return d[a.count][b.count]
    }
}

/// Recently submitted palette queries, kept in UserDefaults. Text only, capped, deduplicated; anything that
/// looks like a credential is never stored.
public struct RecentQueries: Sendable {
    public static let key = "netra.palette.recentQueries"
    public static let maxCount = 8
    public static let maxLength = 120
    nonisolated(unsafe) private let defaults: UserDefaults
    private let storageKey: String

    public init(defaults: UserDefaults = .standard, key: String = RecentQueries.key) {
        self.defaults = defaults; self.storageKey = key
    }

    public var all: [String] { (defaults.stringArray(forKey: storageKey) ?? []).filter(Self.isStorable) }

    @discardableResult
    public func record(_ text: String) -> Bool {
        let t = text.split(whereSeparator: { $0.isWhitespace }).joined(separator: " ")
        guard t.count >= 2, Self.isStorable(t) else { return false }
        var list = all.filter { $0.caseInsensitiveCompare(t) != .orderedSame }
        list.insert(t, at: 0)
        defaults.set(Array(list.prefix(Self.maxCount)), forKey: storageKey)
        return true
    }

    public func clear() { defaults.removeObject(forKey: storageKey) }

    /// Recents matching a typed prefix/fuzzy query (all of them when empty).
    public func matching(_ query: String) -> [String] {
        FuzzyMatch.rank(all, query: query) { [$0] }.map(\.item)
    }

    /// Rejects control characters, over-long text and credential-shaped text (bearer/token/password/api keys, JWTs, long opaque strings).
    public static func isStorable(_ s: String) -> Bool {
        guard !s.isEmpty, s.count <= maxLength, !s.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else { return false }
        let l = s.lowercased()
        for w in ["bearer ", "password", "passwd", "secret", "token", "apikey", "api_key", "api-key", "authorization", "eyj", "-----begin", "sk-"] where l.contains(w) { return false }
        for w in s.split(whereSeparator: { $0.isWhitespace }) where w.count >= 24 && w.allSatisfy({ $0.isLetter || $0.isNumber || "+/=_-".contains($0) })
            && w.contains(where: \.isNumber) && w.contains(where: \.isLetter) { return false }
        return true
    }
}

/// The optional "Ask Netra AI" fallback row. Offering it is only a row: choosing it opens the Ask panel with the
/// text prefilled, and the user must press Ask. Nothing is sent from here.
public enum AskFallback {
    public static func title(for text: String) -> String {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return "Ask Netra AI: " + (t.count > 60 ? String(t.prefix(57)) + "..." : t)
    }
    /// Offered for a non-trivial query, and only when it is storable-safe (no credential-shaped text goes toward a question).
    public static func shouldOffer(_ text: String) -> Bool {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return t.count >= 3 && t.count <= 500 && !t.unicodeScalars.contains(where: { $0.properties.generalCategory == .control })
    }
    /// Link that opens the Ask page with `q` prefilled. `q` is the only key used.
    public static func link(for text: String, section: String = "aiBrief") -> DeepLink {
        DeepLink(section: section, query: ["q": String(text.trimmingCharacters(in: .whitespacesAndNewlines).prefix(DeepLink.maxValueLength))])
    }
}
