// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// A `netra://<section>[?filters]` link. Navigation only: parsing never yields anything that mutates state.
/// `section` is a NavSection raw value; the caller supplies the valid set so unknown sections are rejected.
public struct DeepLink: Equatable, Sendable {
    public static let scheme = "netra"
    /// Read-only filter keys (these mirror the web UI investigation scope). Anything else is rejected.
    public static let allowedKeys: Set<String> = ["q", "namespace", "pod", "node", "direction", "protocol", "action"]
    public static let maxValueLength = 256

    public enum ParseError: Error, Equatable, Sendable {
        case notNetraScheme, unknownSection(String), unexpectedComponent(String), unknownKey(String), duplicateKey(String), badValue(String)
    }

    public let section: String
    public let query: [String: String]

    public init(section: String, query: [String: String] = [:]) {
        self.section = section
        self.query = query
    }

    /// Strict parse. `validSections` are the accepted section ids (matched case-insensitively, canonical casing returned).
    public static func parse(_ url: URL, validSections: Set<String>) throws -> DeepLink {
        guard url.scheme?.lowercased() == scheme else { throw ParseError.notNetraScheme }
        guard let c = URLComponents(url: url, resolvingAgainstBaseURL: false) else { throw ParseError.unexpectedComponent("url") }
        if c.user != nil || c.password != nil { throw ParseError.unexpectedComponent("userinfo") }
        if c.port != nil { throw ParseError.unexpectedComponent("port") }
        if c.fragment != nil { throw ParseError.unexpectedComponent("fragment") }
        if !(c.path.isEmpty || c.path == "/") { throw ParseError.unexpectedComponent("path") }
        let host = c.host ?? ""
        guard let section = validSections.first(where: { $0.lowercased() == host.lowercased() }), !host.isEmpty else {
            throw ParseError.unknownSection(host)
        }
        var q: [String: String] = [:]
        for item in c.queryItems ?? [] {
            guard allowedKeys.contains(item.name) else { throw ParseError.unknownKey(item.name) }
            if q[item.name] != nil { throw ParseError.duplicateKey(item.name) }
            let v = item.value ?? ""
            guard v.count <= maxValueLength, !v.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else {
                throw ParseError.badValue(item.name)
            }
            if !v.isEmpty { q[item.name] = v }
        }
        return DeepLink(section: section, query: q)
    }

    public static func parse(_ string: String, validSections: Set<String>) throws -> DeepLink {
        guard let url = URL(string: string) else { throw ParseError.notNetraScheme }
        return try parse(url, validSections: validSections)
    }

    /// Canonical URL (keys sorted so the output is stable). Drops keys that are not allowed.
    public var url: URL? {
        var c = URLComponents()
        c.scheme = Self.scheme
        c.host = section
        let items = query.filter { Self.allowedKeys.contains($0.key) && !$0.value.isEmpty }
            .sorted { $0.key < $1.key }.map { URLQueryItem(name: $0.key, value: $0.value) }
        if !items.isEmpty { c.queryItems = items }
        return c.url
    }
}

/// Hand-off to the web UI, whose router is hash based: `https://<controller>/#page=<page>&namespace=…`
/// (web/src/lib/investigation.ts `routeHash` / `readRoute`).
public enum WebHandoff {
    /// NavSection id -> web UI page. Sections with no web counterpart are absent (they hand off to overview).
    public static let pages: [String: String] = [
        "overview": "overview", "health": "health", "scorecard": "scorecard", "flows": "flows", "talkers": "talkers",
        "drops": "drops", "topology": "topology", "workloads": "workloads", "pods": "pods", "l7": "l7",
        "sysctl": "sysctl-audit", "nodeResources": "node-resources", "netlink": "netlink", "attachments": "bpf-attachments",
        "maps": "ebpf", "ebpfCoverage": "ebpf", "metrics": "metrics", "anomalies": "metric-anomalies", "alerts": "metric-alerts",
        "insights": "insights", "incidents": "incidents", "security": "security-review", "audit": "audit", "report": "report",
        "policies": "policies", "rules": "ebpf", "features": "features", "capture": "capture", "fleet": "fleet",
        "connections": "connections", "pathDiag": "path", "congestion": "congestion", "explain": "explain",
        "surfaces": "surfaces", "diagnostics": "detect", "tcpEvents": "connections", "dns": "health",
    ]

    /// Web scope key for a deep-link filter key.
    static func webKey(_ k: String) -> String { k == "q" ? "query" : k }

    /// `base` must be http(s) with a host and no credentials. Any path/query/fragment on it is dropped except the path.
    public static func url(base: URL, section: String, query: [String: String] = [:]) -> URL? {
        guard var c = URLComponents(url: base, resolvingAgainstBaseURL: false),
              let s = c.scheme?.lowercased(), s == "http" || s == "https",
              let h = c.host, !h.isEmpty, c.user == nil, c.password == nil else { return nil }
        c.query = nil
        var items = [URLQueryItem(name: "page", value: pages[section] ?? "overview")]
        for (k, v) in query.sorted(by: { $0.key < $1.key }) where DeepLink.allowedKeys.contains(k) && !v.isEmpty {
            items.append(URLQueryItem(name: webKey(k), value: v))
        }
        var f = URLComponents(); f.queryItems = items
        c.fragment = f.percentEncodedQuery
        return c.url
    }

    /// Reverse: web URL -> (page, filters). Returns nil for unknown pages.
    public static func parse(_ url: URL) -> (page: String, query: [String: String])? {
        guard let frag = URLComponents(url: url, resolvingAgainstBaseURL: false)?.percentEncodedFragment else { return nil }
        var f = URLComponents(); f.percentEncodedQuery = frag
        var page: String?, q: [String: String] = [:]
        for i in f.queryItems ?? [] {
            if i.name == "page" { page = i.value; continue }
            let k = i.name == "query" ? "q" : i.name
            if DeepLink.allowedKeys.contains(k), let v = i.value, !v.isEmpty { q[k] = v }
        }
        guard let p = page, Set(pages.values).contains(p) || p == "overview" else { return nil }
        return (p, q)
    }
}
