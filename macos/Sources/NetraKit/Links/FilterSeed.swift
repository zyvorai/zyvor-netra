// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Pure mapping from a deep-link / palette filter (`DeepLink.allowedKeys`) to what a page shows.
/// Display-only: the result seeds a local search box or an existing picker and never builds a request.
///
/// Mapping for pages with only a text search: ONE term is used (a page's search is a substring match,
/// so joining several terms would match nothing). Precedence: q, pod, namespace, node, protocol, action, direction.
/// The remaining keys are reported in `unapplied` so the chip can say so instead of hiding them.
public enum FilterSeed {
    public static let searchPrecedence = ["q", "pod", "namespace", "node", "protocol", "action", "direction"]

    public struct Plan: Equatable, Sendable {
        /// Text for the page's search box ("" when none).
        public var search: String
        /// Values for dedicated page fields, keyed by the link key (only keys listed in `dedicated`).
        public var fields: [String: String]
        /// Keys that are neither in the search box nor a dedicated field.
        public var unapplied: [String]
        /// "pod=web-1 · direction=egress" for the visible chip (empty when the filter is empty).
        public var summary: String
        public var isEmpty: Bool { search.isEmpty && fields.isEmpty }
    }

    /// `dedicated`: keys this page maps onto its own field (they are removed from the text-search candidates).
    public static func plan(_ filter: [String: String], dedicated: Set<String> = []) -> Plan {
        let clean = filter.compactMapValues { v -> String? in
            let t = v.trimmingCharacters(in: .whitespacesAndNewlines)
            return t.isEmpty ? nil : t
        }.filter { DeepLink.allowedKeys.contains($0.key) }
        var fields: [String: String] = [:]
        for k in dedicated { if let v = clean[k] { fields[k] = v } }
        var search = ""
        var used = Set(fields.keys)
        for k in searchPrecedence where !dedicated.contains(k) {
            if let v = clean[k] { search = v; used.insert(k); break }
        }
        let order = searchPrecedence
        let summary = clean.sorted { (order.firstIndex(of: $0.key) ?? 99) < (order.firstIndex(of: $1.key) ?? 99) }
            .map { "\($0.key)=\($0.value)" }.joined(separator: " · ")
        let unapplied = clean.keys.filter { !used.contains($0) }.sorted()
        return Plan(search: search, fields: fields, unapplied: unapplied, summary: summary)
    }

    /// Flows verdict from an `action` filter ("drop", "allow"…); nil when it is not a known verdict.
    public static func flowVerdict(_ action: String) -> String? {
        switch action.lowercased() {
        case "drop", "dropped", "deny", "denied": "DROPPED"
        case "allow", "allowed", "forward", "forwarded": "FORWARDED"
        case "audit": "AUDIT"
        case "error": "ERROR"
        default: nil
        }
    }

    /// Flows direction picker value ("EGRESS"/"INGRESS"); nil when unknown.
    public static func flowDirection(_ d: String) -> String? {
        switch d.lowercased() {
        case "egress": "EGRESS"
        case "ingress": "INGRESS"
        default: nil
        }
    }
}
