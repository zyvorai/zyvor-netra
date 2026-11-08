// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// How a cell is rendered and sorted. Pure data so the formatting is unit-tested.
public enum CellKind: Sendable, Hashable {
    case text, int, number(Int), bytes, percent, ratio, time, seconds, millis, bool
}

extension JSONValue {
    /// Dotted-path lookup: `"summary.top.0.name"`. Numeric parts index arrays.
    public func at(_ path: String) -> JSONValue? {
        if path.isEmpty { return self }
        var v: JSONValue? = self
        for part in path.split(separator: ".") {
            if case .array(let a)? = v, let i = Int(part), a.indices.contains(i) { v = a[i] }
            else { v = v?[String(part)] }
        }
        return v
    }

    public var asDouble: Double? {
        switch self {
        case .number(let n): n
        case .string(let s): Double(s)
        case .bool(let b): b ? 1 : 0
        default: nil
        }
    }

    /// Rows from an array at `path` (or the value itself when `path` is empty and it is an array).
    /// Falls back through `fallbacks` so a page survives a server that renames a list key.
    public func rows(at path: String, fallbacks: [String] = [], idKeys: [String] = ["id", "name"]) -> [ControlRow] {
        for p in [path] + fallbacks {
            if case .array(let a)? = at(p) {
                return a.enumerated().map { i, item in
                    let id = idKeys.compactMap { k in item[k].flatMap { $0 == .null ? nil : $0.summary } }.first
                    return ControlRow(id: (id ?? "row") + "#\(i)", value: item)
                }
            }
        }
        return []
    }

    /// Rows from an object keyed by name (`{"tcp": {...}, "udp": {...}}`): each row gets `key` plus the
    /// value's own fields, or `{"key": k, "value": v}` for a scalar.
    public func mapRows(at path: String) -> [ControlRow] {
        guard case .object(let o)? = at(path) else { return [] }
        return o.keys.sorted().map { k in
            var row: [String: JSONValue]
            if case .object(let inner)? = o[k] { row = inner } else { row = ["value": o[k] ?? .null] }
            if row["key"] == nil { row["key"] = .string(k) }
            return ControlRow(id: k, value: .object(row))
        }
    }
}

public enum CellFormat {
    /// Go's zero `time.Time` serialises as 0001-01-01T00:00:00Z (omitempty does not drop structs): treat anything before 1971 as unset.
    static func isUnsetTime(_ d: Date) -> Bool { d.timeIntervalSince1970 < 31_536_000 }

    static func isUnsetTimeValue(_ v: JSONValue) -> Bool {
        guard case .string(let s) = v else { return false }
        return s.hasPrefix("0001-") || s.hasPrefix("0000-")
    }

    public static func date(_ v: JSONValue?) -> Date? {
        switch v {
        case .string(let s)?:
            let d = (try? Date(s, strategy: Date.ISO8601FormatStyle(includingFractionalSeconds: true)))
                ?? (try? Date(s, strategy: Date.ISO8601FormatStyle()))
            return d.flatMap { isUnsetTime($0) ? nil : $0 }
        case .number(let n)?:
            if n <= 0 { return nil }
            return Date(timeIntervalSince1970: n > 1e12 ? n / 1000 : n)    // seconds or milliseconds
        default: return nil
        }
    }

    public static func bytes(_ n: Double) -> String {
        let units = ["B", "KB", "MB", "GB", "TB", "PB"]; var x = abs(n), i = 0
        while x >= 1024, i < units.count - 1 { x /= 1024; i += 1 }
        return (n < 0 ? "-" : "") + (i == 0 ? "\(Int(x)) B" : String(format: "%.1f %@", x, units[i]))
    }

    public static func duration(_ s: Double) -> String {
        let t = Int(abs(s).rounded())
        if t < 60 { return "\(t)s" }
        if t < 3600 { return "\(t / 60)m \(t % 60)s" }
        if t < 86400 { return "\(t / 3600)h \(t % 3600 / 60)m" }
        return "\(t / 86400)d \(t % 86400 / 3600)h"
    }

    public static func relative(_ d: Date, now: Date = Date()) -> String {
        let s = now.timeIntervalSince(d)
        return s >= 0 ? duration(s) + " ago" : "in " + duration(-s)
    }

    /// Display text for a cell. Missing/null shows as an empty string, never "null".
    /// Arrays of scalars read as "a, b, c" (capped) instead of "[3]"; nested arrays/objects keep the count summary.
    static func listText(_ v: JSONValue, limit: Int = 6) -> String? {
        guard case .array(let a) = v, !a.isEmpty else { return nil }
        var parts: [String] = []
        for e in a {
            switch e { case .array, .object: return nil; default: parts.append(e.summary) }
        }
        let shown = parts.prefix(limit).joined(separator: ", ")
        return parts.count > limit ? "\(shown), +\(parts.count - limit)" : shown
    }

    public static func text(_ v: JSONValue?, _ kind: CellKind, now: Date = Date()) -> String {
        guard let v, v != .null else { return "" }
        switch kind {
        case .text: return listText(v) ?? v.summary
        case .int: return v.asDouble.map { String(Int($0.rounded())) } ?? v.summary
        case .number(let d): return v.asDouble.map { String(format: "%.\(d)f", $0) } ?? v.summary
        case .bytes: return v.asDouble.map(bytes) ?? v.summary
        case .percent: return v.asDouble.map { String(format: "%.1f%%", $0) } ?? v.summary
        case .ratio: return v.asDouble.map { String(format: "%.1f%%", $0 * 100) } ?? v.summary
        case .seconds: return v.asDouble.map(duration) ?? v.summary
        case .millis: return v.asDouble.map { $0 < 10 ? String(format: "%.2f ms", $0) : String(format: "%.0f ms", $0) } ?? v.summary
        case .bool: if case .bool(let b) = v { return b ? "yes" : "no" }; return v.summary
        case .time:
            if isUnsetTimeValue(v) { return "" }
            return date(v).map { relative($0, now: now) } ?? v.summary
        }
    }

    /// Orders two cells by their underlying value, not their display text.
    public static func less(_ a: JSONValue?, _ b: JSONValue?, _ kind: CellKind) -> Bool {
        switch kind {
        case .text, .bool: return (a?.summary ?? "").localizedStandardCompare(b?.summary ?? "") == .orderedAscending
        case .time: return (date(a) ?? .distantPast) < (date(b) ?? .distantPast)
        default: return (a?.asDouble ?? -.infinity) < (b?.asDouble ?? -.infinity)
        }
    }
}

/// Diagnostics for columns that render blank for every row: usually a server field rename.
public struct EmptyColumnReport: Equatable, Sendable {
    public struct Item: Equatable, Sendable, Identifiable {
        public let title: String
        public let path: String
        public var id: String { path + title }
        /// Popover text: "No data for X: server returned keys: a, b, c". Key names only, never values.
        public let message: String
    }
    public static let keyCap = 30
    public let items: [Item]
    public var isEmpty: Bool { items.isEmpty }
    /// Sorted top-level key names of the first row (capped) and how many were left out.
    public let keys: [String]
    public let omittedKeys: Int

    /// `columns` are (title, path, kind). Only reports when `rows` is non-empty.
    public static func compute(rows: [ControlRow], columns: [(title: String, path: String, kind: CellKind)]) -> EmptyColumnReport {
        guard let first = rows.first else { return EmptyColumnReport(items: [], keys: [], omittedKeys: 0) }
        var all: [String] = []
        if case .object(let o) = first.value { all = o.keys.sorted() }
        let keys = Array(all.prefix(keyCap)), omitted = all.count - keys.count
        let list = keys.isEmpty ? "none (row is not an object)" : keys.joined(separator: ", ") + (omitted > 0 ? ", +\(omitted) more" : "")
        let items = columns.filter { c in rows.allSatisfy { isBlank($0.value.at(c.path), c.kind) } }
            .map { Item(title: $0.title, path: $0.path, message: "No data for \($0.title): server returned keys: \(list)") }
        return EmptyColumnReport(items: items, keys: keys, omittedKeys: omitted)
    }

    static func isBlank(_ v: JSONValue?, _ kind: CellKind) -> Bool {
        if case .array(let a)? = v, a.isEmpty { return true }
        return CellFormat.text(v, kind).isEmpty
    }
}
