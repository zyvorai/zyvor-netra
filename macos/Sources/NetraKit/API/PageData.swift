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
    public static func date(_ v: JSONValue?) -> Date? {
        switch v {
        case .string(let s)?:
            return (try? Date(s, strategy: Date.ISO8601FormatStyle(includingFractionalSeconds: true)))
                ?? (try? Date(s, strategy: Date.ISO8601FormatStyle()))
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
    public static func text(_ v: JSONValue?, _ kind: CellKind, now: Date = Date()) -> String {
        guard let v, v != .null else { return "" }
        switch kind {
        case .text: return v.summary
        case .int: return v.asDouble.map { String(Int($0.rounded())) } ?? v.summary
        case .number(let d): return v.asDouble.map { String(format: "%.\(d)f", $0) } ?? v.summary
        case .bytes: return v.asDouble.map(bytes) ?? v.summary
        case .percent: return v.asDouble.map { String(format: "%.1f%%", $0) } ?? v.summary
        case .ratio: return v.asDouble.map { String(format: "%.1f%%", $0 * 100) } ?? v.summary
        case .seconds: return v.asDouble.map(duration) ?? v.summary
        case .millis: return v.asDouble.map { $0 < 10 ? String(format: "%.2f ms", $0) : String(format: "%.0f ms", $0) } ?? v.summary
        case .bool: if case .bool(let b) = v { return b ? "yes" : "no" }; return v.summary
        case .time: return date(v).map { relative($0, now: now) } ?? v.summary
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
