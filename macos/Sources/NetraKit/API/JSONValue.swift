// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Schema-less JSON for endpoints without a typed model yet (powers the generic browser view).
public enum JSONValue: Sendable, Equatable, Codable {
    case null, bool(Bool), number(Double), string(String)
    case array([JSONValue]), object([String: JSONValue])

    public init(from d: Decoder) throws {
        let c = try d.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(Bool.self) { self = .bool(v) }
        else if let v = try? c.decode(Double.self) { self = .number(v) }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        else if let v = try? c.decode([JSONValue].self) { self = .array(v) }
        else { self = .object(try c.decode([String: JSONValue].self)) }
    }
    public func encode(to e: Encoder) throws {
        var c = e.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let v): try c.encode(v)
        case .number(let v): try c.encode(v)
        case .string(let v): try c.encode(v)
        case .array(let v): try c.encode(v)
        case .object(let v): try c.encode(v)
        }
    }
    public subscript(key: String) -> JSONValue? { if case .object(let o) = self { o[key] } else { nil } }
    public var string: String? { if case .string(let s) = self { s } else { nil } }
    public var double: Double? { if case .number(let n) = self { n } else { nil } }
    public var summary: String {
        switch self {
        case .null: "null"
        case .bool(let b): b ? "true" : "false"
        case .number(let n): n == n.rounded() && abs(n) < 1e15 ? String(Int64(n)) : String(n)
        case .string(let s): s
        case .array(let a): "[\(a.count)]"
        case .object(let o): "{\(o.count)}"
        }
    }
}
