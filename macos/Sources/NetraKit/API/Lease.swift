// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// GET /api/v1/lease (leaseclock.Status). Decoding is lenient: a missing or malformed field never fails the poll.
public struct LeaseStatus: Codable, Sendable, Equatable {
    public var mode: String
    public var scopeMode: String?
    public var leaseExpiresAt: Date?
    public var leaseSeconds: Int64?
    public var remainingSeconds: Int64
    public var active: Bool
    public var expired: Bool
    public var note: String?

    enum K: String, CodingKey { case mode, scopeMode, leaseExpiresAt, leaseSeconds, remainingSeconds, active, expired, note }
    public init(mode: String = "observe", scopeMode: String? = nil, leaseExpiresAt: Date? = nil, leaseSeconds: Int64? = nil,
                remainingSeconds: Int64 = 0, active: Bool = false, expired: Bool = false, note: String? = nil) {
        self.mode = mode; self.scopeMode = scopeMode; self.leaseExpiresAt = leaseExpiresAt; self.leaseSeconds = leaseSeconds
        self.remainingSeconds = remainingSeconds; self.active = active; self.expired = expired; self.note = note
    }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: K.self)
        mode = LenientDecode.string(c, .mode) ?? "observe"
        scopeMode = LenientDecode.string(c, .scopeMode)
        leaseExpiresAt = LenientDecode.string(c, .leaseExpiresAt).flatMap(NetraDate.parse)
        leaseSeconds = LenientDecode.double(c, .leaseSeconds).flatMap(LenientDecode.int64)
        remainingSeconds = LenientDecode.double(c, .remainingSeconds).flatMap(LenientDecode.int64) ?? 0
        active = LenientDecode.bool(c, .active) ?? false
        expired = LenientDecode.bool(c, .expired) ?? false
        note = LenientDecode.string(c, .note)
    }
}

/// Tolerant field readers: wrong type or null yields nil instead of failing the whole decode.
enum LenientDecode {
    static func string<K: CodingKey>(_ c: KeyedDecodingContainer<K>, _ k: K) -> String? {
        if let s = try? c.decodeIfPresent(String.self, forKey: k) { return s }
        if let n = try? c.decodeIfPresent(Double.self, forKey: k) { return n == n.rounded() && abs(n) < 1e15 ? String(Int64(n)) : String(n) }
        if let b = try? c.decodeIfPresent(Bool.self, forKey: k) { return b ? "true" : "false" }
        return nil
    }
    /// Accepts numbers and numeric strings (Go `,string` tags).
    static func double<K: CodingKey>(_ c: KeyedDecodingContainer<K>, _ k: K) -> Double? {
        if let n = try? c.decodeIfPresent(Double.self, forKey: k) { return n }
        if let s = try? c.decodeIfPresent(String.self, forKey: k) { return Double(s.trimmingCharacters(in: .whitespaces)) }
        return nil
    }
    static func bool<K: CodingKey>(_ c: KeyedDecodingContainer<K>, _ k: K) -> Bool? {
        if let b = try? c.decodeIfPresent(Bool.self, forKey: k) { return b }
        if let s = try? c.decodeIfPresent(String.self, forKey: k) { return ["true", "1", "yes"].contains(s.lowercased()) }
        return nil
    }
    /// Int conversion that never traps on NaN, infinity or uint64 values beyond Int64.
    static func int64(_ d: Double) -> Int64? {
        guard d.isFinite else { return nil }
        if d >= 9.2e18 { return Int64.max }
        if d <= -9.2e18 { return Int64.min }
        return Int64(d)
    }
}

/// RFC 3339 parsing for Go time.Time output (any number of fractional digits).
public enum NetraDate {
    public static func parse(_ s: String) -> Date? {
        guard !s.isEmpty else { return nil }
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: s) { return d }
        f.formatOptions = [.withInternetDateTime]
        if let d = f.date(from: s) { return d }
        // Nanosecond fractions: trim to milliseconds and retry.
        if let dot = s.firstIndex(of: "."), let end = s[dot...].firstIndex(where: { !$0.isNumber && $0 != "." }) {
            let frac = s[s.index(after: dot)..<end]
            let trimmed = String(s[..<dot]) + "." + String(frac.prefix(3)).padding(toLength: 3, withPad: "0", startingAt: 0) + String(s[end...])
            f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            return f.date(from: trimmed)
        }
        return nil
    }
}

extension JSONDecoder {
    /// Go emits RFC 3339 with optional fractional seconds.
    public static var netra: JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .custom { dec in
            let s = try dec.singleValueContainer().decode(String.self)
            if let v = NetraDate.parse(s) { return v }
            throw DecodingError.dataCorrupted(.init(codingPath: dec.codingPath, debugDescription: "bad date \(s)"))
        }
        return d
    }
}

extension NetraClient {
    public func lease() async throws -> LeaseStatus {
        try JSONDecoder.netra.decode(LeaseStatus.self, from: await send(request("GET", "api/v1/lease")))
    }
    public func json(_ path: String) async throws -> JSONValue {
        try JSONDecoder().decode(JSONValue.self, from: await send(request("GET", path)))
    }
}
