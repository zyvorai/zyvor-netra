// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// GET /api/v1/lease (internal/leaseclock).
public struct LeaseStatus: Codable, Sendable, Equatable {
    public var mode: String
    public var scopeMode: String?
    public var leaseExpiresAt: Date?
    public var leaseSeconds: Int64?
    public var remainingSeconds: Int64
    public var active: Bool
    public var expired: Bool
    public var note: String?
}

extension JSONDecoder {
    /// Go emits RFC 3339 with optional fractional seconds.
    public static var netra: JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .custom { dec in
            let s = try dec.singleValueContainer().decode(String.self)
            let f = ISO8601DateFormatter()
            f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let v = f.date(from: s) { return v }
            f.formatOptions = [.withInternetDateTime]
            if let v = f.date(from: s) { return v }
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
