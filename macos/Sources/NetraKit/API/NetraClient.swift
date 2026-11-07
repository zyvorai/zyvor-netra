// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

public struct ConnectionProfile: Sendable, Equatable {
    public var baseURL: URL
    public var token: String?
    public init(baseURL: URL, token: String? = nil) { self.baseURL = baseURL; self.token = token }
}

public struct WhoAmI: Codable, Sendable, Equatable {
    public var authRequired: Bool
    public var oidcEnabled: Bool
    public var kind: String
    public var role: String
    public var identity: String?
    public var parsedRole: Role { Role(rawValue: role) ?? .none }
    /// Operators may change rules/captures; the UI disables controls otherwise (server still enforces).
    public var canMutate: Bool { parsedRole >= .operator }
    /// Admins additionally change posture (mode), apply policy and open consoles (exec/VNC).
    public var isAdmin: Bool { parsedRole >= .admin }
}

/// Mirrors internal/oidcauth roles; higher includes lower.
public enum Role: String, Sendable, Comparable {
    case none, viewer, `operator`, admin
    var rank: Int { [Role.none: 0, .viewer: 1, .operator: 2, .admin: 3][self]! }
    public static func < (a: Role, b: Role) -> Bool { a.rank < b.rank }
}

public enum NetraError: Error, Sendable, Equatable {
    case http(status: Int, message: String)
    case unauthorized
    case transport(String)
}

/// Pulls the message out of the controller's {"error":"…"} envelope.
public func errorMessage(from body: Data) -> String {
    if let o = try? JSONSerialization.jsonObject(with: body) as? [String: Any] {
        if let m = o["error"] as? String, !m.isEmpty { return m }
        if let m = o["message"] as? String, !m.isEmpty { return m }
    }
    return String(decoding: body, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
}

public struct NetraClient: Sendable {
    public let profile: ConnectionProfile
    let session: URLSession
    public init(profile: ConnectionProfile, session: URLSession = .shared) {
        self.profile = profile; self.session = session
    }

    /// Builds a request. The bearer goes in the Authorization header, never the query string.
    public func request(_ method: String, _ path: String, query: [URLQueryItem] = [],
                        body: Data? = nil, confirmRisk: Bool = false) -> URLRequest {
        var c = URLComponents(url: profile.baseURL.appendingPathComponent(path), resolvingAgainstBaseURL: false)!
        if !query.isEmpty { c.queryItems = query }
        var r = URLRequest(url: c.url!)
        r.httpMethod = method
        r.setValue("application/json", forHTTPHeaderField: "Accept")
        if let t = profile.token, !t.isEmpty { r.setValue("Bearer \(t)", forHTTPHeaderField: "Authorization") }
        if let body { r.httpBody = body; r.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        if confirmRisk { r.setValue("high", forHTTPHeaderField: "X-Netra-Confirm-Risk") }
        return r
    }

    public func send(_ req: URLRequest) async throws -> Data {
        let (data, resp): (Data, URLResponse)
        do { (data, resp) = try await session.data(for: req) }
        catch { throw NetraError.transport(error.localizedDescription) }
        guard let h = resp as? HTTPURLResponse else { throw NetraError.transport("non-HTTP response") }
        if h.statusCode == 401 { throw NetraError.unauthorized }
        guard (200..<300).contains(h.statusCode) else {
            throw NetraError.http(status: h.statusCode, message: errorMessage(from: data))
        }
        return data
    }

    public func get<T: Decodable>(_ path: String, query: [URLQueryItem] = [], as: T.Type = T.self) async throws -> T {
        try JSONDecoder().decode(T.self, from: await send(request("GET", path, query: query)))
    }

    public func whoami() async throws -> WhoAmI { try await get("api/v1/whoami") }
}
