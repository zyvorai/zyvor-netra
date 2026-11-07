// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation
import CryptoKit

/// Authorization-code + PKCE for a public client. The Netra controller verifies the resulting JWT itself
/// (internal/oidcauth: issuer, NETRA_OIDC_AUDIENCE, signature, exp), so the app only has to obtain one
/// and send it as `Authorization: Bearer`. No client secret, and tokens are never logged.
public protocol OIDCTransport: Sendable {
    func send(_ req: URLRequest) async throws -> (Data, Int)
}
public struct URLSessionOIDCTransport: OIDCTransport {
    public init() {}
    public func send(_ req: URLRequest) async throws -> (Data, Int) {
        let (d, r) = try await URLSession.shared.data(for: req)
        return (d, (r as? HTTPURLResponse)?.statusCode ?? 0)
    }
}

public enum OIDCError: Error, Equatable, LocalizedError, Sendable {
    case badIssuer(String), discoveryFailed(String), stateMismatch, nonceMismatch, providerError(String)
    case missingCode, tokenExchangeFailed(String), noRefreshToken, noToken
    public var errorDescription: String? {
        switch self {
        case .badIssuer(let m): m
        case .discoveryFailed(let m): "OIDC discovery failed: \(m)"
        case .stateMismatch: "Sign-in response did not match this request (state mismatch)."
        case .nonceMismatch: "ID token nonce did not match this request."
        case .providerError(let m): "Identity provider error: \(m)"
        case .missingCode: "Sign-in response had no authorization code."
        case .tokenExchangeFailed(let m): "Token request failed: \(m)"
        case .noRefreshToken: "No refresh token; sign in again."
        case .noToken: "The identity provider returned no usable token."
        }
    }
}

public struct OIDCEndpoints: Equatable, Sendable {
    public var authorization: URL
    public var token: URL
}

public struct OIDCTokens: Equatable, Sendable {
    public var bearer: String          // what the Netra API receives
    public var refreshToken: String?
    public var expiresAt: Date?
    public init(bearer: String, refreshToken: String?, expiresAt: Date?) { self.bearer = bearer; self.refreshToken = refreshToken; self.expiresAt = expiresAt }
}

public struct OIDCAuthRequest: Sendable {
    public let url: URL
    public let state: String
    public let nonce: String
    public let verifier: String
    public let redirectURI: String
}

public struct OIDCFlow: Sendable {
    /// Register this exact redirect with the IdP (public client).
    public static let redirectURI = "netra://oidc/callback"
    public static let callbackScheme = "netra"

    let settings: OIDCSettings
    let transport: OIDCTransport
    let now: @Sendable () -> Date

    public init(settings: OIDCSettings, transport: OIDCTransport = URLSessionOIDCTransport(), now: @escaping @Sendable () -> Date = { Date() }) {
        self.settings = settings; self.transport = transport; self.now = now
    }

    // MARK: PKCE helpers

    static func b64url(_ d: Data) -> String {
        d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    public static func randomToken(bytes: Int = 32) -> String {
        var g = SystemRandomNumberGenerator()
        return b64url(Data((0..<bytes).map { _ in UInt8.random(in: 0...255, using: &g) }))
    }
    public static func challenge(for verifier: String) -> String { b64url(Data(SHA256.hash(data: Data(verifier.utf8)))) }

    // MARK: discovery

    public func discover() async throws -> OIDCEndpoints {
        guard let iss = URL(string: settings.issuer), iss.scheme == "https", iss.host != nil else {
            throw OIDCError.badIssuer("The issuer must be an https URL.")
        }
        var base = settings.issuer; while base.hasSuffix("/") { base.removeLast() }
        guard let u = URL(string: base + "/.well-known/openid-configuration") else { throw OIDCError.badIssuer("Bad issuer URL.") }
        var r = URLRequest(url: u); r.setValue("application/json", forHTTPHeaderField: "Accept")
        let (data, status): (Data, Int)
        do { (data, status) = try await transport.send(r) } catch { throw OIDCError.discoveryFailed(error.localizedDescription) }
        guard status == 200, let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw OIDCError.discoveryFailed("HTTP \(status)")
        }
        // Same rule the server applies: the document's issuer must equal the configured one.
        func norm(_ s: String) -> String { var t = s; while t.hasSuffix("/") { t.removeLast() }; return t }
        guard let docIss = o["issuer"] as? String, norm(docIss) == base else {
            throw OIDCError.discoveryFailed("issuer in discovery document does not match")
        }
        guard let a = (o["authorization_endpoint"] as? String).flatMap(URL.init(string:)),
              let t = (o["token_endpoint"] as? String).flatMap(URL.init(string:)),
              a.scheme == "https", t.scheme == "https" else {
            throw OIDCError.discoveryFailed("missing or non-https endpoints")
        }
        return OIDCEndpoints(authorization: a, token: t)
    }

    // MARK: authorize

    public func makeAuthRequest(endpoints: OIDCEndpoints, state: String = OIDCFlow.randomToken(),
                                nonce: String = OIDCFlow.randomToken(), verifier: String = OIDCFlow.randomToken(bytes: 48)) -> OIDCAuthRequest {
        var c = URLComponents(url: endpoints.authorization, resolvingAgainstBaseURL: false)!
        var items = c.queryItems ?? []
        items += [
            .init(name: "response_type", value: "code"),
            .init(name: "client_id", value: settings.clientID),
            .init(name: "redirect_uri", value: Self.redirectURI),
            .init(name: "scope", value: settings.scopes),
            .init(name: "state", value: state),
            .init(name: "nonce", value: nonce),
            .init(name: "code_challenge", value: Self.challenge(for: verifier)),
            .init(name: "code_challenge_method", value: "S256"),
        ]
        c.queryItems = items
        return OIDCAuthRequest(url: c.url!, state: state, nonce: nonce, verifier: verifier, redirectURI: Self.redirectURI)
    }

    /// Validates the redirect (state, provider error) and returns the code.
    public func code(from callback: URL, request: OIDCAuthRequest) throws -> String {
        let q = Dictionary((URLComponents(url: callback, resolvingAgainstBaseURL: false)?.queryItems ?? []).map { ($0.name, $0.value ?? "") },
                           uniquingKeysWith: { a, _ in a })
        guard q["state"] == request.state else { throw OIDCError.stateMismatch }
        if let e = q["error"] { throw OIDCError.providerError(q["error_description"].flatMap { $0.isEmpty ? nil : $0 } ?? e) }
        guard let c = q["code"], !c.isEmpty else { throw OIDCError.missingCode }
        return c
    }

    // MARK: token endpoint

    public func exchange(code: String, request: OIDCAuthRequest, endpoints: OIDCEndpoints) async throws -> OIDCTokens {
        try await tokenCall(endpoints.token, [
            "grant_type": "authorization_code", "code": code, "redirect_uri": request.redirectURI,
            "client_id": settings.clientID, "code_verifier": request.verifier,
        ], nonce: request.nonce, fallbackRefresh: nil)
    }

    public func refresh(refreshToken: String, endpoints: OIDCEndpoints) async throws -> OIDCTokens {
        guard !refreshToken.isEmpty else { throw OIDCError.noRefreshToken }
        return try await tokenCall(endpoints.token, [
            "grant_type": "refresh_token", "refresh_token": refreshToken, "client_id": settings.clientID,
        ], nonce: nil, fallbackRefresh: refreshToken)
    }

    private func tokenCall(_ url: URL, _ form: [String: String], nonce: String?, fallbackRefresh: String?) async throws -> OIDCTokens {
        var r = URLRequest(url: url); r.httpMethod = "POST"
        r.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        r.setValue("application/json", forHTTPHeaderField: "Accept")
        var allowed = CharacterSet.alphanumerics; allowed.insert(charactersIn: "-._~")
        r.httpBody = Data(form.sorted { $0.key < $1.key }.map {
            "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: allowed) ?? "")"
        }.joined(separator: "&").utf8)
        let (data, status): (Data, Int)
        do { (data, status) = try await transport.send(r) } catch { throw OIDCError.tokenExchangeFailed(error.localizedDescription) }
        guard let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw OIDCError.tokenExchangeFailed("HTTP \(status)")
        }
        if status != 200 || o["error"] != nil {
            // Only the error code/description: never echo the response body, which could carry tokens.
            throw OIDCError.tokenExchangeFailed((o["error_description"] as? String) ?? (o["error"] as? String) ?? "HTTP \(status)")
        }
        let idToken = o["id_token"] as? String
        if let nonce, let idToken {
            guard Self.claim(idToken, "nonce") as? String == nonce else { throw OIDCError.nonceMismatch }
        }
        let access = o["access_token"] as? String
        guard let bearer = settings.useAccessToken ? access : (idToken ?? nil), !bearer.isEmpty else { throw OIDCError.noToken }
        var exp: Date?
        if let s = o["expires_in"] as? Double { exp = now().addingTimeInterval(s) }
        else if let n = o["expires_in"] as? Int { exp = now().addingTimeInterval(Double(n)) }
        if !settings.useAccessToken, let e = Self.claim(bearer, "exp") as? Double { exp = Date(timeIntervalSince1970: e) }
        return OIDCTokens(bearer: bearer, refreshToken: (o["refresh_token"] as? String) ?? fallbackRefresh, expiresAt: exp)
    }

    /// Reads a claim from a JWT payload WITHOUT verifying the signature (the controller does that;
    /// the app only uses this for the nonce sanity check and expiry hint).
    public static func claim(_ jwt: String, _ name: String) -> Any? {
        let parts = jwt.split(separator: ".")
        guard parts.count >= 2 else { return nil }
        var b = String(parts[1]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b.count % 4 != 0 { b += "=" }
        guard let d = Data(base64Encoded: b), let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { return nil }
        return o[name]
    }

    /// True when the token is within `leeway` of expiring (unknown expiry counts as fresh).
    public static func needsRefresh(_ t: OIDCTokens, now: Date = Date(), leeway: TimeInterval = 60) -> Bool {
        guard let e = t.expiresAt else { return false }
        return e.timeIntervalSince(now) <= leeway
    }
}
