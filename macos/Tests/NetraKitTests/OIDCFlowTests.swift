// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class FakeTransport: OIDCTransport, @unchecked Sendable {
    var responses: [String: (Data, Int)] = [:]
    var seen: [URLRequest] = []
    func send(_ req: URLRequest) async throws -> (Data, Int) {
        seen.append(req)
        return responses[req.url!.path] ?? (Data(), 404)
    }
}

final class OIDCFlowTests: XCTestCase {
    let settings = OIDCSettings(issuer: "https://idp.example.com/realms/n", clientID: "netra-mac")
    func jwt(_ claims: [String: Any]) -> String {
        let p = try! JSONSerialization.data(withJSONObject: claims)
        return "e30." + OIDCFlow.b64url(p) + ".sig"
    }
    func discoveryDoc(issuer: String = "https://idp.example.com/realms/n") -> Data {
        try! JSONSerialization.data(withJSONObject: ["issuer": issuer,
            "authorization_endpoint": "https://idp.example.com/auth", "token_endpoint": "https://idp.example.com/token"])
    }

    func testPKCEChallengeRFCVector() {
        XCTAssertEqual(OIDCFlow.challenge(for: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
                       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }

    func testDiscoveryAndIssuerMismatch() async throws {
        let t = FakeTransport()
        t.responses["/realms/n/.well-known/openid-configuration"] = (discoveryDoc(), 200)
        let ep = try await OIDCFlow(settings: settings, transport: t).discover()
        XCTAssertEqual(ep.token.path, "/token")
        t.responses["/realms/n/.well-known/openid-configuration"] = (discoveryDoc(issuer: "https://evil"), 200)
        do { _ = try await OIDCFlow(settings: settings, transport: t).discover(); XCTFail() } catch {}
    }

    func testAuthURLAndCallbackChecks() throws {
        let f = OIDCFlow(settings: settings, transport: FakeTransport())
        let ep = OIDCEndpoints(authorization: URL(string: "https://idp.example.com/auth")!, token: URL(string: "https://idp.example.com/token")!)
        let r = f.makeAuthRequest(endpoints: ep, state: "S", nonce: "N", verifier: "V")
        let q = URLComponents(url: r.url, resolvingAgainstBaseURL: false)!.queryItems!
        XCTAssertEqual(q.first { $0.name == "code_challenge_method" }?.value, "S256")
        XCTAssertEqual(q.first { $0.name == "redirect_uri" }?.value, "netra://oidc/callback")
        XCTAssertEqual(try f.code(from: URL(string: "netra://oidc/callback?code=abc&state=S")!, request: r), "abc")
        XCTAssertThrowsError(try f.code(from: URL(string: "netra://oidc/callback?code=abc&state=X")!, request: r)) { XCTAssertEqual($0 as? OIDCError, .stateMismatch) }
        XCTAssertThrowsError(try f.code(from: URL(string: "netra://oidc/callback?state=S&error=access_denied")!, request: r))
        XCTAssertThrowsError(try f.code(from: URL(string: "netra://oidc/callback?state=S")!, request: r))
    }

    func testExchangeNonceAndRefresh() async throws {
        let t = FakeTransport()
        let id = jwt(["nonce": "N", "exp": 4_000_000_000.0])
        t.responses["/token"] = (try JSONSerialization.data(withJSONObject: ["id_token": id, "access_token": "acc", "refresh_token": "rt", "expires_in": 300]), 200)
        let f = OIDCFlow(settings: settings, transport: t)
        let ep = OIDCEndpoints(authorization: URL(string: "https://idp.example.com/auth")!, token: URL(string: "https://idp.example.com/token")!)
        let req = f.makeAuthRequest(endpoints: ep, state: "S", nonce: "N", verifier: "V")
        let tok = try await f.exchange(code: "c", request: req, endpoints: ep)
        XCTAssertEqual(tok.bearer, id); XCTAssertEqual(tok.refreshToken, "rt")
        let body = String(decoding: t.seen[0].httpBody!, as: UTF8.self)
        XCTAssertTrue(body.contains("code_verifier=V")); XCTAssertFalse(body.contains("client_secret"))
        let bad = f.makeAuthRequest(endpoints: ep, state: "S", nonce: "OTHER", verifier: "V")
        do { _ = try await f.exchange(code: "c", request: bad, endpoints: ep); XCTFail() } catch { XCTAssertEqual(error as? OIDCError, .nonceMismatch) }

        // refresh keeps old refresh token when the IdP omits a new one; access-token mode
        t.responses["/token"] = (try JSONSerialization.data(withJSONObject: ["access_token": "acc2", "expires_in": 10]), 200)
        let a = OIDCFlow(settings: OIDCSettings(issuer: settings.issuer, clientID: "c", useAccessToken: true), transport: t, now: { Date(timeIntervalSince1970: 0) })
        let r2 = try await a.refresh(refreshToken: "rt", endpoints: ep)
        XCTAssertEqual(r2.bearer, "acc2"); XCTAssertEqual(r2.refreshToken, "rt")
        XCTAssertTrue(OIDCFlow.needsRefresh(r2, now: Date(timeIntervalSince1970: 5)))
        XCTAssertFalse(OIDCFlow.needsRefresh(r2, now: Date(timeIntervalSince1970: -100)))
    }

    func testErrorDoesNotEchoBody() async throws {
        let t = FakeTransport()
        t.responses["/token"] = (try JSONSerialization.data(withJSONObject: ["error": "invalid_grant", "access_token": "LEAK"]), 400)
        let ep = OIDCEndpoints(authorization: URL(string: "https://idp.example.com/auth")!, token: URL(string: "https://idp.example.com/token")!)
        do { _ = try await OIDCFlow(settings: settings, transport: t).refresh(refreshToken: "r", endpoints: ep); XCTFail() }
        catch { XCTAssertFalse(error.localizedDescription.contains("LEAK")) }
    }
}
