// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class MemSecrets: SecretStore, @unchecked Sendable {
    var d: [String: String] = [:]
    func set(_ s: String, account: String) throws { d[account] = s }
    func get(account: String) -> String? { d[account] }
    func delete(account: String) { d[account] = nil }
}

final class ProfileStoreTests: XCTestCase {
    func make() -> (ProfileStore, MemSecrets, UserDefaults) {
        let ud = UserDefaults(suiteName: "netra.test.\(UUID().uuidString)")!
        let m = MemSecrets()
        return (ProfileStore(defaults: ud, secrets: m), m, ud)
    }

    func testMigrationKeepsURLAndMovesToken() {
        let (s, m, ud) = make()
        ud.set("https://netra.example.com:8443/", forKey: ProfileStore.legacyURLKey)
        m.d["https://netra.example.com:8443/"] = "tok"
        let p = s.migrateLegacyIfNeeded()
        XCTAssertEqual(p.urlString, "https://netra.example.com:8443")
        XCTAssertEqual(s.token(for: p), "tok")
        XCTAssertNil(m.d["https://netra.example.com:8443/"])
        XCTAssertEqual(s.migrateLegacyIfNeeded().id, p.id)   // idempotent
        XCTAssertEqual(s.load().count, 1)
    }

    func testMigrationFreshInstallUsesDefault() {
        let (s, _, _) = make()
        XCTAssertEqual(s.migrateLegacyIfNeeded().urlString, "http://127.0.0.1:8080")
    }

    func testValidation() throws {
        let (s, _, _) = make()
        XCTAssertThrowsError(try s.upsert(ServerProfile(name: " ", urlString: "http://a")))
        XCTAssertThrowsError(try s.upsert(ServerProfile(name: "a", urlString: "ftp://a")))
        XCTAssertThrowsError(try s.upsert(ServerProfile(name: "a", urlString: "nonsense")))
        XCTAssertThrowsError(try s.upsert(ServerProfile(name: "a", urlString: "http://a",
            oidc: OIDCSettings(issuer: "http://idp", clientID: "c"))))
        XCTAssertThrowsError(try s.upsert(ServerProfile(name: "a", urlString: "http://a",
            oidc: OIDCSettings(issuer: "https://idp", clientID: " "))))
    }

    func testUniqueness() throws {
        let (s, _, _) = make()
        try s.upsert(ServerProfile(name: "Prod", urlString: "https://n.example.com"))
        XCTAssertThrowsError(try s.upsert(ServerProfile(name: "prod", urlString: "https://other")))
        XCTAssertThrowsError(try s.upsert(ServerProfile(name: "Two", urlString: "https://N.example.com/")))
        XCTAssertNoThrow(try s.upsert(ServerProfile(name: "Two", urlString: "https://n.example.com:8443")))
    }

    func testTokensAreIsolatedAndRemoved() throws {
        let (s, m, _) = make()
        let a = try s.upsert(ServerProfile(name: "A", urlString: "http://a"))
        let b = try s.upsert(ServerProfile(name: "B", urlString: "http://b"))
        try s.setToken("ta", for: a)
        XCTAssertNil(s.token(for: b))
        s.activeID = a.id
        s.remove(id: a.id)
        XCTAssertNil(m.d[a.tokenAccount])
        XCTAssertEqual(s.active()?.id, b.id)
    }

    func testChangingServerDropsToken() throws {
        let (s, _, _) = make()
        var a = try s.upsert(ServerProfile(name: "A", urlString: "http://a"))
        try s.setToken("ta", for: a)
        a.urlString = "http://evil"
        let a2 = try s.upsert(a)
        XCTAssertNil(s.token(for: a2))
    }

    func testNoSecretsInJSON() throws {
        let (s, _, ud) = make()
        let a = try s.upsert(ServerProfile(name: "A", urlString: "http://a", oidc: OIDCSettings(issuer: "https://i", clientID: "c")))
        try s.setToken("SECRET", for: a)
        let json = String(decoding: ud.data(forKey: ProfileStore.profilesKey)!, as: UTF8.self)
        XCTAssertFalse(json.contains("SECRET"))
    }
}
