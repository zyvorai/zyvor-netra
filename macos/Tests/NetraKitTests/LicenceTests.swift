// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
import Foundation
@testable import NetraKit

/// Vectors are signed with a throwaway keypair (private half discarded), product "netra" except `wrongProductKey`.
final class LicenceTests: XCTestCase {
    static let pub = "CDTEOG3MJcHHG-w-ni7t09KNDHpdaPUWk3TRsctm_Uk"
    static let trialKey = "ZYV1.eyJ2IjoxLCJwcm9kdWN0IjoibmV0cmEiLCJlZGl0aW9uIjoidHJpYWwiLCJpZCI6IjM2ZWRlMDNiZWJkMzdmOWEiLCJsaWNlbnNlZSI6IlRlc3QgTGljZW5zZWUiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJtYWNzIjoxLCJpc3N1ZWQiOjE4MDAwMDAwMDAsImV4cGlyZXMiOjE4MDI1OTIwMDB9.Awodg8URbDwEe-1saIXovy4mGWs2pG68JHug3tnNVQP6ZvMsjTRbpXDelsxZsXQ4PqLlatJWwc0tw0L0WFTcCQ"
    static let proKey = "ZYV1.eyJ2IjoxLCJwcm9kdWN0IjoibmV0cmEiLCJlZGl0aW9uIjoicHJvIiwiaWQiOiJhMGQ0MWE2MTc2MDdiOWVkIiwibGljZW5zZWUiOiJUZXN0IExpY2Vuc2VlIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwibWFjcyI6MywiaXNzdWVkIjoxODAwMDAwMDAwLCJleHBpcmVzIjoxODMxNTM2MDAwfQ.5-9sXI7Ad33B9IPUB4d0ivK3LYO0Mt4ULj4CaNfqaDzWQckhZS-h5ar6bmZUTJmbzVbjF4ErQqN79B9L1uLzBA"
    static let expiredKey = "ZYV1.eyJ2IjoxLCJwcm9kdWN0IjoibmV0cmEiLCJlZGl0aW9uIjoidHJpYWwiLCJpZCI6IjM5ZWFhZjIzYTI4MTAxMDAiLCJsaWNlbnNlZSI6IlRlc3QgTGljZW5zZWUiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJtYWNzIjoxLCJpc3N1ZWQiOjE3OTY1NDQwMDAsImV4cGlyZXMiOjE3OTkxMzYwMDB9.oT7aw5psf8F5BRZ0Vl2TpUMsI48Al1mwlVCbwKSP2i7_iP2ersVnj8JPkZ9Ugg5lHCIrHa0FkFLR3_A1C4EvAg"
    static let wrongProductKey = "ZYV1.eyJ2IjoxLCJwcm9kdWN0IjoidmVsb3JhIiwiZWRpdGlvbiI6InRyaWFsIiwiaWQiOiI5Y2RmNDIzZjM3MDY5OGJjIiwibGljZW5zZWUiOiJUZXN0IExpY2Vuc2VlIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwibWFjcyI6MSwiaXNzdWVkIjoxODAwMDAwMDAwLCJleHBpcmVzIjoxODAyNTkyMDAwfQ.dVTokI83oXtURfpqhm2RHx0aTgmFdDQa5EIxZl7asWN76qIlh2Nax9sDbZ9Vn22_JpQCJKeIYcDM-Kxvxcr3Bg"
    static let issued = 1800000000.0

    func at(_ days: Double) -> Date { Date(timeIntervalSince1970: Self.issued + days * 86400) }
    func verify(_ k: String, _ d: Double) -> LicenceStatus { LicenceKey.verify(k, publicKey: Self.pub, now: at(d)) }
    static func b64(_ d: Data) -> String { d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    var tampered: String {
        let parts = Self.trialKey.split(separator: ".").map(String.init)
        let body = Data(String(decoding: LicenceKey.decode(base64url: parts[1])!, as: UTF8.self).replacingOccurrences(of: "\"macs\":1", with: "\"macs\":9").utf8)
        return "ZYV1.\(Self.b64(body)).\(parts[2])"
    }
    func tempFile() -> FileLicenceStorage {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("netra-lic-\(UUID().uuidString)", isDirectory: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return FileLicenceStorage(url: dir.appendingPathComponent("licence.key"))
    }

    func testEmbeddedKeyIsThe32BytePublicKey() {
        XCTAssertEqual(LicenceKey.decode(base64url: LicenceKey.publicKey)?.count, 32)
        XCTAssertEqual(LicenceKey.product, "netra")
    }

    func testValidTrialAndPro() {
        guard case let .valid(ed, who, email, macs, left, _) = verify(Self.trialKey, 10) else { return XCTFail("trial") }
        XCTAssertEqual(ed, "trial"); XCTAssertEqual(who, "Test Licensee"); XCTAssertEqual(email, "test@example.com"); XCTAssertEqual(macs, 1); XCTAssertEqual(left, 20)
        guard case let .valid(ed2, _, _, macs2, left2, _) = verify(Self.proKey, 100) else { return XCTFail("pro") }
        XCTAssertEqual(ed2, "pro"); XCTAssertEqual(macs2, 3); XCTAssertEqual(left2, 265)
        XCTAssertTrue(verify(Self.trialKey, 29.5).isActive)
        XCTAssertTrue(verify(" \n" + Self.trialKey + "\n", 1).isActive)
    }

    func testExpired() {
        XCTAssertFalse(verify(Self.trialKey, 31).isActive)
        guard case let .invalid(r) = verify(Self.expiredKey, 0) else { return XCTFail() }
        XCTAssertTrue(r.hasPrefix("expired"))
    }

    func testTamperedAndWrongKey() {
        guard case let .invalid(r) = verify(tampered, 1) else { return XCTFail() }
        XCTAssertTrue(r.hasPrefix("signature"))
        let parts = Self.trialKey.split(separator: ".").map(String.init)
        var sig = Array(LicenceKey.decode(base64url: parts[2])!); sig[0] ^= 1
        XCTAssertFalse(verify("ZYV1.\(parts[1]).\(Self.b64(Data(sig)))", 1).isActive)
        // The embedded production key must not accept the throwaway vectors.
        XCTAssertFalse(LicenceKey.verify(Self.trialKey, now: at(1)).isActive)
    }

    func testWrongProduct() {
        guard case let .invalid(r) = verify(Self.wrongProductKey, 0) else { return XCTFail() }
        XCTAssertTrue(r.hasPrefix("wrong product"))
    }

    func testBadFormats() {
        let parts = Self.trialKey.split(separator: ".").map(String.init)
        for bad in ["", "garbage", "ZYV2.a.b", "ZYV1.only", "ZYV1..", "ZYV1.a b.c", "ZYV1.!!!.???", "ZYV1.\(parts[1]).\(parts[2]).extra"] {
            guard case .invalid = verify(bad, 1) else { return XCTFail("accepted \(bad)") }
        }
    }

    @MainActor func testStatusTextPerState() {
        let file = tempFile()
        func manager(_ d: Double) -> LicenceManager { let t = at(d); return LicenceManager(storage: file, publicKey: Self.pub, clock: { t }) }
        var m = manager(10)
        XCTAssertEqual(m.state, .unlicensed)
        XCTAssertTrue(m.state.statusText.hasPrefix("No licence key: Free for evaluation, proof-of-concept"))
        XCTAssertTrue(m.state.showsBuyLink && m.state.showsTrialNote && !m.state.needsAttention)
        XCTAssertEqual(LicenceState.buyURL.absoluteString, "https://zyvor.dev/buy")
        XCTAssertTrue(LicenceState.trialURL.absoluteString.hasPrefix("mailto:sales@zyvor.dev"))

        XCTAssertNil(m.activate(Self.trialKey))
        XCTAssertEqual(m.state.statusText, "Trial: 20 days left")
        XCTAssertEqual(m.state.editionName, "Trial"); XCTAssertEqual(m.state.claims?.licensee, "Test Licensee")
        XCTAssertEqual(manager(29.5).state.statusText, "Trial: 1 day left")
        XCTAssertEqual(manager(31).state.statusText, "Licence expired on 14 Feb 2027")
        XCTAssertTrue(manager(31).state.needsAttention && manager(31).state.showsBuyLink)

        m.remove()
        XCTAssertNil(m.activate("  \n" + Self.proKey + "\n"))
        XCTAssertEqual(manager(100).state.statusText, "Licensed, 265 days left")
        XCTAssertFalse(manager(100).state.needsAttention)
        XCTAssertFalse(manager(100).state.showsBuyLink)
        XCTAssertEqual(manager(351).state.statusText, "Licensed, 14 days left")
        XCTAssertTrue(manager(351).state.needsAttention && manager(351).state.showsBuyLink)
        XCTAssertFalse(manager(350).state.needsAttention)
        XCTAssertEqual(manager(366).state.statusText, "Licence expired on 15 Jan 2028")
        m = manager(1)
    }

    @MainActor func testPersistenceRemoveAndRejections() {
        let file = tempFile()
        func manager(_ d: Double) -> LicenceManager { let t = at(d); return LicenceManager(storage: file, publicKey: Self.pub, clock: { t }) }
        let m = manager(1)
        XCTAssertNil(m.activate(Self.trialKey))
        XCTAssertEqual(file.load(), Self.trialKey)
        XCTAssertEqual((try? FileManager.default.attributesOfItem(atPath: file.url.path)[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertEqual(manager(12).state.statusText, "Trial: 18 days left", "persists across a relaunch")

        XCTAssertEqual(m.activate(Self.expiredKey), "This key expired on 5 Jan 2027.")
        XCTAssertTrue(m.activate(tampered)?.contains("signature") == true)
        XCTAssertTrue(m.activate(Self.wrongProductKey)?.contains("wrong product") == true)
        XCTAssertNotNil(m.activate("not a key")); XCTAssertNotNil(m.activate("   "))
        XCTAssertEqual(file.load(), Self.trialKey, "a refused key leaves the saved key alone")

        try? file.save(tampered)
        if case .unreadable = manager(1).state { XCTAssertTrue(manager(1).state.needsAttention) } else { XCTFail("altered stored key") }

        m.remove()
        XCTAssertEqual(m.state, .unlicensed); XCTAssertNil(file.load()); XCTAssertEqual(manager(1).state, .unlicensed)
    }

    func testVaultFallsBackToFile() {
        struct Refusing: LicenceStorage { func load() -> String? { nil }; func save(_ key: String) throws { throw LicenceStoreError(message: "no") }; func remove() {} }
        let file = tempFile()
        let vault = LicenceVault(primary: Refusing(), fallback: file)
        try? vault.save("ZYV1.x.y")
        XCTAssertEqual(vault.load(), "ZYV1.x.y"); XCTAssertEqual(file.load(), "ZYV1.x.y")
    }

    func testKeychainRoundTripOrFallbackAvailable() {
        let kc = KeychainLicenceStorage(service: "dev.zyvor.netra.licence.test.\(UUID().uuidString)")
        defer { kc.remove() }
        do { try kc.save("ZYV1.a.b"); XCTAssertEqual(kc.load(), "ZYV1.a.b"); kc.remove(); XCTAssertNil(kc.load()) }
        catch { /* unsigned test runner has no keychain entitlement: LicenceVault falls back to the 0600 file (covered above) */ }
    }
}
