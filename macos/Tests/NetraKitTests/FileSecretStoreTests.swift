// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class FileSecretStoreTests: XCTestCase {
    func testRoundTripAndDelete() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("netra-sec-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let store = FileSecretStore(directory: dir)
        try store.set("tok-abc", account: "profile-1")
        XCTAssertEqual(store.get(account: "profile-1"), "tok-abc")
        XCTAssertNil(store.get(account: "other"))

        // Reloading from the same directory still decrypts.
        let again = FileSecretStore(directory: dir)
        XCTAssertEqual(again.get(account: "profile-1"), "tok-abc")

        store.delete(account: "profile-1")
        XCTAssertNil(store.get(account: "profile-1"))
        XCTAssertNil(again.get(account: "profile-1"))
    }

    func testAccountsAreIsolated() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("netra-sec-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let store = FileSecretStore(directory: dir)
        try store.set("a", account: "one")
        try store.set("b", account: "two")
        XCTAssertEqual(store.get(account: "one"), "a")
        XCTAssertEqual(store.get(account: "two"), "b")
        store.delete(account: "one")
        XCTAssertNil(store.get(account: "one"))
        XCTAssertEqual(store.get(account: "two"), "b")
    }
}
