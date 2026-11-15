// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation
import CryptoKit

/// Token storage under Application Support. Avoids the login-keychain password prompt
/// that blocked Connect when Keychain ACLs disagreed with the app identity.
/// Values are AES-GCM encrypted with a device-local key file next to the secrets
/// (never UserDefaults, never logs).
public struct FileSecretStore: SecretStore, @unchecked Sendable {
    private let dir: URL
    private let lock = NSLock()

    public init(directory: URL? = nil) {
        if let directory {
            self.dir = directory
        } else {
            let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
                ?? URL(fileURLWithPath: NSTemporaryDirectory())
            self.dir = base.appendingPathComponent("Netra/secrets", isDirectory: true)
        }
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    private func path(_ account: String) -> URL {
        let safe = account.data(using: .utf8).map { SHA256.hash(data: $0).map { String(format: "%02x", $0) }.joined() } ?? "x"
        return dir.appendingPathComponent(safe + ".box")
    }

    private func keyURL() -> URL { dir.appendingPathComponent("master.key") }

    private func masterKey() throws -> SymmetricKey {
        let url = keyURL()
        if let raw = try? Data(contentsOf: url), raw.count == 32 {
            return SymmetricKey(data: raw)
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        let st = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard st == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(st)) }
        let data = Data(bytes)
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        return SymmetricKey(data: data)
    }

    public func set(_ secret: String, account: String) throws {
        lock.lock(); defer { lock.unlock() }
        let box = try AES.GCM.seal(Data(secret.utf8), using: masterKey())
        guard let combined = box.combined else { throw URLError(.cannotWriteToFile) }
        try combined.write(to: path(account), options: [.atomic, .completeFileProtection])
    }

    public func get(account: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        guard let data = try? Data(contentsOf: path(account)),
              let box = try? AES.GCM.SealedBox(combined: data),
              let key = try? masterKey(),
              let plain = try? AES.GCM.open(box, using: key) else { return nil }
        return String(decoding: plain, as: UTF8.self)
    }

    public func delete(account: String) {
        lock.lock(); defer { lock.unlock() }
        try? FileManager.default.removeItem(at: path(account))
    }
}
