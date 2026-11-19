// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation
import Observation
import Security

/// Where the licence key is kept between launches: the Keychain, or (when the Keychain refuses) a file only this user can read.
public protocol LicenceStorage: Sendable {
    func load() -> String?
    func save(_ key: String) throws
    func remove()
}

struct LicenceStoreError: LocalizedError { let message: String; var errorDescription: String? { message } }

/// Data-protection Keychain, like the API token store. A Developer ID build without a provisioning profile typically gets
/// errSecMissingEntitlement here; `LicenceVault` then uses the file.
public struct KeychainLicenceStorage: LicenceStorage {
    public var service = "dev.zyvor.netra.licence"
    public var account = "licence-key"
    public init(service: String = "dev.zyvor.netra.licence", account: String = "licence-key") { self.service = service; self.account = account }
    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account,
         kSecUseDataProtectionKeychain as String: true]
    }
    public func load() -> String? {
        var q = query; q[kSecReturnData as String] = true; q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }
    public func save(_ key: String) throws {
        let data = Data(key.utf8)
        if SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary) == errSecSuccess { return }
        var add = query; add[kSecValueData as String] = data; add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        let s = SecItemAdd(add as CFDictionary, nil)
        guard s == errSecSuccess else { throw LicenceStoreError(message: "The Keychain refused the licence key (error \(s)).") }
    }
    public func remove() { SecItemDelete(query as CFDictionary) }
}

/// Fallback: `licence.key` under Application Support/Netra, mode 0600.
public struct FileLicenceStorage: LicenceStorage {
    public var url: URL
    public init(url: URL? = nil) {
        if let url { self.url = url } else {
            let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first ?? URL(fileURLWithPath: NSTemporaryDirectory())
            self.url = base.appendingPathComponent("Netra/licence.key")
        }
    }
    public func load() -> String? { try? String(contentsOf: url, encoding: .utf8) }
    public func save(_ key: String) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? fm.removeItem(at: url)
        guard fm.createFile(atPath: url.path, contents: Data(key.utf8), attributes: [.posixPermissions: 0o600]) else { throw LicenceStoreError(message: "Could not write \(url.path).") }
    }
    public func remove() { try? FileManager.default.removeItem(at: url) }
}

/// Keychain first; the file only when the Keychain fails to store the key. Load checks both.
public struct LicenceVault: LicenceStorage {
    public var primary: LicenceStorage
    public var fallback: LicenceStorage
    public init(primary: LicenceStorage = KeychainLicenceStorage(), fallback: LicenceStorage = FileLicenceStorage()) { self.primary = primary; self.fallback = fallback }
    public func load() -> String? { primary.load() ?? fallback.load() }
    public func save(_ key: String) throws {
        do { try primary.save(key); fallback.remove() } catch { try fallback.save(key) }
    }
    public func remove() { primary.remove(); fallback.remove() }
}

/// What the UI shows for this Mac's licence. Soft enforcement only: no Netra feature is disabled in any state.
public enum LicenceState: Equatable, Sendable {
    case unlicensed
    case trial(daysLeft: Int, claims: LicenceKey.Claims)
    case pro(daysLeft: Int, claims: LicenceKey.Claims)
    case expired(on: Date, claims: LicenceKey.Claims)
    case unreadable(String)   // a stored key that no longer verifies (altered, another product)

    public static let buyURL = URL(string: "https://zyvor.dev/buy")!
    public static let trialURL = URL(string: "mailto:sales@zyvor.dev?subject=Netra%2030-day%20trial%20key")!
    public static let warnDays = 14

    /// Mirrors LICENSE: free for non-production use; production use needs a paid licence. Netra keeps working in every state.
    public static let freeNote = "Free for evaluation, proof-of-concept and other non-production use; production use needs a licence"

    public static func evaluate(_ key: String?, now: Date = Date(), publicKey: String = LicenceKey.publicKey) -> LicenceState {
        guard let key, !key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return .unlicensed }
        switch LicenceKey.verify(key, publicKey: publicKey, now: now) {
        case .valid(let ed, _, _, _, let left, _):
            guard let c = LicenceKey.claims(key, publicKey: publicKey) else { return .unreadable("The stored licence key could not be read.") }
            return ed == "trial" ? .trial(daysLeft: left, claims: c) : .pro(daysLeft: left, claims: c)
        case .invalid(let reason):
            if reason.hasPrefix("expired"), let c = LicenceKey.claims(key, publicKey: publicKey) { return .expired(on: c.expires, claims: c) }
            return .unreadable(reason)
        }
    }

    public static func dateText(_ d: Date) -> String {
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.timeZone = TimeZone(identifier: "UTC"); f.dateFormat = "d MMM yyyy"
        return f.string(from: d)
    }
    private static func days(_ n: Int) -> String { n == 1 ? "1 day" : "\(n) days" }

    /// The one-line status. Wording is part of the contract (see LicenceTests).
    public var statusText: String {
        switch self {
        case .unlicensed: return "No licence key: \(Self.freeNote)"
        case .trial(let n, _): return "Trial: \(Self.days(n)) left"
        case .pro(let n, _): return "Licensed, \(Self.days(n)) left"
        case .expired(let d, _): return "Licence expired on \(Self.dateText(d))"
        case .unreadable(let why): return "Licence key not valid: \(why)"
        }
    }
    /// Warn for an expired key, a Pro key with 14 days or fewer left, or a stored key that stopped verifying.
    public var needsAttention: Bool {
        switch self {
        case .pro(let n, _): return n <= Self.warnDays
        case .expired, .unreadable: return true
        default: return false
        }
    }
    public var showsBuyLink: Bool { if case .pro(let n, _) = self { return n <= Self.warnDays }; return true }
    public var showsTrialNote: Bool { if case .unlicensed = self { return true }; return false }
    public var claims: LicenceKey.Claims? {
        switch self { case .trial(_, let c), .pro(_, let c), .expired(_, let c): return c; default: return nil }
    }
    public var editionName: String? { claims.map { $0.edition == "trial" ? "Trial" : "Pro" } }
}

/// Holds the activated key and publishes the state the status line and the Licence window read.
@MainActor @Observable public final class LicenceManager {
    public static let shared = LicenceManager()
    public private(set) var state: LicenceState = .unlicensed
    @ObservationIgnored private let storage: LicenceStorage
    @ObservationIgnored private let publicKey: String
    @ObservationIgnored private let clock: @Sendable () -> Date

    public init(storage: LicenceStorage = LicenceVault(), publicKey: String = LicenceKey.publicKey, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.storage = storage; self.publicKey = publicKey; self.clock = clock
        refresh()
    }

    public func refresh() { state = LicenceState.evaluate(storage.load(), now: clock(), publicKey: publicKey) }

    /// Verifies a pasted key offline and, when valid today, saves it. Returns an error message, or nil on success.
    @discardableResult public func activate(_ pasted: String) -> String? {
        let key = pasted.trimmingCharacters(in: .whitespacesAndNewlines)
        if key.isEmpty { return "Paste a licence key first." }
        switch LicenceKey.verify(key, publicKey: publicKey, now: clock()) {
        case .valid:
            do { try storage.save(key) } catch { return error.localizedDescription }
            refresh(); return nil
        case .invalid(let reason):
            if reason.hasPrefix("expired"), let c = LicenceKey.claims(key, publicKey: publicKey) { return "This key expired on \(LicenceState.dateText(c.expires))." }
            return "This key was not accepted: \(reason)."
        }
    }

    public func remove() { storage.remove(); refresh() }
}
