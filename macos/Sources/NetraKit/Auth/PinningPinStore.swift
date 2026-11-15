// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation
import Security
import CryptoKit

/// Trust-on-first-use pins, one per `host:port`.
///
/// Pins are leaf SHA-256 fingerprints (not secrets), so they live in `UserDefaults` — never the
/// Keychain. Storing them in the Keychain caused macOS to block the UI on a login-password prompt
/// whenever an item was created outside the app (or ACL mismatched).
///
/// Integration steps (for the lead):
/// 1. On connect to an https profile, call `let probe = try await CertificateProbe.probe(url:)`.
///    If `probe.systemTrusted` is true, connect normally. Otherwise, if `pinStore.pin(for: url)` is nil,
///    show `TrustPrompt(probe:onTrust:onCancel:)`; onTrust calls `pinStore.setPin(probe.fingerprint, for: url)`.
/// 2. Build the client with `NetraClient.pinned(profile:pinStore:)` (keep the returned delegate-backed
///    client; the token is only sent after the pin check passes).
/// 3. Use `NetraClient.pinnedWithDelegate` to keep the delegate: `delegate.lastMismatch` (PinMismatchError)
///    is set when the pin changed. Alternatively re-probe and call `pinStore.verify(probe:for:)`.
///    Show a hard failure and require an explicit `removePin` before re-prompting. Never auto-repin.
public struct PinStore: @unchecked Sendable {
    public let defaults: UserDefaults
    public let prefix: String

    public init(defaults: UserDefaults = .standard, prefix: String = "netra.pin.") {
        self.defaults = defaults
        self.prefix = prefix
    }

    /// Test helper: keeps the old `keychain:` call site working by isolating pins in a suite named after the service.
    public init(keychain: KeychainStore) {
        let suite = UserDefaults(suiteName: "pins.\(keychain.service)") ?? .standard
        self.defaults = suite
        self.prefix = "netra.pin."
    }

    public static func key(host: String, port: Int) -> String { "\(host.lowercased()):\(port)" }

    static func hostPort(_ url: URL) -> (String, Int)? {
        guard let h = url.host else { return nil }
        return (h, url.port ?? (url.scheme == "http" ? 80 : 443))
    }

    private func defaultsKey(host: String, port: Int) -> String { prefix + Self.key(host: host, port: port) }

    public func pin(host: String, port: Int) -> String? {
        defaults.string(forKey: defaultsKey(host: host, port: port))
    }
    public func pin(for url: URL) -> String? {
        Self.hostPort(url).flatMap { pin(host: $0.0, port: $0.1) }
    }
    public func setPin(_ fingerprint: String, host: String, port: Int) throws {
        defaults.set(CertificateFingerprint.normalize(fingerprint), forKey: defaultsKey(host: host, port: port))
    }
    public func setPin(_ fingerprint: String, for url: URL) throws {
        guard let hp = Self.hostPort(url) else { throw PinStoreError.invalidURL }
        try setPin(fingerprint, host: hp.0, port: hp.1)
    }
    public func removePin(host: String, port: Int) {
        defaults.removeObject(forKey: defaultsKey(host: host, port: port))
    }

    /// Throws `PinMismatchError` when a pin exists for the URL and differs from the probed certificate.
    public func verify(probe: CertificateProbeResult, for url: URL) throws {
        guard let hp = Self.hostPort(url), let pinned = pin(host: hp.0, port: hp.1) else { return }
        if CertificateFingerprint.normalize(pinned) != CertificateFingerprint.normalize(probe.fingerprint) {
            throw PinMismatchError(host: hp.0, port: hp.1, pinned: pinned, presented: probe.fingerprint)
        }
    }
}

public enum PinStoreError: Error, Sendable { case invalidURL }

/// Hard failure: the server presents a different certificate than the one pinned. Distinct from NetraError.
public struct PinMismatchError: Error, Sendable, Equatable, LocalizedError {
    public let host: String
    public let port: Int
    public let pinned: String
    public let presented: String
    public var errorDescription: String? {
        "Certificate for \(host):\(port) changed. Pinned SHA-256 \(pinned), server presented \(presented). Connection refused."
    }
}

public enum CertificateFingerprint {
    /// Uppercase, colon-separated SHA-256 of DER bytes.
    public static func sha256(der: Data) -> String {
        SHA256.hash(data: der).map { String(format: "%02X", $0) }.joined(separator: ":")
    }
    public static func sha256(_ cert: SecCertificate) -> String { sha256(der: SecCertificateCopyData(cert) as Data) }

    /// Accepts "ab:cd", "ABCD", "ab cd" and returns canonical form.
    public static func normalize(_ s: String) -> String {
        let hex = s.uppercased().filter { $0.isHexDigit }
        var out: [String] = []
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            out.append(String(hex[i..<j])); i = j
        }
        return out.joined(separator: ":")
    }
}
