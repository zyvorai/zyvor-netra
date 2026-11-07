// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation
import Security
import CryptoKit

/// Trust-on-first-use pins, one per `host:port`, stored in the Keychain via `KeychainStore`.
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
public struct PinStore: Sendable {
    public let keychain: KeychainStore
    public init(keychain: KeychainStore = KeychainStore(service: "dev.zyvor.netra.pins")) {
        self.keychain = keychain
    }

    public static func key(host: String, port: Int) -> String { "pin:\(host.lowercased()):\(port)" }

    static func hostPort(_ url: URL) -> (String, Int)? {
        guard let h = url.host else { return nil }
        return (h, url.port ?? (url.scheme == "http" ? 80 : 443))
    }

    public func pin(host: String, port: Int) -> String? {
        keychain.get(account: Self.key(host: host, port: port))
    }
    public func pin(for url: URL) -> String? {
        Self.hostPort(url).flatMap { pin(host: $0.0, port: $0.1) }
    }
    public func setPin(_ fingerprint: String, host: String, port: Int) throws {
        try keychain.set(CertificateFingerprint.normalize(fingerprint), account: Self.key(host: host, port: port))
    }
    public func setPin(_ fingerprint: String, for url: URL) throws {
        guard let hp = Self.hostPort(url) else { throw PinStoreError.invalidURL }
        try setPin(fingerprint, host: hp.0, port: hp.1)
    }
    public func removePin(host: String, port: Int) {
        keychain.delete(account: Self.key(host: host, port: port))
    }

    /// Throws `PinMismatchError` when a pin exists for the URL and differs from the probed certificate.
    public func verify(probe: CertificateProbeResult, for url: URL) throws {
        guard let hp = Self.hostPort(url), let pinned = pin(host: hp.0, port: hp.1) else { return }
        if pinned != probe.fingerprint {
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
