// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation
import Security

/// Accepts a server only if system trust passes, or the leaf SHA-256 equals the pin for host:port.
/// A pinned host whose certificate differs (and is not system-trusted) is a hard failure.
public final class PinningDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    public enum Decision: Equatable, Sendable { case accept, reject, mismatch(pinned: String) }

    private let pinStore: PinStore
    private let lock = NSLock()
    private var _lastMismatch: PinMismatchError?

    public init(pinStore: PinStore) { self.pinStore = pinStore }

    /// Set when the last connection was refused because the pin changed.
    public var lastMismatch: PinMismatchError? { lock.lock(); defer { lock.unlock() }; return _lastMismatch }

    /// Pure decision logic.
    public static func decide(systemTrusted: Bool, fingerprint: String, pinned: String?) -> Decision {
        if systemTrusted { return .accept }
        guard let pinned else { return .reject }
        return pinned == fingerprint ? .accept : .mismatch(pinned: pinned)
    }

    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                           completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let ps = challenge.protectionSpace
        guard ps.authenticationMethod == NSURLAuthenticationMethodServerTrust, let trust = ps.serverTrust,
              let leaf = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first else {
            completionHandler(.performDefaultHandling, nil); return
        }
        let systemOK = SecTrustEvaluateWithError(trust, nil)
        let fp = CertificateFingerprint.sha256(leaf)
        switch Self.decide(systemTrusted: systemOK, fingerprint: fp, pinned: pinStore.pin(host: ps.host, port: ps.port)) {
        case .accept:
            completionHandler(.useCredential, URLCredential(trust: trust))
        case .reject:
            completionHandler(.cancelAuthenticationChallenge, nil)
        case .mismatch(let pinned):
            lock.lock(); _lastMismatch = PinMismatchError(host: ps.host, port: ps.port, pinned: pinned, presented: fp); lock.unlock()
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

public extension NetraClient {
    /// Client whose session trusts system-valid certificates or the pinned leaf fingerprint only.
    /// Retain `delegate` if you want `lastMismatch`; otherwise use `PinStore.verify(probe:for:)`.
    static func pinned(profile: ConnectionProfile, pinStore: PinStore) -> NetraClient {
        pinnedWithDelegate(profile: profile, pinStore: pinStore).client
    }

    static func pinnedWithDelegate(profile: ConnectionProfile, pinStore: PinStore) -> (client: NetraClient, delegate: PinningDelegate) {
        let d = PinningDelegate(pinStore: pinStore)
        let cfg = URLSessionConfiguration.ephemeral
        let s = URLSession(configuration: cfg, delegate: d, delegateQueue: nil)
        return (NetraClient(profile: profile, session: s), d)
    }
}
