// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation
import Security

public struct CertificateProbeResult: Sendable, Equatable {
    public let host: String
    public let port: Int
    public let fingerprint: String      // SHA-256, "AB:CD:..."
    public let subject: String
    public let notBefore: Date?
    public let notAfter: Date?
    public let systemTrusted: Bool
}

public enum CertificateProbeError: Error, Sendable, Equatable, LocalizedError {
    case notHTTPS, unreachable(String), noCertificate
    public var errorDescription: String? {
        switch self {
        case .notHTTPS: "Certificate probe needs an https URL."
        case .unreachable(let m): "Could not reach server: \(m)"
        case .noCertificate: "Server presented no certificate."
        }
    }
}

/// Reads the presented certificate during the TLS handshake, then cancels the challenge,
/// so no HTTP request (and no credential) is ever sent.
public enum CertificateProbe {
    public static func probe(url: URL, timeout: TimeInterval = 8) async throws -> CertificateProbeResult {
        guard url.scheme == "https", let host = url.host else { throw CertificateProbeError.notHTTPS }
        let port = url.port ?? 443
        let box = Box()
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = timeout
        cfg.urlCredentialStorage = nil
        cfg.httpCookieStorage = nil
        let session = URLSession(configuration: cfg, delegate: ProbeDelegate(box: box), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var req = URLRequest(url: URL(string: "https://\(host.contains(":") ? "[\(host)]" : host):\(port)/")!)
        req.httpMethod = "HEAD"
        do { _ = try await session.data(for: req) } catch {
            if let r = box.result { return r }
            throw CertificateProbeError.unreachable((error as? URLError)?.localizedDescription ?? error.localizedDescription)
        }
        if let r = box.result { return r }
        throw CertificateProbeError.noCertificate
    }

    public static func describe(trust: SecTrust, host: String, port: Int) -> CertificateProbeResult? {
        guard let leaf = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first else { return nil }
        let (nb, na) = validity(of: leaf)
        return CertificateProbeResult(host: host, port: port, fingerprint: CertificateFingerprint.sha256(leaf),
                                      subject: (SecCertificateCopySubjectSummary(leaf) as String?) ?? "unknown",
                                      notBefore: nb, notAfter: na,
                                      systemTrusted: SecTrustEvaluateWithError(trust, nil))
    }

    static func validity(of cert: SecCertificate) -> (Date?, Date?) {
        let keys = [kSecOIDX509V1ValidityNotBefore, kSecOIDX509V1ValidityNotAfter] as CFArray
        guard let vals = SecCertificateCopyValues(cert, keys, nil) as? [CFString: Any] else { return (nil, nil) }
        func date(_ k: CFString) -> Date? {
            guard let d = vals[k] as? [CFString: Any], let n = d[kSecPropertyKeyValue] as? NSNumber else { return nil }
            return Date(timeIntervalSinceReferenceDate: n.doubleValue)
        }
        return (date(kSecOIDX509V1ValidityNotBefore), date(kSecOIDX509V1ValidityNotAfter))
    }

    final class Box: @unchecked Sendable {
        private let lock = NSLock()
        private var _r: CertificateProbeResult?
        var result: CertificateProbeResult? {
            get { lock.lock(); defer { lock.unlock() }; return _r }
            set { lock.lock(); _r = newValue; lock.unlock() }
        }
    }

    final class ProbeDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
        let box: Box
        init(box: Box) { self.box = box }
        func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            let ps = challenge.protectionSpace
            if ps.authenticationMethod == NSURLAuthenticationMethodServerTrust, let t = ps.serverTrust {
                box.result = CertificateProbe.describe(trust: t, host: ps.host, port: ps.port)
            }
            completionHandler(.cancelAuthenticationChallenge, nil)   // never proceeds to send a request
        }
    }
}
