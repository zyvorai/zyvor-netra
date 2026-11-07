// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Testing
import Foundation
import Network
import Security
@testable import NetraKit

private let certB64 = "MIIC9jCCAd6gAwIBAgIJAN1rBPD82kkFMA0GCSqGSIb3DQEBCwUAMDAxGTAXBgNVBAMMEG5ldHJhLXRlc3QubG9jYWwxEzARBgNVBAoMClp5dm9yIFRlc3QwHhcNMjYxMTA3MDU1MDMzWhcNMzYxMTA0MDU1MDMzWjAwMRkwFwYDVQQDDBBuZXRyYS10ZXN0LmxvY2FsMRMwEQYDVQQKDApaeXZvciBUZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxvRJhuDjWhTGCtrL4h0R0tYFs0L5zcfqfL+5CQiA24nnbewUoRIF87A+mvcYMnH8sPZf/NXep+oQ7xHOgm0QUn0ZKKGx0v66m1VZIsNbemwIKPVuYL9L5NRyRApHLaNYkS/LDRZi2zgTvGKf2DS/YUt64kFszNDc7d+DIyhuHfyMbA/mPZsj/hr1D4UFJEOQy3I0V0i5MBSGrF4L5R/4q2+6iU/tGrGq0XpT31Chl/9++8aXWhCZbtUajTMQ91I5W+I1MaOzMLOO/LUnx0tYIc1CRdoWNpWLMD91gOS0o8E+2ld+vinNTOLLHTLj2hEhvTau6rYfwCZuPDsmqNe5CQIDAQABoxMwETAPBgNVHREECDAGhwR/AAABMA0GCSqGSIb3DQEBCwUAA4IBAQAiQ/hqm501qi6JD4e+ovRiVDqAsIVyOLHnUQ7etTOM6cUfc/OjXrnlPFJfHqHKp9LLcVis4IOaG7+CXCsZKq8KHFI2nsIEV67ej6R6J6DvyXeXzN8mNF0GwA8NZdoKOlNnpJgk2pAUWZdCgHOvKvNl4w5WJyClT0kc5f7oGuGemhDogcjWxwtVFqV8ZyagOp1pSD2VGIGXKQEDPMVaRARHaH9XLNnuemwGCfebWm2rmdZcNI40AM/DTZEnI6VvqmR7DXpywuUdVRKqKZqfKyGHhPVPWCeFqcwnpvD9CnWcQ/CL+IYH4upME5I/MjEC9pqLaSqLFT9QosaP7Zbb5B9+"
private let p12B64 = "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"
private let expectedFP = "4C:2B:84:C7:FA:55:68:97:D8:59:12:2B:06:5D:6D:86:FA:E2:B3:0F:07:72:88:10:C0:A9:0B:BA:D1:A3:00:F9"

private func testStore() -> PinStore { PinStore(keychain: KeychainStore(service: "dev.zyvor.netra.pins.test.\(UUID().uuidString)")) }

@Test func fingerprintOfFixture() throws {
    let der = Data(base64Encoded: certB64)!
    #expect(CertificateFingerprint.sha256(der: der) == expectedFP)
    let cert = try #require(SecCertificateCreateWithData(nil, der as CFData))
    #expect(CertificateFingerprint.sha256(cert) == expectedFP)
    #expect(CertificateFingerprint.normalize("4c 2b:84c7") == "4C:2B:84:C7")
    let (nb, na) = CertificateProbe.validity(of: cert)
    #expect(nb != nil && na != nil)
}

@Test func decisionLogic() {
    #expect(PinningDelegate.decide(systemTrusted: true, fingerprint: "A", pinned: "B") == .accept)
    #expect(PinningDelegate.decide(systemTrusted: false, fingerprint: "A", pinned: nil) == .reject)
    #expect(PinningDelegate.decide(systemTrusted: false, fingerprint: "A", pinned: "A") == .accept)
    #expect(PinningDelegate.decide(systemTrusted: false, fingerprint: "A", pinned: "B") == .mismatch(pinned: "B"))
}

@Test func pinStoreRoundTripAndVerify() throws {
    let s = testStore()
    defer { s.removePin(host: "127.0.0.1", port: 9443) }
    let url = URL(string: "https://127.0.0.1:9443")!
    #expect(s.pin(for: url) == nil)
    try s.setPin(expectedFP.lowercased(), for: url)
    #expect(s.pin(for: url) == expectedFP)
    #expect(s.pin(host: "127.0.0.1", port: 9444) == nil)
    let ok = CertificateProbeResult(host: "127.0.0.1", port: 9443, fingerprint: expectedFP, subject: "x", notBefore: nil, notAfter: nil, systemTrusted: false)
    try s.verify(probe: ok, for: url)
    let bad = CertificateProbeResult(host: "127.0.0.1", port: 9443, fingerprint: "00", subject: "x", notBefore: nil, notAfter: nil, systemTrusted: false)
    #expect(throws: PinMismatchError.self) { try s.verify(probe: bad, for: url) }
}

/// Local TLS server on 127.0.0.1 presenting the fixture cert.
private func startServer() throws -> (NWListener, UInt16)? {
    var items: CFArray?
    let st = SecPKCS12Import(Data(base64Encoded: p12B64)! as CFData, [kSecImportExportPassphrase as String: "test"] as CFDictionary, &items)
    guard st == errSecSuccess, let dict = (items as? [[String: Any]])?.first,
          let idRef = dict[kSecImportItemIdentity as String],
          let identity = sec_identity_create(idRef as! SecIdentity) else { return nil }
    let tls = NWProtocolTLS.Options()
    sec_protocol_options_set_local_identity(tls.securityProtocolOptions, identity)
    let l = try NWListener(using: NWParameters(tls: tls), on: .any)
    l.newConnectionHandler = { c in
        c.start(queue: .global())
        c.receive(minimumIncompleteLength: 1, maximumLength: 4096) { _, _, _, _ in
            c.send(content: Data("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".utf8), completion: .contentProcessed { _ in c.cancel() })
        }
    }
    let sem = DispatchSemaphore(value: 0)
    l.stateUpdateHandler = { if case .ready = $0 { sem.signal() } }
    l.start(queue: DispatchQueue(label: "srv"))
    guard sem.wait(timeout: .now() + 5) == .success, let p = l.port?.rawValue else { return nil }
    return (l, p)
}

@Test func liveProbeAndPinnedClient() async throws {
    guard let (l, port) = try startServer() else { Issue.record("local TLS server unavailable"); return }
    defer { l.cancel() }
    let url = URL(string: "https://127.0.0.1:\(port)")!
    let probe = try await CertificateProbe.probe(url: url)
    #expect(probe.fingerprint == expectedFP)
    #expect(!probe.systemTrusted)
    #expect(probe.subject.contains("netra-test"))

    let store = testStore()
    defer { store.removePin(host: "127.0.0.1", port: Int(port)) }
    let (c0, _) = NetraClient.pinnedWithDelegate(profile: .init(baseURL: url), pinStore: store)
    await #expect(throws: Error.self) { _ = try await c0.send(c0.request("GET", "x")) }
    try store.setPin(probe.fingerprint, for: url)
    let c1 = NetraClient.pinned(profile: .init(baseURL: url), pinStore: store)
    _ = try await c1.send(c1.request("GET", "x"))
    try store.setPin(String(repeating: "AB:", count: 31) + "AB", for: url)
    let (c2, d2) = NetraClient.pinnedWithDelegate(profile: .init(baseURL: url), pinStore: store)
    await #expect(throws: Error.self) { _ = try await c2.send(c2.request("GET", "x")) }
    #expect(d2.lastMismatch?.presented == expectedFP)
}
