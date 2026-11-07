// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

/// Answers every request from a closure and records them; nothing leaves the process.
final class StubURLProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var handler: ((URLRequest) -> (Int, String))?
    nonisolated(unsafe) static var seen: [URLRequest] = []
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        var req = request
        if req.httpBody == nil, let s = req.httpBodyStream {   // URLSession moves bodies into a stream
            s.open(); var d = Data(); var buf = [UInt8](repeating: 0, count: 4096)
            while s.hasBytesAvailable { let n = s.read(&buf, maxLength: buf.count); if n <= 0 { break }; d.append(buf, count: n) }
            req.httpBody = d
        }
        Self.seen.append(req)
        let (code, body) = Self.handler?(req) ?? (200, "{}")
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: req.url!, statusCode: code, httpVersion: nil, headerFields: nil)!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(body.utf8)); client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

@MainActor
final class ControlMutationsTests: XCTestCase {
    private func client() -> NetraClient {
        let cfg = URLSessionConfiguration.ephemeral; cfg.protocolClasses = [StubURLProtocol.self]
        StubURLProtocol.seen = []
        return NetraClient(profile: .init(baseURL: URL(string: "http://stub.invalid")!, token: "t"), session: URLSession(configuration: cfg))
    }

    func testPolicyApplyCarriesPlanTokenAndCriticalRisk() async {
        let manifest = Data(#"{"metadata":{"name":"p","namespace":"web"}}"#.utf8)
        StubURLProtocol.handler = { r in
            r.url!.path.hasSuffix("/plan")
                ? (200, #"{"plan":{"risk":"critical","warnings":["drops all egress"]},"dryRun":{"passed":true},"receipt":{"token":"tok-123"}}"#)
                : (200, "{}")
        }
        let c = client()
        let flow = MutationFlow(spec: ControlMutations.policyApplySpec(client: c, manifest: manifest, namespace: "web", name: "p"),
                                client: c, gate: .init(canMutate: true), log: ActivityLog())
        await flow.confirm()                                    // refused: no preview yet
        XCTAssertEqual(StubURLProtocol.seen.count, 0)
        await flow.runPreview()
        XCTAssertEqual(flow.effectiveRisk, .critical)
        flow.typedPhrase = "wrong"; await flow.confirm()
        XCTAssertEqual(StubURLProtocol.seen.count, 1)           // still only the plan call
        flow.typedPhrase = "apply web/p"; await flow.confirm()
        let apply = StubURLProtocol.seen.last!
        XCTAssertEqual(apply.url?.path, "/api/v1/policies/apply")
        XCTAssertEqual(apply.value(forHTTPHeaderField: "X-Netra-Plan-Token"), "tok-123")
        XCTAssertEqual(apply.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "critical")
        XCTAssertEqual(apply.httpBody, manifest)
    }

    func testLowRiskPlanNeedsNoPhraseAndNoRiskHeader() async {
        StubURLProtocol.handler = { _ in (200, #"{"plan":{"risk":"low"},"dryRun":{"passed":true},"receipt":{"token":"x"}}"#) }
        let c = client()
        let flow = MutationFlow(spec: ControlMutations.policyApplySpec(client: c, manifest: Data("{}".utf8), namespace: "a", name: "b"),
                                client: c, gate: .init(canMutate: true), log: ActivityLog())
        await flow.runPreview(); await flow.confirm()
        XCTAssertNil(StubURLProtocol.seen.last?.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"))
        XCTAssertEqual(StubURLProtocol.seen.last?.value(forHTTPHeaderField: "X-Netra-Plan-Token"), "x")
    }

    func testReadOnlyTokenSendsNothing() async {
        let c = client()
        for spec in [ControlMutations.modeSpec(client: c, enforce: true, leaseMinutes: 5),
                     ControlMutations.featureSpec(client: c, id: "x", name: "X", enable: true, restartsWorkload: nil)] {
            let flow = MutationFlow(spec: spec, client: c, gate: .init(canMutate: false), log: ActivityLog())
            await flow.runPreview(); await flow.confirm()
        }
        XCTAssertTrue(StubURLProtocol.seen.isEmpty)
    }

    func testEnforceModeRequestShape() async {
        StubURLProtocol.handler = { _ in (200, #"{"mode":"observe"}"#) }
        let c = client()
        let flow = MutationFlow(spec: ControlMutations.modeSpec(client: c, enforce: true, leaseMinutes: 99999),
                                client: c, gate: .init(canMutate: true), log: ActivityLog())
        await flow.runPreview()
        flow.typedPhrase = flow.spec.expectedPhrase; await flow.confirm()
        let r = StubURLProtocol.seen.last!
        XCTAssertEqual(r.httpMethod, "PUT")
        XCTAssertEqual(r.url?.query, "lease=1440m")            // clamped to the server's 24h maximum
        XCTAssertEqual(r.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "high")
    }

    func testFeatureToggleRequiresHighRiskHeader() async {
        StubURLProtocol.handler = { _ in (200, #"{"features":[{"id":"dns","enabled":false}]}"#) }
        let c = client()
        let flow = MutationFlow(spec: ControlMutations.featureSpec(client: c, id: "dns", name: "DNS", enable: true, restartsWorkload: "agent DaemonSet"),
                                client: c, gate: .init(canMutate: true), log: ActivityLog())
        await flow.runPreview()
        XCTAssertTrue(flow.previewSummary?.contains("currently disabled") == true)
        flow.typedPhrase = "enable dns"; await flow.confirm()
        let r = StubURLProtocol.seen.last!
        XCTAssertEqual(r.url?.path, "/api/v1/features/dns")
        XCTAssertEqual(r.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "high")
        XCTAssertEqual(String(decoding: r.httpBody ?? Data(), as: UTF8.self), #"{"enabled":true}"#)
    }

    func testCaptureValidationMirrorsServer() {
        var p = ControlMutations.CaptureParams(); p.node = "n1"
        XCTAssertNotNil(p.validationError)                      // no filter
        p.port = 443; XCTAssertNil(p.validationError)
        p.durationSeconds = 301; XCTAssertNotNil(p.validationError)
        p.durationSeconds = 60; p.backend = "pcap"; XCTAssertNotNil(p.validationError)
    }

    func testPolicyIdentityFromYAMLAndJSON() {
        XCTAssertEqual(ControlMutations.policyIdentity(Data("apiVersion: cilium.io/v2\nmetadata:\n  name: deny-x\n  namespace: prod\nspec: {}\n".utf8))?.name, "deny-x")
        XCTAssertEqual(ControlMutations.policyIdentity(Data("metadata:\n  name: only\n".utf8))?.namespace, "default")
        XCTAssertEqual(ControlMutations.policyIdentity(Data(#"{"metadata":{"name":"j","namespace":"n"}}"#.utf8))?.namespace, "n")
        XCTAssertNil(ControlMutations.policyIdentity(Data("kind: X".utf8)))
    }
}
