// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

@MainActor
final class OpsActionTests: XCTestCase {
    private func client() -> NetraClient {
        let cfg = URLSessionConfiguration.ephemeral; cfg.protocolClasses = [StubURLProtocol.self]
        StubURLProtocol.seen = []
        return NetraClient(profile: .init(baseURL: URL(string: "http://stub.invalid")!, token: "t"), session: URLSession(configuration: cfg))
    }

    func testResyncSendsPostWithManifestAndConfirmHeader() async {
        StubURLProtocol.handler = { r in
            r.url!.path.hasSuffix("/plan")
                ? (200, #"{"plan":{"risk":"high","specChanged":true,"warnings":["narrows egress"]},"dryRun":{"passed":true},"receipt":{"token":"t"}}"#)
                : (200, "{}")
        }
        let c = client()
        let manifest = Data(#"{"metadata":{"name":"p","namespace":"web"}}"#.utf8)
        let flow = MutationFlow(spec: OpsAction.gitopsResyncSpec(client: c, manifest: manifest, namespace: "web", name: "p"),
                                client: c, gate: .init(canMutate: true), log: ActivityLog())
        await flow.runPreview()
        XCTAssertTrue(flow.previewSummary?.contains("Plan risk: high") == true)
        let plan = StubURLProtocol.seen.last!
        XCTAssertEqual(plan.httpMethod, "POST")
        XCTAssertEqual(plan.url?.path, "/api/v1/policies/plan")           // read-only plan of the exact body; its risk drives the header
        XCTAssertEqual(plan.httpBody, manifest)
        flow.typedPhrase = "nope"; await flow.confirm()
        XCTAssertEqual(StubURLProtocol.seen.count, 1)
        flow.typedPhrase = "resync web/p"; await flow.confirm()
        let r = StubURLProtocol.seen.last!
        XCTAssertEqual(r.httpMethod, "POST")
        XCTAssertEqual(r.url?.path, "/api/v1/policies/gitops/resync")
        XCTAssertEqual(r.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "high")
        XCTAssertNil(r.value(forHTTPHeaderField: "X-Netra-Plan-Token"))   // resync issues its own receipt server-side
        XCTAssertEqual(r.httpBody, manifest)
    }

    /// The server compares the header with the plan's own risk, so a critical plan needs "critical", not "high".
    func testResyncOfACriticalPlanConfirmsCritical() async {
        StubURLProtocol.handler = { r in
            r.url!.path.hasSuffix("/plan") ? (200, #"{"plan":{"risk":"critical"},"dryRun":{"passed":true}}"#) : (200, "{}")
        }
        let c = client()
        let flow = MutationFlow(spec: OpsAction.gitopsResyncSpec(client: c, manifest: Data("{}".utf8), namespace: "a", name: "b"),
                                client: c, gate: .init(canMutate: true), log: ActivityLog())
        await flow.runPreview()
        XCTAssertEqual(flow.effectiveRisk, .critical)
        flow.typedPhrase = "resync a/b"; await flow.confirm()
        XCTAssertEqual(StubURLProtocol.seen.last?.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "critical")
    }

    func testResyncServerRefusalIsSurfaced() async {
        StubURLProtocol.handler = { r in r.url!.path.hasSuffix("/plan") ? (200, "{}") : (409, #"{"error":"Cilium is not enabled"}"#) }
        let c = client()
        let flow = MutationFlow(spec: OpsAction.gitopsResyncSpec(client: c, manifest: Data("{}".utf8), namespace: "a", name: "b"),
                                client: c, gate: .init(canMutate: true), log: ActivityLog())
        await flow.runPreview(); flow.typedPhrase = "resync a/b"; await flow.confirm()
        guard case .failed(let m) = flow.phase else { return XCTFail("expected failure") }
        XCTAssertTrue(m.contains("409") && m.contains("Cilium is not enabled"))
    }

    func testReadOnlyTokenSendsNothing() async {
        let c = client()
        let flow = MutationFlow(spec: OpsAction.gitopsResyncSpec(client: c, manifest: Data("{}".utf8), namespace: "a", name: "b"),
                                client: c, gate: .init(canMutate: false), log: ActivityLog())
        await flow.runPreview(); flow.typedPhrase = "resync a/b"; await flow.confirm()
        XCTAssertTrue(StubURLProtocol.seen.isEmpty)
    }

    func testFeatureToggleIsPostWithHighConfirm() async {
        StubURLProtocol.handler = { _ in (200, #"{"features":[{"id":"tlsfp","enabled":false}]}"#) }
        let c = client()
        let flow = MutationFlow(spec: ControlMutations.featureSpec(client: c, id: "tlsfp", name: "TLS", enable: true, restartsWorkload: "agent DaemonSet"),
                                client: c, gate: .init(canMutate: true), log: ActivityLog())
        await flow.runPreview(); flow.typedPhrase = "enable tlsfp"; await flow.confirm()
        let r = StubURLProtocol.seen.last!
        XCTAssertEqual(r.httpMethod, "POST"); XCTAssertEqual(r.url?.path, "/api/v1/features/tlsfp")
        XCTAssertEqual(r.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "high")
        XCTAssertEqual(String(decoding: r.httpBody ?? Data(), as: UTF8.self), #"{"enabled":true}"#)
    }

    func testCatalogFormValidation() {
        let c = client()
        let a = OpsAction.all[0]
        if case .success = a.build(c, ["manifest": ""]) { XCTFail("empty must fail") }
        if case .success = a.build(c, ["manifest": "{}"]) { XCTFail("no name must fail") }
        guard case .success(let s) = a.build(c, ["manifest": #"{"metadata":{"name":"x"}}"#]) else { return XCTFail() }
        XCTAssertEqual(s.expectedPhrase, "resync default/x")
    }

    func testDownloadReturnsBodyAndSanitisedFilename() async throws {
        StubURLProtocol.handler = { _ in (200, "PCAPBYTES") }
        let c = client()
        let f = try await c.download("api/v1/capture/artifacts/abc")
        XCTAssertEqual(String(decoding: f.data, as: UTF8.self), "PCAPBYTES")
        XCTAssertEqual(StubURLProtocol.seen.last?.httpMethod, "GET")
        XCTAssertEqual(NetraClient.dispositionFilename(#"attachment; filename="../../etc/x.pcap""#), "x.pcap")
        StubURLProtocol.handler = { _ in (404, #"{"error":"artifact not found"}"#) }
        do { _ = try await c.download("api/v1/capture/artifacts/zz"); XCTFail() }
        catch NetraError.http(let s, let m) { XCTAssertEqual(s, 404); XCTAssertEqual(m, "artifact not found") }
    }
}
