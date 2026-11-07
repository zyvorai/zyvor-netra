// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

@MainActor
final class PolicyToolsTests: XCTestCase {
    private func client() -> NetraClient {
        let cfg = URLSessionConfiguration.ephemeral; cfg.protocolClasses = [StubURLProtocol.self]
        StubURLProtocol.seen = []
        return NetraClient(profile: .init(baseURL: URL(string: "http://stub.invalid")!, token: "t"), session: URLSession(configuration: cfg))
    }
    private func spec(_ id: String, _ v: FormValues, _ c: NetraClient) throws -> MutationSpec {
        try XCTUnwrap(PolicyTools.find(id)).build(c, v).get()
    }
    private func flow(_ s: MutationSpec, _ c: NetraClient, canMutate: Bool = true) -> MutationFlow {
        MutationFlow(spec: s, client: c, gate: .init(canMutate: canMutate), log: ActivityLog())
    }
    private func body(_ r: URLRequest?) -> [String: Any] {
        (r?.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]) ?? [:]
    }
    private let archive = #"{"schemaVersion":1,"exportedAt":"2026-01-01T00:00:00Z","revisions":[{"id":1,"namespace":"a","name":"p","action":"apply","manifest":{"kind":"CiliumNetworkPolicy"}},{"id":2,"namespace":"a","name":"q","action":"apply","manifest":{"kind":"CiliumNetworkPolicy"}}]}"#

    func testCatalogIsWellFormed() {
        XCTAssertEqual(Set(PolicyTools.actions.map(\.id)).count, PolicyTools.actions.count)
        for a in PolicyTools.actions { XCTAssertEqual(Set(a.fields.map(\.key)).count, a.fields.count) }
    }

    // MARK: read-only

    func testBuildRequestBody() throws {
        let r = try PolicyTools.buildRequest(client(), ["name": "web", "namespace": "prod", "selector": "app=web, tier=fe",
            "kind": "cidr", "to": "10.0.0.0/8, 1.2.3.4", "port": "443", "protocol": "tcp", "includeDns": "true"]).get()
        XCTAssertEqual(r.httpMethod, "POST"); XCTAssertEqual(r.url?.path, "/api/v1/policies/build")
        let b = body(r)
        XCTAssertEqual(Set(b.keys), ["name", "namespace", "selector", "kind", "to", "port", "protocol", "includeDns"])
        XCTAssertEqual(b["selector"] as? [String: String], ["app": "web", "tier": "fe"])
        XCTAssertEqual(b["protocol"] as? String, "TCP"); XCTAssertEqual(b["port"] as? Int, 443)
        XCTAssertNil(r.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"))
    }

    func testBuildValidationMirrorsServer() {
        let c = client()
        func err(_ v: FormValues) -> String? { if case .failure(let e) = PolicyTools.buildRequest(c, v) { e.message } else { nil } }
        XCTAssertNotNil(err(["name": "", "selector": "a=b", "to": "x"]))
        XCTAssertNotNil(err(["name": "n", "selector": "", "to": "x"]))          // namespace-wide refused
        XCTAssertNotNil(err(["name": "n", "selector": "a=b", "to": ""]))
        XCTAssertNotNil(err(["name": "n", "selector": "a=b", "kind": "cidr", "to": "nope"]))
        XCTAssertNotNil(err(["name": "n", "selector": "a=b", "to": "x", "port": "70000"]))
        XCTAssertNotNil(err(["name": "n", "selector": "a=b", "to": "x", "protocol": "ICMP"]))
    }

    func testSimulateSendsRawManifestAndRejectsYAML() throws {
        let c = client()
        let m = #"{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"x","namespace":"d"}}"#
        let r = try PolicyTools.simulateRequest(c, manifest: m).get()
        XCTAssertEqual(r.httpMethod, "POST"); XCTAssertEqual(r.url?.path, "/api/v1/policies/simulate")
        XCTAssertEqual(r.httpBody, Data(m.utf8))
        if case .success = PolicyTools.simulateRequest(c, manifest: "kind: X\n") { XCTFail("YAML must be rejected") }
        if case .success = PolicyTools.simulateRequest(c, manifest: " ") { XCTFail("empty must be rejected") }
    }

    func testDenyHistoryBodyOnlyKnownFields() throws {
        let r = try PolicyTools.denyHistoryRequest(client(), ["kind": "port", "value": "22", "protocol": "tcp", "since": "2h",
            "namespace": "d", "pod": "p", "direction": "", "limit": "500"]).get()
        XCTAssertEqual(r.url?.path, "/api/v1/ebpf/deny/preview-history")
        XCTAssertEqual(Set(body(r).keys), ["kind", "value", "protocol", "since", "namespace", "pod", "limit"])
        if case .success = PolicyTools.denyHistoryRequest(client(), ["kind": "process", "value": "x"]) { XCTFail("process unsupported") }
        if case .success = PolicyTools.denyHistoryRequest(client(), ["kind": "ip", "value": "999.1.1.1"]) { XCTFail("bad ip") }
    }

    func testWatchlistMatchBodyAndLimit() throws {
        let c = client()
        let r = try PolicyTools.watchlistMatchRequest(c, feed: "1.2.3.4\nevil.example\n", limit: 50).get()
        XCTAssertEqual(r.url?.path, "/api/v1/watchlist/match"); XCTAssertEqual(r.url?.query, "limit=50")
        XCTAssertEqual(String(decoding: r.httpBody ?? Data(), as: UTF8.self), "1.2.3.4\nevil.example")
        if case .success = PolicyTools.watchlistMatchRequest(c, feed: "  ") { XCTFail("empty feed") }
    }

    func testReadOnlyToolsDoNotNeedTheMutationGate() async throws {
        StubURLProtocol.handler = { _ in (200, #"{"kind":"CiliumNetworkPolicy","metadata":{"name":"w","namespace":"d"}}"#) }
        let c = client()
        let r = try PolicyTools.buildRequest(c, ["name": "w", "selector": "a=b", "to": "x"]).get()
        let data = try await c.send(r)     // plain send: no MutationFlow, so a read-only token can use it
        XCTAssertEqual(PolicyToolsData.builtManifest(data)?.name, "w")
    }

    func testExportIsAPlainGet() async throws {
        StubURLProtocol.handler = { _ in (200, #"{"schemaVersion":1,"revisions":[]}"#) }
        let c = client()
        let f = try await PolicyTools.exportHistory(c)
        XCTAssertEqual(StubURLProtocol.seen.last?.httpMethod, "GET")
        XCTAssertEqual(StubURLProtocol.seen.last?.url?.path, "/api/v1/policies/history/export")
        XCTAssertEqual(PolicyToolsData.exportFilename(f), "netra-policy-history.json")
        XCTAssertEqual(PolicyToolsData.inspectArchive(String(decoding: f.data, as: UTF8.self)), .success(.init(revisions: 0, policies: 0, exportedAt: nil)))
    }

    // MARK: archive inspection

    func testArchiveInspection() {
        XCTAssertEqual(PolicyToolsData.inspectArchive(archive), .success(.init(revisions: 2, policies: 2, exportedAt: "2026-01-01T00:00:00Z")))
        func bad(_ s: String) -> Bool { if case .failure = PolicyToolsData.inspectArchive(s) { true } else { false } }
        XCTAssertTrue(bad(""))
        XCTAssertTrue(bad(#"{"schemaVersion":2,"revisions":[]}"#))
        XCTAssertTrue(bad(#"{"schemaVersion":1,"revisions":[],"extra":1}"#))
        XCTAssertTrue(bad(#"{"schemaVersion":1,"revisions":[{"namespace":"a","name":"p","action":"x","manifest":{},"oops":1}]}"#))
        XCTAssertTrue(bad(#"{"schemaVersion":1,"revisions":[{"namespace":"a","name":"","action":"x","manifest":{}}]}"#))
    }

    // MARK: history import

    func testImportMergeIsMediumNoPhraseNoReplaceHeader() async throws {
        StubURLProtocol.handler = { _ in (200, #"{"items":[{"id":1}]}"#) }
        let c = client()
        let s = try spec("policy-history-import", ["archive": archive, "mode": "merge"], c)
        XCTAssertEqual(s.risk, .medium)
        let f = flow(s, c)
        await f.confirm()                                   // no preview: blocked
        XCTAssertEqual(StubURLProtocol.seen.count, 0)
        await f.runPreview()
        XCTAssertEqual(StubURLProtocol.seen.last?.httpMethod, "GET")
        XCTAssertTrue(f.previewSummary?.contains("Merge") == true)
        await f.confirm()
        let post = StubURLProtocol.seen.last!
        XCTAssertEqual(post.httpMethod, "POST"); XCTAssertEqual(post.url?.path, "/api/v1/policies/history/import")
        XCTAssertEqual(post.url?.query, "mode=merge")
        XCTAssertNil(post.value(forHTTPHeaderField: "X-Netra-Confirm-History-Replace"))
        XCTAssertEqual(post.httpBody, Data(archive.utf8))
    }

    func testImportReplaceIsHighNeedsPhraseAndSendsBothHeaders() async throws {
        StubURLProtocol.handler = { _ in (200, #"{"items":[]}"#) }
        let c = client()
        let s = try spec("policy-history-import", ["archive": archive, "mode": "replace"], c)
        XCTAssertEqual(s.risk, .high)
        let f = flow(s, c); await f.runPreview()
        f.typedPhrase = "nope"; await f.confirm()
        XCTAssertEqual(StubURLProtocol.seen.count, 1)       // only the preview was sent
        f.typedPhrase = "replace history"; await f.confirm()
        let post = StubURLProtocol.seen.last!
        XCTAssertEqual(post.url?.query, "mode=replace")
        XCTAssertEqual(post.value(forHTTPHeaderField: "X-Netra-Confirm-History-Replace"), "replace")
        XCTAssertEqual(post.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "high")
    }

    func testImportRejectsBadArchiveBeforeAnyRequest() {
        let c = client()
        if case .success = PolicyTools.find("policy-history-import")!.build(c, ["archive": "{}", "mode": "merge"]) { XCTFail() }
        XCTAssertEqual(StubURLProtocol.seen.count, 0)
    }

    func testServerRefusalSurfaces() async throws {
        StubURLProtocol.handler = { r in
            r.httpMethod == "GET" ? (200, #"{"items":[]}"#) : (403, #"{"error":"admin role required"}"#)
        }
        let c = client()
        let f = flow(try spec("policy-history-import", ["archive": archive, "mode": "merge"], c), c)
        await f.runPreview(); await f.confirm()
        guard case .failed(let m) = f.phase else { return XCTFail("expected failure") }
        XCTAssertTrue(m.contains("403") && m.contains("admin role required"), m)
    }

    // MARK: AI destinations deny

    func testAIDenyIsHighLeasedWithTypedPhraseAndHeader() async throws {
        StubURLProtocol.handler = { _ in (200, #"{"result":{"hits":[{"host":"api.openai.com"},{"host":"api.openai.com"},{"host":"claude.ai"}]}}"#) }
        let c = client()
        let s = try spec("ai-destinations-deny", [:], c)
        XCTAssertEqual(s.risk, .high); XCTAssertTrue(s.leaseBound)
        let f = flow(s, c); await f.runPreview()
        XCTAssertEqual(StubURLProtocol.seen.last?.httpMethod, "GET")
        XCTAssertEqual(StubURLProtocol.seen.last?.url?.path, "/api/v1/ebpf/ai-destinations")
        XCTAssertTrue(f.previewSummary?.contains("2 host(s)") == true)
        await f.confirm(); XCTAssertEqual(StubURLProtocol.seen.count, 1)      // phrase missing: nothing sent
        f.typedPhrase = "deny ai destinations"; await f.confirm()
        let post = StubURLProtocol.seen.last!
        XCTAssertEqual(post.httpMethod, "POST"); XCTAssertEqual(post.url?.path, "/api/v1/ebpf/ai-destinations/deny")
        XCTAssertNil(post.httpBody)
        XCTAssertEqual(post.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "high")
    }

    func testAIDenyServerRefusalWithoutLease() async throws {
        StubURLProtocol.handler = { r in
            r.httpMethod == "GET" ? (200, #"{"result":{"hits":[]}}"#) : (409, #"{"error":"AI destination deny requires mode=enforce with an active lease"}"#)
        }
        let c = client()
        let f = flow(try spec("ai-destinations-deny", [:], c), c)
        await f.runPreview(); f.typedPhrase = "deny ai destinations"; await f.confirm()
        guard case .failed(let m) = f.phase else { return XCTFail() }
        XCTAssertTrue(m.contains("409") && m.contains("lease"))
    }

    // MARK: baselines

    func testBaselineCaptureAndClearHeaders() async throws {
        StubURLProtocol.handler = { _ in (200, #"{"captured":true,"baseline":{"capturedAt":"2026-01-01T00:00:00Z"}}"#) }
        let c = client()
        let cap = flow(try spec("baseline-capture", [:], c), c)
        XCTAssertEqual(cap.spec.risk, .medium)
        await cap.runPreview(); await cap.confirm()
        XCTAssertEqual(StubURLProtocol.seen.last?.httpMethod, "POST"); XCTAssertEqual(StubURLProtocol.seen.last?.url?.path, "/api/v1/insights/baseline")
        XCTAssertNil(StubURLProtocol.seen.last?.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"))

        let clr = flow(try spec("baseline-clear", [:], c), c)
        await clr.runPreview(); await clr.confirm()
        let before = StubURLProtocol.seen.count
        XCTAssertEqual(StubURLProtocol.seen.last?.httpMethod, "GET")        // blocked without phrase
        clr.typedPhrase = "clear baseline"; await clr.confirm()
        XCTAssertEqual(StubURLProtocol.seen.count, before + 1)
        let del = StubURLProtocol.seen.last!
        XCTAssertEqual(del.httpMethod, "DELETE"); XCTAssertEqual(del.url?.path, "/api/v1/insights/baseline")
        XCTAssertEqual(del.value(forHTTPHeaderField: "X-Netra-Confirm-Baseline-Clear"), "clear")
        XCTAssertEqual(del.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "high")
    }

    func testRateBaselineWindowAndClear() async throws {
        StubURLProtocol.handler = { _ in (200, #"{"captured":false,"baseline":null}"#) }
        let c = client()
        if case .success = PolicyTools.find("rate-baseline-capture")!.build(c, ["window": "5s"]) { XCTFail("below 30s") }
        if case .success = PolicyTools.find("rate-baseline-capture")!.build(c, ["window": "3h"]) { XCTFail("above 2h") }
        let cap = flow(try spec("rate-baseline-capture", ["window": "1h30m"], c), c)
        await cap.runPreview(); await cap.confirm()
        XCTAssertEqual(StubURLProtocol.seen.last?.url?.path, "/api/v1/insights/rate-baseline")
        XCTAssertEqual(StubURLProtocol.seen.last?.url?.query, "window=1h30m")
        let clr = flow(try spec("rate-baseline-clear", [:], c), c)
        await clr.runPreview(); clr.typedPhrase = "clear rate baseline"; await clr.confirm()
        XCTAssertEqual(StubURLProtocol.seen.last?.httpMethod, "DELETE")
        XCTAssertEqual(StubURLProtocol.seen.last?.url?.path, "/api/v1/insights/rate-baseline")
        XCTAssertEqual(StubURLProtocol.seen.last?.value(forHTTPHeaderField: "X-Netra-Confirm-Rate-Baseline-Clear"), "clear")
    }

    func testReadOnlyTokenBlocksEveryGuardedAction() async throws {
        StubURLProtocol.handler = { _ in (200, "{}") }
        let c = client()
        let values: [String: FormValues] = ["policy-history-import": ["archive": archive, "mode": "merge"], "rate-baseline-capture": ["window": "5m"]]
        for a in PolicyTools.actions {
            let f = flow(try spec(a.id, values[a.id] ?? [:], c), c, canMutate: false)
            await f.runPreview(); f.typedPhrase = f.spec.expectedPhrase; await f.confirm()
            XCTAssertFalse(f.canConfirm, a.id)
        }
        XCTAssertEqual(StubURLProtocol.seen.count, 0)
    }

    func testSummaries() {
        let dh = try! JSONDecoder().decode(JSONValue.self, from: Data(#"{"since":"1h","result":{"flowsSeen":10,"denials":[{"flowCount":3},{"flowCount":2}],"breakage":[{}]}}"#.utf8))
        XCTAssertTrue(PolicyToolsData.denyHistorySummary(dh).contains("matched 5 in 2 group(s); 1 workload"))
        let wl = try! JSONDecoder().decode(JSONValue.self, from: Data(#"{"preview":{"count":2,"skipped":[{}]},"match":{"count":1,"checked":2,"hits":[{}]}}"#.utf8))
        XCTAssertTrue(PolicyToolsData.watchlistSummary(wl).contains("1 observed hit(s)"))
        XCTAssertEqual(PolicyToolsData.rateWindowSeconds("90s"), 90)
        XCTAssertNil(PolicyToolsData.rateWindowSeconds("abc"))
    }
}
