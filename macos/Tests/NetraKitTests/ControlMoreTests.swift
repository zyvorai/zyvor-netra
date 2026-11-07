// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

@MainActor
final class ControlMoreTests: XCTestCase {
    private func client() -> NetraClient {
        let cfg = URLSessionConfiguration.ephemeral; cfg.protocolClasses = [StubURLProtocol.self]
        StubURLProtocol.seen = []
        return NetraClient(profile: .init(baseURL: URL(string: "http://stub.invalid")!, token: "t"), session: URLSession(configuration: cfg))
    }
    private func spec(_ id: String, _ v: FormValues, _ c: NetraClient) throws -> MutationSpec {
        try XCTUnwrap(ControlAction.find(id)).build(c, v).get()
    }
    private func failure(_ id: String, _ v: FormValues) -> String? {
        if case .failure(let e) = ControlAction.find(id)!.build(client(), v) { return e.message } else { return nil }
    }
    private func flow(_ s: MutationSpec, _ c: NetraClient) -> MutationFlow {
        MutationFlow(spec: s, client: c, gate: .init(canMutate: true), log: ActivityLog())
    }
    private func body(_ r: URLRequest?) -> [String: Any] {
        (r?.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]) ?? [:]
    }

    func testCatalogIsWellFormed() {
        XCTAssertEqual(Set(ControlAction.all.map(\.id)).count, ControlAction.all.count)
        for a in ControlAction.all { XCTAssertEqual(Set(a.fields.map(\.key)).count, a.fields.count, a.id) }
    }

    func testCanonicalCIDR() {
        XCTAssertTrue(Form.isCanonicalCIDR("10.0.0.0/8")); XCTAssertTrue(Form.isCanonicalCIDR("10.1.2.3/32"))
        XCTAssertFalse(Form.isCanonicalCIDR("10.0.0.1/8")); XCTAssertFalse(Form.isCanonicalCIDR("10.0.0.0/33"))
        XCTAssertTrue(Form.isCanonicalCIDR("fd00::/8")); XCTAssertFalse(Form.isCanonicalCIDR("fd00::1/8"))
        XCTAssertFalse(Form.isCanonicalCIDR("nope"))
    }

    func testNodeIsolationEnforceIsLeasedHighAndWarnsAboutSSH() async throws {
        StubURLProtocol.handler = { _ in (200, #"{"items":[]}"#) }
        let c = client()
        let s = try spec("node-isolation-set", ["node": "n1", "mode": "enforce", "minutes": "10",
                                                "rules": "10.0.0.0/8 tcp 443\n192.168.0.0/16", "exempt": "none"], c)
        XCTAssertEqual(s.risk, .high); XCTAssertTrue(s.leaseBound)
        let f = flow(s, c); await f.runPreview()
        XCTAssertTrue(f.previewSummary?.contains("WARNING: SSH") == true)
        f.typedPhrase = "isolate n1"; await f.confirm()
        let put = StubURLProtocol.seen.last!
        XCTAssertEqual(put.httpMethod, "PUT"); XCTAssertEqual(put.url?.path, "/api/v1/ebpf/node-isolation/n1")
        XCTAssertEqual(put.url?.query, "lease=10m")
        let b = body(put)
        XCTAssertEqual(Set(b.keys), ["mode", "rules", "exemptLocalPorts"])
        XCTAssertEqual((b["exemptLocalPorts"] as? [Int]), [])
        XCTAssertEqual((b["rules"] as? [[String: Any]])?.first?["protocol"] as? String, "tcp")
    }

    func testNodeIsolationShadowIsLowAndNeedsNoLease() throws {
        let s = try spec("node-isolation-set", ["node": "n1", "mode": "shadow", "rules": "10.0.0.0/8"], client())
        XCTAssertEqual(s.risk, .low); XCTAssertFalse(s.leaseBound)
        XCTAssertNil(s.execute(false).url?.query)
        XCTAssertNil(body(s.execute(false))["exemptLocalPorts"])        // omitted: server keeps SSH exempt
    }

    func testNodeIsolationValidationMirrorsServer() {
        let ok: FormValues = ["node": "n1", "mode": "shadow", "rules": "10.0.0.0/8"]
        XCTAssertNotNil(failure("node-isolation-set", ok.merging(["rules": ""]) { $1 }))             // empty allow-list
        XCTAssertNotNil(failure("node-isolation-set", ok.merging(["rules": "10.0.0.1/8"]) { $1 }))   // host bits
        XCTAssertNotNil(failure("node-isolation-set", ok.merging(["rules": "10.0.0.0/8 icmp"]) { $1 }))
        XCTAssertNotNil(failure("node-isolation-set", ok.merging(["rules": "10.0.0.0/8 tcp 90-80"]) { $1 }))
        XCTAssertNotNil(failure("node-isolation-set", ok.merging(["mode": "enforce", "minutes": "90"]) { $1 }))
        XCTAssertNotNil(failure("node-isolation-set", ok.merging(["node": "a b"]) { $1 }))
    }

    func testShieldEnforceIsHighAndValidated() throws {
        let s = try spec("shield-set", ["mode": "enforce", "ipv4": "10.0.0.5", "synPps": "5000", "burst": "10"], client())
        XCTAssertEqual(s.risk, .high); XCTAssertEqual(s.expectedPhrase, "shield enforce")
        XCTAssertEqual(Set(body(s.execute(true)).keys), ["mode", "protectedIpv4", "synPps", "burstSeconds"])
        XCTAssertNotNil(failure("shield-set", ["mode": "audit", "ipv4": "2001:db8::1"]))        // v6 in v4 list
        XCTAssertNotNil(failure("shield-set", ["mode": "audit"]))                                // nothing protected
        XCTAssertNotNil(failure("shield-set", ["mode": "audit", "protectAll": "true", "synPps": "10000001"]))
        XCTAssertNotNil(failure("shield-set", ["mode": "audit", "protectAll": "true", "burst": "61"]))
        XCTAssertEqual(try spec("shield-set", ["mode": "audit", "protectAll": "true"], client()).risk, .low)
    }

    func testScopeAndConnRateSendOnlyServerFields() throws {
        let c = client()
        let sc = try spec("scope-set", ["mode": "selected", "namespace": "web", "labels": "app=api, tier=be"], c)
        let b = body(sc.execute(false))
        XCTAssertEqual(Set(b.keys), ["mode", "scopes"])
        XCTAssertEqual((b["scopes"] as? [[String: Any]])?.first?["labels"] as? [String: String], ["app": "api", "tier": "be"])
        XCTAssertEqual(body(sc.preview()).keys.sorted(), ["scopes"])
        XCTAssertEqual(sc.preview().url?.path, "/api/v1/ebpf/scope/preview")
        XCTAssertNotNil(failure("scope-set", ["mode": "selected"]))                              // empty scope refused
        XCTAssertNotNil(failure("scope-set", ["mode": "selected", "labels": "oops"]))
        let all = try spec("scope-set", ["mode": "all"], c)
        XCTAssertEqual(body(all.execute(false))["mode"] as? String, "all")

        let cr = try spec("conn-rate-add", ["namespace": "web", "perSecond": "50"], c)
        XCTAssertTrue(cr.leaseBound)
        XCTAssertEqual(Set(body(cr.execute(false)).keys), ["selector", "perSecond"])
        XCTAssertNotNil(failure("conn-rate-add", ["namespace": "web", "perSecond": "0"]))
        XCTAssertEqual(try spec("conn-rate-delete", ["id": "abc"], c).execute(false).httpMethod, "DELETE")
    }

    func testNetpolDenyNeedsPhraseButAllowDoesNot() throws {
        let c = client()
        let deny = try spec("netpol-rule-add", ["namespace": "web", "action": "deny", "peer": "10.0.0.9", "protocol": "TCP", "direction": "egress"], c)
        XCTAssertEqual(deny.risk, .high); XCTAssertEqual(deny.expectedPhrase, "deny web")
        XCTAssertEqual(Set(body(deny.execute(true)).keys), ["selector", "action", "peerIpv4", "protocol", "direction"])
        let allow = try spec("netpol-rule-add", ["namespace": "web", "action": "allow", "port": "443", "protocol": "ANY", "direction": "both"], c)
        XCTAssertEqual(allow.risk, .medium)
        XCTAssertEqual(body(allow.execute(false))["port"] as? Int, 443)
        XCTAssertNotNil(failure("netpol-rule-add", ["namespace": "web", "action": "allow"]))              // no peer and no port
        XCTAssertNotNil(failure("netpol-rule-add", ["namespace": "web", "action": "allow", "peer": "::1"]))
        let t = try spec("netpol-toggle", ["version": "v1", "enabled": "true"], c)
        XCTAssertEqual(t.execute(false).url?.path, "/api/v1/ebpf/netpol/config")
        XCTAssertEqual(try spec("netpol-toggle", ["version": "v2", "enabled": "false"], c).execute(false).url?.path, "/api/v1/ebpf/netpol/v2/config")
    }

    func testDefaultDenyPlanAndApplyShareExactBytesAndCarryToken() async throws {
        StubURLProtocol.handler = { r in
            r.url!.path.hasSuffix("/plan")
                ? (200, #"{"risk":"critical","matchedWorkloads":3,"workloadsWithAllowRule":0,"receipt":{"token":"dd-1"}}"#) : (200, "{}")
        }
        let c = client()
        let s = try spec("default-deny", ["namespace": "web", "enabled": "true", "minutes": "5", "allowNoRules": "true"], c)
        let f = flow(s, c); await f.runPreview()
        XCTAssertEqual(f.effectiveRisk, .critical)
        let plan = StubURLProtocol.seen.last!
        XCTAssertEqual(plan.url?.query, "allowNoRules=true")
        f.typedPhrase = "default-deny web"; await f.confirm()
        let put = StubURLProtocol.seen.last!
        XCTAssertEqual(put.httpMethod, "PUT"); XCTAssertEqual(put.url?.path, "/api/v1/ebpf/netpol/default-deny")
        XCTAssertEqual(put.httpBody, plan.httpBody)                                       // token binds the exact bytes
        XCTAssertEqual(put.value(forHTTPHeaderField: "X-Netra-Plan-Token"), "dd-1")
        XCTAssertEqual(put.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "critical")
        XCTAssertEqual(body(put)["lease"] as? String, "5m")
        XCTAssertNil(body(try spec("default-deny", ["namespace": "web", "enabled": "false"], c).execute(false))["lease"])
    }

    func testDenyImportParsingAndGuard() async throws {
        let p = ControlAction.parseDenyImport(["1.2.3.4", "10.0.0.0/8 ingress", "cidr 192.168.0.0/16", "evil.example", "sni bad.example"])
        XCTAssertNil(p.error)
        XCTAssertEqual(p.entries.map(\.type), ["ip", "cidr", "cidr", "dns", "sni"])
        XCTAssertEqual(p.entries[1].direction, "ingress")
        XCTAssertNotNil(ControlAction.parseDenyImport(["dns evil.example egress"]).error)           // dns has no direction
        XCTAssertNotNil(ControlAction.parseDenyImport(["1.2.3.4 sideways"]).error)
        XCTAssertNotNil(ControlAction.parseDenyImport(["bad host!"]).error)
        XCTAssertNotNil(failure("deny-import", ["entries": ""]))
        XCTAssertNotNil(failure("deny-import", ["entries": (0..<1001).map { "10.0.\($0 / 250).\($0 % 250 + 1)" }.joined(separator: "\n")]))

        StubURLProtocol.handler = { _ in (200, #"{"items":[]}"#) }
        let c = client()
        let s = try spec("deny-import", ["entries": "1.2.3.4\n# comment\nevil.example"], c)
        XCTAssertEqual(s.risk, .high)
        let f = flow(s, c)
        await f.confirm(); XCTAssertEqual(StubURLProtocol.seen.count, 0)                         // preview first
        await f.runPreview(); f.typedPhrase = "wrong"; await f.confirm(); XCTAssertEqual(StubURLProtocol.seen.count, 1)
        f.typedPhrase = "import 2 denies"; await f.confirm()
        let post = StubURLProtocol.seen.last!
        XCTAssertEqual(post.url?.path, "/api/v1/ebpf/deny/import")
        let entries = body(post)["entries"] as? [[String: Any]]
        XCTAssertEqual(entries?.count, 2); XCTAssertEqual(entries?.last?["type"] as? String, "dns")
        XCTAssertEqual(post.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "high")
    }

    func testIntelFeedPutIsPlainTextAndAppliesNothing() throws {
        let c = client()
        let s = try spec("intel-feed-put", ["feed": "1.2.3.4\nevil.example", "source": "isac", "note": "weekly", "ttlHours": "24"], c)
        XCTAssertEqual(s.risk, .medium)
        let r = s.execute(false)
        XCTAssertEqual(r.httpMethod, "PUT"); XCTAssertEqual(r.url?.path, "/api/v1/intel/feed")
        XCTAssertEqual(r.value(forHTTPHeaderField: "Content-Type"), "text/plain")
        XCTAssertEqual(r.value(forHTTPHeaderField: "X-Netra-Intel-Source"), "isac")
        XCTAssertEqual(Set((r.url?.query ?? "").split(separator: "&").map(String.init)), ["note=weekly", "ttl=24h"])
        XCTAssertEqual(String(decoding: r.httpBody ?? Data(), as: UTF8.self), "1.2.3.4\nevil.example")
        XCTAssertEqual(s.preview().url?.path, "/api/v1/intel/preview")
        XCTAssertNotNil(failure("intel-feed-put", ["feed": "  "]))
        XCTAssertNotNil(failure("intel-feed-put", ["feed": "x", "ttlHours": "721"]))
    }

    func testIntelApplyIsHighLeasedAndSendsConfirmHeader() async throws {
        StubURLProtocol.handler = { _ in (200, #"{"entries":[{"type":"ip","value":"1.2.3.4"}]}"#) }
        let c = client()
        let s = try spec("intel-apply", ["matchedOnly": "true"], c)
        XCTAssertEqual(s.risk, .high); XCTAssertTrue(s.leaseBound)
        let f = flow(s, c); await f.runPreview()
        f.typedPhrase = "apply matched intel"; await f.confirm()
        let r = StubURLProtocol.seen.last!
        XCTAssertEqual(r.url?.path, "/api/v1/intel/apply"); XCTAssertEqual(r.url?.query, "matchedOnly=true")
        XCTAssertEqual(r.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "high")
        XCTAssertEqual(try spec("intel-feed-rollback", ["revision": "3"], c).execute(false).url?.path, "/api/v1/intel/rollback/3")
        XCTAssertNotNil(failure("intel-feed-rollback", ["revision": "0"]))
    }

    func testBulkCaptureCarriesNodesAndReusesCaptureRules() throws {
        let c = client()
        let s = try spec("capture-bulk", ["nodes": "n2, n1\nn1", "backend": "ebpf", "proto": "tcp", "port": "443", "duration": "30"], c)
        let b = body(s.execute(false))
        XCTAssertEqual(b["nodes"] as? [String], ["n1", "n2"])
        XCTAssertEqual(b["durationSeconds"] as? Int, 30); XCTAssertEqual(b["protocol"] as? String, "tcp")
        XCTAssertEqual(s.execute(false).url?.path, "/api/v1/capture/bulk")
        XCTAssertNotNil(failure("capture-bulk", ["nodes": "n1", "backend": "ebpf", "duration": "60"]))   // unfiltered whole-interface
        XCTAssertNotNil(failure("capture-bulk", ["nodes": "", "backend": "ebpf", "proto": "tcp", "duration": "60"]))
        XCTAssertNotNil(failure("capture-bulk", ["nodes": "n1", "backend": "ebpf", "proto": "tcp", "duration": "301"]))
    }

    func testReadOnlyTokenSendsNothingForAnyAction() async throws {
        let c = client()
        let s = try spec("deny-import", ["entries": "1.2.3.4"], c)
        let f = MutationFlow(spec: s, client: c, gate: .init(canMutate: false), log: ActivityLog())
        await f.runPreview(); f.typedPhrase = "import 1 deny"; await f.confirm()
        XCTAssertEqual(StubURLProtocol.seen.filter { $0.httpMethod != "GET" }.count, 0)
    }
}
