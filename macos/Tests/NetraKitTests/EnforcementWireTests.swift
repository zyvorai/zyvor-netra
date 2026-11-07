// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

/// Wire contract of every enforcement action against the Go server (internal/api). The server decodes most
/// bodies with DisallowUnknownFields, so each test pins the EXACT verb, path, query, headers and body key set,
/// copied from the Go struct tags named next to it, and the keys the previews read from the server's replies.
@MainActor
final class EnforcementWireTests: XCTestCase {
    private func client() -> NetraClient {
        let cfg = URLSessionConfiguration.ephemeral; cfg.protocolClasses = [StubURLProtocol.self]
        StubURLProtocol.seen = []
        return NetraClient(profile: .init(baseURL: URL(string: "http://stub.invalid")!, token: "t"), session: URLSession(configuration: cfg))
    }
    private func spec(_ id: String, _ v: FormValues, _ c: NetraClient) throws -> MutationSpec {
        try XCTUnwrap(ControlAction.find(id)).build(c, v).get()
    }
    private func fail(_ id: String, _ v: FormValues) -> String? {
        if case .failure(let e) = ControlAction.find(id)!.build(client(), v) { return e.message } else { return nil }
    }
    private func keys(_ r: URLRequest?) -> Set<String> { Set(obj(r).keys) }
    private func obj(_ r: URLRequest?) -> [String: Any] {
        (r?.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]) ?? [:]
    }
    private func queryItems(_ r: URLRequest?) -> [String: String] {
        guard let u = r?.url, let items = URLComponents(url: u, resolvingAgainstBaseURL: false)?.queryItems else { return [:] }
        return Dictionary(uniqueKeysWithValues: items.map { ($0.name, $0.value ?? "") })
    }
    /// Previews, types the phrase and sends. Returns the preview text and every request seen.
    @discardableResult
    private func run(_ s: MutationSpec, _ c: NetraClient, reply: String = "{}") async -> MutationFlow {
        StubURLProtocol.handler = { _ in (200, reply) }
        let f = MutationFlow(spec: s, client: c, gate: .init(canMutate: true), log: ActivityLog())
        await f.runPreview()
        f.typedPhrase = s.expectedPhrase
        await f.confirm()
        return f
    }

    // MARK: node isolation: nodeIsolationBody {policyId, mode, rules[{cidr,protocol,portFrom,portTo}], exemptLocalPorts}

    func testNodeIsolationEveryKeyAndLeaseQuery() async throws {
        let c = client()
        let s = try spec("node-isolation-set", ["node": "worker-1", "mode": "enforce", "minutes": "60", "policyId": "p1",
                                                "rules": "10.0.0.0/8 tcp 8000-8100\n2001:db8::/32 any 53\n0.0.0.0/0 udp 443", "exempt": "22, 53, 22"], c)
        let f = await run(s, c, reply: #"{"items":[{"node":"worker-1","mode":"shadow"}]}"#)
        XCTAssertTrue(f.previewSummary?.contains("already has a shadow policy") == true, f.previewSummary ?? "")
        XCTAssertEqual(StubURLProtocol.seen.first?.httpMethod, "GET")
        XCTAssertEqual(StubURLProtocol.seen.first?.url?.path, "/api/v1/ebpf/node-isolation")
        let put = StubURLProtocol.seen.last!
        XCTAssertEqual(put.httpMethod, "PUT"); XCTAssertEqual(put.url?.path, "/api/v1/ebpf/node-isolation/worker-1")
        XCTAssertEqual(queryItems(put), ["lease": "60m"])                    // Go duration, validated 1m...1h
        XCTAssertEqual(put.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "high")
        XCTAssertEqual(keys(put), ["policyId", "mode", "rules", "exemptLocalPorts"])
        let rules = try XCTUnwrap(obj(put)["rules"] as? [[String: Any]])
        XCTAssertEqual(Set(rules[0].keys), ["cidr", "protocol", "portFrom", "portTo"])
        XCTAssertEqual(Set(rules[1].keys), ["cidr", "portFrom"])               // "any" and a single port: portTo omitted
        XCTAssertEqual(obj(put)["exemptLocalPorts"] as? [Int], [22, 53])      // deduplicated and sorted like the server
    }

    func testNodeIsolationShadowSendsNoLeaseAndClearIsADelete() async throws {
        let c = client()
        let s = try spec("node-isolation-set", ["node": "n1", "mode": "shadow", "minutes": "5", "rules": "10.0.0.0/8"], c)
        XCTAssertTrue(queryItems(s.execute(false)).isEmpty)                  // lease is read only for enforce
        let clear = try spec("node-isolation-clear", ["node": "n1"], c)
        let r = clear.execute(false)
        XCTAssertEqual(r.httpMethod, "DELETE"); XCTAssertEqual(r.url?.path, "/api/v1/ebpf/node-isolation/n1")
        XCTAssertNil(r.httpBody)
        XCTAssertEqual(clear.risk, .low)
    }

    func testNodeIsolationValidationEdges() {
        let ok: FormValues = ["node": "n1", "mode": "shadow", "rules": "10.0.0.0/8"]
        func with(_ k: String, _ v: String) -> FormValues { ok.merging([k: v]) { $1 } }
        XCTAssertNotNil(fail("node-isolation-set", with("exempt", ",")))               // would silently drop every exemption
        XCTAssertNotNil(fail("node-isolation-set", with("exempt", "0")))
        XCTAssertNotNil(fail("node-isolation-set", with("exempt", "65536")))
        XCTAssertNotNil(fail("node-isolation-set", with("exempt", (1...17).map(String.init).joined(separator: ","))))
        XCTAssertNil(fail("node-isolation-set", with("exempt", (1...16).map(String.init).joined(separator: ","))))
        XCTAssertNotNil(fail("node-isolation-set", with("policyId", String(repeating: "é", count: 65))))   // 130 bytes > 128
        XCTAssertNil(fail("node-isolation-set", with("policyId", String(repeating: "é", count: 64))))
        XCTAssertNotNil(fail("node-isolation-set", with("rules", (0..<65).map { "10.\($0).0.0/16" }.joined(separator: "\n"))))
        XCTAssertNil(fail("node-isolation-set", with("rules", (0..<64).map { "10.\($0).0.0/16" }.joined(separator: "\n"))))
        XCTAssertNotNil(fail("node-isolation-set", with("rules", "10.0.0.0/8 tcp 0")))
        XCTAssertNotNil(fail("node-isolation-set", with("rules", "10.0.0.0/8 tcp 70000")))
        XCTAssertNotNil(fail("node-isolation-set", ["node": "n1", "mode": "enforce", "minutes": "0", "rules": "10.0.0.0/8"]))
        XCTAssertNil(fail("node-isolation-set", ["node": "n1", "mode": "enforce", "minutes": "1", "rules": "10.0.0.0/8"]))
        XCTAssertNotNil(fail("node-isolation-set", with("mode", "observe")))
    }

    // MARK: shield: models.ShieldConfig {mode, protectAll, protectedIpv4, protectedIpv6, synPps, udpPps, icmpPps, otherPps, burstSeconds}

    func testShieldEveryKeyAndPreviewReadsTheStoredConfig() async throws {
        let c = client()
        let s = try spec("shield-set", ["mode": "enforce", "protectAll": "true", "ipv4": "10.0.0.5, 10.0.0.6", "ipv6": "2001:db8::1",
                                        "synPps": "1000", "udpPps": "2000", "icmpPps": "3000", "otherPps": "10000000", "burst": "60"], c)
        let f = await run(s, c, reply: #"{"shield":{"generation":3,"mode":"audit"},"revision":9}"#)
        XCTAssertTrue(f.previewSummary?.contains("currently audit") == true, f.previewSummary ?? "")
        let first = StubURLProtocol.seen.first!, put = StubURLProtocol.seen.last!
        XCTAssertEqual(first.url?.path, "/api/v1/ebpf/config")                // GET /ebpf/shield is the drop diagnostics, not the config
        XCTAssertEqual(put.httpMethod, "PUT"); XCTAssertEqual(put.url?.path, "/api/v1/ebpf/shield")
        XCTAssertTrue(queryItems(put).isEmpty)
        XCTAssertEqual(keys(put), ["mode", "protectAll", "protectedIpv4", "protectedIpv6", "synPps", "udpPps", "icmpPps", "otherPps", "burstSeconds"])
        XCTAssertEqual(put.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "high")
        // never configured: the config carries no "shield" key at all
        let g = await run(s, client(), reply: #"{"mode":"observe"}"#)
        XCTAssertTrue(g.previewSummary?.contains("currently off") == true, g.previewSummary ?? "")
    }

    func testShieldOffNeedsNoProtectedAddresses() throws {
        let s = try spec("shield-set", ["mode": "off"], client())
        XCTAssertEqual(s.risk, .low)
        XCTAssertEqual(keys(s.execute(false)), ["mode"])
        XCTAssertNotNil(fail("shield-set", ["mode": "audit", "ipv4": "10.0.0.0/8"]))      // exact addresses only
        XCTAssertNotNil(fail("shield-set", ["mode": "audit", "ipv6": "10.0.0.1"]))
        XCTAssertNotNil(fail("shield-set", ["mode": "burst"]))
    }

    // MARK: scope: {mode, scopes[EBPFWorkloadScope]}; preview {scopes} -> {matched, count, totalPods}

    func testScopeBodiesAndPreviewKeys() async throws {
        let c = client()
        let sel = try spec("scope-set", ["mode": "selected", "namespace": "web", "pod": "api-0", "workloadKind": "Deployment", "workloadName": "api", "labels": "app=api"], c)
        let b = obj(sel.execute(false))
        XCTAssertEqual(Set(b.keys), ["mode", "scopes"])
        XCTAssertEqual(Set(((b["scopes"] as? [[String: Any]])?.first ?? [:]).keys), ["namespace", "pod", "workloadKind", "workloadName", "labels"])
        XCTAssertEqual(sel.execute(false).httpMethod, "PUT"); XCTAssertEqual(sel.execute(false).url?.path, "/api/v1/ebpf/scope")
        let f = await run(sel, c, reply: #"{"matched":[{"pod":"api-0"}],"count":1,"totalPods":12}"#)
        XCTAssertTrue(f.previewSummary?.contains("Matches 1 of 12") == true, f.previewSummary ?? "")
        let all = try spec("scope-set", ["mode": "all", "namespace": "ignored"], c)
        XCTAssertEqual(obj(all.execute(false))["scopes"] as? [Any] != nil, true)        // "scopes": [] is valid for all
        XCTAssertEqual(keys(all.execute(false)), ["mode", "scopes"])
        XCTAssertEqual(all.risk, .low)
    }

    func testScopeLabelParsingMatchesServerTrimming() throws {
        let c = client()
        let s = try spec("scope-set", ["mode": "selected", "labels": " a = b , c= "], c)
        let labels = ((obj(s.execute(false))["scopes"] as? [[String: Any]])?.first?["labels"] as? [String: String])
        XCTAssertEqual(labels, ["a": "b", "c": ""])
        XCTAssertNotNil(fail("scope-set", ["mode": "selected", "labels": "=v"]))           // empty key
    }

    // MARK: conn rate: EBPFConnRateLimit {selector, perSecond uint32}

    func testConnRateBodyAndBounds() async throws {
        let c = client()
        let s = try spec("conn-rate-add", ["namespace": "web", "labels": "app=api", "perSecond": "4294967295"], c)
        let post = s.execute(false)
        XCTAssertEqual(post.httpMethod, "POST"); XCTAssertEqual(post.url?.path, "/api/v1/ebpf/conn-rate-limit")
        XCTAssertEqual(keys(post), ["selector", "perSecond"])
        XCTAssertNotNil(fail("conn-rate-add", ["namespace": "web", "perSecond": "4294967296"]))     // overflows uint32
        XCTAssertNotNil(fail("conn-rate-add", ["namespace": "web", "perSecond": "-1"]))
        XCTAssertNotNil(fail("conn-rate-add", ["namespace": "web", "perSecond": "1.5"]))
        let d = try spec("conn-rate-delete", ["id": "connratelimit-2"], c)
        let f = await run(d, c, reply: #"{"connRateLimits":[{"id":"connratelimit-2"}]}"#)
        XCTAssertTrue(f.previewSummary?.contains("Removes limit") == true)
        XCTAssertEqual(StubURLProtocol.seen.last?.httpMethod, "DELETE")
        XCTAssertEqual(StubURLProtocol.seen.last?.url?.path, "/api/v1/ebpf/conn-rate-limit/connratelimit-2")
        let g = await run(d, c, reply: #"{"mode":"observe"}"#)          // connRateLimits is omitempty on the server
        XCTAssertTrue(g.previewSummary?.contains("No limit with ID") == true)
    }

    // MARK: netpol rules: models.NetPolRule {selector, peerIpv4, port, protocol, direction, action}

    func testNetpolRuleKeysAndEnums() async throws {
        let c = client()
        let s = try spec("netpol-rule-add", ["namespace": "web", "action": "deny", "peer": "10.0.0.9", "port": "443", "protocol": "udp", "direction": "ingress"], c)
        let post = s.execute(true)
        XCTAssertEqual(post.httpMethod, "POST"); XCTAssertEqual(post.url?.path, "/api/v1/ebpf/netpol/rules")
        XCTAssertEqual(keys(post), ["selector", "action", "peerIpv4", "port", "protocol", "direction"])
        XCTAssertEqual(obj(post)["protocol"] as? String, "UDP")                // server accepts TCP|UDP|ANY, uppercased
        XCTAssertEqual(obj(post)["direction"] as? String, "ingress")
        XCTAssertEqual(s.risk, .high)
        XCTAssertNotNil(fail("netpol-rule-add", ["namespace": "web", "action": "allow", "port": "65536"]))
        XCTAssertNotNil(fail("netpol-rule-add", ["namespace": "web", "action": "allow", "peer": "10.0.0.0/8"]))   // exact IPv4 only
        XCTAssertNotNil(fail("netpol-rule-add", ["namespace": "web", "action": "block", "port": "1"]))
        XCTAssertNil(fail("netpol-rule-add", ["namespace": "web", "action": "allow", "port": "1", "protocol": "ANY", "direction": "egress"]))
        let del = try spec("netpol-rule-delete", ["id": "netpolrule-4"], c)
        let f = await run(del, c, reply: #"{"netPolRules":[{"id":"netpolrule-4"}]}"#)
        XCTAssertTrue(f.previewSummary?.contains("Removes rule") == true)
        XCTAssertEqual(StubURLProtocol.seen.last?.httpMethod, "DELETE")
        XCTAssertEqual(StubURLProtocol.seen.last?.url?.path, "/api/v1/ebpf/netpol/rules/netpolrule-4")
    }

    func testNetpolToggleBodyIsOnlyEnabled() throws {
        let c = client()
        for (ver, path) in [("v1", "/api/v1/ebpf/netpol/config"), ("v2", "/api/v1/ebpf/netpol/v2/config")] {
            let r = try spec("netpol-toggle", ["version": ver, "enabled": "true"], c).execute(false)
            XCTAssertEqual(r.httpMethod, "PUT"); XCTAssertEqual(r.url?.path, path)
            XCTAssertEqual(obj(r)["enabled"] as? Bool, true); XCTAssertEqual(keys(r), ["enabled"])
        }
        XCTAssertEqual(obj(try spec("netpol-toggle", ["version": "v2", "enabled": "false"], c).execute(false))["enabled"] as? Bool, false)
    }

    // MARK: default-deny: netPolDefaultDenyRequest {selector, enabled, lease}; plan token binds the exact bytes

    func testDefaultDenyKeysQueryAndRiskHeaders() async throws {
        let c = client()
        let s = try spec("default-deny", ["namespace": "web", "enabled": "true", "minutes": "60"], c)
        let f = await run(s, c, reply: #"{"risk":"medium","matchedWorkloads":2,"workloadsWithAllowRule":2,"receipt":{"token":"T"}}"#)
        XCTAssertTrue(f.previewSummary?.contains("Matches 2 workload(s); 2 covered") == true, f.previewSummary ?? "")
        let plan = StubURLProtocol.seen.first!, put = StubURLProtocol.seen.last!
        XCTAssertEqual(plan.httpMethod, "POST"); XCTAssertEqual(plan.url?.path, "/api/v1/ebpf/netpol/default-deny/plan")
        XCTAssertTrue(queryItems(plan).isEmpty)                                  // ?allowNoRules=true only on request
        XCTAssertEqual(keys(plan), ["selector", "enabled", "lease"])
        XCTAssertEqual(obj(plan)["lease"] as? String, "60m")
        XCTAssertEqual(plan.httpBody, put.httpBody)
        XCTAssertEqual(put.value(forHTTPHeaderField: "X-Netra-Plan-Token"), "T")
        XCTAssertNil(put.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"))     // server only asks for it at high/critical
        XCTAssertEqual(f.effectiveRisk, .medium)
    }

    func testDefaultDenyServerHighTierConfirmsHigh() async throws {
        let c = client()
        let s = try spec("default-deny", ["namespace": "web", "enabled": "true", "minutes": "5"], c)
        await run(s, c, reply: #"{"risk":"high","matchedWorkloads":2,"workloadsWithAllowRule":1,"receipt":{"token":"T"}}"#)
        XCTAssertEqual(StubURLProtocol.seen.last?.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "high")
    }

    func testDefaultDenyDisableAndValidation() throws {
        let c = client()
        let off = try spec("default-deny", ["namespace": "web", "enabled": "false", "minutes": "999"], c)
        XCTAssertEqual(keys(off.execute(false)), ["selector", "enabled"])           // lease only when enabling
        XCTAssertEqual(off.risk, .low)
        XCTAssertNotNil(fail("default-deny", ["namespace": "web", "enabled": "true", "minutes": "61"]))
        XCTAssertNotNil(fail("default-deny", ["namespace": "web", "enabled": "true", "minutes": "0"]))
        XCTAssertNotNil(fail("default-deny", ["enabled": "true", "minutes": "5"]))     // empty selector
        let allow = try spec("default-deny", ["namespace": "web", "enabled": "true", "minutes": "5", "allowNoRules": "true"], c)
        XCTAssertEqual(queryItems(allow.preview()), ["allowNoRules": "true"])
        XCTAssertTrue(queryItems(allow.execute(false)).isEmpty)
    }

    // MARK: deny import: denyImportRequest {entries[{type,value,direction}]}

    func testDenyImportKeySetAndDefaults() async throws {
        let c = client()
        let s = try spec("deny-import", ["entries": "1.2.3.4 both\ncidr 10.0.0.0/8\nsni a.example\ndns b.example"], c)
        let post = s.execute(true)
        XCTAssertEqual(post.httpMethod, "POST"); XCTAssertEqual(post.url?.path, "/api/v1/ebpf/deny/import")
        XCTAssertEqual(keys(post), ["entries"])
        let e = try XCTUnwrap(obj(post)["entries"] as? [[String: Any]])
        XCTAssertEqual(Set(e[0].keys), ["type", "value", "direction"])
        XCTAssertEqual(Set(e[1].keys), ["type", "value"])                       // direction omitted: server defaults to egress
        XCTAssertEqual(Set(e[2].keys), ["type", "value"])
        XCTAssertEqual(e.map { $0["type"] as? String }, ["ip", "cidr", "sni", "dns"])
        let f = await run(s, c, reply: #"{"items":[{"id":"a"},{"id":"b"}]}"#)
        XCTAssertTrue(f.previewSummary?.contains("2 existing rule(s)") == true, f.previewSummary ?? "")
        XCTAssertEqual(StubURLProtocol.seen.first?.url?.path, "/api/v1/ebpf/rules")
        XCTAssertNotNil(fail("deny-import", ["entries": "#only a comment"]))
    }

    func testDenyImportThousandEntriesAccepted() throws {
        let lines = (0..<1000).map { "10.\($0 / 250).\($0 % 250).1" }.joined(separator: "\n")
        XCTAssertNil(fail("deny-import", ["entries": lines]))
    }

    // MARK: intel: PUT /intel/feed (raw text; ?note ?ttl; X-Netra-Intel-Source), DELETE, POST /intel/rollback/{n}, POST /intel/apply

    func testIntelPutNoteWithPlusAndAmpersandSurvivesTheQueryString() throws {
        let c = client()
        let s = try spec("intel-feed-put", ["feed": "1.2.3.4", "note": "a+b & c=d", "ttlHours": "720"], c)
        let r = s.execute(false)
        XCTAssertEqual(queryItems(r)["ttl"], "720h")
        let raw = r.url?.query ?? ""
        XCTAssertFalse(raw.contains("+"), raw)                                  // Go would decode a literal + as a space
        XCTAssertEqual(URLComponents(string: "http://x/?" + raw)?.queryItems?.first { $0.name == "note" }?.value, "a+b & c=d")
        XCTAssertEqual(r.value(forHTTPHeaderField: "Authorization"), "Bearer t")
    }

    func testIntelPutLimitsAndHeaderSafety() throws {
        XCTAssertNotNil(fail("intel-feed-put", ["feed": "x", "ttlHours": "-1"]))
        XCTAssertNil(fail("intel-feed-put", ["feed": "x", "ttlHours": "0"]))
        XCTAssertNotNil(fail("intel-feed-put", ["feed": "x", "source": String(repeating: "s", count: 513)]))
        XCTAssertNil(fail("intel-feed-put", ["feed": "x", "source": String(repeating: "s", count: 512)]))
        XCTAssertNotNil(fail("intel-feed-put", ["feed": "x", "note": String(repeating: "é", count: 513)]))     // 1026 bytes
        XCTAssertNotNil(fail("intel-feed-put", ["feed": "x", "source": "séc"]))                             // header: ASCII only
        XCTAssertNotNil(fail("intel-feed-put", ["feed": String(repeating: "a", count: (1 << 20) + 1)]))
        XCTAssertNil(fail("intel-feed-put", ["feed": String(repeating: "a", count: 1 << 20)]))
        let none = try? spec("intel-feed-put", ["feed": "x"], client())
        XCTAssertNil(none?.execute(false).value(forHTTPHeaderField: "X-Netra-Intel-Source"))   // server defaults to "operator"
        XCTAssertNil(none?.execute(false).url?.query)
    }

    func testIntelClearAndRollbackPreviewReadFeedRevision() async throws {
        let c = client()
        let reply = #"{"feed":{"revision":7,"count":2,"empty":false},"entries":[{"type":"ip","value":"1.2.3.4"},{"type":"dns","value":"a.example"}]}"#
        let clear = await run(try spec("intel-feed-clear", [:], c), c, reply: reply)
        XCTAssertTrue(clear.previewSummary?.contains("revision 7 (2 entries)") == true, clear.previewSummary ?? "")
        XCTAssertEqual(StubURLProtocol.seen.last?.httpMethod, "DELETE"); XCTAssertEqual(StubURLProtocol.seen.last?.url?.path, "/api/v1/intel/feed")
        XCTAssertNil(StubURLProtocol.seen.last?.httpBody)
        let rb = await run(try spec("intel-feed-rollback", ["revision": "3"], c), c, reply: reply)
        XCTAssertTrue(rb.previewSummary?.contains("revision 7") == true && rb.previewSummary?.contains("revision 3") == true, rb.previewSummary ?? "")
        XCTAssertEqual(StubURLProtocol.seen.last?.httpMethod, "POST"); XCTAssertEqual(StubURLProtocol.seen.last?.url?.path, "/api/v1/intel/rollback/3")
        XCTAssertNil(StubURLProtocol.seen.last?.httpBody)
        XCTAssertNotNil(fail("intel-feed-rollback", ["revision": "-2"]))
        XCTAssertNotNil(fail("intel-feed-rollback", ["revision": "abc"]))
    }

    func testIntelPutPreviewReportsSkippedLines() async throws {
        let c = client()
        let f = await run(try spec("intel-feed-put", ["feed": "1.2.3.4\nbad line!"], c), c,
                          reply: #"{"preview":{"entries":[{"type":"ip","value":"1.2.3.4"}],"skipped":[{"line":2,"message":"x"}],"count":1,"dropped":0},"autoApplied":false}"#)
        XCTAssertTrue(f.previewSummary?.contains("parsed 1 entry and skipped 1 line") == true, f.previewSummary ?? "")
        XCTAssertEqual(StubURLProtocol.seen.first?.httpMethod, "POST"); XCTAssertEqual(StubURLProtocol.seen.first?.url?.path, "/api/v1/intel/preview")
        XCTAssertEqual(StubURLProtocol.seen.first?.value(forHTTPHeaderField: "Content-Type"), "text/plain")
    }

    func testIntelApplyQueryHeaderAndEmptyFeed() async throws {
        let c = client()
        for (flag, expectQuery) in [("true", "matchedOnly=true"), ("false", nil as String?)] {
            let s = try spec("intel-apply", ["matchedOnly": flag], c)
            await run(s, c, reply: #"{"feed":{"revision":1},"entries":[{"type":"ip","value":"1.2.3.4"}]}"#)
            let r = StubURLProtocol.seen.last!
            XCTAssertEqual(r.httpMethod, "POST"); XCTAssertEqual(r.url?.path, "/api/v1/intel/apply")
            XCTAssertEqual(r.url?.query, expectQuery)
            XCTAssertEqual(r.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "high")
            XCTAssertNil(r.httpBody)
        }
        let empty = await run(try spec("intel-apply", ["matchedOnly": "true"], c), c, reply: #"{"feed":{"empty":true},"entries":[]}"#)
        XCTAssertTrue(empty.previewSummary?.contains("empty") == true, empty.previewSummary ?? "")
    }

    // MARK: capture bulk: {nodes, backend, protocol, host, port, snapLen, maxPps, durationSeconds}

    func testBulkCaptureKeySet() throws {
        let c = client()
        let r = try spec("capture-bulk", ["nodes": "b a", "backend": "afpacket", "proto": "udp", "host": "10.0.0.1", "port": "53", "duration": "300"], c).execute(false)
        XCTAssertEqual(r.httpMethod, "POST"); XCTAssertEqual(r.url?.path, "/api/v1/capture/bulk")
        XCTAssertEqual(keys(r), ["nodes", "backend", "protocol", "host", "port", "durationSeconds"])
        XCTAssertEqual(obj(r)["durationSeconds"] as? Int, 300)
        let host = try spec("capture-bulk", ["nodes": "a", "backend": "ebpf", "host": "10.0.0.1", "duration": "1"], c).execute(false)
        XCTAssertEqual(keys(host), ["nodes", "backend", "host", "durationSeconds"])
        XCTAssertNotNil(fail("capture-bulk", ["nodes": "a", "backend": "ebpf", "port": "70000", "duration": "60"]))
        XCTAssertNotNil(fail("capture-bulk", ["nodes": "a", "backend": "ebpf", "port": "80", "duration": "0"]))
    }

    // MARK: metric alerts: POST /metrics/alerts/{id}/ack, POST /metrics/alerts/silences {rule,node,chart,duration,until,comment}

    func testMetricAlertWire() async throws {
        let c = client()
        let ack = try XCTUnwrap(try? MetricAlertActions.ack(alertID: "ab12cd34ef56ab12", label: "x").build(c, ["id": "ab12cd34ef56ab12"]).get())
        let ar = ack.execute(false)
        XCTAssertEqual(ar.httpMethod, "POST"); XCTAssertEqual(ar.url?.path, "/api/v1/metrics/alerts/ab12cd34ef56ab12/ack"); XCTAssertNil(ar.httpBody)
        let sil = try XCTUnwrap(try? MetricAlertActions.silence(rule: "r*").build(c, ["rule": "r*", "node": "", "chart": "", "duration": "1h30m", "comment": "maint"]).get())
        let sr = sil.execute(false)
        XCTAssertEqual(sr.httpMethod, "POST"); XCTAssertEqual(sr.url?.path, "/api/v1/metrics/alerts/silences")
        XCTAssertTrue(keys(sr).isSubset(of: ["rule", "node", "chart", "duration", "until", "comment"]))    // no unknown key
        XCTAssertEqual(obj(sr)["duration"] as? String, "1h30m"); XCTAssertNil(obj(sr)["until"])
        let del = try XCTUnwrap(try? MetricAlertActions.removeSilence(id: "a1b2", label: "s").build(c, ["id": "a1b2"]).get())
        XCTAssertEqual(del.execute(false).httpMethod, "DELETE"); XCTAssertEqual(del.execute(false).url?.path, "/api/v1/metrics/alerts/silences/a1b2")
        let f = await run(sil, c, reply: #"{"active":[{"id":"1","rule":"rx","node":"n","chart":"c"},{"id":"2","rule":"zz","node":"n","chart":"c"}],"silences":[]}"#)
        XCTAssertTrue(f.previewSummary?.hasPrefix("1 raised alert(s) match") == true, f.previewSummary ?? "")
        XCTAssertEqual(StubURLProtocol.seen.first?.url?.path, "/api/v1/metrics/alerts")
        // the server (time.ParseDuration + AddSilence) accepts 0 < d <= 30 days
        if case .success = MetricAlertActions.silence().build(c, ["rule": "a", "duration": "720h1s"]) { XCTFail("over 30 days") }
        if case .success = MetricAlertActions.silence().build(c, ["rule": "a", "duration": "0s"]) { XCTFail("zero duration") }
        if case .success = MetricAlertActions.silence().build(c, ["duration": "1h"]) { XCTFail("matcher required") }
        if case .failure = MetricAlertActions.silence().build(c, ["rule": "a", "duration": "720h"]) { XCTFail("exactly 30 days is valid") }
    }

    // MARK: policy tools

    func testPolicyToolsWire() throws {
        let c = client()
        // POST /policies/build: models.BuildPolicyRequest {name, namespace, selector, kind, to, port, protocol, includeDns}
        let b = try PolicyTools.buildRequest(c, ["name": "p", "namespace": "web", "selector": "app=api", "kind": "cidr", "to": "10.0.0.1, 10.0.0.0/8",
                                                  "port": "443", "protocol": "tcp", "includeDns": "true"]).get()
        XCTAssertEqual(b.httpMethod, "POST"); XCTAssertEqual(b.url?.path, "/api/v1/policies/build")
        XCTAssertEqual(keys(b), ["name", "namespace", "selector", "kind", "to", "port", "protocol", "includeDns"])
        XCTAssertEqual(obj(b)["protocol"] as? String, "TCP")
        // POST /ebpf/deny/preview-history: denysim.Proposal + since
        let h = try PolicyTools.denyHistoryRequest(c, ["kind": "port", "value": "443", "direction": "egress", "protocol": "tcp", "since": "2h",
                                                        "namespace": "web", "pod": "p", "workloadKind": "Deployment", "workloadName": "w", "limit": "10"]).get()
        XCTAssertEqual(h.url?.path, "/api/v1/ebpf/deny/preview-history")
        XCTAssertEqual(keys(h), ["kind", "value", "direction", "protocol", "since", "namespace", "pod", "workloadKind", "workloadName", "limit"])
        // POST /watchlist/match?limit=
        let w = try PolicyTools.watchlistMatchRequest(c, feed: "1.2.3.4", limit: 9999).get()
        XCTAssertEqual(w.url?.path, "/api/v1/watchlist/match"); XCTAssertEqual(queryItems(w), ["limit": "500"])
    }

    func testPolicyGuardedActionsWire() async throws {
        let c = client()
        let archive = #"{"schemaVersion":1,"exportedAt":"2026-01-01T00:00:00Z","revisions":[{"id":1,"at":"2026-01-01T00:00:00Z","actor":"a","namespace":"n","name":"p","action":"apply","manifest":{"metadata":{"name":"p","namespace":"n"}}}]}"#
        let imp = try XCTUnwrap(PolicyTools.find("policy-history-import")).build(c, ["archive": archive, "mode": "replace"]).get()
        XCTAssertEqual(imp.risk, .high)
        await run(imp, c, reply: #"{"items":[]}"#)
        let post = StubURLProtocol.seen.last!
        XCTAssertEqual(post.httpMethod, "POST"); XCTAssertEqual(post.url?.path, "/api/v1/policies/history/import")
        XCTAssertEqual(queryItems(post), ["mode": "replace"])
        XCTAssertEqual(post.value(forHTTPHeaderField: "X-Netra-Confirm-History-Replace"), "replace")
        XCTAssertEqual(post.httpBody, Data(archive.utf8))
        let merge = try XCTUnwrap(PolicyTools.find("policy-history-import")).build(c, ["archive": archive, "mode": "merge"]).get()
        XCTAssertEqual(queryItems(merge.execute(false)), ["mode": "merge"])
        XCTAssertNil(merge.execute(false).value(forHTTPHeaderField: "X-Netra-Confirm-History-Replace"))

        let ai = try XCTUnwrap(PolicyTools.find("ai-destinations-deny")).build(c, [:]).get()
        await run(ai, c, reply: #"{"result":{"hits":[{"host":"api.openai.com"}]}}"#)
        let a = StubURLProtocol.seen.last!
        XCTAssertEqual(a.httpMethod, "POST"); XCTAssertEqual(a.url?.path, "/api/v1/ebpf/ai-destinations/deny")
        XCTAssertEqual(a.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"), "high"); XCTAssertNil(a.httpBody)

        for (id, path, header) in [("baseline-clear", "/api/v1/insights/baseline", "X-Netra-Confirm-Baseline-Clear"),
                                   ("rate-baseline-clear", "/api/v1/insights/rate-baseline", "X-Netra-Confirm-Rate-Baseline-Clear")] {
            let s = try XCTUnwrap(PolicyTools.find(id)).build(c, [:]).get()
            await run(s, c, reply: #"{"captured":true,"baseline":{"capturedAt":"x"}}"#)
            let d = StubURLProtocol.seen.last!
            XCTAssertEqual(d.httpMethod, "DELETE"); XCTAssertEqual(d.url?.path, path)
            XCTAssertEqual(d.value(forHTTPHeaderField: header), "clear")
        }
        let cap = try XCTUnwrap(PolicyTools.find("baseline-capture")).build(c, [:]).get().execute(false)
        XCTAssertEqual(cap.httpMethod, "POST"); XCTAssertEqual(cap.url?.path, "/api/v1/insights/baseline")
        let rate = try XCTUnwrap(PolicyTools.find("rate-baseline-capture")).build(c, ["window": "90m"]).get().execute(false)
        XCTAssertEqual(rate.url?.path, "/api/v1/insights/rate-baseline"); XCTAssertEqual(queryItems(rate), ["window": "90m"])
        if case .success = PolicyTools.find("rate-baseline-capture")!.build(c, ["window": "29s"]) { XCTFail("server falls back to 5m below 30s") }
        if case .success = PolicyTools.find("rate-baseline-capture")!.build(c, ["window": "2h1s"]) { XCTFail("server falls back to 5m above 2h") }
    }

    // MARK: routes the server restricts, so the UI message can name them

    func testRolesAndGatingAreDocumentedByTheCatalog() {
        // admin-only on the server (rbac.go adminOnly): node-isolation PUT, scope PUT, shield PUT, netpol config PUTs,
        // default-deny PUT, intel feed PUT/DELETE, intel apply, policy history import. Cilium-gated (s.cilium): the
        // gitops resync and the policy plan/apply/lockdown/rollback/delete routes. Nothing here may be enforcement-free
        // of a lease or a risk confirmation where the server expects one.
        for id in ["node-isolation-set", "shield-set", "scope-set", "netpol-toggle", "default-deny", "intel-feed-put", "intel-feed-clear", "intel-apply"] {
            XCTAssertNotNil(ControlAction.find(id), id)
        }
        XCTAssertEqual(OpsAction.all[0].maxRisk, .critical)
    }
}
