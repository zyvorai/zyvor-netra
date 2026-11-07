// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Testing
import Foundation
@testable import NetraKit

@Test func sseParsesSplitChunks() {
    var p = SSEParser()
    #expect(p.feed("event: flow\ndata: {\"a\":1}").isEmpty)
    let e = p.feed("\n\n: keepalive\ndata: x\ndata: y\n\n")
    #expect(e.count == 2)
    #expect(e[0] == SSEEvent(event: "flow", data: "{\"a\":1}", id: nil))
    #expect(e[1].data == "x\ny")
}

@Test func errorEnvelope() {
    #expect(errorMessage(from: Data("{\"error\":\"nope\"}".utf8)) == "nope")
    #expect(errorMessage(from: Data(" plain ".utf8)) == "plain")
}

@Test func requestUsesHeaderNotQuery() {
    let c = NetraClient(profile: .init(baseURL: URL(string: "https://n.example")!, token: "tok"))
    let r = c.request("PUT", "api/v1/ebpf/mode", body: Data("{}".utf8), confirmRisk: true)
    #expect(r.value(forHTTPHeaderField: "Authorization") == "Bearer tok")
    #expect(r.value(forHTTPHeaderField: "X-Netra-Confirm-Risk") == "high")
    #expect(r.url?.query == nil)
}

@Test func gateRules() {
    #expect(MutationGate(canMutate: false).decide(risk: .low, previewed: true, typedPhrase: nil, expectedPhrase: "x") == .blocked(reason: "This token is read-only"))
    let g = MutationGate(canMutate: true)
    #expect(g.decide(risk: .low, previewed: false, typedPhrase: nil, expectedPhrase: "x") == .needsPreview)
    #expect(g.decide(risk: .high, previewed: true, typedPhrase: "no", expectedPhrase: "x") == .needsTypedConfirmation(phrase: "x"))
    #expect(g.decide(risk: .high, previewed: true, typedPhrase: "x", expectedPhrase: "x") == .allowed(confirmRiskHeader: true))
}

@Test func leaseFailsOpenToObserve() {
    let now = Date()
    #expect(LeaseTracker(expiresAt: now.addingTimeInterval(-1)).effectiveMode(declared: "enforce", now: now) == "observe")
    #expect(LeaseTracker(expiresAt: now.addingTimeInterval(60)).effectiveMode(declared: "enforce", now: now) == "enforce")
}

@Test func roleTiers() throws {
    func who(_ r: String) throws -> WhoAmI {
        try JSONDecoder().decode(WhoAmI.self, from: Data("{\"authRequired\":true,\"oidcEnabled\":false,\"kind\":\"apikey\",\"role\":\"\(r)\"}".utf8))
    }
    #expect(try !who("viewer").canMutate)
    #expect(try who("operator").canMutate && !who("operator").isAdmin)
    #expect(try who("admin").isAdmin)
    #expect(try !who("bogus").canMutate)
}

@Test func leaseDecodesGoTimestamps() throws {
    let j = #"{"generatedAt":"2026-11-07T10:00:00.123456Z","mode":"enforce","leaseExpiresAt":"2026-11-07T10:05:00Z","leaseSeconds":300,"remainingSeconds":299,"active":true,"expired":false,"note":"n"}"#
    let l = try JSONDecoder.netra.decode(LeaseStatus.self, from: Data(j.utf8))
    #expect(l.mode == "enforce" && l.active && l.remainingSeconds == 299)
    #expect(l.leaseExpiresAt != nil)
}

@Test func jsonValueRoundTrip() throws {
    let v = try JSONDecoder().decode(JSONValue.self, from: Data(#"{"summary":{"healthScore":87.5},"a":[1,"x",null,true]}"#.utf8))
    #expect(v["summary"]?["healthScore"]?.double == 87.5)
    #expect(v["a"]?.summary == "[4]")
}

@Test func keychainRoundTrip() throws {
    let k = KeychainStore(service: "dev.zyvor.netra.tests")
    defer { k.delete(account: "t") }
    do { try k.set("secret", account: "t") } catch { return }   // keychain may be unavailable in CI sandboxes
    #expect(k.get(account: "t") == "secret")
}
