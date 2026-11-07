// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

@MainActor
final class MetricAlertActionTests: XCTestCase {
    private func client() -> NetraClient {
        let cfg = URLSessionConfiguration.ephemeral; cfg.protocolClasses = [StubURLProtocol.self]
        StubURLProtocol.seen = []
        return NetraClient(profile: .init(baseURL: URL(string: "http://stub.invalid")!, token: "t"), session: URLSession(configuration: cfg))
    }
    private func spec(_ a: ControlAction, _ c: NetraClient, _ v: FormValues) throws -> MutationSpec {
        var vals = v
        for f in a.fields where vals[f.key] == nil { vals[f.key] = f.initial }
        return try a.build(c, vals).get()
    }

    func testDurationParsing() {
        XCTAssertEqual(MetricAlertActions.parseDuration("2h"), 7200)
        XCTAssertEqual(MetricAlertActions.parseDuration("1h30m"), 5400)
        XCTAssertEqual(MetricAlertActions.parseDuration("90s"), 90)
        XCTAssertNil(MetricAlertActions.parseDuration("soon"))
        XCTAssertNil(MetricAlertActions.parseDuration("5"))
        XCTAssertNil(MetricAlertActions.parseDuration(""))
    }

    func testAckPreviewsThenPostsOnlyToAckPath() async throws {
        StubURLProtocol.handler = { r in
            r.httpMethod == "GET" ? (200, #"{"active":[{"id":"ab12","rule":"cpu","node":"n1","status":"critical"}]}"#) : (200, #"{"status":"acknowledged"}"#)
        }
        let c = client()
        let flow = MutationFlow(spec: try spec(MetricAlertActions.ack(alertID: "ab12", label: "cpu"), c, [:]), client: c, gate: .init(canMutate: true), log: ActivityLog())
        await flow.confirm()
        XCTAssertEqual(StubURLProtocol.seen.count, 0, "no preview, no send")
        await flow.runPreview()
        XCTAssertEqual(flow.effectiveRisk, .low)
        XCTAssertTrue(flow.previewSummary?.contains("cpu on n1") == true)
        await flow.confirm()
        let last = StubURLProtocol.seen.last!
        XCTAssertEqual(last.httpMethod, "POST"); XCTAssertEqual(last.url?.path, "/api/v1/metrics/alerts/ab12/ack")
        XCTAssertNil(last.value(forHTTPHeaderField: "X-Netra-Confirm-Risk"))
    }

    func testAckRefusesPathInjection() {
        let c = client()
        XCTAssertThrowsError(try spec(MetricAlertActions.ack(alertID: "x", label: "x"), c, ["id": "../../ebpf/mode"]))
    }

    func testSilenceValidationAndBody() async throws {
        let c = client()
        XCTAssertThrowsError(try spec(MetricAlertActions.silence(), c, [:]))                       // no matcher
        XCTAssertThrowsError(try spec(MetricAlertActions.silence(rule: "cpu"), c, ["duration": "9999h"]))
        XCTAssertThrowsError(try spec(MetricAlertActions.silence(rule: "cpu"), c, ["duration": "later"]))
        StubURLProtocol.handler = { r in r.httpMethod == "GET" ? (200, #"{"active":[{"id":"a","rule":"cpu_high","node":"n1","chart":"c"}]}"#) : (201, "{}") }
        let flow = MutationFlow(spec: try spec(MetricAlertActions.silence(rule: "cpu*"), c, ["comment": "maint"]), client: c, gate: .init(canMutate: true), log: ActivityLog())
        await flow.runPreview()
        XCTAssertTrue(flow.previewSummary?.hasPrefix("1 raised") == true)
        await flow.confirm()
        let last = StubURLProtocol.seen.last!
        XCTAssertEqual(last.url?.path, "/api/v1/metrics/alerts/silences")
        let body = try JSONSerialization.jsonObject(with: last.httpBody ?? Data()) as? [String: String]
        XCTAssertEqual(body?["rule"], "cpu*"); XCTAssertEqual(body?["duration"], "2h"); XCTAssertEqual(body?["comment"], "maint")
    }

    func testRemoveSilenceIsDeleteAndReadOnlyTokenBlocked() async throws {
        StubURLProtocol.handler = { r in r.httpMethod == "GET" ? (200, #"{"silences":[{"id":"s1"}]}"#) : (204, "") }
        let c = client()
        let s = try spec(MetricAlertActions.removeSilence(id: "s1", label: "s1"), c, [:])
        let ro = MutationFlow(spec: s, client: c, gate: .init(canMutate: false), log: ActivityLog())
        await ro.runPreview(); await ro.confirm()
        XCTAssertEqual(StubURLProtocol.seen.count, 0)
        let flow = MutationFlow(spec: s, client: c, gate: .init(canMutate: true), log: ActivityLog())
        await flow.runPreview(); await flow.confirm()
        XCTAssertEqual(StubURLProtocol.seen.last?.httpMethod, "DELETE")
        XCTAssertEqual(StubURLProtocol.seen.last?.url?.path, "/api/v1/metrics/alerts/silences/s1")
    }

    func testGlob() {
        XCTAssertTrue(MetricAlertActions.glob("cpu*", "cpu_high"))
        XCTAssertTrue(MetricAlertActions.glob("*", "x"))
        XCTAssertFalse(MetricAlertActions.glob("mem*", "cpu"))
    }
}
