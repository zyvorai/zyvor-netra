// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class MetricsLiveTests: XCTestCase {
    func testSocketURL() {
        XCTAssertEqual(MetricsLive.socketURL(base: URL(string: "https://netra.example:30870")!)?.absoluteString, "wss://netra.example:30870/api/v1/metrics/stream")
        XCTAssertEqual(MetricsLive.socketURL(base: URL(string: "http://localhost:8080")!)?.absoluteString, "ws://localhost:8080/api/v1/metrics/stream")
        XCTAssertNil(MetricsLive.socketURL(base: URL(string: "ftp://x")!))
    }

    func testSubscribeEncoding() throws {
        let s = LiveSubscription(id: LiveSubscription.id(context: "net.bytes", node: nil, chart: nil), context: "net.bytes", nodes: ["n1"], window: 900, points: 300)
        let msg = MetricsLive.subscribeMessage([s])
        let o = try JSONSerialization.jsonObject(with: Data(msg.utf8)) as! [String: Any]
        let a = (o["subscribe"] as! [[String: Any]])[0]
        XCTAssertEqual(a["id"] as? String, "net.bytes|*|*")
        XCTAssertEqual(a["window"] as? Int, 900)
        XCTAssertEqual(a["nodes"] as? [String], ["n1"])
        XCTAssertNil(a["groupBy"])
        let many = (0..<60).map { LiveSubscription(id: "\($0)", context: "c", window: 60) }
        let o2 = try JSONSerialization.jsonObject(with: Data(MetricsLive.subscribeMessage(many).utf8)) as! [String: Any]
        XCTAssertEqual((o2["subscribe"] as! [Any]).count, 50)
    }

    static let frame = """
    {"t":1700000000,"results":{"a|*|*":{"context":"net.bytes","tier":0,"interval":1,"after":1,"before":3,"timestamps":[1,2,3],
    "dimensions":[{"name":"rx","values":[1,null,3]}],"matched":1},"bad":{"nope":true}}}
    """

    func testParseFrameDropsBadResult() throws {
        let f = try XCTUnwrap(MetricsLive.parseFrame(Data(Self.frame.utf8)))
        XCTAssertEqual(f.t, 1700000000)
        XCTAssertEqual(f.results.keys.sorted(), ["a|*|*"])
        XCTAssertEqual(f.results["a|*|*"]?.timestamps, [1, 2, 3])
        XCTAssertNil(MetricsLive.parseFrame(Data("not json".utf8)))
        XCTAssertEqual(MetricsLive.parseFrame(Data(#"{"t":5,"results":{}}"#.utf8))?.results.count, 0)
    }

    // MARK: fake transport

    final class Script: @unchecked Sendable {
        let lock = NSLock()
        var opens = 0
        var sent: [String] = []
        var plans: [[Result<String, Error>]]
        init(_ p: [[Result<String, Error>]]) { plans = p }
        func nextPlan() -> [Result<String, Error>]? { lock.lock(); defer { lock.unlock() }; opens += 1; return plans.isEmpty ? nil : plans.removeFirst() }
        func record(_ s: String) { lock.lock(); sent.append(s); lock.unlock() }
    }
    struct FakeConnector: WSConnecting {
        let script: Script
        func open() async throws -> WSTransport {
            guard let p = script.nextPlan() else { throw NetraError.transport("down") }
            return FakeTransport(script: script, plan: p)
        }
    }
    final class FakeTransport: WSTransport, @unchecked Sendable {
        let script: Script; var plan: [Result<String, Error>]
        init(script: Script, plan: [Result<String, Error>]) { self.script = script; self.plan = plan }
        func send(_ text: String) async throws { script.record(text) }
        func receive() async throws -> Data {
            if plan.isEmpty { try await Task.sleep(for: .seconds(60)); return Data() }
            return Data(try plan.removeFirst().get().utf8)
        }
        func close() {}
    }

    func testReconnectsAfterFailureAndResubscribes() async throws {
        let script = Script([[.success(Self.frame), .failure(NetraError.transport("reset"))], [.success(Self.frame)]])
        let s = WSClient.stream(connector: FakeConnector(script: script), hello: { "HELLO" },
                                decode: { MetricsLive.parseFrame($0) },
                                backoff: SSEBackoff(base: 0.01, maximum: 0.02))
        var states: [WSState] = [], frames = 0
        for try await u in s {
            switch u {
            case .state(let st): states.append(st)
            case .message: frames += 1
            }
            if frames == 2 { break }
        }
        XCTAssertEqual(script.sent, ["HELLO", "HELLO"])
        XCTAssertTrue(states.contains { if case .reconnecting = $0 { return true } else { return false } })
        XCTAssertEqual(states.filter { $0 == .live }.count, 2)
    }

    func testUnauthorizedIsTerminal() async {
        let script = Script([[.failure(NetraError.unauthorized)]])
        let s = WSClient.stream(connector: FakeConnector(script: script), hello: { nil }, decode: { MetricsLive.parseFrame($0) })
        do { for try await _ in s {}; XCTFail("expected throw") } catch { XCTAssertEqual(error as? NetraError, .unauthorized) }
        XCTAssertEqual(script.opens, 1)
    }

    func testIdleTimeoutReconnects() async throws {
        let script = Script([[], [.success(Self.frame)]])
        let s = WSClient.stream(connector: FakeConnector(script: script), hello: { nil }, decode: { MetricsLive.parseFrame($0) },
                                backoff: SSEBackoff(base: 0.01, maximum: 0.02), idleTimeout: 0.1)
        for try await u in s { if case .message = u { break } }
        XCTAssertEqual(script.opens, 2)
    }

    func testCancellationFinishesStream() async {
        let script = Script([[]])
        let s = WSClient.stream(connector: FakeConnector(script: script), hello: { nil }, decode: { MetricsLive.parseFrame($0) })
        let t = Task { var n = 0; for try await _ in s { n += 1 }; return n }
        try? await Task.sleep(for: .milliseconds(50))
        t.cancel()
        _ = try? await t.value
        XCTAssertTrue(t.isCancelled)
    }
}
