// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class FlowsTests: XCTestCase {
    let flowJSON = """
    {"time":"2026-05-01T10:00:00.123456789Z","verdict":"DROPPED","trafficDirection":"EGRESS",
     "IP":{"source":"10.0.0.1","destination":"1.2.3.4"},
     "l4":{"TCP":{"sourcePort":4000,"destinationPort":443}},
     "source":{"namespace":"prod","podName":"web-1"},"destination":{"identity":2},
     "dropReasonDesc":"POLICY_DENIED","future":{"x":1}}
    """

    func testFlowDecoding() throws {
        let f = try JSONDecoder().decode(FlowRecord.self, from: Data(flowJSON.utf8))
        XCTAssertEqual(f.verdict, "DROPPED")
        XCTAssertEqual(f.source, "prod/web-1")
        XCTAssertEqual(f.destination, "2")
        XCTAssertEqual(f.proto, "TCP")
        XCTAssertEqual(f.destinationEndpoint, "1.2.3.4:443")
        XCTAssertNotNil(f.timestamp)
        XCTAssertTrue(f.prettyJSON.contains("\"future\""))
    }

    func testTolerantEmptyFlow() throws {
        let f = try JSONDecoder().decode(FlowRecord.self, from: Data("{}".utf8))
        XCTAssertEqual(f.source, "world"); XCTAssertEqual(f.proto, ""); XCTAssertEqual(f.destinationPort, 0)
    }

    func testSSEChunkHandlingSplitsAnywhere() {
        let stream = "event: ready\ndata: {\"source\":\"x\"}\n\n: ping\nevent: flow\ndata: \(flowJSON.replacingOccurrences(of: "\n", with: ""))\n\n"
        let bytes = Data(stream.utf8)
        for size in [1, 3, 7, 1000] {
            var feeder = SSEByteFeeder(); var events: [SSEEvent] = []
            var i = 0
            while i < bytes.count { events += feeder.feed(bytes[i..<min(i + size, bytes.count)]); i += size }
            XCTAssertEqual(events.map(\.event), ["ready", "flow"], "chunk \(size)")
            XCTAssertEqual(decodeFlowEvent(events[1])?.verdict, "DROPPED")
            XCTAssertNil(decodeFlowEvent(events[0]))
        }
    }

    func testMultibyteUTF8SplitAcrossChunks() {
        let bytes = Data("event: flow\ndata: {\"verdict\":\"é→x\"}\n\n".utf8)
        var feeder = SSEByteFeeder(); var out: [SSEEvent] = []
        for b in bytes { out += feeder.feed(Data([b])) }
        XCTAssertEqual(decodeFlowEvent(out[0])?.verdict, "é→x")
    }

    func testRingBufferBounds() {
        var r = FlowRingBuffer<Int>(capacity: 3)
        for i in 1...5 { r.append(i) }
        XCTAssertEqual(r.elements, [3, 4, 5]); XCTAssertEqual(r.count, 3)
        r.removeAll(); r.append(9); XCTAssertEqual(r.elements, [9])
    }

    func testBackoffCaps() {
        let b = SSEBackoff(base: 0.5, maximum: 4)
        XCTAssertEqual([1, 2, 3, 4, 10].map { b.delay(attempt: $0) }, [0.5, 1, 2, 4, 4])
    }

    func testHistoryAndSummaryDecoding() throws {
        let h = """
        {"records":[{"observedAt":"2026-05-01T10:00:00Z","namespace":"prod","pod":"web","workloadKind":"Deployment","workloadName":"web","peer":"1.2.3.4","port":443,"protocol":"TCP","bytes":99,"tlsSni":"a.b"}],"matched":1,"limitations":["x"]}
        """
        let r = try JSONDecoder().decode(FlowHistory.self, from: Data(h.utf8))
        XCTAssertEqual(r.records[0].workload, "Deployment/web"); XCTAssertEqual(r.records[0].bytes, 99)
        XCTAssertEqual(r.records[0].proto, "TCP")
        let s = try JSONDecoder().decode(FlowsSummary.self, from: Data(#"{"total":5,"verdicts":{"DROPPED":2},"protocols":{},"dropReasons":[{"name":"p","count":2}],"topDestinations":[]}"#.utf8))
        XCTAssertEqual(s.total, 5); XCTAssertEqual(s.dropReasons.first?.count, 2); XCTAssertTrue(s.topWorkloads.isEmpty)
    }

    func testStreamRequestUsesBearerHeader() {
        let c = NetraClient(profile: .init(baseURL: URL(string: "http://127.0.0.1:8080")!, token: "t0k"))
        var f = FlowFilterParams(); f.verdict = "DROPPED"
        let r = c.flowStreamRequest(number: 50, filter: f)
        XCTAssertEqual(r.value(forHTTPHeaderField: "Authorization"), "Bearer t0k")
        XCTAssertEqual(r.url?.query, "number=50&verdict=DROPPED")
        XCTAssertEqual(r.url?.path, "/api/v1/flows/stream")
    }
}
