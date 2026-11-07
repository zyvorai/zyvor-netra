// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class TopologyTests: XCTestCase {
    func testDecodeEdgeRowsBuildsGraph() throws {
        let json = #"""
        {"items":[
         {"node":"n1","namespace":"shop","pod":"web-1","workloadKind":"Deployment","workloadName":"web","destination":"10.0.0.5","protocol":"tcp","packets":10,"bytes":100,"blocked":1,"future":"x"},
         {"node":"n1","namespace":"shop","pod":"web-2","workloadKind":"Deployment","workloadName":"web","destination":"10.0.0.5","protocol":"tcp","packets":5,"bytes":50,"blocked":0},
         {"node":"n1","destination":"1.1.1.1","protocol":"udp","packets":"3"},
         {"bogus":true}
        ]}
        """#
        let g = try TopologyGraph.decodeEdgeRows(Data(json.utf8))
        XCTAssertEqual(g.nodes.count, 4)   // web workload, host node, two destinations
        let e = g.edges.first { $0.target == "dest/10.0.0.5" }
        XCTAssertEqual(e?.packets, 15)
        XCTAssertEqual(e?.blocked, 1)
        XCTAssertEqual(g.edges.count, 2)
    }
    func testDependencyGraphTolerant() throws {
        let json = #"{"generatedAt":"2026-01-01T00:00:00Z","nodes":[{"id":"a","kind":"workload","namespace":"x","name":"a"},{"id":"b","kind":"external","ip":"8.8.8.8","name":"b"},{"name":"noid"}],"edges":[{"source":"a","target":"b","protocol":"tcp","port":443,"packets":9,"external":true}]}"#
        let g = try JSONDecoder().decode(TopologyGraph.self, from: Data(json.utf8))
        XCTAssertEqual(g.nodes.map(\.label), ["x/a", "8.8.8.8"])
        XCTAssertEqual(g.edges[0].label, "tcp/443")
        XCTAssertTrue(g.edges[0].external)
        XCTAssertEqual(g.neighbors(of: "a"), ["b"])
    }
    func testBlastRadius() throws {
        let json = #"{"root":"a","maxHops":2,"nodes":[{"id":"a","hops":0},{"id":"b","hops":1}],"edges":[],"truncated":true,"caveat":"c"}"#
        let b = try JSONDecoder().decode(BlastRadius.self, from: Data(json.utf8))
        XCTAssertEqual(b.hops["b"], 1); XCTAssertTrue(b.truncated)
    }
    func testLayoutSeparatesAndConnectedNodesAttract() {
        var l = ForceLayout()
        let edges = [("a", "b"), ("b", "c")]
        l.sync(nodes: ["a", "b", "c", "d"], edges: edges)
        for _ in 0..<400 { l.step(edges: edges) }
        func dist(_ x: String, _ y: String) -> Double {
            let p = l.positions[x]!, q = l.positions[y]!
            return ((p.x - q.x) * (p.x - q.x) + (p.y - q.y) * (p.y - q.y)).squareRoot()
        }
        XCTAssertGreaterThan(dist("a", "c"), 20)          // no overlap
        XCTAssertLessThan(dist("a", "b"), 300)
        XCTAssertTrue(l.positions.values.allSatisfy { $0.x.isFinite && $0.y.isFinite })
        XCTAssertTrue(l.settled)
    }
    func testSyncKeepsSurvivorsAndPins() {
        var l = ForceLayout()
        l.sync(nodes: ["a", "b"], edges: [("a", "b")])
        l.move("a", to: Vec2(5, 5)); l.pinned = ["a"]
        l.sync(nodes: ["a", "c"], edges: [("a", "c")])
        XCTAssertEqual(l.positions["a"], Vec2(5, 5))
        XCTAssertNil(l.positions["b"])
        l.step(edges: [("a", "c")])
        XCTAssertEqual(l.positions["a"], Vec2(5, 5))
    }
}
