// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class Ipv6DataTests: XCTestCase {
    private func j(_ s: String) -> JSONValue { try! JSONDecoder().decode(JSONValue.self, from: Data(s.utf8)) }

    func testExtRowsSortedByFragmentsAndRate() {
        let v = j(#"""
        {"summary":{"anomalies":[{"severity":"warning","kind":"b","subject":"n2","message":"m2","value":3},{"severity":"critical","kind":"a","subject":"n1","message":"m1"}]},
         "nodes":[{"node":"n1","extHeaders":[{"direction":"ingress","hook":"tc","packets":1000,"fragmented":250,"chainTruncated":1},{"direction":"egress","hook":"tc","packets":0}]},
                  {"node":"n2","extHeaders":[{"direction":"ingress","hook":"xdp","packets":10,"fragmented":1}]}]}
        """#)
        let r = Ipv6Data.extRows(v)
        XCTAssertEqual(r.map(\.node), ["n1", "n2", "n1"])
        XCTAssertEqual(r[0].fragmentRate, 0.25)
        XCTAssertNil(r[2].fragmentRate)
        XCTAssertEqual(Ipv6Data.anomalies(v).map(\.kind), ["a", "b"])
        XCTAssertEqual(Ipv6Data.anomalies(v)[0].severity, .critical)
    }

    func testEmptyAndMissing() {
        XCTAssertTrue(Ipv6Data.extRows(.null).isEmpty)
        XCTAssertTrue(Ipv6Data.anomalies(j("{}")).isEmpty)
        XCTAssertTrue(Ipv6Data.findings(j(#"{"nodes":[{"node":"a"}]}"#)).isEmpty)
        XCTAssertTrue(Ipv6Data.windows(.null).isEmpty)
    }

    private let kn = #"""
    {"nodes":[
     {"node":"a","snapshot":{"tunables":[{"name":"net.core.x","value":"1"}],"counters":[{"name":"TcpExt.A","value":5}]},
      "window":{"node":"a","warming":false,"seconds":30,"softnetDroppedPerSecond":2.5},
      "findings":[{"severity":"warning","layer":"qdisc","signal":"s1","evidence":["e=1"],"risk":"r"},
                  {"severity":"critical","layer":"softnet","signal":"s2","evidence":[],"tunable":"net.core.x","currentValue":"1","suggestedValue":"2","applyCommand":"sysctl -w net.core.x=2","rollbackCommand":"sysctl -w net.core.x=1","windowSeconds":30}]},
     {"node":"b","snapshot":{},"window":{"node":"b","warming":true}}]}
    """#

    func testFindingsMostSevereFirst() {
        let f = Ipv6Data.findings(j(kn))
        XCTAssertEqual(f.map(\.signal), ["s2", "s1"])
        XCTAssertEqual(f[0].applyCommand, "sysctl -w net.core.x=2")
        XCTAssertEqual(f[0].windowSeconds, 30)
        XCTAssertEqual(f[1].evidence, ["e=1"])
    }

    func testWindowsWarmingHasNoRates() {
        let w = Ipv6Data.windows(j(kn))
        XCTAssertFalse(w[0].warming)
        XCTAssertEqual(w[0].rates.first?.perSecond, 2.5)
        XCTAssertEqual(w[0].rates.count, 6)
        XCTAssertTrue(w[1].warming)
        XCTAssertTrue(w[1].rates.isEmpty)
    }

    func testSnapshotRows() {
        let r = Ipv6Data.snapshotRows(j(kn), node: "a")
        XCTAssertEqual(r.map(\.name), ["net.core.x", "TcpExt.A"].sorted())
        XCTAssertTrue(Ipv6Data.snapshotRows(j(kn), node: "zz").isEmpty)
    }
}
