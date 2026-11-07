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


// Fixture copies models.IPv6DiagnosticsResponse / KernelNetworkDiagnosticsResponse json tags.
extension Ipv6DataTests {
    func testGoShapedIPv6AndKernelNetwork() {
        let jv: (String) -> JSONValue = { try! JSONDecoder().decode(JSONValue.self, from: Data($0.utf8)) }
        let v6 = jv(#"{"summary":{"packets":2000,"extHeaderPackets":10,"fragmented":50,"nonFirstFragments":5,"chainTruncated":0,"anomalies":[{"severity":"warning","kind":"ipv6-fragmentation","subject":"n1","message":"m","value":0.025}]},"nodes":[{"node":"n1","extHeaders":[{"direction":"ingress","hook":"tc","packets":2000,"extHeaderPackets":10,"totalExtHeaders":12,"fragmented":50,"nonFirstFragments":5,"moreFragments":3,"chainTruncated":0}]}]}"#)
        let rows = Ipv6Data.extRows(v6)
        XCTAssertEqual(rows.count, 1); XCTAssertEqual(rows[0].fragmented, 50); XCTAssertEqual(rows[0].fragmentRate, 0.025); XCTAssertEqual(rows[0].hook, "tc")
        XCTAssertEqual(Ipv6Data.anomalies(v6)[0].value, 0.025)
        let kn = jv(#"""
        {"summary":{"nodes":1,"findings":1,"critical":0,"warnings":1,"warming":0},
         "nodes":[{"node":"n1","snapshot":{"tunables":[{"name":"net.core.somaxconn","value":"128","source":"/proc"}],"counters":[{"name":"softnet_dropped","value":9,"source":"/proc"}]},
           "window":{"node":"n1","startAt":"2026-11-07T09:55:00Z","endAt":"2026-11-07T10:00:00Z","seconds":300,"warming":false,"softnetDropped":9,"softnetDroppedPerSecond":0.03,"softnetTimeSqueeze":0,"softnetTimeSqueezePerSecond":0,"rxDropped":0,"rxDroppedPerSecond":0,"txDropped":0,"txDroppedPerSecond":0,"rxMissed":0,"rxMissedPerSecond":0,"qdiscDrops":0,"qdiscDropsPerSecond":0},
           "findings":[{"severity":"warning","layer":"softnet","signal":"drops","evidence":["e"],"explanation":"x","recommendation":"r","tunable":"net.core.netdev_max_backlog","currentValue":"1000","suggestedValue":"2000","applyCommand":"sysctl -w","rollbackCommand":"sysctl -w","risk":"low","windowSeconds":300}]}],"limitations":["l"]}
        """#)
        let f = Ipv6Data.findings(kn)
        XCTAssertEqual(f.count, 1); XCTAssertEqual(f[0].signal, "drops"); XCTAssertEqual(f[0].suggestedValue, "2000"); XCTAssertEqual(f[0].windowSeconds, 300)
        let w = Ipv6Data.windows(kn)
        XCTAssertFalse(w[0].warming); XCTAssertEqual(w[0].rates.first?.perSecond, 0.03); XCTAssertEqual(w[0].counters, 1)
        XCTAssertEqual(Ipv6Data.snapshotRows(kn, node: "n1").map(\.name), ["net.core.somaxconn", "softnet_dropped"])
    }
}
