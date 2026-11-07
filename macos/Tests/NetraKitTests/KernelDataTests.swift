// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class KernelDataTests: XCTestCase {
    private func j(_ s: String) -> JSONValue { try! JSONDecoder().decode(JSONValue.self, from: Data(s.utf8)) }

    func testPressureLevels() {
        XCTAssertEqual(KernelData.pressure(nil), .info)
        XCTAssertEqual(KernelData.pressure(0.5), .ok)
        XCTAssertEqual(KernelData.pressure(0.75), .warning)
        XCTAssertEqual(KernelData.pressure(0.95), .critical)
        XCTAssertNil(KernelData.ratio(5, 0))
    }

    func testMapsSortedByFill() {
        let v = j(#"{"maps":[{"id":"a","title":"A","group":"deny","bpfMap":"a","count":10,"limit":100,"entries":["x"]},{"id":"b","title":"B","group":"rate","bpfMap":"b","count":4000,"limit":4096,"entries":[]},{"id":"c","count":3,"limit":0}]}"#)
        let m = KernelData.mapPressures(v)
        XCTAssertEqual(m.map(\.id), ["b", "a", "c"])
        XCTAssertEqual(m[0].level, .critical)
        XCTAssertEqual(m[1].entries, ["x"])
        XCTAssertEqual(m[2].level, .info)
    }

    func testListenBucketsOrdered() {
        let v = j(#"{"buckets":{"full":2,"empty":90,"le_25":5}}"#)
        XCTAssertEqual(KernelData.listenBuckets(v).map(\.id), ["empty", "le_25", "full"])
        XCTAssertEqual(KernelData.listenFill(j(#"{"queue":8,"max":10}"#)), 0.8)
        XCTAssertTrue(KernelData.listenBuckets(.null).isEmpty)
    }

    private let attach = #"""
    {"nodes":[
     {"node":"n1","reporting":true,"stale":false,"tcxSupported":true,"total":2,
      "hooks":["tc_ingress"],"configuredInterfaces":["eth0","eth1"],
      "attached":[{"name":"eth0","index":2,"type":"device","xdp":{"id":5,"name":"netra_xdp","owner":"netra","mode":"native"},
                   "tcxIngress":[{"id":7,"name":"cil_from_host","owner":"cilium"},{"id":8,"name":"netra_tc_in","owner":"netra"}]}]},
     {"node":"n2","reporting":false,"unavailable":"inventory off","configuredInterfaces":["eth0"]}]}
    """#

    func testAttachDriftAndRows() {
        let v = j(attach)
        let nodes = KernelData.attachNodes(v)
        XCTAssertEqual(nodes.first?.node, "n1")
        XCTAssertEqual(nodes.first?.missing, ["eth1"])
        XCTAssertTrue(nodes.first?.drift ?? false)
        XCTAssertEqual(nodes.last?.missing, [], "not reporting means unknown, not drift")
        let rows = KernelData.attachRows(v)
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows[0].netra, 2); XCTAssertEqual(rows[0].cilium, 1)
        XCTAssertEqual(rows[0].xdp, "netra_xdp (netra, native)")
        XCTAssertEqual(rows[0].tcxIngress, "cil_from_host (cilium) → netra_tc_in (netra)")
    }

    func testFindingsWorstFirst() {
        let v = j(#"{"findings":[{"severity":"info","kind":"k","node":"b","message":"m"},{"severity":"critical","kind":"x","node":"a","message":"boom","value":3,"interfaces":["eth0"]}]}"#)
        let f = KernelData.findings(v)
        XCTAssertEqual(f.map(\.severity), [.critical, .info])
        XCTAssertEqual(f[0].interfaces, ["eth0"])
    }

    func testNetlinkRowsActorAndTimeline() {
        let v = j(#"""
        {"events":[
         {"sequence":1,"epoch":9,"observedAt":"2026-01-01T00:00:10Z","node":"n1","kind":"route","action":"new","destination":"10.0.0.0/8","gateway":"10.0.0.1","interfaceIndex":3,"origin":"process","actor":{"confidence":"probable","comm":"ip","pid":42,"cgroupId":777}},
         {"sequence":2,"epoch":9,"observedAt":"2026-01-01T00:00:20Z","node":"n1","kind":"link","action":"delete","interface":"veth1","state":"down","origin":"kernel"},
         {"sequence":3,"epoch":9,"observedAt":"2026-01-01T00:02:00Z","node":"n1","kind":"link","action":"new","interface":"veth2"}]}
        """#)
        let r = KernelData.netlinkRows(v)
        XCTAssertEqual(r.first?.id, "n1/9/3")
        let route = r.first { $0.kind == "route" }!
        XCTAssertEqual(route.requester, "ip (42)"); XCTAssertEqual(route.cgroup, 777)
        XCTAssertEqual(route.subject, "10.0.0.0/8 via 10.0.0.1"); XCTAssertEqual(route.iface, "if3")
        XCTAssertEqual(r.first { $0.sequenceIs(2) }?.requester, "kernel")
        XCTAssertEqual(r.first?.requester, "unattributed")
        let bins = KernelData.netlinkTimeline(r)
        XCTAssertEqual(bins.count, 3)  // route+link in minute 0, link in minute 2
        XCTAssertEqual(bins.filter { $0.kind == "link" }.count, 2)
    }

    func testNetlinkNodes() {
        let v = j(#"{"nodes":[{"node":"n1","reporting":true,"sequence":10,"dropped":0,"missed":2,"overruns":0,"counts":{"links":4,"routes":9},"actor":{"available":true}},{"node":"n0","reporting":false,"unavailable":"off"}]}"#)
        let n = KernelData.netlinkNodes(v)
        XCTAssertEqual(n.map(\.node), ["n0", "n1"])
        XCTAssertTrue(n[1].lossy); XCTAssertTrue(n[1].actorAvailable); XCTAssertEqual(n[1].routes, 9)
        XCTAssertFalse(n[0].lossy)
    }

    func testSysctl() {
        let v = j(#"""
        {"nodes":[{"node":"n1","findings":[{"severity":"info","category":"c","name":"ip_forward","currentValue":"1","rationale":"r"},
          {"severity":"warning","category":"c","name":"rp_filter","interface":"eth0","currentValue":"0","expectedValue":"1","rationale":"r"}]}],
         "outliers":[{"name":"rp_filter","interface":"eth0","category":"c","majorityValue":"1","outlierNodes":["n1"]}]}
        """#)
        let r = KernelData.sysctlRows(v)
        XCTAssertEqual(r.map(\.name), ["rp_filter", "ip_forward"])
        XCTAssertTrue(r[0].deviates); XCTAssertFalse(r[1].deviates)
        XCTAssertEqual(KernelData.sysctlOutliers(v).first?.nodes, ["n1"])
    }

    func testNodeResources() {
        let v = j(#"{"nodes":[{"node":"n1","stale":false,"ageSeconds":3,"host":{"cpuPercent":200,"cpuCores":4,"loadAvg1":2,"memoryTotalBytes":1000,"memoryUsedBytes":900,"uptimeSeconds":60,"kernelRelease":"6.8"}}]}"#)
        let n = KernelData.nodeResources(v)[0]
        XCTAssertEqual(n.cpuRatio, 0.5); XCTAssertEqual(n.memRatio, 0.9); XCTAssertEqual(n.loadRatio, 0.5)
        XCTAssertEqual(KernelData.nodeResources(.null), [])
    }
}

private extension KernelData.NetlinkRow { func sequenceIs(_ n: Int) -> Bool { id.hasSuffix("/\(n)") } }
