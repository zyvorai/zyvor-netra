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


// Fixtures below copy the field names from the Go structs (internal/api/netlink.go, internal/models/netlink.go,
// internal/api/bpf_attach.go, internal/models/bpfattach.go, internal/models/sysctl_audit.go, internal/models/sysres.go,
// internal/api/listen_queues.go, internal/ebpfmaps) rather than from the Swift readers.
extension KernelDataTests {
    func testNetlinkRowsFromGoShape() {
        let v = j(#"""
        {"observedAt":"2026-11-07T10:00:00.123456789Z","view":"all","since":"2026-11-07T09:00:00Z","limit":500,
         "nodes":[{"node":"n1","observedAt":"2026-11-07T10:00:00Z","stale":false,"reporting":true,"epoch":7,"sequence":42,
                   "dropped":1,"missed":0,"overruns":0,"resubscribes":2,"suppressed":0,"generation":3,
                   "counts":{"links":4,"addresses":6,"routes":9,"neighbors":12},"historySince":"2026-11-07T09:05:00.5Z",
                   "actor":{"available":true}}],
         "events":[{"epoch":7,"sequence":41,"observedAt":"2026-11-07T09:59:59.987654321Z","node":"n1","kind":"route","action":"new",
                    "interfaceIndex":3,"interface":"eth0","destination":"10.0.0.0/8","gateway":"10.1.1.1","origin":"process",
                    "actor":{"confidence":"exact","comm":"ip","pid":4242,"cgroupId":99}},
                   {"sequence":40,"observedAt":"2026-11-07T09:59:00Z","node":"n1","kind":"link","action":"new","interfaceIndex":5,"state":"up","mtu":1500,"origin":"kernel"}]}
        """#)
        let rows = KernelData.netlinkRows(v)
        XCTAssertEqual(rows.count, 2)
        XCTAssertNotNil(rows[0].time, "nanosecond RFC3339 must parse")
        XCTAssertEqual(rows[0].subject, "10.0.0.0/8 via 10.1.1.1")
        XCTAssertEqual(rows[0].requester, "ip (4242)")
        XCTAssertEqual(rows[0].cgroup, 99); XCTAssertEqual(rows[0].confidence, "exact")
        XCTAssertEqual(rows[1].iface, "if5"); XCTAssertEqual(rows[1].requester, "kernel"); XCTAssertEqual(rows[1].subject, "up mtu 1500")
        let n = KernelData.netlinkNodes(v)[0]
        XCTAssertEqual(n.events, 42); XCTAssertEqual(n.routes, 9); XCTAssertEqual(n.neighbors, 12)
        XCTAssertTrue(n.actorAvailable); XCTAssertTrue(n.lossy); XCTAssertNotNil(n.historySince)
    }

    func testFindingsFromNetlinkAndAttachGoShape() {
        let f = KernelData.findings(j(#"{"observedAt":"2026-11-07T10:00:00Z","window":"15m0s","evaluated":2,"skipped":0,"findings":[{"severity":"warning","kind":"route-churn","node":"n1","subject":"n1","message":"m","value":12,"firstObserved":"2026-11-07T09:50:00Z","lastObserved":"2026-11-07T09:59:00Z"},{"severity":"critical","kind":"xdp-replaced","node":"n2","subject":"n2","message":"x","interfaces":["eth0"]}]}"#))
        XCTAssertEqual(f.map(\.kind), ["xdp-replaced", "route-churn"])
        XCTAssertEqual(f[0].interfaces, ["eth0"]); XCTAssertEqual(f[1].value, 12); XCTAssertNotNil(f[1].lastObserved)
    }

    func testAttachmentsFromGoShape() {
        let v = j(#"""
        {"observedAt":"2026-11-07T10:00:00Z","evaluated":1,"skipped":0,"findings":[],
         "nodes":[{"node":"n1","observedAt":"2026-11-07T10:00:00Z","stale":false,"reporting":true,"tcxSupported":true,
                   "hooks":["tcx/ingress"],"configuredInterfaces":["eth0","eth1"],"total":1,
                   "attached":[{"name":"eth0","index":2,"type":"device","state":"up",
                                "xdp":{"id":7,"name":"netra_xdp","owner":"netra","mode":"native"},
                                "tcxIngress":[{"id":8,"name":"netra_in","owner":"netra"},{"id":9,"name":"cil_from","owner":"cilium"}]}]}]}
        """#)
        let nodes = KernelData.attachNodes(v)
        XCTAssertEqual(nodes[0].missing, ["eth1"]); XCTAssertTrue(nodes[0].drift); XCTAssertTrue(nodes[0].tcxSupported)
        let rows = KernelData.attachRows(v)
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows[0].iface, "eth0"); XCTAssertEqual(rows[0].index, 2)
        XCTAssertEqual(rows[0].xdp, "netra_xdp (netra, native)")
        XCTAssertEqual(rows[0].tcxIngress, "netra_in (netra) → cil_from (cilium)")
        XCTAssertEqual(rows[0].netra, 2); XCTAssertEqual(rows[0].cilium, 1)
    }

    func testSysctlAndNodeResourcesFromGoShape() {
        let s = j(#"""
        {"summary":{"nodes":1,"findings":2,"critical":1,"warnings":0,"informational":1,"outliers":1},
         "nodes":[{"node":"n1","snapshot":{"entries":[]},"findings":[
            {"severity":"critical","category":"security","name":"net.ipv4.conf.all.rp_filter","interface":"all","currentValue":"0","expectedValue":"1","rationale":"why"},
            {"severity":"info","category":"tcp","name":"net.ipv4.ip_forward","currentValue":"1","rationale":"r","informational":true}]}],
         "outliers":[{"name":"net.ipv4.ip_forward","category":"tcp","majorityValue":"1","outlierNodes":["n2"]}],"limitations":["a"]}
        """#)
        let rows = KernelData.sysctlRows(s)
        XCTAssertEqual(rows.map(\.severity), [.critical, .info])
        XCTAssertEqual(rows[0].current, "0"); XCTAssertEqual(rows[0].expected, "1"); XCTAssertTrue(rows[0].deviates)
        XCTAssertEqual(rows[0].iface, "all"); XCTAssertFalse(rows[0].rationale.isEmpty)
        let o = KernelData.sysctlOutliers(s)
        XCTAssertEqual(o[0].majority, "1"); XCTAssertEqual(o[0].nodes, ["n2"])
        let r = KernelData.nodeResources(j(#"""
        {"generatedAt":"2026-11-07T10:00:00Z","summary":{"nodes":1,"totalCpuCores":4,"avgCpuPercent":50,"totalMemoryBytes":8000,"usedMemoryBytes":4000},
         "nodes":[{"node":"n1","stale":false,"ageSeconds":3,"host":{"loadAvg1":1.5,"loadAvg5":1,"loadAvg15":0.5,"cpuCores":4,"cpuPercent":200,
            "memoryTotalBytes":8000,"memoryUsedBytes":4000,"memoryAvailableBytes":4000,"memoryCachedBytes":100,"uptimeSeconds":86400,"kernelRelease":"6.8.0"}}],"limitations":[]}
        """#))
        XCTAssertEqual(r[0].cores, 4); XCTAssertEqual(r[0].cpuPercent, 200); XCTAssertEqual(r[0].cpuRatio, 0.5)
        XCTAssertEqual(r[0].memRatio, 0.5); XCTAssertEqual(r[0].uptime, 86400); XCTAssertEqual(r[0].kernel, "6.8.0"); XCTAssertEqual(r[0].load1, 1.5)
    }

    func testListenQueuesAndMapsFromGoShape() {
        let v = j(#"""
        {"nodes":[{"node":"n1","reporting":true},{"node":"n2","reporting":false,"unavailable":"off"}],"nodesReporting":1,"nodesNotReporting":1,
         "listeners":3,"full":1,"saturated":2,"synRecv":4,"buckets":{"empty":10,"le_25":0,"le_50":0,"le_75":0,"lt_100":1,"full":2},
         "top":[{"node":"n1","family":"ipv4","addr":"0.0.0.0","port":8080,"queue":128,"max":128,"synRecv":2,"peak":128,"peakPct":100}]}
        """#)
        XCTAssertEqual(KernelData.listenBuckets(v).map(\.count), [10, 0, 0, 0, 1, 2])
        let top = v.rows(at: "top")[0].value
        XCTAssertEqual(KernelData.listenFill(top), 1.0)
        XCTAssertEqual(CellFormat.text(top.at("peakPct"), .percent), "100.0%"); XCTAssertEqual(CellFormat.text(top.at("port"), .int), "8080")
        let m = KernelData.mapPressures(j(#"{"generatedAt":"2026-11-07T10:00:00Z","mode":"shadow","revision":3,"pinRoot":"/sys/fs/bpf/netra","note":"n","filledMaps":1,"emptyMaps":0,"totalEntries":5,"maps":[{"id":"deny-v4","title":"Deny IPv4","group":"deny","bpfMap":"blocked_v4","count":5,"limit":4096,"entries":["1.2.3.4"]}]}"#))
        XCTAssertEqual(m[0].bpfMap, "blocked_v4"); XCTAssertEqual(m[0].limit, 4096); XCTAssertEqual(m[0].entries, ["1.2.3.4"])
    }
}
