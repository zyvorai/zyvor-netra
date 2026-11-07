// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Bespoke views for: talkers, ports, protocols, drops, dns (all read-only).
/// Any other section falls back to the generic JSON browser.
enum TrafficPages {
    @MainActor @ViewBuilder static func view(for section: NavSection) -> some View {
        switch section {
        case .talkers: TalkersPage()
        case .ports: PortsPage()
        case .protocols: ProtocolsPage()
        case .drops: DropsPage()
        case .dns: DNSPage()
        default: JSONBrowserView(section: section).id(section)
        }
    }
}

/// GET /api/v1/talkers: {rows:[{destination,packets,bytes,blocked,nodes}], count}
private struct TalkersPage: View {
    var body: some View {
        DataPageView(PageConfig(
            title: "Top talkers", endpoint: "api/v1/talkers", query: [.init(name: "limit", value: "100")],
            rowsPath: "rows", idKeys: ["destination"],
            columns: [
                .init(title: "Destination", path: "destination", width: 220), .init(title: "Packets", path: "packets", kind: .int, width: 90),
                .init(title: "Bytes", path: "bytes", kind: .bytes, width: 90), .init(title: "Blocked", path: "blocked", kind: .int, width: 80),
                .init(title: "Nodes", path: "nodes", kind: .int, width: 60),
            ],
            stats: [
                .init(title: "Destinations", symbol: "person.2.wave.2") { String($0.rows(at: "rows").count) },
                .init(title: "Packets", symbol: "shippingbox") { TrafficData.compact(TrafficData.sum($0, key: "packets")) },
                .init(title: "Bytes", symbol: "internaldrive") { CellFormat.bytes(TrafficData.sum($0, key: "bytes")) },
                .init(title: "Blocked packets", symbol: "xmark.octagon", tint: .red) { TrafficData.compact(TrafficData.sum($0, key: "blocked")) },
                .init(title: "Blocked destinations", symbol: "nosign", tint: .orange) { v in
                    String(v.rows(at: "rows").filter { ($0.value["blocked"]?.asDouble ?? 0) > 0 }.count) },
                .init(title: "Top share", symbol: "chart.bar") { v in
                    let t = TrafficData.sum(v, key: "packets")
                    return TrafficData.talkerBars(v, top: 1).first.map { "\($0.label) \(TrafficData.percent($0.value, of: t))" } ?? "" },
            ],
            liveEvery: 10, emptyText: "No talkers observed yet."
        )) { v in RankedBarsCard(title: "Top destinations by packets", bars: TrafficData.talkerBars(v)) }
    }
}

/// GET /api/v1/ports: {rows:[{port,protocol,key,packets,blocked,flows}], count}
private struct PortsPage: View {
    var body: some View {
        DataPageView(PageConfig(
            title: "Port heat", endpoint: "api/v1/ports", query: [.init(name: "limit", value: "100")],
            rowsPath: "rows", idKeys: ["key"],
            columns: [
                .init(title: "Port", path: "port", kind: .int, width: 70), .init(title: "Protocol", path: "protocol", width: 80),
                .init(title: "Packets", path: "packets", kind: .int, width: 90), .init(title: "Blocked", path: "blocked", kind: .int, width: 80),
                .init(title: "Flows", path: "flows", kind: .int, width: 70),
            ],
            stats: [
                .init(title: "Ports", symbol: "door.left.hand.open") { String($0.rows(at: "rows").count) },
                .init(title: "Packets", symbol: "shippingbox") { TrafficData.compact(TrafficData.sum($0, key: "packets")) },
                .init(title: "Flows", symbol: "arrow.left.arrow.right") { TrafficData.compact(TrafficData.sum($0, key: "flows")) },
                .init(title: "Blocked packets", symbol: "xmark.octagon", tint: .red) { TrafficData.compact(TrafficData.sum($0, key: "blocked")) },
                .init(title: "Hottest", symbol: "flame", tint: .orange) { TrafficData.portBars($0, top: 1).first?.label ?? "" },
            ],
            liveEvery: 10, emptyText: "No port data yet."
        )) { v in RankedBarsCard(title: "Top destination ports by packets", bars: TrafficData.portBars(v)) }
    }
}

/// GET /api/v1/protocols: {rows:[{protocol,packets,bytes,blocked,flows}]}
private struct ProtocolsPage: View {
    var body: some View {
        DataPageView(PageConfig(
            title: "Protocol mix", endpoint: "api/v1/protocols",
            rowsPath: "rows", idKeys: ["protocol"],
            columns: [
                .init(title: "Protocol", path: "protocol", width: 100), .init(title: "Packets", path: "packets", kind: .int, width: 90),
                .init(title: "Bytes", path: "bytes", kind: .bytes, width: 90), .init(title: "Flows", path: "flows", kind: .int, width: 70),
                .init(title: "Blocked", path: "blocked", kind: .int, width: 80),
            ],
            stats: [
                .init(title: "Protocols", symbol: "point.3.connected.trianglepath.dotted") { String($0.rows(at: "rows").count) },
                .init(title: "Packets", symbol: "shippingbox") { TrafficData.compact(TrafficData.sum($0, key: "packets")) },
                .init(title: "Bytes", symbol: "internaldrive") { CellFormat.bytes(TrafficData.sum($0, key: "bytes")) },
                .init(title: "Flows", symbol: "arrow.left.arrow.right") { TrafficData.compact(TrafficData.sum($0, key: "flows")) },
                .init(title: "Blocked packets", symbol: "xmark.octagon", tint: .red) { TrafficData.compact(TrafficData.sum($0, key: "blocked")) },
            ],
            liveEvery: 10, emptyText: "No protocol data yet."
        )) { v in ShareDonutCard(title: "Share of packets", bars: TrafficData.protocolBars(v)) }
    }
}
