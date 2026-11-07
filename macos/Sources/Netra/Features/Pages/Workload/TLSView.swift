// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// JA3/JA4 fingerprints of observed TLS ClientHellos joined with the risk board. Metadata only; read-only.
struct TLSPage: View {
    var body: some View {
        WLPage(title: "TLS fingerprints", subtitle: "api/v1/ebpf/tls-fingerprints", liveEvery: 10, load: { c in
            async let f = wlGET(c, "api/v1/ebpf/tls-fingerprints", [URLQueryItem(name: "limit", value: "500")])
            async let r = wlOptional(c, "api/v1/ebpf/tls-fingerprints/risk", [URLQueryItem(name: "limit", value: "500")])
            return .object(["fingerprints": try await f, "risk": await r ?? .null])
        }) { value, query in
            let rows = WorkloadData.tlsRows(fingerprints: value["fingerprints"], risk: value["risk"])
            let s = WorkloadData.tlsSummary(fingerprints: value["fingerprints"], risk: value["risk"])
            VStack(spacing: 0) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        StatCard(title: "Unique JA3", value: "\(s.unique)", symbol: "fingerprint")
                        StatCard(title: "ClientHellos", value: "\(s.observations)", symbol: "number")
                        StatCard(title: "Rare", value: value["risk"] == .null ? "n/a" : "\(s.rare)", symbol: "exclamationmark.triangle", tint: s.rare > 0 ? .orange : .secondary)
                        StatCard(title: "ECH sightings", value: "\(s.ech)", symbol: "eye.slash", tint: s.ech > 0 ? .red : .secondary)
                        StatCard(title: "No SNI", value: "\(s.missingSNI)", symbol: "questionmark.circle", tint: s.missingSNI > 0 ? .orange : .secondary)
                        StatCard(title: "QUIC", value: "\(s.quic)", symbol: "bolt")
                    }.padding([.horizontal, .top])
                }.padding(.bottom, 8)
                if !s.enabled {
                    Label("TLS fingerprinting is disabled on this controller.", systemImage: "info.circle").font(.caption).foregroundStyle(.secondary).padding(.horizontal).padding(.bottom, 6)
                } else if let note = value["fingerprints"]?["note"]?.string {
                    Text(note).font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal).padding(.bottom, 6)
                }
                ChartRow {
                    BarCard(title: "Most frequent fingerprints", data: rows.sorted { WorkloadData.num($0.value, "count") > WorkloadData.num($1.value, "count") }.prefix(6)
                        .map { (WorkloadData.str($0.value, "sni").isEmpty ? WorkloadData.str($0.value, "ja3Short") : WorkloadData.str($0.value, "sni"), WorkloadData.num($0.value, "count")) })
                    DonutCard(title: "Risk", data: WLevel.allCases.map { l in
                        (l.label, Double(rows.filter { WorkloadData.str($0.value, "riskLevel") == l.label }.count), l.tint)
                    })
                }
                WLTable(rows: rows, columns: [
                    WCol(title: "Risk", path: "riskLevel", sortPath: "riskRank", style: .level, width: 90),
                    WCol(title: "SNI", path: "sni", width: 170), WCol(title: "JA3", path: "ja3Short", width: 100),
                    WCol(title: "TLS", path: "versionText"), WCol(title: "ALPN", path: "alpn"),
                    WCol(title: "Seen", path: "count", kind: .int), WCol(title: "Last seen", path: "lastSeen", kind: .time),
                    WCol(title: "Node", path: "node"), WCol(title: "JA4", path: "ja4", width: 150),
                ], query: query, empty: "No TLS fingerprints observed yet.", fields: [
                    WField(label: "SNI", path: "sni"), WField(label: "JA3", path: "ja3"), WField(label: "JA4", path: "ja4"),
                    WField(label: "TLS version", path: "versionText"), WField(label: "ALPN", path: "alpn"),
                    WField(label: "Transport", path: "transport"), WField(label: "ECH", path: "ech", kind: .bool),
                    WField(label: "Risk", path: "riskLevel"), WField(label: "Reasons", path: "reasons"),
                    WField(label: "Seen", path: "count", kind: .int), WField(label: "First seen", path: "firstSeen", kind: .time),
                    WField(label: "Last seen", path: "lastSeen", kind: .time), WField(label: "Node", path: "node"),
                ])
            }
        }
    }
}
