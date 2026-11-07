// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Congestion map (read-only). GET /api/v1/namespaces/heat?limit=N: {generatedAt, rows:[{namespace,packets,bytes,blocked,destinations}], count}
/// plus GET /api/v1/ai/congestion-brief: {headline,severity,summary,findings:[{severity,kind,subject,message}],nextSteps,engine,generatedAt}.
/// The brief is tolerated if it fails (it needs the AI snapshot).
struct MoreCongestionPage: View {
    var body: some View {
        MoreLoader(title: "Congestion", endpoint: "api/v1/namespaces/heat", query: [.init(name: "limit", value: "100")],
                   secondary: [("api/v1/ai/congestion-brief", [])], liveEvery: 10) { heat, extra in
            let rows = heat.rows(at: "rows", idKeys: ["namespace"])
            VStack(spacing: 0) {
                StatRow(stats: [
                    .init(title: "Namespaces", symbol: "square.stack.3d.up") { String($0.rows(at: "rows").count) },
                    .init(title: "Packets", symbol: "shippingbox") { TrafficData.compact(TrafficData.sum($0, key: "packets")) },
                    .init(title: "Blocked", symbol: "xmark.octagon", tint: .red) { TrafficData.compact(TrafficData.sum($0, key: "blocked")) },
                    .init(title: "Hottest", symbol: "thermometer.high", tint: .orange) { MoreData.hottestNamespace($0) ?? "" },
                ], value: heat).padding([.horizontal, .top])
                if let brief = extra.first ?? nil { briefCard(brief) }
                else { Text("The AI congestion brief is unavailable; showing namespace heat only.").font(.caption).foregroundStyle(.secondary).padding(.horizontal) }
                RankedBarsCard(title: "Namespaces by packets", bars: TrafficData.rankedBars(heat, top: 10, valueKey: "packets", blockedKey: "blocked") { $0["namespace"]?.string })
                MoreRowsTable(rows: rows, columns: [
                    .init(title: "Namespace", path: "namespace", width: 200), .init(title: "Packets", path: "packets", kind: .int, width: 90),
                    .init(title: "Bytes", path: "bytes", kind: .bytes, width: 90), .init(title: "Blocked", path: "blocked", kind: .int, width: 80),
                    .init(title: "Destinations", path: "destinations", kind: .int, width: 90),
                ], empty: "No namespace traffic observed yet.")
            }
        }
    }

    private func briefCard(_ b: JSONValue) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                HStack { MoreLevel(text: b["severity"]?.string ?? ""); Text(b["headline"]?.string ?? "").font(.headline); Spacer()
                    Text(b["engine"]?.string ?? "").font(.caption).foregroundStyle(.secondary) }
                Text(b["summary"]?.string ?? "").textSelection(.enabled)
                ForEach(b.rows(at: "findings", idKeys: ["kind"])) { f in
                    Text("\(f.value["kind"]?.string ?? "") \(f.value["subject"]?.string ?? ""): \(f.value["message"]?.string ?? "")")
                        .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                }
                let steps = MoreData.strings(b, at: "nextSteps")
                if !steps.isEmpty { Text("Next: " + steps.joined(separator: " · ")).font(.caption) }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }.padding(.horizontal).padding(.bottom, 8)
    }
}
