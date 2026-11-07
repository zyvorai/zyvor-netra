// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// Pod inventory with health, restarts and lockdown state. Read-only (no exec, no console).
struct PodsPage: View {
    var body: some View {
        WLPage(title: "Pods", subtitle: "api/v1/pods", liveEvery: 10, load: { c in try await wlGET(c, "api/v1/pods", timeout: 30) }) { value, query in
            let rows = WorkloadData.podRows(value)
            let s = WorkloadData.podSummary(rows)
            VStack(spacing: 0) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        StatCard(title: "Pods", value: "\(s.total)", symbol: "cube")
                        StatCard(title: "Running", value: "\(s.running)", symbol: "checkmark.circle", tint: .green)
                        StatCard(title: "Not ready", value: "\(s.notReady)", symbol: "exclamationmark.triangle", tint: s.notReady > 0 ? .orange : .secondary)
                        StatCard(title: "Failed / unknown", value: "\(s.failed)", symbol: "xmark.octagon", tint: s.failed > 0 ? .red : .secondary)
                        StatCard(title: "Restarts", value: "\(s.restarts)", symbol: "arrow.triangle.2.circlepath", tint: s.restarts > 0 ? .orange : .secondary)
                        StatCard(title: "Locked down", value: "\(s.lockedDown)", symbol: "lock.fill", tint: s.lockedDown > 0 ? .red : .secondary)
                    }.padding([.horizontal, .top])
                }.padding(.bottom, 8)
                ChartRow {
                    DonutCard(title: "Phase", data: [
                        ("Running", Double(s.running), .green), ("Pending", Double(s.pending), .orange),
                        ("Failed", Double(s.failed), .red),
                        ("Other", Double(s.total - s.running - s.pending - s.failed), .gray),
                    ])
                    BarCard(title: "Most restarts", data: rows.filter { ($0.value.at("restartTotal")?.asDouble ?? 0) > 0 }
                        .sorted { ($0.value.at("restartTotal")?.asDouble ?? 0) > ($1.value.at("restartTotal")?.asDouble ?? 0) }
                        .prefix(5).map { (($0.value.at("name")?.string ?? "?"), $0.value.at("restartTotal")?.asDouble ?? 0) }, tint: .orange)
                }
                WLTable(rows: rows, columns: [
                    WCol(title: "Namespace", path: "namespace", width: 90),
                    WCol(title: "Pod", path: "name", width: 150),
                    WCol(title: "Health", path: "health", sortPath: "healthRank", style: .level, width: 90),
                    WCol(title: "Phase", path: "phase"),
                    WCol(title: "Ready", path: "containersText"),
                    WCol(title: "Restarts", path: "restartTotal", kind: .int),
                    WCol(title: "Age", path: "started", kind: .time),
                    WCol(title: "Node", path: "node"),
                    WCol(title: "IP", path: "podIP"),
                    WCol(title: "Owner", path: "owner", width: 110),
                    WCol(title: "Lockdown", path: "lockedDownText", sortPath: "lockedDown", style: .lockedBadge, width: 100),
                ], query: query, empty: "No pods returned.") { row in
                    VStack(alignment: .leading, spacing: 12) {
                        let ns = row.value.at("namespace")?.string ?? "", name = row.value.at("name")?.string ?? ""
                        KVSection(title: "Pod", items: [
                            ("Namespace", ns), ("Name", name),
                            ("Health", CellFormat.text(row.value.at("health"), .text)),
                            ("Service account", CellFormat.text(row.value.at("serviceAccountName"), .text)),
                            ("Started", CellFormat.text(row.value.at("started"), .time)),
                        ])
                        if !ns.isEmpty, !name.isEmpty { WorkloadDetailView(kind: "pod", namespace: ns, name: name, allowLogs: true) }
                        if !ns.isEmpty, !name.isEmpty { ConOpenButton(namespace: ns, name: name) }
                        LabelsView(pairs: WorkloadData.labelPairs(row.value.at("labels")))
                        RawJSON(value: row.value)
                    }
                }
            }
        }
    }
}
