// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// GET /api/v1/node-resources: host CPU, load and memory per node, plus the busiest workloads by CPU.
struct NodeResourcesPage: View {
    @State private var selection: String?
    @State private var sort = [KeyPathComparator(\KernelData.NodeRes.cpuPercent, order: .reverse)]

    var body: some View {
        KernelLoader(title: "Node resources", endpoint: "api/v1/node-resources", query: [.init(name: "limit", value: "50")], liveEvery: 5) { v, _ in
            let nodes = KernelData.nodeResources(v).sorted(using: sort)
            let s = v.at("summary")
            VStack(spacing: 0) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        StatCard(title: "Fresh nodes", value: s?.at("nodes")?.summary ?? "", symbol: "server.rack")
                        StatCard(title: "CPU cores", value: s?.at("totalCpuCores")?.summary ?? "", symbol: "cpu")
                        StatCard(title: "Avg CPU", value: CellFormat.text(s?.at("avgCpuPercent"), .number(1)) + "%", symbol: "gauge.medium")
                        StatCard(title: "Memory used", value: memory(s), symbol: "memorychip")
                        StatCard(title: "Highest CPU", value: s?.at("highestCpuNode")?.string ?? "", symbol: "flame", tint: .orange)
                        StatCard(title: "Highest memory", value: s?.at("highestMemoryNode")?.string ?? "", symbol: "memorychip.fill", tint: .orange)
                    }.padding([.horizontal, .top])
                }.padding(.bottom, 8)
                if nodes.isEmpty { KernelEmpty(text: "No nodes are reporting host resources.") } else {
                    HSplitView {
                        VStack(spacing: 0) {
                            Chart(nodes) { n in
                                BarMark(x: .value("Node", n.node), y: .value("Memory %", (n.memRatio ?? 0) * 100)).foregroundStyle(by: .value("Metric", "Memory"))
                                    .position(by: .value("Metric", "Memory"))
                                BarMark(x: .value("Node", n.node), y: .value("CPU %", (n.cpuRatio ?? 0) * 100)).foregroundStyle(by: .value("Metric", "CPU"))
                                    .position(by: .value("Metric", "CPU"))
                            }
                            .chartYScale(domain: 0...100).chartYAxisLabel("% of capacity")
                            .frame(height: 140).padding(.horizontal)
                            .accessibilityLabel("CPU and memory utilisation per node")
                            Table(nodes, selection: $selection, sortOrder: $sort) {
                                TableColumn("Node", value: \.node) { n in HStack { Text(n.node); if n.stale { Label("stale", systemImage: "clock.badge.exclamationmark").font(.caption).foregroundStyle(.orange) } } }.width(min: 110)
                                TableColumn("CPU", value: \.cpuPercent) { FillBar(ratio: $0.cpuRatio, detail: "\($0.cores) cores") }.width(min: 170)
                                TableColumn("Memory", value: \.memUsed) { n in FillBar(ratio: n.memRatio, detail: "\(CellFormat.bytes(n.memUsed)) / \(CellFormat.bytes(n.memTotal))") }.width(min: 230)
                                TableColumn("Load 1/5/15") { n in Text(String(format: "%.2f  %.2f  %.2f", n.load1, n.load5, n.load15)).monospacedDigit() }.width(min: 120)
                                TableColumn("Uptime", value: \.uptime) { Text(CellFormat.duration($0.uptime)) }.width(min: 70)
                                TableColumn("Kernel", value: \.kernel) { Text($0.kernel) }.width(min: 70)
                            }
                        }
                        workloads(v, node: nodes.first { $0.id == selection }).frame(minWidth: 260, idealWidth: 340)
                    }
                }
            }
        }
    }

    private func memory(_ s: JSONValue?) -> String {
        guard let u = s?.at("usedMemoryBytes")?.asDouble, let t = s?.at("totalMemoryBytes")?.asDouble else { return "" }
        return "\(CellFormat.bytes(u)) / \(CellFormat.bytes(t))"
    }

    @ViewBuilder private func workloads(_ v: JSONValue, node: KernelData.NodeRes?) -> some View {
        let rows = v.rows(at: "topWorkloadsByCpu", idKeys: ["cgroupId", "pod"])
        List {
            if let node {
                Section(node.node) {
                    LabeledContent("Memory cached", value: CellFormat.bytes(node.memCached))
                    LabeledContent("Report age", value: CellFormat.duration(node.ageSeconds))
                    LabeledContent("CPU (sum of cores)", value: String(format: "%.1f%%", node.cpuPercent))
                }
            }
            Section("Top workloads by CPU") {
                if rows.isEmpty { Text("No workload attribution.").foregroundStyle(.secondary) }
                ForEach(rows) { r in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(r.value.at("workloadName")?.string ?? r.value.at("pod")?.string ?? r.value.at("cgroupPath")?.string ?? "cgroup").lineLimit(1)
                        HStack {
                            Text([r.value.at("namespace")?.string, r.value.at("node")?.string].compactMap { $0 }.joined(separator: " · ")).foregroundStyle(.secondary)
                            Spacer()
                            Text(CellFormat.text(r.value.at("cpuPercent"), .number(1)) + "% · " + CellFormat.text(r.value.at("memoryUsedBytes"), .bytes)).monospacedDigit()
                        }.font(.caption)
                    }
                }
            }
        }
    }
}
