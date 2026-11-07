// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

struct TopologyInspector: View {
    let model: TopologyModel
    var body: some View {
        if let id = model.selected, let n = model.nodeByID(id) {
            let out = model.graph.edges.filter { $0.source == id }
            let inc = model.graph.edges.filter { $0.target == id }
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    Text(n.label).font(.headline).textSelection(.enabled)
                    row("Kind", n.kind)
                    if !n.workloadKind.isEmpty { row("Workload", n.workloadKind) }
                    if !n.ip.isEmpty { row("IP", n.ip) }
                    row("Outbound edges", "\(out.count)")
                    row("Inbound edges", "\(inc.count)")
                    row("Packets", fmt(out.map(\.packets).reduce(0, +) + inc.map(\.packets).reduce(0, +)))
                    let blocked = (out + inc).map(\.blocked).reduce(0, +)
                    if blocked > 0 { row("Blocked", fmt(blocked)) }
                    if let b = model.blast, model.showBlast {
                        Divider()
                        row("Blast radius", "\(b.hops.count) nodes within \(b.maxHops) hops")
                        if b.truncated { Text("Truncated").font(.caption).foregroundStyle(.orange) }
                        if !b.caveat.isEmpty { Text(b.caveat).font(.caption).foregroundStyle(.secondary) }
                    }
                    if let e = model.blastError, model.showBlast { Text(e).font(.caption).foregroundStyle(.secondary) }
                    Divider()
                    ForEach(Array((out + inc).prefix(40))) { e in
                        Text("\(model.nodeByID(e.source)?.label ?? e.source) → \(model.nodeByID(e.target)?.label ?? e.target)  \(e.label)")
                            .font(.caption).foregroundStyle(e.blocked > 0 ? .red : .secondary)
                    }
                }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("No selection", systemImage: "cursorarrow.click", description: Text("Click a node"))
        }
    }
    private func row(_ k: String, _ v: String) -> some View {
        HStack { Text(k).foregroundStyle(.secondary); Spacer(); Text(v).textSelection(.enabled) }.font(.callout)
    }
    private func fmt(_ d: Double) -> String { d.formatted(.number.notation(.compactName)) }
}
