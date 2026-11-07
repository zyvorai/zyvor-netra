// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

struct TopologyView: View {
    @Environment(AppModel.self) private var model
    @State private var topo = TopologyModel()

    var body: some View {
        VStack(spacing: 8) {
            toolbar
            if let e = topo.error { Label(e, systemImage: "exclamationmark.triangle").foregroundStyle(.orange).font(.callout) }
            HSplitView {
                Group {
                    if topo.graph.nodes.isEmpty && topo.error == nil && !topo.loading {
                        ContentUnavailableView("No edges observed yet", systemImage: "circle.hexagongrid")
                    } else {
                        TopologyCanvas(model: topo)
                    }
                }.frame(minWidth: 400)
                TopologyInspector(model: topo).frame(minWidth: 240, idealWidth: 280, maxWidth: 380)
            }
        }
        .padding(12)
        .navigationTitle("Topology")
        .task(id: topo.source) {
            while !Task.isCancelled {
                await topo.load(client: model.client)
                try? await Task.sleep(for: .seconds(20))
            }
        }
        .onChange(of: topo.selected) { _, _ in Task { await topo.loadBlast(client: model.client) } }
        .onChange(of: topo.showBlast) { _, _ in Task { await topo.loadBlast(client: model.client) } }
        .onDisappear { topo.stopSim() }
    }

    private var toolbar: some View {
        HStack {
            Picker("Source", selection: $topo.source) {
                ForEach(TopologyModel.Source.allCases) { Text($0.rawValue).tag($0) }
            }.pickerStyle(.segmented).frame(width: 240).labelsHidden()
            TextField("Search nodes", text: $topo.search).textFieldStyle(.roundedBorder).frame(maxWidth: 220)
            Toggle("Blast radius", isOn: $topo.showBlast).help("Overlay /insights/blast-radius for the selected node")
            Spacer()
            Text("\(topo.graph.nodes.count) nodes · \(topo.graph.edges.count) edges")
                .font(.caption).foregroundStyle(.secondary)
            Button { topo.zoom = max(0.2, topo.zoom / 1.25) } label: { Image(systemName: "minus.magnifyingglass") }
            Button { topo.zoom = min(4, topo.zoom * 1.25) } label: { Image(systemName: "plus.magnifyingglass") }
            Button("Fit") { topo.fit() }
            Button { Task { await topo.load(client: model.client) } } label: { Image(systemName: "arrow.clockwise") }
        }
    }
}
