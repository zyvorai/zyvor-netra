// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

@MainActor @Observable
final class TopologyModel {
    enum Source: String, CaseIterable, Identifiable { case observed = "Observed flows", dependencies = "Dependencies"
        var id: String { rawValue } }

    var graph = TopologyGraph()
    var layout = ForceLayout()
    var source: Source = .observed
    var search = ""
    var selected: String?
    var showBlast = false
    var blast: BlastRadius?
    var blastError: String?
    var error: String?
    var loading = false
    var zoom = 1.0
    var pan = CGSize.zero
    private var simTask: Task<Void, Never>?
    private var loadTask: Task<Void, Never>?

    var edgePairs: [(String, String)] { graph.edges.map { ($0.source, $0.target) } }

    func nodeByID(_ id: String) -> TopologyNode? { graph.nodes.first { $0.id == id } }

    /// Nodes matching the search box (empty set when no query).
    var highlighted: Set<String> {
        let q = search.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return [] }
        return Set(graph.nodes.filter {
            FuzzyMatch.match(query: q, in: $0.label) != nil || FuzzyMatch.match(query: q, in: $0.id) != nil
        }.map(\.id))
    }

    func load(client: NetraClient?) async {
        guard let client else { error = "Not connected"; return }
        loading = true; defer { loading = false }
        do {
            let g = source == .observed ? try await client.topologyGraph() : try await client.dependencyGraph()
            graph = g; error = nil
            layout.sync(nodes: g.nodes.map(\.id), edges: edgePairs)
            if let s = selected, nodeByID(s) == nil { selected = nil }
            startSim()
        } catch { self.error = "\(error)" }
        if showBlast { await loadBlast(client: client) }
    }

    func loadBlast(client: NetraClient?) async {
        guard let client, let s = selected else { blast = nil; return }
        do { blast = try await client.blastRadius(root: s); blastError = nil }
        catch { blast = nil; blastError = "Blast radius unavailable: \(error)" }
    }

    func startSim() {
        simTask?.cancel()
        simTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                let edges = self.edgePairs
                for _ in 0..<2 { self.layout.step(edges: edges) }
                if self.layout.settled { return }
                try? await Task.sleep(for: .milliseconds(16))
            }
        }
    }
    func stopSim() { simTask?.cancel() }

    func worldToScreen(_ p: Vec2, in size: CGSize) -> CGPoint {
        CGPoint(x: size.width / 2 + pan.width + p.x * zoom, y: size.height / 2 + pan.height + p.y * zoom)
    }
    func screenToWorld(_ p: CGPoint, in size: CGSize) -> Vec2 {
        Vec2((p.x - size.width / 2 - pan.width) / zoom, (p.y - size.height / 2 - pan.height) / zoom)
    }
    func hit(_ p: CGPoint, in size: CGSize) -> String? {
        var best: (String, Double)?
        for (id, pos) in layout.positions {
            let s = worldToScreen(pos, in: size)
            let d = hypot(s.x - p.x, s.y - p.y)
            if d <= 12 + 2 * zoom, d < (best?.1 ?? .infinity) { best = (id, d) }
        }
        return best?.0
    }
    func fit() { zoom = 1; pan = .zero }
}
