// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

struct TopologyCanvas: View {
    @Bindable var model: TopologyModel
    @State private var dragNode: String?
    @State private var dragStartPan = CGSize.zero
    @State private var dragMoved = false
    @State private var zoomStart: Double?

    var body: some View {
        GeometryReader { geo in
            Canvas { ctx, size in draw(ctx, size) }
                .contentShape(Rectangle())
                .gesture(DragGesture(minimumDistance: 0)
                    .onChanged { v in
                        if !dragMoved && dragNode == nil && v.translation == .zero {
                            dragNode = model.hit(v.startLocation, in: geo.size)
                            dragStartPan = model.pan
                        }
                        if hypot(v.translation.width, v.translation.height) > 3 { dragMoved = true }
                        guard dragMoved else { return }
                        if let id = dragNode {
                            model.layout.pinned.insert(id)
                            model.layout.move(id, to: model.screenToWorld(v.location, in: geo.size))
                        } else {
                            model.pan = CGSize(width: dragStartPan.width + v.translation.width,
                                               height: dragStartPan.height + v.translation.height)
                        }
                    }
                    .onEnded { v in
                        if !dragMoved {
                            model.selected = model.hit(v.startLocation, in: geo.size)
                        } else if let id = dragNode {
                            model.layout.pinned.remove(id)
                            model.startSim()
                        }
                        dragNode = nil; dragMoved = false
                    })
                .gesture(MagnifyGesture()
                    .onChanged { v in
                        if zoomStart == nil { zoomStart = model.zoom }
                        model.zoom = min(4, max(0.2, zoomStart! * v.magnification))
                    }
                    .onEnded { _ in zoomStart = nil })
        }
        .background(Color(nsColor: .textBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(.separator))
    }

    static func color(for kind: String) -> Color {
        switch kind {
        case "workload": .purple
        case "service": .green
        case "pod": .cyan
        case "external": .gray
        default: .blue
        }
    }

    private func draw(_ ctx: GraphicsContext, _ size: CGSize) {
        let hl = model.highlighted
        let searching = !hl.isEmpty || !model.search.trimmingCharacters(in: .whitespaces).isEmpty
        let sel = model.selected
        let near: Set<String> = sel.map { model.graph.neighbors(of: $0).union([$0]) } ?? []
        let blast = model.showBlast ? model.blast?.hops : nil

        for e in model.graph.edges {
            guard let a = model.layout.positions[e.source], let b = model.layout.positions[e.target] else { continue }
            let pa = model.worldToScreen(a, in: size), pb = model.worldToScreen(b, in: size)
            var path = Path(); path.move(to: pa); path.addLine(to: pb)
            let involved = sel == nil || e.source == sel || e.target == sel
            var c: Color = e.blocked > 0 ? .red : .secondary
            if let blast, blast[e.source] != nil, blast[e.target] != nil { c = .orange }
            let w = max(1, min(6, log10(e.packets + 10)))
            ctx.stroke(path, with: .color(c.opacity(involved ? 0.7 : 0.15)),
                       style: StrokeStyle(lineWidth: w, dash: e.external ? [5, 4] : []))
            if model.zoom > 1.3 && involved {
                ctx.draw(Text(e.label).font(.system(size: 9)).foregroundStyle(.secondary),
                         at: CGPoint(x: (pa.x + pb.x) / 2, y: (pa.y + pb.y) / 2))
            }
        }
        for n in model.graph.nodes {
            guard let p = model.layout.positions[n.id] else { continue }
            let s = model.worldToScreen(p, in: size)
            let r = 7 + 2 * model.zoom
            var fill = Self.color(for: n.kind)
            var dim = (sel != nil && !near.contains(n.id)) || (searching && !hl.contains(n.id))
            if let blast {
                if let h = blast[n.id] { fill = h == 0 ? .red : .orange; dim = false } else { dim = true }
            }
            let rect = CGRect(x: s.x - r, y: s.y - r, width: 2 * r, height: 2 * r)
            ctx.fill(Path(ellipseIn: rect), with: .color(fill.opacity(dim ? 0.25 : 1)))
            if n.id == sel || hl.contains(n.id) {
                ctx.stroke(Path(ellipseIn: rect.insetBy(dx: -4, dy: -4)),
                           with: .color(n.id == sel ? .accentColor : .yellow), lineWidth: 2)
            }
            if model.zoom > 0.6 && !dim {
                ctx.draw(Text(n.label).font(.system(size: 10)), at: CGPoint(x: s.x, y: s.y + r + 8))
            }
        }
    }
}
