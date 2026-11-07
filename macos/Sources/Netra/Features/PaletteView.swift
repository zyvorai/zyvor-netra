// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

struct PaletteView: View {
    @Environment(AppModel.self) private var model
    @Binding var isPresented: Bool
    @State private var query = ""
    @State private var index = 0
    @FocusState private var focused: Bool

    init(isPresented: Binding<Bool> = .constant(true)) { _isPresented = isPresented }

    @State private var store = PaletteStore()

    private var results: [PaletteEntry] { store.entries(query: query) }

    var body: some View {
        VStack(spacing: 0) {
            TextField("Go to, search, or try: drops on ns payments last hour…", text: $query)
                .textFieldStyle(.plain).font(.title3).padding(12).focused($focused)
                .onSubmit { choose(index) }
                .onKeyPress(.downArrow) { index = min(index + 1, max(results.count - 1, 0)); return .handled }
                .onKeyPress(.upArrow) { index = max(index - 1, 0); return .handled }
                .onKeyPress(.escape) { isPresented = false; return .handled }
                .onChange(of: query) { _, _ in index = 0 }
            Divider()
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(Array(results.enumerated()), id: \.element.id) { i, s in
                            HStack {
                                Label(s.title, systemImage: s.symbol)
                                Spacer()
                                Text(s.subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.horizontal, 12).padding(.vertical, 6)
                                .background(i == index ? Color.accentColor.opacity(0.25) : .clear)
                                .contentShape(Rectangle())
                                .onTapGesture { choose(i) }
                                .id(s.id)
                        }
                        if results.isEmpty { Text("No matches").foregroundStyle(.secondary).padding() }
                    }
                }
                .onChange(of: index) { _, i in if results.indices.contains(i) { proxy.scrollTo(results[i].id) } }
            }
            .frame(maxHeight: 320)
        }
        .frame(width: 560)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(.separator))
        .shadow(radius: 24)
        .onAppear { query = ""; index = 0; focused = true }
        .task { await store.load(client: model.client) }
    }

    private func choose(_ i: Int) {
        guard results.indices.contains(i) else { return }
        let router = LinkRouter.shared
        let entry = results[i]
        if case .recent(let t) = entry { query = t; return }   // refill, stay open
        switch entry {
        case .intent, .askAI, .object: store.recents.record(query)
        default: break
        }
        switch entry {
        case .recent: break
        case .intent(let it): router.open(it.link, model: model)
        case .askAI(let t): router.open(AskFallback.link(for: t), model: model)   // navigation only; user presses Ask
        case .section(let s): router.open(DeepLink(section: s.rawValue), model: model)
        case .object(let o): router.open(DeepLink(section: o.section, query: o.query), model: model)
        case .openWeb: router.openInWeb(model: model)
        case .copyLink: router.copyDeepLink(section: model.selection ?? .overview)
        }
        isPresented = false
    }
}

struct PaletteOverlay: ViewModifier {
    @State private var shown = false
    func body(content: Content) -> some View {
        content
            .overlay {
                if shown {
                    ZStack(alignment: .top) {
                        Color.black.opacity(0.2).ignoresSafeArea().onTapGesture { shown = false }
                        PaletteView(isPresented: $shown).padding(.top, 80)
                    }
                }
            }
            .background {
                Button("") { shown.toggle() }.keyboardShortcut("k", modifiers: .command).opacity(0).allowsHitTesting(false)
            }
    }
}

extension View {
    /// Adds the ⌘K command palette. Requires AppModel in the environment.
    func paletteOverlay() -> some View { modifier(PaletteOverlay()) }
}
