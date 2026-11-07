// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Brief, Digest and Suggestions: GET the heuristic output, render it as cards, offer the Ask panel.
struct AIPage: View {
    let section: NavSection
    @Environment(AppModel.self) private var model
    @State private var value: JSONValue?
    @State private var status: AskData.Status?
    @State private var error: String?
    @State private var loading = false
    @State private var question = ""

    var body: some View {
        Group {
            if model.client == nil || model.whoami == nil {
                ContentUnavailableView("Not connected", systemImage: "bolt.slash", description: Text("Connect to a Netra controller first."))
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        AskStatusStrip(status: status)
                        if let value { content(value) }
                        else if let error { ContentUnavailableView("Couldn't load \(section.title)", systemImage: "exclamationmark.triangle", description: Text(error)) }
                        else { ProgressView().controlSize(.large).frame(maxWidth: .infinity) }
                        AskPanel(question: $question)
                    }.padding()
                }
            }
        }
        .navigationTitle(section.title).navigationSubtitle(section.endpoint ?? "")
        .toolbar { Button("Refresh", systemImage: "arrow.clockwise") { Task { await load() } }.disabled(loading) }
        .task(id: section) { value = nil; error = nil; await load() }
    }

    @ViewBuilder private func content(_ v: JSONValue) -> some View {
        switch section {
        case .aiDigest:
            let d = AskData.digest(v)
            AskCard(title: d.headline.isEmpty ? "Digest" : d.headline, symbol: "newspaper") {
                VStack(alignment: .leading, spacing: 8) {
                    HStack { AskSeverityBadge(severity: d.severity)
                        Label(d.changed ? "Changed since last digest" : "Unchanged", systemImage: d.changed ? "arrow.triangle.2.circlepath" : "equal.circle")
                            .font(.caption).foregroundStyle(d.changed ? .orange : .secondary) }
                    if !d.card.isEmpty { AskRichText(text: d.card) }
                    if !d.whyChangedProse.isEmpty { AskRichText(text: d.whyChangedProse).foregroundStyle(.secondary) }
                    ForEach(d.whyChanged, id: \.self) { Label($0, systemImage: "chevron.right").font(.callout) }
                }
            }
            if !d.suggestions.isEmpty { AskSuggestionChips(items: d.suggestions, question: $question) }
            AskBriefCards(brief: d.brief)
        case .aiSuggestions:
            let items = AskData.suggestions(v)
            if items.isEmpty { ContentUnavailableView("No suggestions", systemImage: "wand.and.stars", description: Text("Nothing stands out right now.")) }
            else { AskSuggestionChips(items: items, question: $question) }
        default:
            let b = AskData.brief(v)
            if b.isEmpty { ContentUnavailableView("No brief yet", systemImage: "sparkles") } else { AskBriefCards(brief: b) }
        }
    }

    private func load() async {
        guard let c = model.client else { return }
        loading = true; defer { loading = false }
        async let st = try? JSONDecoder().decode(JSONValue.self, from: c.send(c.request("GET", "api/v1/ai/status")))
        do {
            var req = c.request("GET", section.endpoint ?? ""); req.timeoutInterval = 60
            value = try JSONDecoder().decode(JSONValue.self, from: await c.send(req)); error = nil
        } catch NetraError.http(let s, let m) { error = "HTTP \(s): \(m)" } catch { self.error = error.localizedDescription }
        if let s = await st { status = AskData.status(s) }
    }
}

struct AskStatusStrip: View {
    let status: AskData.Status?
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: status?.enabled == true ? "brain" : "gearshape.2").foregroundStyle(status?.enabled == true ? .purple : .secondary)
            Text(status?.label ?? "AI status unknown").font(.callout.weight(.medium))
            if let m = status?.mutations, !m.isEmpty { Text(m).font(.caption).foregroundStyle(.secondary) }
            Spacer()
        }
        .padding(8).background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
        .accessibilityElement(children: .combine)
    }
}

/// Suggested follow-up questions. Tapping fills the Ask field; it never asks or applies anything by itself.
struct AskSuggestionChips: View {
    let items: [String]
    @Binding var question: String
    var body: some View {
        AskCard(title: "Suggested questions", symbol: "wand.and.stars") {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(items, id: \.self) { q in
                    Button { question = q } label: {
                        HStack { Image(systemName: "questionmark.bubble"); Text(q).multilineTextAlignment(.leading); Spacer() }
                            .padding(8).background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
                    }.buttonStyle(.plain).accessibilityHint("Puts this question in the Ask field")
                }
            }
        }
    }
}
