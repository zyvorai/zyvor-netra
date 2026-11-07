// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit
import AppKit

/// "Ask Netra": POST /api/v1/ai/ask (read-only question) and POST /api/v1/ai/draft (text-only preview).
/// Requests are built with the plain client and never carry X-Netra-Confirm-Risk; nothing here applies anything.
struct AskPanel: View {
    @Environment(AppModel.self) private var model
    @Binding var question: String
    @State private var answer: AskData.Brief?
    @State private var draft: AskData.Draft?
    @State private var busy = false
    @State private var error: String?
    @State private var conversationID = UUID().uuidString
    @FocusState private var focused: Bool

    var body: some View {
        AskCard(title: "Ask Netra", symbol: "text.bubble") {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    TextField("Ask about drops, DNS, stale agents, exposure…", text: $question, axis: .vertical)
                        .lineLimit(1...3).textFieldStyle(.roundedBorder).focused($focused)
                        .onSubmit { Task { await ask() } }
                        .accessibilityLabel("Question for Netra")
                    Button("Ask", systemImage: "paperplane.fill") { Task { await ask() } }
                        .keyboardShortcut(.return, modifiers: .command).disabled(!canSend)
                    Button("Draft rule", systemImage: "doc.text") { Task { await makeDraft() } }
                        .help("Preview a rule as text. Nothing is applied.").disabled(!canSend)
                    Button("New conversation", systemImage: "arrow.counterclockwise") { reset() }
                        .labelStyle(.iconOnly).help("Start a new conversation")
                }
                Text("Read-only: answers come from the controller's heuristic engine (or its optional LLM rewrite). Questions never change mode, rules or policy.")
                    .font(.caption).foregroundStyle(.secondary)
                if busy { ProgressView().controlSize(.small) }
                if let error { Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.red).font(.callout) }
                if let answer { AskAnswerView(brief: answer) }
                if let draft { AskDraftView(draft: draft) }
            }
        }
    }

    private var canSend: Bool { !busy && model.client != nil && !question.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

    private func post(_ path: String) async throws -> JSONValue {
        guard let c = model.client else { throw NetraError.transport("not connected") }
        // Plain client request: no confirmRisk, so this can never be taken for a mutation.
        var req = c.request("POST", path, body: AskData.askBody(question: question, conversationID: path.hasSuffix("/ask") ? conversationID : nil))
        req.timeoutInterval = 60
        return try JSONDecoder().decode(JSONValue.self, from: await c.send(req))
    }

    private func ask() async {
        guard canSend else { return }
        busy = true; error = nil; draft = nil; defer { busy = false }
        do { answer = AskData.brief(try await post("api/v1/ai/ask")) } catch { self.error = describe(error) }
    }

    private func makeDraft() async {
        guard canSend else { return }
        busy = true; error = nil; answer = nil; defer { busy = false }
        do { draft = AskData.draft(try await post("api/v1/ai/draft")) } catch { self.error = describe(error) }
    }

    private func reset() {
        let old = conversationID; conversationID = UUID().uuidString; answer = nil; draft = nil; error = nil
        guard let c = model.client else { return }
        // Best-effort: clear server-side conversation memory (POST /ai/forget; read-only state, not a mutation of Netra config).
        let body = try? JSONSerialization.data(withJSONObject: ["conversationId": old])
        Task { _ = try? await c.send(c.request("POST", "api/v1/ai/forget", body: body)) }
    }

    private func describe(_ e: Error) -> String {
        if case NetraError.http(let s, let m) = e { return "HTTP \(s): \(m)" }
        return e.localizedDescription
    }
}

struct AskAnswerView: View {
    let brief: AskData.Brief
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Divider()
            HStack { AskSeverityBadge(severity: brief.severity); Text(brief.headline).font(.headline); Spacer()
                Text(brief.engine).font(.caption).foregroundStyle(.secondary) }
            if !brief.summary.isEmpty { AskRichText(text: brief.summary) }
            if !brief.nextSteps.isEmpty {
                ForEach(Array(brief.nextSteps.enumerated()), id: \.offset) { _, s in Label { AskRichText(text: s) } icon: { Image(systemName: "chevron.right") } }
            }
            if !brief.citations.isEmpty { Text("Citations").font(.caption).foregroundStyle(.secondary); AskFlowChips(items: brief.citations) }
        }
    }
}

/// Draft output is display-only: text plus a copy button. There is no apply path in this app.
struct AskDraftView: View {
    let draft: AskData.Draft
    @State private var copied = false
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Divider()
            Label("Draft (text only, nothing is applied)", systemImage: "doc.plaintext").font(.headline)
            HStack(spacing: 8) {
                Text(draft.understood ? "Understood" : "Not understood").font(.caption.weight(.semibold))
                if !draft.confidence.isEmpty { Text("confidence: \(draft.confidence)").font(.caption).foregroundStyle(.secondary) }
                if !draft.kind.isEmpty { Text(draft.kind).font(.caption).padding(.horizontal, 6).background(.quaternary, in: Capsule()) }
            }
            Text(draft.copyText).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                .background(.quaternary.opacity(0.6), in: RoundedRectangle(cornerRadius: 8))
            if !draft.note.isEmpty { Text(draft.note).font(.caption).foregroundStyle(.secondary) }
            Text("To act on this, review it and use the Rules or Policies pages (which require explicit confirmation) or the CLI yourself.")
                .font(.caption).foregroundStyle(.secondary)
            Button(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc") {
                NSPasteboard.general.clearContents(); NSPasteboard.general.setString(draft.copyText, forType: .string); copied = true
            }
        }
    }
}
