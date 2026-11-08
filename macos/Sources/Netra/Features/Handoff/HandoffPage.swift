// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import AppKit
import NetraKit

/// On-call handoff: the controller's shift-note pack (report, playbook, fleet, coverage, audit, drop reasons).
/// Read-only. Copy or save the Markdown for a ticket, or save the JSON; nothing here changes the controller.
struct HandoffPage: View {
    @Environment(AppModel.self) private var model
    @State private var text = ""
    @State private var headline = HandoffHeadline()
    @State private var loading = false
    @State private var problem: String?
    @State private var note: String?

    var body: some View {
        Group {
            if model.client == nil || model.whoami == nil {
                ContentUnavailableView("Not connected", systemImage: "bolt.slash", description: Text("Connect to a Netra controller first."))
            } else {
                VStack(alignment: .leading, spacing: 0) {
                    summary.padding()
                    Divider()
                    if let problem {
                        Label(problem, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red).padding()
                    }
                    ScrollView {
                        Text(text.isEmpty && !loading ? "Nothing loaded yet." : text)
                            .font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading).padding()
                    }
                }
            }
        }
        .navigationTitle("Handoff")
        .navigationSubtitle("Read-only shift-note pack")
        .toolbar {
            ToolbarItemGroup {
                if loading { ProgressView().controlSize(.small) }
                Button { Task { await load() } } label: { Label("Refresh", systemImage: "arrow.clockwise") }
                    .disabled(loading || model.client == nil)
                Button { copy() } label: { Label("Copy Markdown", systemImage: "doc.on.doc") }.disabled(text.isEmpty)
                Button { Task { await save(.markdown) } } label: { Label("Save Markdown…", systemImage: "square.and.arrow.down") }
                    .disabled(model.client == nil)
                Button { Task { await save(.json) } } label: { Label("Save JSON…", systemImage: "curlybraces") }
                    .disabled(model.client == nil)
            }
        }
        .task(id: model.client == nil) { if model.client != nil { await load() } }
    }

    private var summary: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 18) {
                stat("Agents", headline.agents, extra: headline.staleAgents.map { "\($0) stale" })
                stat("Workloads", headline.workloads)
                stat("Detached programs", headline.detachedPrograms)
                stat("Missing map entries", headline.missingMaps)
                stat("Drop events", headline.dropEvents, extra: headline.blockedEvents.map { "\($0) blocked" })
                Spacer()
            }
            HStack {
                if let g = headline.generatedAt { Text("Generated \(g)").font(.caption).foregroundStyle(.secondary) }
                if let note { Text(note).font(.caption).foregroundStyle(.secondary).textSelection(.enabled) }
            }
            Label("Observe-only: this pack never applies policy or extends a lease.", systemImage: "eye")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func stat(_ title: String, _ value: Int?, extra: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value.map(String.init) ?? "–").font(.title3.monospacedDigit().weight(.semibold))
            if let extra { Text(extra).font(.caption2).foregroundStyle(.secondary) }
        }
    }

    private func load() async {
        guard let c = model.client else { return }
        loading = true; problem = nil; defer { loading = false }
        do {
            async let md = c.handoff(.markdown)
            async let js = c.handoff(.json)
            let (m, j) = try await (md, js)
            text = String(decoding: m.data, as: UTF8.self)
            headline = HandoffHeadline.parse(j.data)
        } catch { problem = opsDescribe(error) }
    }

    private func copy() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        note = "Copied to the clipboard."
    }

    private func save(_ format: HandoffFormat) async {
        guard let c = model.client else { return }
        do {
            let f = try await c.handoff(format)
            let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
            note = OpsSave.save(f.data, suggestedName: "netra-handoff-\(stamp).\(format.fileExtension)").map { "Saved: \($0)" }
        } catch { problem = opsDescribe(error) }
    }
}
