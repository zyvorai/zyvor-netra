// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import AppKit
import UniformTypeIdentifiers
import NetraKit

/// The read-only computations. Each one POSTs input and shows what the server computed: none of them
/// applies, saves or enforces anything (the server lets viewers call them), so no MutationFlow is involved.
enum TlTool: String, Identifiable, CaseIterable {
    case build, simulate, denyHistory, watchlist
    var id: String { rawValue }
    var title: String {
        switch self {
        case .build: "Build policy"
        case .simulate: "Simulate policy"
        case .denyHistory: "Replay a deny"
        case .watchlist: "Watchlist match"
        }
    }
    var blurb: String {
        switch self {
        case .build: "Generates a CiliumNetworkPolicy manifest from a few fields. It only returns text: nothing is applied or saved."
        case .simulate: "Evaluates a candidate policy against observed dependencies and workload labels. Read-only; no plan token is issued and nothing is applied."
        case .denyHistory: "Replays a proposed deny against retained flow history. A historical estimate, not a determination, and nothing is denied."
        case .watchlist: "Checks a feed (IPs, CIDRs, names) against what agents observed. Observe-only: nothing is added to any rule."
        }
    }
    var symbol: String {
        switch self {
        case .build: "hammer"
        case .simulate: "play.rectangle"
        case .denyHistory: "clock.arrow.circlepath"
        case .watchlist: "binoculars"
        }
    }
    var fields: [FormField] {
        switch self {
        case .build: PolicyTools.buildFields
        case .denyHistory: PolicyTools.denyHistoryFields
        case .simulate: [.init("manifest", "CiliumNetworkPolicy (JSON)", .multiline)]
        case .watchlist: [.init("feed", "Feed", .multiline, help: "One IP, CIDR or name per line, CSV (type,value,direction) or JSON"),
                          .init("limit", "Max hits", .number, initial: "200", help: "1-500")]
        }
    }
}

struct TlReadSheet: View {
    @State var tool: TlTool
    var seed: FormValues = [:]
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var values: FormValues = [:]
    @State private var running = false
    @State private var problem: String?
    @State private var headline = ""
    @State private var output = ""
    @State private var builtManifest = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(tool.title).font(.headline)
            Label(tool.blurb, systemImage: "eye").font(.callout).foregroundStyle(.secondary)
            ScrollView { VStack(alignment: .leading, spacing: 10) { ForEach(tool.fields) { field($0) } } }.frame(maxHeight: 300)
            if let problem { Label(problem, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red).font(.callout) }
            if !headline.isEmpty { Text(headline).font(.callout.weight(.medium)).textSelection(.enabled) }
            if !output.isEmpty {
                ScrollView { Text(output).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading) }
                    .frame(minHeight: 140, maxHeight: 240).padding(6).background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 6))
            }
            HStack {
                if tool == .build, !builtManifest.isEmpty {
                    Button("Copy manifest") { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(builtManifest, forType: .string) }
                    Button("Simulate this") { values = ["manifest": builtManifest]; tool = .simulate; headline = ""; output = "" }
                }
                if running { ProgressView().controlSize(.small) }
                Spacer()
                Button("Close") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Run") { Task { await run() } }.keyboardShortcut(.defaultAction).disabled(running || model.client == nil)
            }
        }
        .padding().frame(width: 560)
        .onAppear { for f in tool.fields where values[f.key] == nil { values[f.key] = seed[f.key] ?? f.initial } }
    }

    @ViewBuilder private func field(_ f: FormField) -> some View {
        let b = Binding(get: { values[f.key] ?? f.initial }, set: { values[f.key] = $0 })
        VStack(alignment: .leading, spacing: 3) {
            switch f.kind {
            case .toggle: Toggle(f.label, isOn: Binding(get: { b.wrappedValue == "true" }, set: { b.wrappedValue = $0 ? "true" : "false" }))
            case .choice(let o): Picker(f.label, selection: b) { ForEach(o, id: \.self) { Text($0.isEmpty ? "any" : $0).tag($0) } }
            case .multiline:
                Text(f.label).font(.caption.weight(.medium))
                TextEditor(text: b).font(.system(.caption, design: .monospaced)).frame(height: 120)
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(.quaternary))
            case .text, .number: TextField(f.label, text: b).textFieldStyle(.roundedBorder)
            }
            if !f.help.isEmpty { Text(f.help).font(.caption2).foregroundStyle(.secondary) }
        }
    }

    private func run() async {
        guard let c = model.client else { return }
        problem = nil; headline = ""; output = ""; builtManifest = ""
        let built: Result<URLRequest, FormError>
        switch tool {
        case .build: built = PolicyTools.buildRequest(c, values)
        case .simulate: built = PolicyTools.simulateRequest(c, manifest: values["manifest"] ?? "")
        case .denyHistory: built = PolicyTools.denyHistoryRequest(c, values)
        case .watchlist: built = PolicyTools.watchlistMatchRequest(c, feed: values["feed"] ?? "", limit: Int(values["limit"] ?? "") ?? 200)
        }
        guard case .success(let req) = built else { if case .failure(let e) = built { problem = e.message }; return }
        running = true; defer { running = false }
        do {
            let data = try await c.send(req)
            let v = (try? JSONDecoder().decode(JSONValue.self, from: data)) ?? .null
            switch tool {
            case .build:
                if let m = PolicyToolsData.builtManifest(data) { headline = m.summary; output = m.text; builtManifest = m.text }
                else { output = String(decoding: data, as: UTF8.self) }
            case .simulate: headline = PolicyToolsData.simulateSummary(v); output = PolicyToolsData.pretty(v)
            case .denyHistory: headline = PolicyToolsData.denyHistorySummary(v); output = PolicyToolsData.pretty(v["result"] ?? v)
            case .watchlist: headline = PolicyToolsData.watchlistSummary(v); output = PolicyToolsData.pretty(v["match"] ?? v)
            }
        } catch { problem = tlDescribe(error) }
    }
}

/// Pick an exported history archive from disk, check it locally, then run the guarded import.
struct TlImportSheet: View {
    var log: ActivityLog
    var onDone: () -> Void
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var archive = ""
    @State private var mode = "merge"
    @State private var picking = false
    @State private var flow: MutationFlow?
    @State private var problem: String?

    var body: some View {
        if let flow {
            MutationSheet(flow: flow, onClose: { onDone(); dismiss() }) {
                Text("Rewrites the controller's rollback history only. Admin role required by the server.").font(.callout)
            }
        } else {
            VStack(alignment: .leading, spacing: 10) {
                HStack { Text("Import policy history").font(.headline); RiskBadge(risk: .high) }
                Text("Merge appends to the recorded history. Replace discards it first and needs a typed phrase. Nothing is applied to the cluster.")
                    .font(.callout).foregroundStyle(.secondary)
                Picker("Mode", selection: $mode) { Text("Merge").tag("merge"); Text("Replace").tag("replace") }.pickerStyle(.segmented)
                HStack {
                    Button("Choose file…") { picking = true }
                    if case .success(let i) = PolicyToolsData.inspectArchive(archive) {
                        Text("\(i.revisions) revision(s), \(i.policies) policy(ies)").font(.caption).foregroundStyle(.secondary)
                    }
                }
                if let problem { Label(problem, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red).font(.callout) }
                HStack {
                    Spacer()
                    Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                    Button("Continue") { begin() }.keyboardShortcut(.defaultAction).disabled(!model.gate.canMutate || archive.isEmpty)
                }
            }
            .padding().frame(width: 480)
            .fileImporter(isPresented: $picking, allowedContentTypes: [.json]) { r in
                guard case .success(let url) = r else { return }
                let scoped = url.startAccessingSecurityScopedResource(); defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                if let d = try? Data(contentsOf: url), d.count <= PolicyToolsData.archiveByteLimit {
                    archive = String(decoding: d, as: UTF8.self); problem = nil
                } else { problem = "Could not read that file (or it is over 16 MB)" }
            }
        }
    }

    private func begin() {
        guard let c = model.client, let a = PolicyTools.find("policy-history-import") else { return }
        switch a.build(c, ["archive": archive, "mode": mode]) {
        case .failure(let e): problem = e.message
        case .success(let spec): flow = MutationFlow(spec: spec, client: c, gate: model.gate, log: log)
        }
    }
}

/// Policies-tab menu: every tool in one place. Read-only tools are open to any token; guarded ones are disabled for read-only tokens.
struct TlToolsMenu: View {
    var log: ActivityLog
    var onChanged: () -> Void
    @Environment(AppModel.self) private var model
    @State private var tool: TlTool?
    @State private var guarded: ControlAction?
    @State private var importing = false
    @State private var note: String?

    var body: some View {
        Menu("Policy tools", systemImage: "wrench.and.screwdriver") {
            ForEach(TlTool.allCases) { t in Button(t.title + "…", systemImage: t.symbol) { tool = t } }
            Divider()
            Button("Export policy history…", systemImage: "square.and.arrow.up") { Task { await export() } }
            Button("Import policy history…", systemImage: "square.and.arrow.down.on.square") { importing = true }.disabled(!model.gate.canMutate)
            Divider()
            ForEach(PolicyTools.actions.filter { $0.id != "policy-history-import" }) { a in
                Button(a.title + "…", systemImage: a.symbol) { guarded = a }.disabled(!model.gate.canMutate)
            }
        }
        .sheet(item: $tool) { TlReadSheet(tool: $0) }
        .sheet(item: $guarded) { ActionFormSheet(action: $0, log: log) }
        .sheet(isPresented: $importing) { TlImportSheet(log: log, onDone: onChanged) }
        .alert("Policy history", isPresented: Binding(get: { note != nil }, set: { if !$0 { note = nil } })) { Button("OK") {} } message: { Text(note ?? "") }
    }

    @MainActor private func export() async {
        guard let c = model.client else { return }
        do {
            let f = try await PolicyTools.exportHistory(c)
            let panel = NSSavePanel()
            panel.nameFieldStringValue = PolicyToolsData.exportFilename(f)
            panel.allowedContentTypes = [.json]
            guard panel.runModal() == .OK, let url = panel.url else { return }
            try f.data.write(to: url, options: .atomic)
            note = "Saved \(f.recordCount.map { "\($0) revisions, " } ?? "")\(f.data.count) bytes."
        } catch { note = "Export failed: \(tlDescribe(error))" }
    }
}

func tlDescribe(_ e: Error) -> String {
    switch e as? NetraError {
    case .http(let s, let m): "HTTP \(s): \(m)"
    case .unauthorized: "unauthorized"
    case .transport(let m): m
    case nil: e.localizedDescription
    }
}
