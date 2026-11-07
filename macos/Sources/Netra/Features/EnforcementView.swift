// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Every remaining guarded mutation, driven by the catalog in NetraKit (`ControlAction.all`).
/// Nothing here sends anything: each action opens a form, then the usual preview -> phrase -> confirm sheet.
struct EnforcementView: View {
    @Environment(AppModel.self) private var model
    @State private var log = ActivityLog()
    @State private var query = ""
    @State private var chosen: ControlAction?
    @State private var showActivity = false

    private var groups: [(String, [ControlAction])] {
        let hits = (ControlAction.all + PolicyTools.actions).filter {
            query.isEmpty || [$0.title, $0.group, $0.summary].contains { $0.localizedCaseInsensitiveContains(query) }
        }
        var order: [String] = []
        for a in hits where !order.contains(a.group) { order.append(a.group) }
        return order.map { g in (g, hits.filter { $0.group == g }) }
    }

    var body: some View {
        Group {
            if model.client == nil || model.whoami == nil {
                ContentUnavailableView("Not connected", systemImage: "bolt.slash", description: Text("Connect to a Netra controller first."))
            } else {
                HSplitView {
                    List {
                        if !model.gate.canMutate {
                            Label("This token is read-only. Every action is disabled.", systemImage: "lock").foregroundStyle(.orange)
                        }
                        ForEach(groups, id: \.0) { g, actions in
                            Section(g) {
                                ForEach(actions) { a in
                                    Button { chosen = a } label: { row(a) }
                                        .buttonStyle(.plain).disabled(!model.gate.canMutate)
                                }
                            }
                        }
                    }
                    if showActivity { ActivityPanel(log: log).frame(minWidth: 260, idealWidth: 300) }
                }
            }
        }
        .navigationTitle("Enforcement")
        .searchable(text: $query, prompt: "Find an action")
        .toolbar { Toggle("Activity", systemImage: "list.bullet.rectangle", isOn: $showActivity) }
        .sheet(item: $chosen) { a in ActionFormSheet(action: a, log: log) }
    }

    private func row(_ a: ControlAction) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: a.symbol).frame(width: 24).foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 2) {
                HStack { Text(a.title).font(.body.weight(.medium)); RiskBadge(risk: a.maxRisk) }
                Text(a.summary).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
        .padding(.vertical, 3).contentShape(Rectangle())
    }
}

struct RiskBadge: View {
    let risk: Risk
    var body: some View {
        Text(risk.rawValue).font(.caption2.weight(.semibold)).padding(.horizontal, 6).padding(.vertical, 1)
            .background(color.opacity(0.18), in: Capsule()).foregroundStyle(color)
            .help("Highest risk this action can reach. The server's plan can raise it.")
    }
    private var color: Color {
        switch risk { case .low: .green; case .medium: .yellow; case .high: .orange; case .critical: .red }
    }
}

/// Collects a catalog action's fields, validates them like the server does, then hands off to the guarded flow.
struct ActionFormSheet: View {
    let action: ControlAction
    var log: ActivityLog
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var values: FormValues = [:]
    @State private var flow: MutationFlow?
    @State private var problem: String?

    var body: some View {
        if let flow {
            MutationSheet(flow: flow, onClose: { dismiss() }) {
                Text(action.summary).font(.callout).foregroundStyle(.secondary)
            }
            .padding().frame(width: 540)
        } else {
            VStack(alignment: .leading, spacing: 10) {
                HStack { Text(action.title).font(.headline); RiskBadge(risk: action.maxRisk) }
                Text(action.summary).font(.callout).foregroundStyle(.secondary)
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) { ForEach(action.fields) { field($0) } }.padding(.vertical, 2)
                }.frame(maxHeight: 380)
                if let problem { Label(problem, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red).font(.callout) }
                HStack {
                    Spacer()
                    Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                    Button("Continue") { begin() }.keyboardShortcut(.defaultAction).disabled(!model.gate.canMutate)
                }
            }
            .padding().frame(width: 540)
            .onAppear { for f in action.fields where values[f.key] == nil { values[f.key] = f.initial } }
        }
    }

    @ViewBuilder private func field(_ f: FormField) -> some View {
        let binding = Binding(get: { values[f.key] ?? f.initial }, set: { values[f.key] = $0 })
        VStack(alignment: .leading, spacing: 3) {
            switch f.kind {
            case .toggle:
                Toggle(f.label, isOn: Binding(get: { binding.wrappedValue == "true" }, set: { binding.wrappedValue = $0 ? "true" : "false" }))
            case .choice(let options):
                Picker(f.label, selection: binding) { ForEach(options, id: \.self) { Text($0.isEmpty ? "any" : $0).tag($0) } }
            case .multiline:
                Text(f.label).font(.caption.weight(.medium))
                TextEditor(text: binding).font(.system(.caption, design: .monospaced)).frame(height: 110)
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(.quaternary))
            case .text, .number:
                TextField(f.label, text: binding).textFieldStyle(.roundedBorder)
            }
            if !f.help.isEmpty { Text(f.help).font(.caption2).foregroundStyle(.secondary) }
        }
    }

    private func begin() {
        guard let c = model.client else { return }
        switch action.build(c, values) {
        case .failure(let e): problem = e.message
        case .success(let spec):
            problem = nil
            flow = MutationFlow(spec: spec, client: c, gate: model.gate, log: log)
        }
    }
}
