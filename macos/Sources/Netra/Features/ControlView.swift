// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

struct ControlColumn: Identifiable { let title: String; let key: String; var id: String { key } }

/// Read-only data tables for the control pages, with a JSON inspector for the selected row.
struct ControlView: View {
    var section: NavSection = .rules
    @Environment(AppModel.self) private var model
    @State private var log = ActivityLog()
    @State private var rows: [ControlRow] = []
    @State private var history: [ControlRow] = []
    @State private var captureTab = 0           // 0 active, 1 history
    @State private var selection: ControlRow.ID?
    @State private var historySelection: ControlRow.ID?
    @State private var error: String?
    @State private var loading = false
    @State private var showActivity = false
    @State private var ruleSheet = false
    @State private var ruleSeed = RuleDraft()
    @State private var rollbackFlow: MutationFlow?
    @State private var captureSheet = false
    @State private var policySheet = false
    @State private var lockSheet: LockdownSheet.Mode?
    @State private var actionFlow: MutationFlow?     // feature toggle / capture stop
    @State private var actionNote = ""

    private var columns: [ControlColumn] {
        switch section {
        case .rules: [.init(title: "ID", key: "id"), .init(title: "Type", key: "type"), .init(title: "Summary", key: "summary"),
                      .init(title: "Direction", key: "direction"), .init(title: "By", key: "createdBy"), .init(title: "Updated", key: "updatedAt")]
        case .policies: [.init(title: "Name", key: "metadata.name"), .init(title: "Namespace", key: "metadata.namespace"),
                         .init(title: "Kind", key: "kind"), .init(title: "Created", key: "metadata.creationTimestamp")]
        case .features: [.init(title: "Feature", key: "title"), .init(title: "On", key: "enabled"), .init(title: "Scope", key: "scope"),
                         .init(title: "Source", key: "source"), .init(title: "Note", key: "note")]
        default: captureTab == 0
            ? [.init(title: "Node", key: "node"), .init(title: "Backend", key: "backend"), .init(title: "Protocol", key: "protocol"),
               .init(title: "Host", key: "host"), .init(title: "Port", key: "port"), .init(title: "Started", key: "startedAt")]
            : [.init(title: "Node", key: "node"), .init(title: "Reason", key: "reason"), .init(title: "Trigger", key: "triggerKind"),
               .init(title: "Frames", key: "artifactFrames"), .init(title: "Started", key: "startedAt"), .init(title: "Ended", key: "endedAt")]
        }
    }
    private let historyColumns: [ControlColumn] = [.init(title: "Rev", key: "id"), .init(title: "At", key: "at"),
                                                   .init(title: "Actor", key: "actor"), .init(title: "Action", key: "action")]

    var body: some View {
        Group {
            if model.client == nil || model.whoami == nil {
                ContentUnavailableView("Not connected", systemImage: "bolt.slash", description: Text("Connect to a Netra controller first."))
            } else {
                HSplitView {
                    VStack(spacing: 0) {
                        if section == .capture {
                            Picker("", selection: $captureTab) { Text("Active").tag(0); Text("History").tag(1) }
                                .pickerStyle(.segmented).padding(8)
                        }
                        if let error { Text(error).foregroundStyle(.red).font(.callout).padding(8) }
                        table(rows, columns: columns, selection: $selection)
                        if let sel = selectedRule ?? selectedPolicyRow {
                            Divider()
                            Text("History of \(sel.text("id").isEmpty ? policyKey(sel) : sel.text("id"))").font(.caption).padding(.top, 6)
                            table(history, columns: historyColumns, selection: $historySelection).frame(height: 160)
                        }
                    }
                    .frame(minWidth: 480)
                    inspector.frame(minWidth: 260, idealWidth: 320)
                    if showActivity { ActivityPanel(log: log).frame(minWidth: 260, idealWidth: 300) }
                }
            }
        }
        .navigationTitle(section.title)
        .toolbar {
            ToolbarItemGroup {
                if section == .rules {
                    Button("New rule…", systemImage: "plus.circle") { ruleSeed = RuleDraft(); ruleSheet = true }
                        .disabled(!model.gate.canMutate)
                        .help(model.gate.canMutate ? "Add or remove any rule kind, with a preview first" : "This token is read-only")
                    Button("Remove…", systemImage: "minus.circle") {
                        if let r = selectedRule, let d = RuleDraft.removal(from: r) { ruleSeed = d; ruleSheet = true }
                    }
                    .disabled(!model.gate.canMutate || selectedRule.flatMap(RuleDraft.removal(from:)) == nil)
                    Button("Roll back…", systemImage: "arrow.uturn.backward") { startRollback() }
                        .disabled(!model.gate.canMutate || selectedRule == nil || selectedRevision == nil)
                }
                if section == .policies {
                    Button("Apply policy…", systemImage: "square.and.arrow.down") { policySheet = true }
                        .disabled(!model.gate.canMutate).help(model.gate.canMutate ? "Plan, then apply with a plan token" : "This token is read-only")
                    Button("Lock down…", systemImage: "lock.shield") { lockSheet = .lockdown }
                        .disabled(!model.gate.canMutate).help(model.gate.canMutate ? "Build a lockdown policy for a workload, then plan and apply it" : "This token is read-only")
                    Button("Unlock…", systemImage: "lock.open") { lockSheet = .unlock }
                        .disabled(!model.gate.canMutate).help("Lift a workload's lockdown")
                    Button("Roll back…", systemImage: "arrow.uturn.backward") { startRollback() }
                        .disabled(!model.gate.canMutate || selectedPolicyRow == nil || selectedRevision == nil)
                        .help("Restore the selected revision of the selected policy")
                }
                if section == .features, let f = selectedRow {
                    let on = f.text("enabled") == "true"
                    Button(on ? "Disable…" : "Enable…", systemImage: "switch.2") { startFeatureToggle(f, enable: !on) }
                        .disabled(!model.gate.canMutate)
                }
                if section == .capture {
                    Button("Start capture…", systemImage: "record.circle") { captureSheet = true }.disabled(!model.gate.canMutate)
                    if captureTab == 0, let c = selectedRow {
                        Button("Stop", systemImage: "stop.circle") { startCaptureStop(c) }.disabled(!model.gate.canMutate)
                    }
                }
                Toggle("Activity", systemImage: "list.bullet.rectangle", isOn: $showActivity)
                Button("Refresh", systemImage: "arrow.clockwise") { Task { await load() } }.disabled(loading)
            }
        }
        .task(id: "\(section.rawValue)-\(captureTab)") { selection = nil; await load() }
        .task(id: selection) { await loadHistory() }
        .sheet(isPresented: $captureSheet) { CaptureStartSheet(log: log) { Task { await load() } } }
        .sheet(isPresented: $policySheet) { PolicyApplySheet(log: log) { Task { await load() } } }
        .sheet(item: $lockSheet) { mode in LockdownSheet(mode: mode, log: log, seed: selectedPolicyRow.flatMap(lockSeed)) { Task { await load() } } }
        .sheet(isPresented: Binding(get: { actionFlow != nil }, set: { if !$0 { actionFlow = nil } })) {
            if let flow = actionFlow {
                MutationSheet(flow: flow, onClose: { actionFlow = nil; Task { await load() } }) {
                    Text(actionNote).font(.callout)
                }
            }
        }
        .sheet(isPresented: $ruleSheet) { RuleSheet(log: log, initial: ruleSeed) { Task { await load() } } }
        .sheet(isPresented: Binding(get: { rollbackFlow != nil }, set: { if !$0 { rollbackFlow = nil } })) {
            if let flow = rollbackFlow {
            MutationSheet(flow: flow, onClose: { rollbackFlow = nil; Task { await load(); await loadHistory() } }) {
                Text(section == .policies
                     ? "Re-applies the chosen recorded revision of this policy. Netra checkpoints the current state first and asks for confirmation when the plan is high risk."
                     : "Re-applies the 'after' state of the chosen revision as a new edit on this rule.").font(.callout)
            }
            }
        }
    }

    private var selectedRow: ControlRow? { rows.first { $0.id == selection } }

    private func startFeatureToggle(_ f: ControlRow, enable: Bool) {
        guard let c = model.client else { return }
        let id = f.text("id"), name = f.text("title").isEmpty ? id : f.text("title")
        let target = f.text("target")
        let workload = target == "daemonset" ? "agent DaemonSet" : target.isEmpty ? nil : "controller Deployment"
        actionNote = "\(enable ? "Enables" : "Disables") \(name) by patching a workload environment variable."
        actionFlow = MutationFlow(spec: ControlMutations.featureSpec(client: c, id: id, name: name, enable: enable, restartsWorkload: workload),
                                  client: c, gate: model.gate, log: log)
    }

    private func startCaptureStop(_ row: ControlRow) {
        guard let c = model.client else { return }
        let node = row.text("node")
        actionNote = "Stops the active capture on \(node)."
        actionFlow = MutationFlow(spec: ControlMutations.captureStopSpec(client: c, node: node), client: c, gate: model.gate, log: log)
    }

    private var selectedRule: ControlRow? { section == .rules ? rows.first { $0.id == selection } : nil }
    private var selectedPolicyRow: ControlRow? { section == .policies ? rows.first { $0.id == selection } : nil }
    private func policyKey(_ r: ControlRow) -> String { "\(r.text("metadata.namespace"))/\(r.text("metadata.name"))" }
    /// Pre-fills the lockdown/unlock sheet from a selected `netra-lockdown-*` policy's workload label.
    private func lockSeed(_ r: ControlRow) -> (namespace: String, name: String)? {
        let w = r.value["metadata"]?["labels"]?["netra.zyvor.dev/workload"]?.string ?? ""
        let ns = r.text("metadata.namespace")
        return w.isEmpty || ns.isEmpty ? nil : (ns, w)
    }
    private var selectedRevision: ControlRow? { history.first { $0.id == historySelection } }

    private func table(_ data: [ControlRow], columns: [ControlColumn], selection: Binding<ControlRow.ID?>) -> some View {
        Table(data, selection: selection) {
            TableColumnForEach(columns) { c in
                TableColumn(c.title) { (r: ControlRow) in Text(r.text(c.key)).lineLimit(1) }
            }
        }
    }

    private var inspector: some View {
        let row = rows.first { $0.id == selection }
        return ScrollView {
            if let row {
                Text(pretty(row.value)).font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding()
            } else {
                ContentUnavailableView("No selection", systemImage: "sidebar.right", description: Text("Select a row to inspect."))
            }
        }
    }

    private func pretty(_ v: JSONValue) -> String {
        let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return (try? e.encode(v)).map { String(decoding: $0, as: UTF8.self) } ?? v.summary
    }

    private func load() async {
        guard let c = model.client, model.whoami != nil else { return }
        loading = true; defer { loading = false }
        do {
            switch section {
            case .rules: rows = try await c.rules()
            case .policies: rows = try await c.policies()
            case .features: rows = try await c.features()
            default: rows = captureTab == 0 ? try await c.captureActive() : try await c.captureHistory()
            }
            error = nil
        } catch { rows = []; self.error = "\(error)" }
    }

    private func loadHistory() async {
        history = []; historySelection = nil
        guard let c = model.client else { return }
        if let pol = selectedPolicyRow {
            history = (try? await c.policyHistory(namespace: pol.text("metadata.namespace"), name: pol.text("metadata.name"))) ?? []
            return
        }
        guard section == .rules, let id = selectedRule?.text("id"), !id.isEmpty else { return }
        history = (try? await c.ruleHistory(id: id)) ?? []
    }

    private func startRollback() {
        if let pol = selectedPolicyRow, let rev = selectedRevision, let c = model.client {
            rollbackFlow = MutationFlow(spec: ControlMutations.policyRollbackSpec(client: c, namespace: pol.text("metadata.namespace"),
                                                                                    name: pol.text("metadata.name"), revision: rev.text("id")),
                                        client: c, gate: model.gate, log: log)
            return
        }
        guard let c = model.client, let rule = selectedRule, let rev = selectedRevision else { return }
        let rid = rule.text("id"), revID = rev.text("id")
        let spec = MutationSpec(title: "Roll back rule \(rid) to revision \(revID)", risk: .medium,
            expectedPhrase: "", leaseBound: true,
            // Dry run: re-read the rule's history (read-only) to confirm the revision still exists.
            preview: { c.request("GET", "api/v1/ebpf/rules/\(rid)/history") },
            summarize: { v in "Revision \(revID) of rule \(rid) found among \(v["items"]?.controlItems.count ?? 0) revision(s)." },
            execute: { c.ruleRollbackRequest(id: rid, revision: revID, confirmRisk: $0) })
        rollbackFlow = MutationFlow(spec: spec, client: c, gate: model.gate, log: log)
    }
}
