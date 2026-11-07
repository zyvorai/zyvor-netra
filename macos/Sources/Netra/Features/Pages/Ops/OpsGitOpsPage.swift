// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

/// GET /policies/gitops/status, and a guarded resync (POST /policies/gitops/resync) of the selected manifest.
/// The server is Cilium-gated and may refuse; its message is shown as-is.
struct OpsGitOpsPage: View {
    @Environment(AppModel.self) private var model
    @State private var status: GitOpsStatus?
    @State private var selection: GitOpsManifest.ID?
    @State private var error: String?
    @State private var log = ActivityLog()
    @State private var flow: MutationFlow?
    @State private var manualSheet = false

    private var selected: GitOpsManifest? { status?.manifests.first { $0.id == selection } }

    var body: some View {
        if model.client == nil || model.whoami == nil { OpsNotConnected() } else {
            VStack(alignment: .leading, spacing: 0) {
                if let error {
                    ContentUnavailableView("GitOps unavailable", systemImage: "arrow.triangle.2.circlepath", description: Text(error))
                } else if let s = status {
                    HStack(spacing: 16) {
                        Label(s.dir.isEmpty ? "no dir" : s.dir, systemImage: "folder")
                        Label("Auto-apply \(s.autoApply ? "on" : "off")", systemImage: s.autoApply ? "bolt" : "eye")
                        Label("Last run \(s.lastRun)", systemImage: "clock")
                    }.font(.callout).padding(8)
                    ForEach(s.loadErrors, id: \.self) { Label($0, systemImage: "exclamationmark.triangle").foregroundStyle(.orange).font(.caption).padding(.horizontal, 8) }
                    Table(s.manifests, selection: $selection) {
                        TableColumn("Path") { (m: GitOpsManifest) in Text(m.path).lineLimit(1) }
                        TableColumn("Policy") { (m: GitOpsManifest) in Text("\(m.namespace)/\(m.name)") }
                        TableColumn("Risk") { (m: GitOpsManifest) in Text(m.risk ?? "") }
                        TableColumn("Drift") { (m: GitOpsManifest) in Text(m.drifted ? "drifted" : "") .foregroundStyle(.orange) }
                        TableColumn("Applied") { (m: GitOpsManifest) in Text(m.applied ? "yes" : "no") }
                        TableColumn("Note") { (m: GitOpsManifest) in Text(m.error ?? m.note ?? "").lineLimit(1) }
                    }
                } else { ProgressView().controlSize(.large).frame(maxWidth: .infinity, maxHeight: .infinity) }
            }
            .navigationTitle("GitOps")
            .navigationSubtitle("api/v1/policies/gitops/status")
            .toolbar {
                Button("Resync selected…", systemImage: "arrow.triangle.2.circlepath") { startResync() }
                    .disabled(!model.gate.canMutate || selected?.manifestJSON == nil)
                    .help(model.gate.canMutate ? "Force-apply the selected manifest (needs Cilium enabled on the controller)" : "This token is read-only")
                Button("Resync a manifest…", systemImage: "square.and.pencil") { manualSheet = true }.disabled(!model.gate.canMutate)
                Button("Refresh", systemImage: "arrow.clockwise") { Task { await load() } }
            }
            .task { await load() }
            .sheet(isPresented: Binding(get: { flow != nil }, set: { if !$0 { flow = nil } })) {
                if let flow {
                    MutationSheet(flow: flow, onClose: { self.flow = nil; Task { await load() } }) {
                        Text("Applies this manifest through the policy pipeline regardless of drift. The server refuses when Cilium is not enabled, and requires a confirmation for high or critical risk.").font(.callout)
                    }
                }
            }
            .sheet(isPresented: $manualSheet) { ActionFormSheet(action: OpsAction.all[0], log: log) }
        }
    }

    private func startResync() {
        guard let c = model.client, let m = selected, let body = m.manifestJSON else { return }
        flow = MutationFlow(spec: OpsAction.gitopsResyncSpec(client: c, manifest: body, namespace: m.namespace, name: m.name),
                            client: c, gate: model.gate, log: log)
    }

    private func load() async {
        guard let c = model.client else { return }
        do {
            let v = try JSONDecoder().decode(JSONValue.self, from: await c.send(c.request("GET", "api/v1/policies/gitops/status")))
            status = GitOpsStatus(v); error = nil
        } catch { status = nil; self.error = opsDescribe(error) }
    }
}
