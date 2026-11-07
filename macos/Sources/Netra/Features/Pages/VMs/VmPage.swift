// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

/// KubeVirt VMs from GET /api/v1/vms ({available, items:[{name,namespace,running,phase,node,podName,podIP,labels,lockedDown}]}).
/// Console and capture actions are gated inside their sheets; this page only lists and routes.
struct VmPage: View {
    var body: some View {
        DataPageView(PageConfig(
            title: "VMs", endpoint: "api/v1/vms", rowsPath: "items", idKeys: ["name"],
            columns: [
                PageColumn(title: "Namespace", path: "namespace", width: 100),
                PageColumn(title: "VM", path: "name", width: 140),
                PageColumn(title: "Phase", path: "phase"),
                PageColumn(title: "Node", path: "node"),
                PageColumn(title: "Pod IP", path: "podIP"),
                PageColumn(title: "Locked down", path: "lockedDown"),
            ],
            stats: [PageStat(title: "VMs", symbol: "desktopcomputer") { String($0.rows(at: "items").count) },
                    PageStat(title: "Running", symbol: "play.circle", tint: .green) { v in
                        String(v.rows(at: "items").filter { $0.value.at("running")?.summary == "true" }.count) }],
            emptyText: "No VMs. KubeVirt may not be installed on this cluster."
        )) { value in VmActions(value: value) }
    }
}

struct VmActions: View {
    let value: JSONValue
    @State private var pick = ""
    @State private var vnc: (String, String)?
    @State private var capNode: String?
    private struct Vm: Hashable { let id: String, ns: String, name: String, node: String }
    private var vms: [Vm] {
        value.rows(at: "items", idKeys: ["name"]).compactMap {
            guard let n = $0.value.at("name")?.string, let ns = $0.value.at("namespace")?.string else { return nil }
            return Vm(id: "\(ns)/\(n)", ns: ns, name: n, node: $0.value.at("node")?.string ?? "")
        }
    }
    var body: some View {
        let list = vms
        let cur = list.first { $0.id == pick } ?? list.first
        HStack {
            if value.at("available")?.summary == "false" {
                Label("KubeVirt is not available on this cluster.", systemImage: "info.circle").font(.callout).foregroundStyle(.secondary)
            }
            if !list.isEmpty {
                Picker("VM", selection: Binding(get: { cur?.id ?? "" }, set: { pick = $0 })) {
                    ForEach(list, id: \.id) { Text($0.id).tag($0.id) }
                }.frame(maxWidth: 320)
                Button("Open console…", systemImage: "display") { if let c = cur { vnc = (c.ns, c.name) } }
                Button("Capture stream…", systemImage: "record.circle") { if let c = cur { capNode = c.node } }
                    .disabled(cur?.node.isEmpty ?? true)
            }
            Spacer()
        }
        .padding([.horizontal, .top], 12).padding(.bottom, 6)
        .sheet(isPresented: Binding(get: { vnc != nil }, set: { if !$0 { vnc = nil } })) {
            if let v = vnc { ConVNCView(namespace: v.0, name: v.1) }
        }
        .sheet(isPresented: Binding(get: { capNode != nil }, set: { if !$0 { capNode = nil } })) {
            if let n = capNode { VmCaptureSheet(node: n) }
        }
    }
}
