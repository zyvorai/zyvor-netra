// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import UniformTypeIdentifiers
import NetraKit

/// Start a packet capture on one node (PUT /vms/{node}/capture) through the guarded flow.
struct CaptureStartSheet: View {
    var log: ActivityLog
    var defaultNode = ""
    var onDone: () -> Void
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var p = ControlMutations.CaptureParams()
    @State private var flow: MutationFlow?

    var body: some View {
        if let flow {
            MutationSheet(flow: flow, onClose: { onDone(); dismiss() }) {
                Text("Filtered capture on \(p.node): \(p.backend), \(p.durationSeconds)s.").font(.callout)
            }
        } else {
            Form {
                TextField("Node", text: $p.node)
                Picker("Backend", selection: $p.backend) { Text("eBPF").tag("ebpf"); Text("AF_PACKET").tag("afpacket") }
                Picker("Protocol", selection: $p.proto) {
                    Text("Any").tag(""); Text("TCP").tag("tcp"); Text("UDP").tag("udp"); Text("ICMP").tag("icmp")
                }
                TextField("Host (IP)", text: $p.host)
                TextField("Port", value: $p.port, format: .number.grouping(.never))
                Stepper("Duration: \(p.durationSeconds)s", value: $p.durationSeconds, in: 1...300, step: 15)
                Text("At least one filter is required. Whole-interface captures are refused.")
                    .font(.caption).foregroundStyle(.secondary)
                if let e = p.validationError { Label(e, systemImage: "exclamationmark.circle").font(.caption).foregroundStyle(.orange) }
                HStack {
                    Spacer()
                    Button("Cancel") { dismiss() }
                    Button("Continue") {
                        guard let c = model.client else { return }
                        flow = MutationFlow(spec: ControlMutations.captureStartSpec(client: c, params: p), client: c, gate: model.gate, log: log)
                    }.disabled(p.validationError != nil || !model.gate.canMutate)
                }
            }
            .padding().frame(width: 400)
            .onAppear { if p.node.isEmpty { p.node = defaultNode } }
        }
    }
}

/// Plan then apply a CiliumNetworkPolicy manifest (plan token + risk confirmation come from the flow).
struct PolicyApplySheet: View {
    var log: ActivityLog
    var onDone: () -> Void
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    @State private var picking = false
    @State private var flow: MutationFlow?
    @State private var ident: (namespace: String, name: String)?

    var body: some View {
        if let flow, let ident {
            MutationSheet(flow: flow, onClose: { onDone(); dismiss() }) {
                Text("Apply \(ident.namespace)/\(ident.name). Netra plans first and applies only with the plan token it issues.").font(.callout)
            }
        } else {
            VStack(alignment: .leading, spacing: 10) {
                Text("Apply policy").font(.headline)
                Text("Paste a policy manifest (YAML or JSON) or open a file.").font(.callout).foregroundStyle(.secondary)
                TextEditor(text: $text).font(.system(.caption, design: .monospaced)).frame(height: 220)
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(.quaternary))
                if !text.isEmpty, ControlMutations.policyIdentity(Data(text.utf8)) == nil {
                    Label("Couldn't find metadata.name in this manifest", systemImage: "exclamationmark.circle").font(.caption).foregroundStyle(.orange)
                }
                HStack {
                    Button("Open file…") { picking = true }
                    Spacer()
                    Button("Cancel") { dismiss() }
                    Button("Continue") { begin() }.disabled(ControlMutations.policyIdentity(Data(text.utf8)) == nil || !model.gate.canMutate)
                }
            }
            .padding().frame(width: 520)
            .fileImporter(isPresented: $picking, allowedContentTypes: [.yaml, .json, .plainText]) { r in
                if case .success(let url) = r, url.startAccessingSecurityScopedResource() {
                    defer { url.stopAccessingSecurityScopedResource() }
                    text = (try? String(contentsOf: url, encoding: .utf8)) ?? text
                }
            }
        }
    }

    private func begin() {
        guard let c = model.client, let id = ControlMutations.policyIdentity(Data(text.utf8)) else { return }
        ident = id
        flow = MutationFlow(spec: ControlMutations.policyApplySpec(client: c, manifest: Data(text.utf8), namespace: id.namespace, name: id.name),
                            client: c, gate: model.gate, log: log)
    }
}

/// Switch datapath mode. Enforce is lease-bounded and fails open to observe.
struct ModeSheet: View {
    var log: ActivityLog
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var enforce = true
    @State private var minutes = 15
    @State private var flow: MutationFlow?

    var body: some View {
        if let flow {
            MutationSheet(flow: flow, onClose: { Task { await model.connect() }; dismiss() }) { EmptyView() }
        } else {
            Form {
                Picker("Mode", selection: $enforce) { Text("Enforce (leased)").tag(true); Text("Observe").tag(false) }.pickerStyle(.segmented)
                if enforce {
                    Stepper("Lease: \(minutes) min", value: $minutes, in: ControlMutations.leaseRange, step: 5)
                    Text("When the lease ends the datapath fails open to observe.").font(.caption).foregroundStyle(.secondary)
                }
                HStack {
                    Spacer()
                    Button("Cancel") { dismiss() }
                    Button("Continue") {
                        guard let c = model.client else { return }
                        flow = MutationFlow(spec: ControlMutations.modeSpec(client: c, enforce: enforce, leaseMinutes: minutes),
                                            client: c, gate: model.gate, log: log)
                    }.disabled(!model.gate.canMutate)
                }
            }.padding().frame(width: 380)
        }
    }
}
