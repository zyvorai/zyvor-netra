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

/// Lock a workload down (build -> plan -> apply, always high risk) or lift a lockdown.
struct LockdownSheet: View {
    enum Mode: String, Identifiable { case lockdown, unlock; var id: String { rawValue } }
    var mode: Mode
    var log: ActivityLog
    var seed: (namespace: String, name: String)?
    var onDone: () -> Void
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var namespace = "default"
    @State private var name = ""
    @State private var kind = "pod"
    @State private var flow: MutationFlow?
    @State private var building = false
    @State private var buildError: String?

    var body: some View {
        if let flow {
            MutationSheet(flow: flow, onClose: { onDone(); dismiss() }) {
                Text(mode == .lockdown
                     ? "Blocks all ingress and all egress except DNS for \(namespace)/\(name). Netra plans first and applies only with the plan token; the policy is removed with Unlock."
                     : "Removes the lockdown policy for \(namespace)/\(name).").font(.callout)
            }
        } else {
            VStack(alignment: .leading, spacing: 10) {
                Text(mode == .lockdown ? "Lock down a workload" : "Unlock a workload").font(.headline)
                TextField("Namespace", text: $namespace).textFieldStyle(.roundedBorder)
                TextField(kind == "vm" ? "VM name" : "Pod name", text: $name).textFieldStyle(.roundedBorder)
                Picker("Kind", selection: $kind) { Text("Pod").tag("pod"); Text("VM").tag("vm") }.pickerStyle(.segmented)
                if let buildError { Label(buildError, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red).font(.callout) }
                HStack {
                    Spacer()
                    Button("Cancel") { dismiss() }
                    Button(building ? "Building…" : "Continue") { Task { await begin() } }
                        .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty || namespace.isEmpty || building || !model.gate.canMutate)
                }
            }
            .padding().frame(width: 420)
            .onAppear { if let seed { namespace = seed.namespace; name = seed.name } }
        }
    }

    private func begin() async {
        guard let c = model.client else { return }
        let n = name.trimmingCharacters(in: .whitespaces)
        buildError = nil
        switch mode {
        case .unlock:
            flow = MutationFlow(spec: ControlMutations.unlockSpec(client: c, namespace: namespace, name: n, kind: kind),
                                client: c, gate: model.gate, log: log)
        case .lockdown:
            building = true; defer { building = false }
            do {
                let manifest = try await ControlMutations.buildLockdown(client: c, namespace: namespace, name: n, kind: kind)
                let id = ControlMutations.policyIdentity(manifest) ?? (namespace, n)
                flow = MutationFlow(spec: ControlMutations.lockdownApplySpec(client: c, manifest: manifest, namespace: id.namespace, name: id.name),
                                    client: c, gate: model.gate, log: log)
            } catch { buildError = "\(error)" }
        }
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

/// Add or remove any fast-path rule kind through the guarded flow (dry run where the server has one).
struct RuleSheet: View {
    var log: ActivityLog
    var initial = RuleDraft()
    var onDone: () -> Void
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var d = RuleDraft()
    @State private var flow: MutationFlow?
    @State private var seeded = false

    private var directions: [String] { d.kind == .synDrop || d.kind == .synDropCIDR ? ["egress", "ingress"] : ["egress", "ingress", "both"] }

    var body: some View {
        if let flow {
            MutationSheet(flow: flow, onClose: { onDone(); dismiss() }) {
                Text(d.removing ? "Removes this entry; traffic it matched is no longer affected by it."
                     : d.action == .allow ? "Exempts matching traffic from deny rules."
                     : "Denies matching traffic. Takes effect only under an enforce lease and fails open to observe.")
                    .font(.callout)
            }
        } else {
            Form {
                Picker("Change", selection: $d.removing) { Text("Add").tag(false); Text("Remove").tag(true) }.pickerStyle(.segmented)
                Picker("Kind", selection: $d.kind) { ForEach(RuleKind.allCases) { Text($0.title).tag($0) } }
                if d.kind.supportsAllow {
                    Picker("Action", selection: $d.action) { Text("Deny").tag(RuleAction.deny); Text("Allow").tag(RuleAction.allow) }.pickerStyle(.segmented)
                }
                switch d.kind {
                case .port:
                    TextField("Port", value: $d.port, format: .number.grouping(.never))
                    Picker("Protocol", selection: $d.proto) { ForEach(["ANY", "TCP", "UDP"], id: \.self) { Text($0).tag($0) } }
                case .capability:
                    Picker("Capability", selection: $d.value) { Text("CAP_NET_ADMIN").tag("CAP_NET_ADMIN"); Text("CAP_NET_RAW").tag("CAP_NET_RAW") }
                default:
                    TextField(placeholder, text: $d.value)
                }
                if d.kind == .rate {
                    TextField("Packets/s", value: $d.pps, format: .number.grouping(.never))
                    TextField("Bytes/s (optional)", value: $d.bps, format: .number.grouping(.never))
                }
                if d.kind.hasDirection {
                    Picker("Direction", selection: $d.direction) { ForEach(directions, id: \.self) { Text($0).tag($0) } }
                }
                if let e = d.validationError, !(d.v.isEmpty && d.port == 0 && d.kind != .capability) {
                    Label(e, systemImage: "exclamationmark.circle").font(.caption).foregroundStyle(.orange)
                }
                Text(d.hasDryRun ? "A dry run replays this against observed traffic before you confirm."
                                 : "The server has no dry run for this change; the preview shows current rules.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    Button("Cancel") { dismiss() }
                    Button("Continue") {
                        guard let c = model.client else { return }
                        flow = MutationFlow(spec: d.spec(client: c), client: c, gate: model.gate, log: log)
                    }.disabled(d.validationError != nil || !model.gate.canMutate)
                }
            }
            .padding().frame(width: 420)
            .onAppear { if !seeded { d = initial; if d.kind == .capability && d.value.isEmpty { d.value = "CAP_NET_ADMIN" }; seeded = true } }
            .onChange(of: d.kind) { _, k in
                if !k.supportsAllow { d.action = .deny }
                if k == .capability, !d.value.hasPrefix("CAP_") { d.value = "CAP_NET_ADMIN" }
                if (k == .synDrop || k == .synDropCIDR), d.direction == "both" { d.direction = "egress" }
            }
        }
    }

    private var placeholder: String {
        switch d.kind {
        case .ip, .synDrop, .rate: "IP address"
        case .cidr, .synDropCIDR: "CIDR (e.g. 10.0.0.0/8)"
        case .uid: "User ID"
        case .dns, .sni: "Name (e.g. example.com)"
        case .process: "Process name (comm, max 15 bytes)"
        case .exeHash: "SHA-256 (64 hex characters)"
        default: "Value"
        }
    }
}
