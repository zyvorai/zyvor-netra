// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        NavigationSplitView {
            List(selection: $model.selection) {
                ForEach(SectionGroup.all) { g in
                    SwiftUI.Section(g.title) {
                        ForEach(g.sections) { s in
                            Label(s.title, systemImage: s.symbol).tag(s)
                        }
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 200, ideal: 230)
            .safeAreaInset(edge: .bottom) { ConnectionBadge().padding(10) }
        } detail: {
            switch model.selection ?? .overview {
            case .overview: OverviewView()
            case .lease: LeaseView()
            case .flows: FlowsView()
            case .metrics, .anomalies, .alerts: MetricsView(section: model.selection ?? .metrics)
            case .rules, .policies, .features, .capture: ControlView(section: model.selection ?? .rules)
            case .topology: TopologyView()
            case .enforcement: EnforcementView()
            case let s: JSONBrowserView(section: s).id(s)
            }
        }
        .paletteOverlay()
        .sheet(item: Binding(get: { model.pendingTrust.map(TrustItem.init) }, set: { if $0 == nil { model.pendingTrust = nil } })) { item in
            TrustPrompt(probe: item.probe,
                        onTrust: { Task { await model.trustPending() } },
                        onCancel: { model.pendingTrust = nil })
        }
        .sheet(isPresented: $model.showConnect) {
            ConnectForm().frame(width: 460).padding()
        }
        .onChange(of: model.connection) { _, c in
            if case .failed = c, model.pendingTrust == nil { model.showConnect = true }
        }
    }
}

struct TrustItem: Identifiable { let probe: CertificateProbeResult; var id: String { probe.fingerprint } }

struct ConnectionBadge: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        HStack(spacing: 8) {
            Circle().fill(color).frame(width: 9, height: 9)
            VStack(alignment: .leading, spacing: 0) {
                Text(label).font(.callout.weight(.medium))
                Text(model.baseURLText).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
        }
        .padding(8)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10))
        .onTapGesture { model.showConnect = true }
        .help("Click to edit connection")
    }
    private var color: Color {
        switch model.connection {
        case .connected: .green
        case .connecting: .yellow
        case .failed: .red
        case .disconnected: .gray
        }
    }
    private var label: String {
        switch model.connection {
        case .connected(let w): "\(w.role.capitalized)\(w.identity.map { " · \($0)" } ?? "")"
        case .connecting: "Connecting…"
        case .failed(let m): m
        case .disconnected: "Not connected"
        }
    }
}

struct ConnectForm: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var url = ""
    @State private var token = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Connect to Netra").font(.title2.bold())
            Text("The token is stored in your Keychain and sent only as a Bearer header.")
                .font(.callout).foregroundStyle(.secondary)
            TextField("Controller URL", text: $url).textFieldStyle(.roundedBorder)
            SecureField("API token (blank if auth is off)", text: $token).textFieldStyle(.roundedBorder)
            if url.hasPrefix("https") {
                Button("Forget pinned certificate", role: .destructive) { model.forgetPin() }
                    .buttonStyle(.link).font(.caption)
            }
            if case .failed(let m) = model.connection {
                Label(m, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red).font(.callout)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Connect") {
                    Task { await model.saveAndConnect(url: url, token: token)
                        if case .connected = model.connection { dismiss() } }
                }.keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent)
            }
        }
        .onAppear { url = model.baseURLText }
    }
}
