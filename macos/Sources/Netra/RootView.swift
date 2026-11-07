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
            case let s: PageRouter(section: s).id(s)
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
                Text([model.activeProfile?.name, model.baseURLText].compactMap { $0 }.joined(separator: " · ")).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
        }
        .padding(8)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10))
        .onTapGesture { model.showConnect = true }
        .contextMenu {
            ForEach(model.profiles) { p in
                Button { Task { await model.switchProfile(p.id) } } label: {
                    Label(p.name, systemImage: p.id == model.activeProfileID ? "checkmark" : "server.rack")
                }
            }
            Divider()
            Button("Edit connection…") { model.showConnect = true }
        }
        .help("Click to edit connection; right-click to switch profile")
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
    @State private var name = ""
    @State private var url = ""
    @State private var token = ""
    @State private var issuer = ""
    @State private var clientID = ""
    @State private var scopes = "openid profile email offline_access"
    @State private var useAccessToken = false
    @State private var creating = false
    @State private var error: String?
    @State private var confirmDelete = false

    private var oidc: OIDCSettings {
        OIDCSettings(issuer: issuer, clientID: clientID, scopes: scopes, useAccessToken: useAccessToken)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Connect to Netra").font(.title2.bold())
            HStack {
                Picker("Profile", selection: Binding(
                    get: { creating ? "" : (model.activeProfileID ?? "") },
                    set: { id in if !id.isEmpty { creating = false; Task { await model.switchProfile(id); load() } } })) {
                    if creating { Text("New profile").tag("") }
                    ForEach(model.profiles) { Text($0.name).tag($0.id) }
                }
                Button { creating = true; name = ""; url = ""; token = ""; issuer = ""; clientID = ""; error = nil } label: { Image(systemName: "plus") }
                    .help("New profile")
                Button(role: .destructive) { confirmDelete = true } label: { Image(systemName: "trash") }
                    .disabled(creating || model.profiles.count < 2).help("Delete this profile and its stored token")
            }
            Text("Each profile keeps its own token in your Keychain; switching servers never carries a token or pinned certificate across.")
                .font(.callout).foregroundStyle(.secondary)
            TextField("Profile name", text: $name).textFieldStyle(.roundedBorder)
            TextField("Controller URL", text: $url).textFieldStyle(.roundedBorder)
            SecureField(creating ? "API token (blank if auth is off)" : "API token (blank keeps the stored one)", text: $token).textFieldStyle(.roundedBorder)
            DisclosureGroup("Single sign-on (OIDC)") {
                VStack(alignment: .leading, spacing: 8) {
                    TextField("Issuer (https://…)", text: $issuer).textFieldStyle(.roundedBorder)
                    TextField("Client ID (public client)", text: $clientID).textFieldStyle(.roundedBorder)
                    TextField("Scopes", text: $scopes).textFieldStyle(.roundedBorder)
                    Toggle("Send the access token instead of the ID token", isOn: $useAccessToken)
                    Text("Register the redirect URI \(OIDCFlow.redirectURI) with the IdP. The controller must have NETRA_OIDC_ISSUER/AUDIENCE set; its audience must appear in the token sent.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Sign in with SSO") {
                        Task {
                            guard await saveOnly() else { return }
                            await model.signInWithSSO()
                            if case .connected = model.connection { dismiss() }
                        }
                    }.disabled(issuer.isEmpty || clientID.isEmpty || url.isEmpty)
                }.padding(.top, 4)
            }
            HStack {
                if !creating, url.hasPrefix("https") {
                    Button("Forget pinned certificate", role: .destructive) { model.forgetPin() }.buttonStyle(.link).font(.caption)
                }
                if !creating {
                    Button("Clear stored token") { model.clearToken() }.buttonStyle(.link).font(.caption)
                }
            }
            if let error { Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red).font(.callout) }
            else if case .failed(let m) = model.connection {
                Label(m, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red).font(.callout)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Connect") {
                    Task {
                        if await connectNow(), case .connected = model.connection { dismiss() }
                    }
                }.keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent)
            }
        }
        .onAppear(perform: load)
        .confirmationDialog("Delete this profile?", isPresented: $confirmDelete) {
            Button("Delete profile", role: .destructive) {
                if let id = model.activeProfileID { Task { await model.deleteProfile(id); load() } }
            }
        }
    }

    private func load() {
        guard let p = model.activeProfile else { return }
        name = p.name; url = p.urlString; token = ""; error = nil
        issuer = p.oidc?.issuer ?? ""; clientID = p.oidc?.clientID ?? ""
        scopes = p.oidc?.scopes ?? "openid profile email offline_access"; useAccessToken = p.oidc?.useAccessToken ?? false
    }

    /// Persist the form without connecting (creating switches to the new profile). Returns false on a validation error.
    private func saveOnly() async -> Bool {
        error = nil
        if creating {
            do {
                let p = try model.saveProfile(ServerProfile(name: name, urlString: url, oidc: oidc), token: token)
                creating = false
                await model.switchProfile(p.id)   // also connects; SSO callers reconnect after sign-in
            } catch { self.error = error.localizedDescription; return false }
        } else if var p = model.activeProfile {
            p.name = name; p.urlString = url; p.oidc = oidc
            do { try model.saveProfile(p, token: token) } catch { self.error = error.localizedDescription; return false }
        }
        return true
    }

    private func connectNow() async -> Bool {
        error = nil
        if creating { return await saveOnly() }
        await model.saveAndConnect(url: url, token: token, name: name, oidc: oidc)
        return true
    }
}
