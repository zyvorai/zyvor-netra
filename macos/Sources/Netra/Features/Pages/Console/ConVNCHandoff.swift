// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

/// VM console handoff. The server relays KubeVirt's RFB stream (GET /api/v1/vms/{ns}/{name}/vnc), but this
/// app has no RFB renderer, so VNC opens in the web UI (Workloads page, noVNC) in the default browser.
struct ConVNCHandoff: View {
    let namespace: String, name: String
    @Environment(AppModel.self) private var model
    @Environment(\.openURL) private var openURL
    @State private var consoleEnabled: Bool?

    var body: some View {
        let a = ConsoleData.availability(consoleEnabled: consoleEnabled, whoami: model.whoami)
        VStack(alignment: .leading, spacing: 4) {
            Button("Open VNC in browser…", systemImage: "display") {
                if let u = URL(string: model.baseURLText) { openURL(ConsoleData.webUIURL(base: u)) }
            }.disabled(a != .allowed)
            if case .disabled(let why) = a { Text(why).font(.caption).foregroundStyle(.secondary) }
            else { Text("Opens the web UI; select \(namespace)/\(name) on Workloads and press Connect VNC.").font(.caption).foregroundStyle(.secondary) }
        }
        .task {
            guard let c = model.client else { return }
            consoleEnabled = (try? await c.send(c.request("GET", ConsoleData.statusPath))).map(ConsoleData.consoleEnabled(fromStatus:)) ?? false
        }
    }
}
