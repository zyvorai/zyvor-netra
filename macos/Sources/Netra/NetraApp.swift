// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

@main
struct NetraApp: App {
    @State private var model = AppModel()
    @Environment(\.openWindow) private var openWindow

    var body: some Scene {
        WindowGroup("Netra", id: "main") {
            RootView()
                .linkRouting()
                .environment(model)
                .frame(minWidth: 960, minHeight: 600)
                .task { await model.start() }
        }
        .commands {
            CommandGroup(after: .appInfo) {
                Button("Licence…") { openWindow(id: "licence") }
            }
            CommandGroup(after: .newItem) {
                Button("Connect…") { model.showConnect = true }.keyboardShortcut("k", modifiers: [.command, .shift])
                Button("Reconnect") { Task { await model.connect() } }.keyboardShortcut("r", modifiers: .command)
            }
            CommandMenu("Go") {
                ForEach(Array(NavSection.allCases.prefix(9).enumerated()), id: \.offset) { i, s in
                    Button(s.title) { model.selection = s }.keyboardShortcut(KeyEquivalent(Character("\(i + 1)")), modifiers: .command)
                }
            }
        }

        Window("Licence", id: "licence") { LicenceView() }.windowResizability(.contentSize)

        MenuBarExtra {
            MenuBarView().environment(model)
        } label: {
            Image(systemName: model.effectiveMode == "enforce" ? "shield.lefthalf.filled" : "eye")
        }
        .menuBarExtraStyle(.window)

        Settings {
            TabView {
                ConnectForm().environment(model).padding().tabItem { Label("Connection", systemImage: "network") }
                NotificationSettingsView().padding().tabItem { Label("Notifications", systemImage: "bell") }
                LicenceView().tabItem { Label("Licence", systemImage: "key") }
            }
            .frame(width: 540)
        }
    }
}
