// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

/// Per-category notification toggles (persisted in UserDefaults by NotificationService).
struct NotificationSettingsView: View {
    @State private var service = NotificationService.shared

    var body: some View {
        Form {
            if !service.isAvailable {
                Text("Notifications need Netra to run as an app bundle. They are off while running as a bare executable.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            ForEach(NotifyCategory.allCases) { c in
                Toggle(c.title, isOn: Binding(get: { service.isEnabled(c) }, set: { service.setEnabled(c, $0) }))
                    .disabled(!service.isAvailable)
            }
            Text("Notifications show only the rule or title, severity and node. Acknowledge on a metric alert changes notification state only.")
                .font(.caption).foregroundStyle(.secondary)
            LabeledContent("macOS permission", value: service.authorization).font(.caption)
        }
    }
}
