// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

enum OpsPages {
    @MainActor @ViewBuilder static func view(for section: NavSection) -> some View {
        switch section {
        default: JSONBrowserView(section: section).id(section)
        }
    }
}
