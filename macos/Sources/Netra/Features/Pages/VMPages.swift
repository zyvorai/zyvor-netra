// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI

/// Bespoke views for: vms.
enum VMPages {
    @MainActor @ViewBuilder static func view(for section: NavSection) -> some View {
        switch section {
        case .vms: VmPage()
        default: JSONBrowserView(section: section).id(section)
        }
    }
}
