// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Bespoke read-only views for: optimizer, playbooks, baselines, agents, surfaces.
enum PlatformPages {
    @MainActor @ViewBuilder static func view(for section: NavSection) -> some View {
        switch section {
        case .optimizer: PlatOptimizerPage().id(section)
        case .playbooks: PlatPlaybooksPage().id(section)
        case .baselines: PlatBaselinesPage().id(section)
        case .agents: PlatAgentsPage().id(section)
        case .surfaces: PlatSurfacesPage().id(section)
        default: JSONBrowserView(section: section).id(section)
        }
    }
}
