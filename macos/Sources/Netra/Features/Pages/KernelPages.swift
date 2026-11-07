// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Bespoke views for: listenQueues, sysctl, nodeResources, netlink, attachments, maps.
/// All read-only observe surfaces; anything else falls back to the JSON browser.
enum KernelPages {
    @MainActor @ViewBuilder static func view(for section: NavSection) -> some View {
        switch section {
        case .listenQueues: ListenQueuesPage().id(section)
        case .sysctl: SysctlPage().id(section)
        case .nodeResources: NodeResourcesPage().id(section)
        case .netlink: NetlinkPage().id(section)
        case .attachments: AttachmentsPage().id(section)
        case .maps: MapsPage().id(section)
        case .ipv6: Ipv6Page().id(section)
        case .kernelNetwork: KernelNetworkPage().id(section)
        default: JSONBrowserView(section: section).id(section)
        }
    }
}
