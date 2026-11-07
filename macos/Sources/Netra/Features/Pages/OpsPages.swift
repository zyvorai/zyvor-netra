// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

enum OpsPages {
    @MainActor @ViewBuilder static func view(for section: NavSection) -> some View {
        switch section {
        case .exports: OpsExportsPage()
        case .artifacts: OpsArtifactsPage()
        case .gitops: OpsGitOpsPage()
        // Sections.swift points tenants at api/v1/tenants, which is not a route; the real one is fleet/tenants.
        case .tenants:
            DataPageView(PageConfig(title: "Tenants", endpoint: "api/v1/fleet/tenants", rowsPath: "tenants", idKeys: ["tenant"],
                columns: [.init(title: "Tenant", path: "tenant"), .init(title: "Risk", path: "risk"), .init(title: "Score", path: "riskScore"),
                          .init(title: "Clusters", path: "clusterCount"), .init(title: "OK", path: "okClusters"),
                          .init(title: "Agents", path: "agentCount"), .init(title: "Stale", path: "staleAgents"),
                          .init(title: "Workloads", path: "workloads")],
                stats: [.init(title: "Tenants", value: { $0["count"]?.summary ?? "0" }),
                        .init(title: "Untagged clusters", value: { $0["untaggedClusters"]?.summary ?? "0" })],
                liveEvery: nil, emptyText: "No tenants. Tag clusters with NETRA_CLUSTER_TENANT or a fleet peer."))
        default: JSONBrowserView(section: section).id(section)
        }
    }
}
