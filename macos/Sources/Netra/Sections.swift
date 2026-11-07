// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI

enum NavSection: String, CaseIterable, Identifiable, Hashable {
    case overview, health, scorecard, slo
    case flows, talkers, ports, protocols, drops, dns, topology, workloads, pods, l7, tls
    case diagnostics, listenQueues, sysctl, nodeResources, netlink, attachments, maps, ipv6, kernelNetwork
    case metrics, anomalies, alerts, insights, incidents, security, intel
    case audit, compliance, report
    case aiBrief, aiDigest, aiSuggestions
    case rules, policies, lease, features, capture, fleet, enforcement
    case tcpEvents, connections, pathDiag, congestion, ebpfCoverage
    case explain, investigate, optimizer, playbooks, baselines
    case agents, surfaces, exports, artifacts, gitops, tenants, metricContexts
    case insightsDetail, processWatch, datapathDetail, fleetExporters
    case vms
    case changes

    var id: String { rawValue }

    var title: String {
        switch self {
        case .slo: "SLO"
        case .dns: "DNS"
        case .l7: "L7"
        case .tls: "TLS fingerprints"
        case .aiBrief: "Brief"
        case .aiDigest: "Digest"
        case .aiSuggestions: "Suggestions"
        case .enforcement: "Enforcement"
        case .listenQueues: "Listen queues"
        case .nodeResources: "Node resources"
        case .attachments: "BPF attachments"
        case .maps: "BPF maps"
        case .sysctl: "Sysctl audit"
        case .tcpEvents: "TCP events"
        case .pathDiag: "Path & ICMP"
        case .ebpfCoverage: "eBPF coverage"
        case .metricContexts: "Metric contexts"
        case .gitops: "GitOps"
        case .ipv6: "IPv6"
        case .kernelNetwork: "Kernel network"
        case .insightsDetail: "Insights detail"
        case .processWatch: "Process watch"
        case .datapathDetail: "Datapath detail"
        case .fleetExporters: "Fleet flows & exporters"
        case .vms: "VMs"
        case .changes: "What changed"
        default: rawValue.prefix(1).uppercased() + rawValue.dropFirst()
        }
    }

    var symbol: String {
        switch self {
        case .overview: "gauge.with.dots.needle.67percent"
        case .health: "heart.text.square"
        case .scorecard: "checklist"
        case .slo: "target"
        case .flows: "waveform.path.ecg"
        case .talkers: "person.2.wave.2"
        case .ports: "door.left.hand.open"
        case .protocols: "point.3.connected.trianglepath.dotted"
        case .drops: "arrow.down.right.and.arrow.up.left.slash.circle"
        case .dns: "network"
        case .topology: "circle.hexagongrid"
        case .workloads: "shippingbox"
        case .pods: "cube"
        case .l7: "text.bubble"
        case .tls: "lock.shield"
        case .diagnostics: "stethoscope"
        case .listenQueues: "tray.full"
        case .sysctl: "slider.horizontal.3"
        case .nodeResources: "cpu"
        case .netlink: "arrow.triangle.branch"
        case .attachments: "paperclip"
        case .maps: "map"
        case .ipv6: "6.circle"
        case .kernelNetwork: "cpu.fill"
        case .metrics: "chart.xyaxis.line"
        case .anomalies: "waveform.badge.exclamationmark"
        case .alerts: "bell.badge"
        case .insights: "lightbulb"
        case .incidents: "exclamationmark.triangle"
        case .security: "shield.lefthalf.filled"
        case .intel: "eye.trianglebadge.exclamationmark"
        case .audit: "list.bullet.clipboard"
        case .compliance: "checkmark.seal"
        case .report: "doc.richtext"
        case .aiBrief: "sparkles"
        case .aiDigest: "newspaper"
        case .aiSuggestions: "wand.and.stars"
        case .rules: "hand.raised"
        case .policies: "scroll"
        case .lease: "timer"
        case .features: "switch.2"
        case .capture: "record.circle"
        case .fleet: "server.rack"
        case .enforcement: "shield.checkered"
        case .tcpEvents: "arrow.left.arrow.right"
        case .connections: "link"
        case .pathDiag: "point.topleft.down.to.point.bottomright.curvepath"
        case .congestion: "thermometer.medium"
        case .ebpfCoverage: "checkmark.shield"
        case .explain: "questionmark.bubble"
        case .investigate: "magnifyingglass.circle"
        case .optimizer: "slider.horizontal.below.rectangle"
        case .playbooks: "book"
        case .baselines: "chart.bar.doc.horizontal"
        case .agents: "antenna.radiowaves.left.and.right"
        case .surfaces: "square.grid.3x3"
        case .exports: "square.and.arrow.up"
        case .artifacts: "doc.zipper"
        case .gitops: "arrow.triangle.2.circlepath"
        case .tenants: "building.2"
        case .metricContexts: "list.bullet.rectangle"
        case .insightsDetail: "lightbulb.2"
        case .processWatch: "eye.trianglebadge.exclamationmark.fill"
        case .datapathDetail: "chart.bar.xaxis"
        case .fleetExporters: "externaldrive.connected.to.line.below"
        case .vms: "desktopcomputer"
        case .changes: "clock.arrow.circlepath"
        }
    }

    /// Read endpoint backing the generic viewer until a bespoke view replaces it.
    var endpoint: String? {
        switch self {
        case .overview, .lease, .enforcement: nil
        case .health: "api/v1/ebpf/health"
        case .scorecard: "api/v1/scorecard"
        case .slo: "api/v1/slo"
        case .flows: "api/v1/flows/summary"
        case .talkers: "api/v1/talkers"
        case .ports: "api/v1/ports"
        case .protocols: "api/v1/protocols"
        case .drops: "api/v1/ebpf/drops"
        case .dns: "api/v1/dns/board"
        case .topology: "api/v1/ebpf/topology"
        case .workloads: "api/v1/ebpf/workloads"
        case .pods: "api/v1/pods"
        case .l7: "api/v1/ebpf/l7"
        case .tls: "api/v1/ebpf/tls-fingerprints"
        case .diagnostics: "api/v1/ebpf/diagnose"
        case .listenQueues: "api/v1/listen-queues"
        case .sysctl: "api/v1/ebpf/sysctl-audit"
        case .nodeResources: "api/v1/node-resources"
        case .netlink: "api/v1/netlink"
        case .attachments: "api/v1/ebpf/attachments"
        case .maps: "api/v1/ebpf/maps"
        case .ipv6: "api/v1/ebpf/ipv6"
        case .kernelNetwork: "api/v1/ebpf/kernel-network"
        case .metrics: "api/v1/metrics/summary"
        case .anomalies: "api/v1/metrics/anomalies"
        case .alerts: "api/v1/metrics/alerts"
        case .insights: "api/v1/insights/summary"
        case .incidents: "api/v1/incidents"
        case .security: "api/v1/security/incidents"
        case .intel: "api/v1/intel/hits"
        case .audit: "api/v1/audit"
        case .compliance: "api/v1/compliance"
        case .report: "api/v1/report"
        case .aiBrief: "api/v1/ai/brief"
        case .aiDigest: "api/v1/ai/digest"
        case .aiSuggestions: "api/v1/ai/suggestions"
        case .rules: "api/v1/ebpf/rules"
        case .policies: "api/v1/policies"
        case .features: "api/v1/features"
        case .capture: "api/v1/capture/status"
        case .fleet: "api/v1/fleet"
        case .tcpEvents: "api/v1/ebpf/tcp-events"
        case .connections: "api/v1/agents"
        case .pathDiag: "api/v1/ebpf/path"
        case .congestion: "api/v1/namespaces/heat"
        case .ebpfCoverage: "api/v1/ebpf/coverage"
        case .explain: "api/v1/ebpf/explain"
        case .investigate: "api/v1/investigate/connection"
        case .optimizer: "api/v1/security/optimizer"
        case .playbooks: "api/v1/playbooks"
        case .baselines: "api/v1/baselines"
        case .agents: "api/v1/agents"
        case .surfaces: "api/v1/ebpf/coverage"
        case .exports: "api/v1/export/status"
        case .artifacts: "api/v1/capture/history"
        case .gitops: "api/v1/policies/gitops/status"
        case .tenants: "api/v1/fleet/tenants"
        case .metricContexts: "api/v1/metrics/contexts"
        case .insightsDetail: "api/v1/insights/red"
        case .processWatch: "api/v1/ebpf/capdrift"
        case .datapathDetail: "api/v1/ebpf/reasons"
        case .fleetExporters: "api/v1/fleet/flows/history"
        case .vms: "api/v1/vms"
        case .changes: nil
        }
    }
}

struct SectionGroup: Identifiable {
    let title: String
    let sections: [NavSection]
    var id: String { title }

    static let all: [SectionGroup] = [
        .init(title: "Now", sections: [.overview, .health, .scorecard, .slo]),
        .init(title: "Traffic", sections: [.flows, .talkers, .ports, .protocols, .drops, .dns, .topology, .tcpEvents, .connections, .pathDiag, .congestion]),
        .init(title: "Workloads", sections: [.workloads, .pods, .vms, .l7, .tls]),
        .init(title: "Kernel", sections: [.diagnostics, .listenQueues, .sysctl, .nodeResources, .netlink, .attachments, .maps, .ipv6, .kernelNetwork, .ebpfCoverage, .datapathDetail]),
        .init(title: "Detect", sections: [.metrics, .metricContexts, .anomalies, .alerts, .insights, .incidents, .security, .intel, .insightsDetail, .processWatch, .explain, .investigate, .optimizer, .playbooks, .baselines]),
        .init(title: "Record", sections: [.audit, .compliance, .report, .changes]),
        .init(title: "Ask Netra", sections: [.aiBrief, .aiDigest, .aiSuggestions]),
        .init(title: "Platform", sections: [.agents, .surfaces, .exports, .artifacts, .gitops, .tenants, .fleetExporters]),
        .init(title: "Control", sections: [.lease, .rules, .policies, .features, .capture, .enforcement, .fleet]),
    ]
}
