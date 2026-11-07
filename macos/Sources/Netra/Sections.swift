// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI

enum NavSection: String, CaseIterable, Identifiable, Hashable {
    case overview, health, scorecard, slo
    case flows, talkers, ports, protocols, drops, dns, topology, workloads, pods, l7, tls
    case diagnostics, listenQueues, sysctl, nodeResources, netlink, attachments, maps
    case metrics, anomalies, alerts, insights, incidents, security, intel
    case audit, compliance, report
    case aiBrief, aiDigest, aiSuggestions
    case rules, policies, lease, features, capture, fleet, enforcement

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
        }
    }
}

struct SectionGroup: Identifiable {
    let title: String
    let sections: [NavSection]
    var id: String { title }

    static let all: [SectionGroup] = [
        .init(title: "Now", sections: [.overview, .health, .scorecard, .slo]),
        .init(title: "Traffic", sections: [.flows, .talkers, .ports, .protocols, .drops, .dns, .topology]),
        .init(title: "Workloads", sections: [.workloads, .pods, .l7, .tls]),
        .init(title: "Kernel", sections: [.diagnostics, .listenQueues, .sysctl, .nodeResources, .netlink, .attachments, .maps]),
        .init(title: "Detect", sections: [.metrics, .anomalies, .alerts, .insights, .incidents, .security, .intel]),
        .init(title: "Record", sections: [.audit, .compliance, .report]),
        .init(title: "Ask Netra", sections: [.aiBrief, .aiDigest, .aiSuggestions]),
        .init(title: "Control", sections: [.lease, .rules, .policies, .features, .capture, .enforcement, .fleet]),
    ]
}
