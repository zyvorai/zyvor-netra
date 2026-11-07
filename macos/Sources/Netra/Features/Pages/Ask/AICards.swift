// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

func AskseverityColor(_ s: String) -> Color {
    switch s.lowercased() {
    case "critical", "high": .red
    case "warning", "medium": .orange
    case "info", "low", "ok": .green
    default: .secondary
    }
}

/// Markdown-ish text: inline markdown with newlines preserved; falls back to plain text.
struct AskRichText: View {
    let text: String
    var body: some View {
        let a = (try? AttributedString(markdown: text, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace))) ?? AttributedString(text)
        Text(a).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct AskSeverityBadge: View {
    let severity: String
    var body: some View {
        Text(severity.isEmpty ? "n/a" : severity.uppercased())
            .font(.caption2.weight(.bold)).padding(.horizontal, 7).padding(.vertical, 2)
            .background(AskseverityColor(severity).opacity(0.18), in: Capsule())
            .foregroundStyle(AskseverityColor(severity))
            .accessibilityLabel("Severity \(severity)")
    }
}

/// Citation chip: jumps to the page that shows the finding when the kind maps to a section.
struct AskCitationChip: View {
    let finding: AskData.Finding
    @Environment(AppModel.self) private var model
    var body: some View {
        let target = finding.sectionID.flatMap(NavSection.init(rawValue:))
        let label = finding.subject.isEmpty ? finding.kind : "\(finding.kind): \(finding.subject)"
        Button { if let target { model.selection = target } } label: {
            HStack(spacing: 4) {
                Circle().fill(AskseverityColor(finding.severity)).frame(width: 6, height: 6)
                Text(label).lineLimit(1)
                if target != nil { Image(systemName: "arrow.up.right").font(.caption2) }
            }
            .font(.caption).padding(.horizontal, 8).padding(.vertical, 3)
            .background(.quaternary, in: Capsule())
        }
        .buttonStyle(.plain).disabled(target == nil)
        .help(finding.message)
        .accessibilityLabel("\(finding.severity) \(label). \(finding.message)")
        .accessibilityHint(target == nil ? "" : "Opens \(target!.title)")
    }
}

struct AskFindingRow: View {
    let finding: AskData.Finding
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            AskSeverityBadge(severity: finding.severity)
            VStack(alignment: .leading, spacing: 2) {
                if !finding.subject.isEmpty { Text(finding.subject).font(.callout.weight(.medium)) }
                Text(finding.message).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                if !finding.kind.isEmpty { AskCitationChip(finding: finding) }
            }
            Spacer(minLength: 0)
        }
    }
}

struct AskCard<Content: View>: View {
    let title: String
    var symbol: String? = nil
    @ViewBuilder var content: Content
    var body: some View {
        GroupBox {
            content.frame(maxWidth: .infinity, alignment: .leading).padding(.top, 4)
        } label: {
            Label(title, systemImage: symbol ?? "circle").labelStyle(AskSymbolLabel(show: symbol != nil))
        }
    }
}
private struct AskSymbolLabel: LabelStyle {
    let show: Bool
    func makeBody(configuration c: Configuration) -> some View {
        HStack(spacing: 5) { if show { c.icon }; c.title }.font(.headline)
    }
}

/// Brief body shared by the Brief and Digest pages and by Ask answers.
struct AskBriefCards: View {
    let brief: AskData.Brief
    var showSnapshotStats = true
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            AskCard(title: brief.headline.isEmpty ? "Brief" : brief.headline, symbol: "sparkles") {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        AskSeverityBadge(severity: brief.severity)
                        Text(brief.engine.isEmpty ? "heuristic" : brief.engine + (brief.model.isEmpty ? "" : " / \(brief.model)"))
                            .font(.caption).foregroundStyle(.secondary)
                        if let t = brief.generatedAt { Text(CellFormat.relative(t)).font(.caption).foregroundStyle(.secondary) }
                    }
                    if !brief.summary.isEmpty { AskRichText(text: brief.summary) }
                }
            }
            if showSnapshotStats, brief.healthScore != nil || brief.agentsTotal > 0 {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        StatCard(title: "Health score", value: brief.healthScore.map(String.init) ?? "", symbol: "heart.text.square", tint: .green)
                        StatCard(title: "Agents", value: "\(brief.agentsTotal)", symbol: "server.rack")
                        StatCard(title: "Stale agents", value: "\(brief.agentsStale)", symbol: "clock.badge.exclamationmark", tint: brief.agentsStale > 0 ? .orange : .green)
                        StatCard(title: "Mode", value: brief.mode, symbol: "shield")
                    }
                }
            }
            if !brief.findings.isEmpty {
                AskCard(title: "Findings (\(brief.findings.count))", symbol: "exclamationmark.bubble") {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(brief.findings.sorted { AskData.severityRank($0.severity) < AskData.severityRank($1.severity) }) { AskFindingRow(finding: $0) }
                    }
                }
            }
            if !brief.metrics.isEmpty {
                AskCard(title: "Metric alerts and anomalous metrics (\(brief.metrics.count))", symbol: "chart.xyaxis.line") {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(brief.metrics) { AskFindingRow(finding: $0) }
                    }
                }
            }
            if !brief.nextSteps.isEmpty {
                AskCard(title: "Next steps", symbol: "arrow.turn.down.right") {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(Array(brief.nextSteps.enumerated()), id: \.offset) { i, s in
                            HStack(alignment: .firstTextBaseline) { Text("\(i + 1).").monospacedDigit().foregroundStyle(.secondary); AskRichText(text: s) }
                        }
                    }
                }
            }
            if !brief.citations.isEmpty {
                AskCard(title: "Evidence", symbol: "link") {
                    AskFlowChips(items: brief.citations)
                }
            }
        }
    }
}

/// Wrapping row of citation chips.
struct AskFlowChips: View {
    let items: [AskData.Finding]
    var body: some View {
        AskChipLayout { ForEach(items) { AskCitationChip(finding: $0) } }
    }
}

struct AskChipLayout: Layout {
    var spacing: CGFloat = 6
    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        arrange(proposal.width ?? 600, subviews).size
    }
    func placeSubviews(in b: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let r = arrange(b.width, subviews)
        for (i, p) in r.points.enumerated() { subviews[i].place(at: CGPoint(x: b.minX + p.x, y: b.minY + p.y), proposal: .unspecified) }
    }
    private func arrange(_ width: CGFloat, _ subviews: Subviews) -> (size: CGSize, points: [CGPoint]) {
        var x: CGFloat = 0, y: CGFloat = 0, rowH: CGFloat = 0, maxX: CGFloat = 0, pts: [CGPoint] = []
        for s in subviews {
            let sz = s.sizeThatFits(.unspecified)
            if x > 0, x + sz.width > width { x = 0; y += rowH + spacing; rowH = 0 }
            pts.append(CGPoint(x: x, y: y)); x += sz.width + spacing; rowH = max(rowH, sz.height); maxX = max(maxX, x)
        }
        return (CGSize(width: maxX, height: y + rowH), pts)
    }
}
