// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Alerts only notify. Ack and silence change notification state; they never touch mode, rules or policy.
struct AlertsPage: View {
    @Environment(AppModel.self) private var model
    @State private var snap = Poller<MetricAlertSnapshot>()
    @State private var actionError: String?
    @State private var showSilence = false
    @State private var sRule = ""
    @State private var sNode = ""
    @State private var sChart = ""
    @State private var sDuration = "2h"
    @State private var sComment = ""

    private var canMutate: Bool { model.gate.canMutate }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text("Metric alerts").font(.title3.weight(.semibold))
                    Spacer()
                    if let s = snap.value?.stats {
                        StatusBadge(text: "\(s.critical) critical", tint: alertTint("critical"))
                        StatusBadge(text: "\(s.warning) warning", tint: alertTint("warning"))
                    }
                }
                Label("Ack and silence change notification state only. They do not change rules, mode or policy.", systemImage: "bell.slash")
                    .font(.caption).foregroundStyle(.secondary)
                if !canMutate { Text("This token is read-only; ack and silence are disabled.").font(.caption).foregroundStyle(.secondary) }
                if let e = snap.error { ErrorBanner(text: e) }
                if let e = actionError { ErrorBanner(text: e) }

                if let s = snap.value {
                    if s.active.isEmpty {
                        ContentUnavailableView("No raised alerts", systemImage: "checkmark.circle", description: Text("\(s.rules.count) rules evaluating."))
                            .frame(height: 160)
                    }
                    ForEach(s.active) { a in alertRow(a) }
                    silences(s)
                    if !s.history.isEmpty {
                        Text("Recent transitions").font(.headline)
                        ForEach(s.history.prefix(15), id: \.rowID) { t in
                            Text("\(relative(t.time))  \(t.rule) on \(t.node): \(t.from) to \(t.to)").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                } else if snap.error == nil { ProgressView().frame(maxWidth: .infinity) }
            }.padding(16)
        }
        .navigationTitle("Alerts")
        .task { await loop() }
        .sheet(isPresented: $showSilence) { silenceForm }
    }

    private func alertRow(_ a: MetricAlert) -> some View {
        HStack(alignment: .top) {
            StatusBadge(text: a.status.capitalized, tint: alertTint(a.status))
            VStack(alignment: .leading, spacing: 2) {
                Text(a.rule).font(.callout.weight(.medium))
                Text("\(a.node) · \(a.chart)\(a.dimension.map { " / " + $0 } ?? "")").font(.caption).foregroundStyle(.secondary)
                if let i = a.info, !i.isEmpty { Text(i).font(.caption2).foregroundStyle(.secondary) }
                HStack(spacing: 6) {
                    if let v = a.value { Text(MetricsFormat.value(v, units: a.units)).font(.caption.monospacedDigit()) }
                    Text("since " + relative(a.since)).font(.caption2).foregroundStyle(.secondary)
                    if a.silenced == true { StatusBadge(text: "Silenced", tint: .secondary) }
                    if a.acked == true { StatusBadge(text: "Acked" + (a.ackedBy.map { " by \($0)" } ?? ""), tint: .secondary) }
                }
            }
            Spacer()
            Button("Acknowledge") { Task { await ack(a) } }
                .disabled(!canMutate || a.acked == true)
                .help("Marks this alert acknowledged (notification state only)")
        }
        .padding(10).background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
    }

    private func silences(_ s: MetricAlertSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Silences").font(.headline)
                Spacer()
                Button("New silence") { showSilence = true }.disabled(!canMutate)
                    .help("Suppresses notifications only; alert status is still tracked")
            }
            if s.silences.isEmpty { Text("None").font(.caption).foregroundStyle(.secondary) }
            ForEach(s.silences) { x in
                HStack {
                    VStack(alignment: .leading, spacing: 1) {
                        Text([x.rule, x.node, x.chart].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ").nilIfEmpty ?? "all alerts").font(.callout)
                        Text("until \(MetricsFormat.parseTime(x.until)?.formatted(date: .abbreviated, time: .shortened) ?? x.until)" + ((x.comment ?? "").isEmpty ? "" : " · \(x.comment!)"))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Remove", role: .destructive) { Task { await unsilence(x) } }.disabled(!canMutate)
                }
            }
        }
    }

    private var silenceForm: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("New silence").font(.headline)
            Text("Suppresses notifications for matching alerts. Globs allowed (*). Notification state only.").font(.caption).foregroundStyle(.secondary)
            TextField("Rule", text: $sRule); TextField("Node", text: $sNode); TextField("Chart", text: $sChart)
            TextField("Duration (e.g. 2h)", text: $sDuration); TextField("Comment", text: $sComment)
            HStack {
                Spacer()
                Button("Cancel") { showSilence = false }
                Button("Create silence") { Task { await createSilence() } }
                    .keyboardShortcut(.defaultAction).disabled(!canMutate || sDuration.isEmpty || (sRule + sNode + sChart).isEmpty)
            }
        }.textFieldStyle(.roundedBorder).padding().frame(width: 400)
    }

    private func loop() async {
        while !Task.isCancelled {
            guard let c = model.client else { return }
            await snap.refresh { try await c.metricsAlerts() }
            try? await Task.sleep(for: .seconds(5))
        }
    }

    private func run(_ op: @Sendable (NetraClient) async throws -> Void) async {
        guard canMutate, let c = model.client else { return }
        do { try await op(c); actionError = nil } catch { actionError = snap.message(error) }
        await snap.refresh { try await c.metricsAlerts() }
    }
    private func ack(_ a: MetricAlert) async { let id = a.id; await run { try await $0.ackMetricAlert(id: id) } }
    private func unsilence(_ s: MetricSilence) async { let id = s.id; await run { try await $0.deleteMetricSilence(id: id) } }
    private func createSilence() async {
        let (r, n, ch, d, cm) = (sRule, sNode, sChart, sDuration, sComment)
        await run { _ = try await $0.addMetricSilence(rule: r, node: n, chart: ch, duration: d, comment: cm) }
        if actionError == nil { showSilence = false; sRule = ""; sNode = ""; sChart = ""; sComment = "" }
    }
}

private extension String { var nilIfEmpty: String? { isEmpty ? nil : self } }
