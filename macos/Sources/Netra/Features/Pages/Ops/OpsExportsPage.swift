// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

/// SIEM pull exports: GET /export/status, then /export/{flows,events,blocks,audit}?format=&limit= saved to disk.
struct OpsExportsPage: View {
    @Environment(AppModel.self) private var model
    @State private var status: JSONValue?
    @State private var kind: OpsExportKind = .flows
    @State private var format: OpsExportFormat = .json
    @State private var limit = 200
    @State private var busy = false
    @State private var message: String?
    @State private var error: String?

    var body: some View {
        if model.client == nil || model.whoami == nil { OpsNotConnected() } else {
            Form {
                Section("Export") {
                    Picker("Source", selection: $kind) { ForEach(OpsExportKind.allCases) { Text($0.title).tag($0) } }
                    Picker("Format", selection: $format) { ForEach(OpsExportFormat.allCases) { Text($0.rawValue).tag($0) } }
                    Stepper("Limit: \(limit)", value: $limit, in: 1...kind.maxLimit, step: kind.maxLimit >= 1000 ? 100 : 50)
                    Text("Server default \(kind.defaultLimit), maximum \(kind.maxLimit). otlp-trace turns each blocked event into a span.")
                        .font(.caption).foregroundStyle(.secondary)
                    HStack {
                        Button("Export and save…", systemImage: "square.and.arrow.down") { Task { await export() } }.disabled(busy)
                        if busy { ProgressView().controlSize(.small) }
                    }
                    if let message { Label(message, systemImage: "checkmark.circle").foregroundStyle(.green) }
                    if let error { Label(error, systemImage: "xmark.octagon").foregroundStyle(.red) }
                }
                Section("Server status (GET /export/status)") {
                    if let s = status {
                        row("Formats", (s["formats"]?.controlItems ?? []).compactMap(\.string).joined(separator: ", "))
                        row("Syslog push", s["syslogEnabled"] == .bool(true) ? "on: \(s["syslogAddr"]?.string ?? "") (\(s["syslogNetwork"]?.string ?? ""), \(s["syslogFormat"]?.string ?? ""))" : "off")
                        row("Pull endpoints", (s["pull"]?.controlItems ?? []).compactMap(\.string).joined(separator: "\n"))
                        if let n = s["note"]?.string { Text(n).font(.caption).foregroundStyle(.secondary) }
                    } else { Text("Loading…").foregroundStyle(.secondary) }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Exports")
            .toolbar { Button("Refresh", systemImage: "arrow.clockwise") { Task { await loadStatus() } } }
            .task { await loadStatus() }
            .onChange(of: kind) { _, k in limit = min(max(limit, 1), k.maxLimit) }
        }
    }

    private func row(_ k: String, _ v: String) -> some View {
        LabeledContent(k) { Text(v).textSelection(.enabled).multilineTextAlignment(.trailing) }
    }

    private func loadStatus() async {
        guard let c = model.client else { return }
        do { status = try JSONDecoder().decode(JSONValue.self, from: await c.send(c.request("GET", "api/v1/export/status"))); error = nil }
        catch { self.error = opsDescribe(error) }
    }

    private func export() async {
        guard let c = model.client else { return }
        busy = true; message = nil; error = nil; defer { busy = false }
        do {
            let f = try await c.download(kind.path, query: OpsData.exportQuery(format: format, limit: limit, kind: kind))
            let name = OpsData.exportFilename(kind: kind, format: format)
            if let r = OpsSave.save(f.data, suggestedName: name) {
                if r.hasPrefix("Could not") { error = r } else { message = "Saved \(f.recordCount.map { "\($0) record(s), " } ?? "")\(f.data.count) bytes to \(r)" }
            }
        } catch { self.error = opsDescribe(error) }
    }
}
