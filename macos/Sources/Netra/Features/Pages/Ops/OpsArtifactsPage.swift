// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import AppKit
import NetraKit

/// Capture artifacts. There is no list route for /capture/artifacts, so ids come from GET /capture/history
/// (entries with an artifactId). Download is a binary GET; Wireshark is offered only when installed.
struct OpsArtifactsPage: View {
    @Environment(AppModel.self) private var model
    @State private var rows: [ControlRow] = []
    @State private var selection: ControlRow.ID?
    @State private var context: String?
    @State private var error: String?
    @State private var message: String?
    @State private var busy = false
    private let wireshark = OpsData.wiresharkInstalled()

    private var selected: ControlRow? { rows.first { $0.id == selection } }
    private var artifactID: String { selected?.text("artifactId") ?? "" }

    var body: some View {
        if model.client == nil || model.whoami == nil { OpsNotConnected() } else {
            HSplitView {
                VStack(spacing: 0) {
                    if let error { Text(error).foregroundStyle(.red).font(.callout).padding(8) }
                    if let message { Text(message).foregroundStyle(.green).font(.callout).padding(8) }
                    Table(rows, selection: $selection) {
                        TableColumn("Artifact") { (r: ControlRow) in Text(r.text("artifactId")).lineLimit(1) }
                        TableColumn("Node") { (r: ControlRow) in Text(r.text("node")) }
                        TableColumn("Trigger") { (r: ControlRow) in Text([r.text("triggerSource"), r.text("triggerKind")].filter { !$0.isEmpty }.joined(separator: "/")) }
                        TableColumn("Frames") { (r: ControlRow) in Text(r.text("artifactFrames")) }
                        TableColumn("Bytes") { (r: ControlRow) in Text(r.text("artifactBytes")) }
                        TableColumn("Context") { (r: ControlRow) in Text(r.text("contextAvailable") == "true" ? "yes" : "") }
                        TableColumn("Ended") { (r: ControlRow) in Text(r.text("endedAt")) }
                    }
                    .overlay { if rows.isEmpty { ContentUnavailableView("No artifacts", systemImage: "doc.zipper", description: Text("Auto-capture writes a PCAP here when it is configured (NETRA_AUTO_CAPTURE_DIR).")) } }
                }.frame(minWidth: 480)
                detail.frame(minWidth: 260, idealWidth: 320)
            }
            .navigationTitle("Artifacts")
            .navigationSubtitle("from api/v1/capture/history")
            .toolbar {
                Button("Download PCAP…", systemImage: "arrow.down.circle") { Task { await downloadPCAP(openInWireshark: false) } }
                    .disabled(!OpsData.isSafeArtifactID(artifactID) || busy)
                if wireshark {
                    Button("Open in Wireshark", systemImage: "waveform.path.ecg") { Task { await downloadPCAP(openInWireshark: true) } }
                        .disabled(!OpsData.isSafeArtifactID(artifactID) || busy)
                }
                Button("Refresh", systemImage: "arrow.clockwise") { Task { await load() } }
            }
            .task { await load() }
            .task(id: selection) { context = nil; await loadContext() }
        }
    }

    @ViewBuilder private var detail: some View {
        ScrollView {
            if let r = selected {
                VStack(alignment: .leading, spacing: 8) {
                    Text(pretty(r.value)).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    if r.text("contextAvailable") == "true" {
                        Divider()
                        Text("Drop-incident context").font(.headline)
                        Text(context ?? "Loading…").font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        Button("Save context JSON…") { Task { await saveContext() } }.disabled(!OpsData.isSafeArtifactID(artifactID))
                    }
                }.frame(maxWidth: .infinity, alignment: .leading).padding()
            } else { ContentUnavailableView("No selection", systemImage: "sidebar.right", description: Text("Select an artifact.")) }
        }
    }

    private func pretty(_ v: JSONValue) -> String {
        let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return (try? e.encode(v)).map { String(decoding: $0, as: UTF8.self) } ?? v.summary
    }

    private func load() async {
        guard let c = model.client else { return }
        do {
            let v = try JSONDecoder().decode(JSONValue.self, from: await c.send(c.request("GET", "api/v1/capture/history", query: [.init(name: "limit", value: "200")])))
            rows = OpsData.artifactRows(fromHistory: v); error = nil
        } catch { rows = []; self.error = opsDescribe(error) }
    }

    private func loadContext() async {
        guard let c = model.client, OpsData.isSafeArtifactID(artifactID), selected?.text("contextAvailable") == "true" else { return }
        do {
            let f = try await c.download("api/v1/capture/artifacts/\(artifactID)/context")
            context = String(decoding: f.data.prefix(64 * 1024), as: UTF8.self)
        } catch { context = opsDescribe(error) }
    }

    private func saveContext() async {
        guard let c = model.client else { return }
        do {
            let f = try await c.download("api/v1/capture/artifacts/\(artifactID)/context")
            if let p = OpsSave.save(f.data, suggestedName: f.filename ?? "\(artifactID).context.json") { message = "Saved to \(p)" }
        } catch { self.error = opsDescribe(error) }
    }

    private func downloadPCAP(openInWireshark: Bool) async {
        guard let c = model.client, OpsData.isSafeArtifactID(artifactID) else { return }
        busy = true; message = nil; error = nil; defer { busy = false }
        do {
            let f = try await c.download("api/v1/capture/artifacts/\(artifactID)")
            let name = f.filename ?? "\(artifactID).pcap"
            if openInWireshark {
                let dir = FileManager.default.temporaryDirectory.appendingPathComponent("netra-pcap", isDirectory: true)
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                let url = dir.appendingPathComponent(name)
                try f.data.write(to: url, options: .atomic)
                _ = try await NSWorkspace.shared.open([url], withApplicationAt: URL(fileURLWithPath: OpsData.wiresharkPath), configuration: .init())
                message = "Opened \(name) in Wireshark"
            } else if let p = OpsSave.save(f.data, suggestedName: name) { message = "Saved to \(p)" }
        } catch { self.error = opsDescribe(error) }
    }
}
