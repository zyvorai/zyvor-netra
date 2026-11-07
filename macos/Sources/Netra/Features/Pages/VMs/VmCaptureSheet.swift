// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import AppKit
import UniformTypeIdentifiers
import NetraKit

/// Subscribes to GET /api/v1/vms/{node}/capture/ws (an already-running capture; this never starts or stops
/// one) and records frames into an in-memory pcap, capped at VMCapture.maxRecordingBytes. Only counts and the
/// outcome are logged; packet bytes are never logged.
@MainActor @Observable
final class VmCaptureSession {
    enum Phase: Equatable { case idle, connecting, live, ended(String) }
    private(set) var phase: Phase = .idle
    private(set) var frames = 0
    private(set) var bytes = 0
    private(set) var dropped = 0
    private(set) var bad = 0
    @ObservationIgnored private(set) var pcap = PCAPBuilder()
    private var socket: ConsoleSocket?
    private var task: Task<Void, Never>?
    let log: ActivityLog
    let node: String
    init(node: String, log: ActivityLog) { self.node = node; self.log = log }
    private var path: String { VMCapture.capturePath(node: node) }

    func connect(client: NetraClient) {
        guard phase == .idle else { return }
        phase = .connecting; pcap = PCAPBuilder(); frames = 0; bytes = 0; dropped = 0; bad = 0
        log.append(title: "VM capture stream \(node)", method: "GET", path: "/" + path, outcome: .attempted)
        let s = ConsoleSocket(client: client, path: path)
        socket = s; s.connect()
        task = Task { [weak self] in
            for await ev in s.events {
                guard let self else { return }
                switch ev {
                case .opened: self.phase = .live
                case .binary(let d):
                    self.phase = .live
                    if let f = try? VMCapture.decode(d) {
                        if self.pcap.append(f) { self.frames += 1; self.bytes += d.count } else { self.dropped += 1 }
                    } else { self.bad += 1 }
                case .text: break
                case .closed(_, let r): self.end(r.isEmpty ? "Stream closed" : r, ok: true)
                case .failed(let m): self.end(m, ok: false)
                }
            }
            self?.end("Stream closed", ok: true)
        }
    }
    func stop() { end("Stopped", ok: true) }
    private func end(_ why: String, ok: Bool) {
        if case .ended = phase { return }
        if phase == .idle { return }
        socket?.close(); socket = nil; task?.cancel(); phase = .ended(why)
        log.append(title: "VM capture stream \(node)", method: "GET", path: "/" + path, outcome: ok ? .succeeded : .failed,
                   detail: ok ? "\(frames) frames recorded" : why)
    }
}

struct VmCaptureSheet: View {
    let node: String
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var typed = ""
    @State private var log = ActivityLog()
    @State private var session: VmCaptureSession?
    @State private var saveError: String?

    private var decision: GateDecision { VMCapture.decision(whoami: model.whoami, typed: typed, node: node) }
    private var phrase: String { VMCapture.phrase(node: node) }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("Capture stream: \(node)", systemImage: "record.circle").font(.headline)
                Spacer()
                Button("Close") { session?.stop(); dismiss() }.keyboardShortcut(.cancelAction)
            }
            if case .disabled(let why) = VMCapture.availability(whoami: model.whoami) {
                Label(why, systemImage: "lock.fill").foregroundStyle(.orange).font(.callout)
            } else if let s = session { live(s) } else { confirm }
            if let saveError { Text(saveError).font(.caption).foregroundStyle(.orange) }
        }
        .padding().frame(minWidth: 520, minHeight: 260)
        .onDisappear { session?.stop() }
    }

    private var confirm: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("High risk: packet bytes from \(node) are streamed to this Mac and kept in memory until you save or close. Observe only: this does not start or stop a capture (use Control > Capture first).", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.red).font(.callout)
            Text("Type \(phrase) to continue").font(.caption).foregroundStyle(.secondary)
            HStack {
                TextField(phrase, text: $typed).textFieldStyle(.roundedBorder).frame(maxWidth: 360)
                Button("Subscribe", systemImage: "bolt.fill") {
                    guard let c = model.client, decision == .allowed(confirmRiskHeader: true) else { return }
                    typed = ""
                    let s = VmCaptureSession(node: node, log: log); session = s; s.connect(client: c)
                }.disabled(decision != .allowed(confirmRiskHeader: true))
            }
        }
    }

    private func live(_ s: VmCaptureSession) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                switch s.phase {
                case .connecting: ProgressView().controlSize(.small); Text("Connecting…")
                case .live: Image(systemName: "circle.fill").foregroundStyle(.green).font(.caption2); Text("Receiving")
                case .ended(let w): Image(systemName: "circle").foregroundStyle(.secondary).font(.caption2); Text(w)
                case .idle: EmptyView()
                }
            }
            Text("\(s.frames) frames, \(ByteCountFormatter.string(fromByteCount: Int64(s.bytes), countStyle: .binary))"
                 + (s.dropped > 0 ? ", \(s.dropped) dropped (memory cap)" : "") + (s.bad > 0 ? ", \(s.bad) malformed" : ""))
                .monospacedDigit()
            Text("Nothing arrives until a capture is running on this node.").font(.caption).foregroundStyle(.secondary)
            HStack {
                Button("Save .pcap…", systemImage: "square.and.arrow.down") { save(s) }.disabled(s.frames == 0)
                if case .ended = s.phase {} else { Button("Stop") { s.stop() } }
            }
        }
    }

    private func save(_ s: VmCaptureSession) {
        let p = NSSavePanel()
        p.allowedContentTypes = [UTType(filenameExtension: "pcap") ?? .data]
        p.nameFieldStringValue = "netra-\(node).pcap"
        guard p.runModal() == .OK, let url = p.url else { return }
        do { try s.pcap.data.write(to: url, options: .atomic); saveError = nil }
        catch { saveError = "Couldn't save: \(error.localizedDescription)" }
    }
}
