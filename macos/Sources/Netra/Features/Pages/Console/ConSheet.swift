// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

/// Drives one exec session. Output/input contents live only in memory and are never logged;
/// ActivityLog gets only the target and outcome.
@MainActor @Observable
final class ConSession {
    enum Phase: Equatable { case idle, connecting, live, ended(String) }
    private(set) var phase: Phase = .idle
    private(set) var screen = ConsoleScreen()
    private(set) var revision = 0
    private var socket: ConsoleSocket?
    private var pump: Task<Void, Never>?
    private var decoder = ConsoleUTF8Decoder()
    let log: ActivityLog
    let namespace: String, name: String

    init(namespace: String, name: String, log: ActivityLog) { self.namespace = namespace; self.name = name; self.log = log }

    private var path: String { ConsoleData.execPath(namespace: namespace, name: name) }

    func connect(client: NetraClient, container: String?, cols: Int, rows: Int) {
        guard phase == .idle || { if case .ended = phase { true } else { false } }() else { return }
        screen = ConsoleScreen(); decoder = ConsoleUTF8Decoder(); phase = .connecting
        log.append(title: "Pod exec \(namespace)/\(name)", method: "GET", path: "/" + path, outcome: .attempted,
                   detail: "container: \(container ?? "default")")
        let s = ConsoleSocket(client: client, path: path, query: ConsoleData.execQuery(container: container))
        socket = s
        s.connect()
        pump = Task { [weak self] in
            for await ev in s.events {
                guard let self else { return }
                switch ev {
                case .opened:
                    self.phase = .live
                    try? await s.sendResize(cols: cols, rows: rows)
                case .binary(let d): self.append(self.decoder.feed(d))
                case .text(let t):
                    switch ConsoleData.classify(textFrame: t) {
                    case .execError(let m): self.append("[exec error] \(m)\n")
                    case .execStatus(let m): self.append("\n[exec] \(m)\n")
                    case .none: self.append(t)
                    }
                case .closed(_, let reason): self.end(reason.isEmpty ? "Session closed" : reason, ok: true)
                case .failed(let m): self.end(m, ok: false)
                }
            }
            self?.end("Session closed", ok: true)
        }
    }

    func sendLine(_ line: String) { send(Data((line + "\n").utf8)) }
    func sendInterrupt() { send(Data([0x03])) }
    func sendEOF() { send(Data([0x04])) }
    private func send(_ d: Data) {
        guard phase == .live, let s = socket else { return }
        Task { try? await s.send(data: d) }
    }
    func resize(cols: Int, rows: Int) {
        guard phase == .live, let s = socket else { return }
        Task { try? await s.sendResize(cols: cols, rows: rows) }
    }
    func disconnect() { socket?.close(); end("Disconnected", ok: true) }

    private func append(_ s: String) { guard !s.isEmpty else { return }; screen.feed(s); revision += 1 }
    private func end(_ why: String, ok: Bool) {
        if case .ended = phase { return }
        if phase == .idle { return }
        socket?.close(); socket = nil; pump?.cancel()
        phase = .ended(why)
        log.append(title: "Pod exec \(namespace)/\(name)", method: "GET", path: "/" + path, outcome: ok ? .succeeded : .failed, detail: ok ? "session ended" : why)
    }
}

/// "Open console…" entry point for a pod row.
struct ConOpenButton: View {
    let namespace: String, name: String
    @State private var show = false
    var body: some View {
        Button("Open console…", systemImage: "terminal") { show = true }
            .sheet(isPresented: $show) { ConSheet(namespace: namespace, name: name) }
    }
}

struct ConSheet: View {
    let namespace: String, name: String
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var consoleEnabled: Bool?
    @State private var containers: [String] = []
    @State private var container = ""
    @State private var typed = ""
    @State private var confirmed = false
    @State private var log = ActivityLog()
    @State private var session: ConSession?
    @State private var input = ""
    @State private var size = CGSize(width: 800, height: 400)
    @State private var loadError: String?

    private var availability: ConsoleData.Availability { ConsoleData.availability(consoleEnabled: consoleEnabled, whoami: model.whoami) }
    private var decision: GateDecision {
        ConsoleData.execDecision(whoami: model.whoami, consoleEnabled: consoleEnabled, typed: typed, namespace: namespace, name: name)
    }
    private var cols: Int { max(20, Int(size.width / 7.3)) }
    private var rows: Int { max(5, Int(size.height / 15)) }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("Console: \(namespace)/\(name)", systemImage: "terminal").font(.headline)
                Spacer()
                Button("Close") { session?.disconnect(); dismiss() }.keyboardShortcut(.cancelAction)
            }
            if case .disabled(let why) = availability {
                Label(why, systemImage: "lock.fill").foregroundStyle(.orange).font(.callout)
            } else if !confirmed {
                confirmBlock
            } else if let session {
                terminal(session)
            }
            if let loadError { Text(loadError).font(.caption).foregroundStyle(.orange) }
        }
        .padding().frame(minWidth: 760, minHeight: 520)
        .task { await load() }
        .onDisappear { session?.disconnect() }
    }

    private var confirmBlock: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("High risk: an interactive shell runs inside the pod with its service account. Your input and its output are not stored.", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.red).font(.callout)
            if containers.count > 1 {
                Picker("Container", selection: $container) { ForEach(containers, id: \.self) { Text($0).tag($0) } }.frame(maxWidth: 320)
            }
            Text("Type \(ConsoleData.execPhrase(namespace: namespace, name: name)) to continue").font(.caption).foregroundStyle(.secondary)
            HStack {
                TextField(ConsoleData.execPhrase(namespace: namespace, name: name), text: $typed).textFieldStyle(.roundedBorder).frame(maxWidth: 360)
                Button("Connect", systemImage: "bolt.fill") { start() }.disabled(decision != .allowed(confirmRiskHeader: true))
            }
        }
    }

    private func terminal(_ s: ConSession) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                switch s.phase {
                case .connecting: ProgressView().controlSize(.small); Text("Connecting…")
                case .live: Image(systemName: "circle.fill").foregroundStyle(.green).font(.caption2); Text("Connected")
                case .ended(let w): Image(systemName: "circle").foregroundStyle(.secondary).font(.caption2); Text(w)
                case .idle: EmptyView()
                }
                Spacer()
                Button("Ctrl-C") { s.sendInterrupt() }.disabled(s.phase != .live)
                Button("Ctrl-D") { s.sendEOF() }.disabled(s.phase != .live)
                if case .ended = s.phase { Button("Reconnect") { confirmed = false; typed = "" } }
                else { Button("Disconnect") { s.disconnect() } }
            }.font(.caption)
            GeometryReader { geo in
                ScrollViewReader { proxy in
                    ScrollView {
                        Text(s.screen.text + " ").font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading).id("end").padding(6)
                    }
                    .onChange(of: s.revision) { proxy.scrollTo("end", anchor: .bottom) }
                }
                .onAppear { size = geo.size }
                .onChange(of: geo.size) { _, n in size = n; s.resize(cols: cols, rows: rows) }
            }
            .background(Color.black.opacity(0.9), in: RoundedRectangle(cornerRadius: 6)).foregroundStyle(.green.opacity(0.9))
            TextField("Type a command, press Return", text: $input)
                .font(.system(.body, design: .monospaced)).textFieldStyle(.roundedBorder)
                .disabled(s.phase != .live)
                .onSubmit { s.sendLine(input); input = "" }
        }
    }

    private func start() {
        guard let c = model.client, decision == .allowed(confirmRiskHeader: true) else {
            log.append(title: "Pod exec \(namespace)/\(name)", method: "GET", path: "", outcome: .blocked, detail: "gate"); return
        }
        confirmed = true; typed = ""
        let s = ConSession(namespace: namespace, name: name, log: log)
        session = s
        s.connect(client: c, container: container.isEmpty ? nil : container, cols: cols, rows: rows)
    }

    private func load() async {
        guard let c = model.client else { return }
        do {
            consoleEnabled = ConsoleData.consoleEnabled(fromStatus: try await c.send(c.request("GET", ConsoleData.statusPath)))
        } catch { consoleEnabled = false; loadError = "Couldn't read server status: \(error.localizedDescription)" }
        if let d = try? await wlGET(c, WorkloadData.detailPath(kind: "pod", namespace: namespace, name: name)) {
            containers = WorkloadData.items(d, "containers").compactMap { $0["name"]?.string }
            if container.isEmpty { container = containers.first ?? "" }
        }
    }
}
