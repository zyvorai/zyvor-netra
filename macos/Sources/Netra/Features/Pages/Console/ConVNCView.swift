// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import AppKit
import NetraKit

/// One native VNC session. Screen contents, keystrokes and pointer positions live only in memory and are
/// never logged; ActivityLog gets only the target and outcome.
@MainActor @Observable
final class ConVNCSession {
    enum Phase: Equatable { case idle, connecting, live, ended(String) }
    private(set) var phase: Phase = .idle
    private(set) var image: CGImage?
    private(set) var size = CGSize.zero
    private var rfb: RFBClient?
    private var task: Task<Void, Never>?
    let log: ActivityLog
    let namespace: String, name: String
    private var title: String { "VM VNC \(namespace)/\(name)" }

    init(namespace: String, name: String, log: ActivityLog) { self.namespace = namespace; self.name = name; self.log = log }

    func connect(client: NetraClient) {
        guard phase == .idle || { if case .ended = phase { true } else { false } }() else { return }
        phase = .connecting; image = nil
        let path = ConsoleData.vncPath(namespace: namespace, name: name)
        log.append(title: title, method: "GET", path: "/" + path, outcome: .attempted)
        let socket = ConsoleSocket(client: client, path: path)
        socket.setMaximumMessageSize(16 << 20)
        socket.connect()
        let c = RFBClient(transport: RFBSocketTransport(socket: socket))
        rfb = c
        let sink: @Sendable (RFBMachine.Event, RFBFramebuffer) -> Void = { [weak self] event, fb in
            Task { @MainActor in self?.apply(event, fb) }
        }
        task = Task { [weak self] in
            do {
                try await c.run(onEvent: sink)
                self?.end("Session closed", ok: true)
            } catch { self?.end((error as? LocalizedError)?.errorDescription ?? error.localizedDescription, ok: false) }
        }
    }

    private func apply(_ event: RFBMachine.Event, _ fb: RFBFramebuffer) {
        switch event {
        case .ready: phase = .live; size = CGSize(width: fb.width, height: fb.height); render(fb)
        case .updated: render(fb)
        case .bell: NSSound.beep()
        }
    }

    private func render(_ fb: RFBFramebuffer) {
        guard fb.width > 0, let provider = CGDataProvider(data: Data(fb.pixels) as CFData) else { return }
        image = CGImage(width: fb.width, height: fb.height, bitsPerComponent: 8, bitsPerPixel: 32, bytesPerRow: fb.width * 4,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!,
                        bitmapInfo: CGBitmapInfo(rawValue: CGBitmapInfo.byteOrder32Little.rawValue | CGImageAlphaInfo.noneSkipFirst.rawValue),
                        provider: provider, decode: nil, shouldInterpolate: true, intent: .defaultIntent)
    }

    func pointer(x: Int, y: Int, buttons: UInt8) { guard phase == .live, let c = rfb else { return }; Task { await c.pointer(x: x, y: y, buttons: buttons) } }
    func key(_ keysym: UInt32, down: Bool) { guard phase == .live, let c = rfb else { return }; Task { await c.key(keysym: keysym, down: down) } }
    func disconnect() { end("Disconnected", ok: true) }

    private func end(_ why: String, ok: Bool) {
        if case .ended = phase { return }
        if phase == .idle { return }
        Task { [rfb] in await rfb?.close() }
        rfb = nil; task?.cancel(); phase = .ended(why)
        log.append(title: title, method: "GET", path: "/" + ConsoleData.vncPath(namespace: namespace, name: name),
                   outcome: ok ? .succeeded : .failed, detail: ok ? "session ended" : why)
    }
}

/// Maps AppKit key events to X11 keysyms (Latin-1 and BMP characters directly, specials by key code).
enum ConVNCKeys {
    static func keysym(for event: NSEvent) -> UInt32? {
        let special: [UInt16: UInt32] = [
            36: 0xFF0D, 76: 0xFF0D, 48: 0xFF09, 51: 0xFF08, 117: 0xFFFF, 53: 0xFF1B, 123: 0xFF51, 126: 0xFF52, 124: 0xFF53, 125: 0xFF54,
            115: 0xFF50, 119: 0xFF57, 116: 0xFF55, 121: 0xFF56, 122: 0xFFBE, 120: 0xFFBF, 99: 0xFFC0, 118: 0xFFC1, 96: 0xFFC2,
            97: 0xFFC3, 98: 0xFFC4, 100: 0xFFC5, 101: 0xFFC6, 109: 0xFFC7, 103: 0xFFC8, 111: 0xFFC9,
        ]
        if let s = special[event.keyCode] { return s }
        guard let u = event.characters?.unicodeScalars.first, u.value >= 0x20, !(0xF700...0xF8FF).contains(u.value) else { return nil }
        return u.value < 0x100 ? u.value : 0x0100_0000 + u.value
    }
    static func modifierKeysym(keyCode: UInt16) -> UInt32? {
        [56: 0xFFE1, 60: 0xFFE2, 59: 0xFFE3, 62: 0xFFE4, 58: 0xFFE9, 61: 0xFFEA, 55: 0xFFEB, 54: 0xFFEC][keyCode].map(UInt32.init)
    }
}

/// Draws the framebuffer and forwards mouse and keyboard when it has focus.
struct ConVNCSurface: NSViewRepresentable {
    let image: CGImage?
    let size: CGSize
    let session: ConVNCSession

    func makeNSView(context: Context) -> Surface { let v = Surface(); v.session = session; return v }
    func updateNSView(_ v: Surface, context: Context) { v.session = session; v.fbSize = size; v.layer?.contents = image }

    final class Surface: NSView {
        weak var session: ConVNCSession?
        var fbSize = CGSize.zero
        private var buttons: UInt8 = 0
        override var acceptsFirstResponder: Bool { true }
        override var isFlipped: Bool { true }
        override init(frame: NSRect) {
            super.init(frame: frame); wantsLayer = true
            layer?.backgroundColor = NSColor.black.cgColor; layer?.contentsGravity = .resizeAspect
            addTrackingArea(NSTrackingArea(rect: .zero, options: [.mouseMoved, .activeInKeyWindow, .inVisibleRect], owner: self))
        }
        required init?(coder: NSCoder) { fatalError() }

        private func map(_ e: NSEvent) -> (Int, Int)? {
            guard fbSize.width > 0, fbSize.height > 0, bounds.width > 0, bounds.height > 0 else { return nil }
            let p = convert(e.locationInWindow, from: nil)
            let scale = min(bounds.width / fbSize.width, bounds.height / fbSize.height)
            let w = fbSize.width * scale, h = fbSize.height * scale
            let ox = (bounds.width - w) / 2, oy = (bounds.height - h) / 2
            return (Int((p.x - ox) / scale), Int((p.y - oy) / scale))
        }
        private func send(_ e: NSEvent) { if let (x, y) = map(e) { session?.pointer(x: x, y: y, buttons: buttons) } }
        override func mouseMoved(with e: NSEvent) { send(e) }
        override func mouseDragged(with e: NSEvent) { send(e) }
        override func rightMouseDragged(with e: NSEvent) { send(e) }
        override func mouseDown(with e: NSEvent) { window?.makeFirstResponder(self); buttons |= 1; send(e) }
        override func mouseUp(with e: NSEvent) { buttons &= ~1; send(e) }
        override func rightMouseDown(with e: NSEvent) { buttons |= 4; send(e) }
        override func rightMouseUp(with e: NSEvent) { buttons &= ~4; send(e) }
        override func otherMouseDown(with e: NSEvent) { buttons |= 2; send(e) }
        override func otherMouseUp(with e: NSEvent) { buttons &= ~2; send(e) }
        override func scrollWheel(with e: NSEvent) {
            guard let (x, y) = map(e), e.scrollingDeltaY != 0 else { return }
            let bit: UInt8 = e.scrollingDeltaY > 0 ? 8 : 16
            session?.pointer(x: x, y: y, buttons: buttons | bit); session?.pointer(x: x, y: y, buttons: buttons)
        }
        override func keyDown(with e: NSEvent) { if let k = ConVNCKeys.keysym(for: e) { session?.key(k, down: true) } }
        override func keyUp(with e: NSEvent) { if let k = ConVNCKeys.keysym(for: e) { session?.key(k, down: false) } }
        override func performKeyEquivalent(with e: NSEvent) -> Bool {
            guard window?.firstResponder === self else { return false }
            if e.type == .keyDown { keyDown(with: e) }
            return true
        }
        override func flagsChanged(with e: NSEvent) {
            guard let k = ConVNCKeys.modifierKeysym(keyCode: e.keyCode) else { return }
            let flag: NSEvent.ModifierFlags = [56: .shift, 60: .shift, 59: .control, 62: .control, 58: .option, 61: .option, 55: .command, 54: .command][e.keyCode] ?? []
            session?.key(k, down: e.modifierFlags.contains(flag))
        }
    }
}

/// Sheet: availability + typed phrase gate, then the live framebuffer. Falls back to the browser handoff.
struct ConVNCView: View {
    let namespace: String, name: String
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var consoleEnabled: Bool?
    @State private var typed = ""
    @State private var log = ActivityLog()
    @State private var session: ConVNCSession?

    private var availability: ConsoleData.Availability { ConsoleData.availability(consoleEnabled: consoleEnabled, whoami: model.whoami) }
    private var decision: GateDecision {
        ConsoleData.vncDecision(whoami: model.whoami, consoleEnabled: consoleEnabled, typed: typed, namespace: namespace, name: name)
    }
    private var phrase: String { ConsoleData.vncPhrase(namespace: namespace, name: name) }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("VNC: \(namespace)/\(name)", systemImage: "display").font(.headline)
                Spacer()
                Button("Close") { session?.disconnect(); dismiss() }.keyboardShortcut(.cancelAction)
            }
            if case .disabled(let why) = availability {
                Label(why, systemImage: "lock.fill").foregroundStyle(.orange).font(.callout)
            } else if let session { screen(session) } else { confirmBlock }
            if session == nil || { if case .ended(let w) = session?.phase { w.contains("authentication") || w.contains("protocol") || w.contains("encoding") } else { false } }() {
                ConVNCHandoff(namespace: namespace, name: name)
            }
        }
        .padding().frame(minWidth: 820, minHeight: 620)
        .task {
            guard let c = model.client else { return }
            consoleEnabled = (try? await c.send(c.request("GET", ConsoleData.statusPath))).map(ConsoleData.consoleEnabled(fromStatus:)) ?? false
        }
        .onDisappear { session?.disconnect() }
    }

    private var confirmBlock: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("High risk: you see and control the VM's screen, keyboard and mouse. Only VNC without a password is supported; screen contents and keystrokes are never stored or logged.", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.red).font(.callout)
            Text("Type \(phrase) to continue").font(.caption).foregroundStyle(.secondary)
            HStack {
                TextField(phrase, text: $typed).textFieldStyle(.roundedBorder).frame(maxWidth: 360)
                Button("Connect", systemImage: "bolt.fill") { start() }.disabled(decision != .allowed(confirmRiskHeader: true))
            }
        }
    }

    private func screen(_ s: ConVNCSession) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                switch s.phase {
                case .connecting: ProgressView().controlSize(.small); Text("Connecting…")
                case .live: Image(systemName: "circle.fill").foregroundStyle(.green).font(.caption2); Text("Connected. Click the screen to type.")
                case .ended(let w): Image(systemName: "circle").foregroundStyle(.secondary).font(.caption2); Text(w).lineLimit(3)
                case .idle: EmptyView()
                }
                Spacer()
                if case .ended = s.phase { Button("Reconnect") { session = nil; typed = "" } }
                else { Button("Disconnect") { s.disconnect() } }
            }.font(.caption)
            ConVNCSurface(image: s.image, size: s.size, session: s)
                .clipShape(RoundedRectangle(cornerRadius: 6))
        }
    }

    private func start() {
        guard let c = model.client, decision == .allowed(confirmRiskHeader: true) else {
            log.append(title: "VM VNC \(namespace)/\(name)", method: "GET", path: "", outcome: .blocked, detail: "gate"); return
        }
        typed = ""
        let s = ConVNCSession(namespace: namespace, name: name, log: log)
        session = s
        s.connect(client: c)
    }
}
